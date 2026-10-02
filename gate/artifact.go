// SPDX-License-Identifier: Apache-2.0

// Package gate contains the I/O boundaries of rdy.
package gate

import (
	"archive/tar"
	"archive/zip"
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

func command(ctx context.Context, dir, name string, args ...string) ([]byte, error) {
	c := exec.CommandContext(ctx, name, args...)
	c.Dir = dir
	var stderr strings.Builder
	c.Stderr = &stderr
	b, e := c.Output()
	if e != nil {
		return nil, fmt.Errorf("%s: %s: %w", name, strings.TrimSpace(stderr.String()), e)
	}
	return b, nil
}

// Missing lists every non-merge patch from previous absent on branch.
func Missing(ctx context.Context, repo, branch, previous string) ([]string, error) {
	if previous == "" {
		return nil, nil
	}
	b, e := command(ctx, repo, "git", "log", "--no-merges", "--cherry-pick", "--right-only", "--format=%H %s", branch+"..."+previous, "--")
	if e != nil {
		return nil, e
	}
	s := strings.TrimSpace(string(b))
	if s == "" {
		return nil, nil
	}
	return strings.Split(s, "\n"), nil
}

func target(root, name string) (string, error) {
	if strings.Contains(name, "\\") || (runtime.GOOS == "windows" && strings.Contains(name, ":")) || filepath.IsAbs(name) || strings.HasPrefix(name, "/") {
		return "", fmt.Errorf("unsafe archive path %q", name)
	}
	p := filepath.Join(root, filepath.FromSlash(name))
	r, e := filepath.Rel(root, p)
	if e != nil || r == ".." || strings.HasPrefix(r, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("unsafe archive path %q", name)
	}
	return p, nil
}

func writeMember(path string, r io.Reader, size int64) error {
	return writeMemberLimited(path, r, size, 1<<30)
}

func writeMemberLimited(path string, r io.Reader, size, limit int64) error {
	if size < 0 || size > limit {
		return fmt.Errorf("archive member exceeds size limit")
	}
	if e := os.MkdirAll(filepath.Dir(path), 0o700); e != nil {
		return e
	}
	f, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if e != nil {
		return e
	}
	_, copyErr := io.CopyN(f, r, size)
	closeErr := f.Close()
	if copyErr != nil {
		return copyErr
	}
	return closeErr
}

func manifest(data []byte) string {
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	var lines []string
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			break
		}
		if strings.HasPrefix(line, " ") && len(lines) > 0 {
			lines[len(lines)-1] += line[1:]
		} else {
			lines = append(lines, line)
		}
	}
	for _, line := range lines {
		key, value, ok := strings.Cut(line, ":")
		if ok && strings.EqualFold(key, "Implementation-Version") {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

// Extract safely extracts supported artifacts and reads the declared version.
func Extract(ctx context.Context, artifact, root string) (string, error) {
	return extract(ctx, artifact, root, nil)
}

func extract(ctx context.Context, artifact, root string, links *int) (string, error) {
	if e := ctx.Err(); e != nil {
		return "", e
	}
	if e := os.MkdirAll(root, 0o700); e != nil {
		return "", e
	}
	extension := strings.ToLower(filepath.Ext(artifact))
	switch extension {
	case ".jar", ".war":
		z, e := zip.OpenReader(artifact)
		if e != nil {
			return "", e
		}
		defer func() { _ = z.Close() }()
		var version string
		var total int64
		for _, f := range z.File {
			if e = ctx.Err(); e != nil {
				return "", e
			}
			p, err := target(root, f.Name)
			if err != nil {
				return "", err
			}
			if f.Mode()&os.ModeSymlink != 0 {
				return "", fmt.Errorf("symlinks are not permitted")
			}
			if f.FileInfo().IsDir() {
				if e = os.MkdirAll(p, 0o700); e != nil {
					return "", e
				}
				continue
			}
			if f.UncompressedSize64 > 1<<30 {
				return "", fmt.Errorf("archive member too large")
			}
			size := int64(f.UncompressedSize64)
			total += size
			if total > 4<<30 {
				return "", fmt.Errorf("archive exceeds 4 GiB")
			}
			r, err := f.Open()
			if err != nil {
				return "", err
			}
			err = writeMember(p, r, size)
			closeErr := r.Close()
			if err != nil {
				return "", err
			}
			if closeErr != nil {
				return "", closeErr
			}
			if f.Name == "META-INF/MANIFEST.MF" {
				data, err := os.ReadFile(p)
				if err != nil {
					return "", err
				}
				version = manifest(data)
			}
		}
		return version, nil
	case ".rpm", ".deb":
		var b []byte
		var e error
		declared, e := artifactVersion(ctx, artifact, command)
		b = []byte(declared)
		if e != nil {
			return "", e
		}
		scratch, e := os.MkdirTemp("", "rdy-tar-")
		if e != nil {
			return "", e
		}
		defer func() { _ = os.RemoveAll(scratch) }()
		archive := filepath.Join(scratch, "payload.tar")
		if _, e = command(ctx, "", "bsdtar", "-cf", archive, "@"+artifact); e != nil {
			return "", e
		}
		if e = extractTarFile(ctx, archive, root, links); e != nil {
			return "", e
		}
		if extension == ".deb" {
			paths, e := filepath.Glob(filepath.Join(root, "data.tar*"))
			if e != nil {
				return "", e
			}
			if len(paths) != 1 {
				return "", fmt.Errorf("deb has no unique data archive")
			}
			if _, e = command(ctx, "", "bsdtar", "-cf", archive, "@"+paths[0]); e != nil {
				return "", e
			}
			if e = extractTarFile(ctx, archive, root, links); e != nil {
				return "", e
			}
		}
		return strings.TrimSpace(string(b)), nil
	default:
		return "", fmt.Errorf("unsupported artifact %q; supported types: .jar .war .rpm .deb, or --sbom", artifact)
	}
}

func extractTarFile(ctx context.Context, path, root string, links *int) error {
	f, e := os.Open(path)
	if e != nil {
		return e
	}
	defer func() { _ = f.Close() }()
	n, err := extractTarCoverage(ctx, f, root, 1<<30, 4<<30)
	if links != nil {
		*links += n
	}
	return err
}

func extractTarLimited(ctx context.Context, reader io.Reader, root string, memberLimit, totalLimit int64) error {
	_, err := extractTarPolicy(ctx, reader, root, memberLimit, totalLimit, rejectLinks)
	return err
}

type linkPolicy bool

const (
	rejectLinks linkPolicy = false
	skipLinks   linkPolicy = true
)

func extractTarCoverage(ctx context.Context, reader io.Reader, root string, memberLimit, totalLimit int64) (int, error) {
	return extractTarPolicy(ctx, reader, root, memberLimit, totalLimit, skipLinks)
}

func extractTarPolicy(ctx context.Context, reader io.Reader, root string, memberLimit, totalLimit int64, policy linkPolicy) (links int, err error) {
	r := tar.NewReader(contextReader{ctx, reader})
	var e error
	var total int64
	for {
		if e = ctx.Err(); e != nil {
			return links, e
		}
		h, err := r.Next()
		if err == io.EOF {
			return links, nil
		}
		if err != nil {
			return links, err
		}
		p, err := target(root, h.Name)
		if err != nil {
			return links, err
		}
		switch h.Typeflag {
		case tar.TypeDir:
			if e = os.MkdirAll(p, 0o700); e != nil {
				return links, e
			}
		case tar.TypeSymlink, tar.TypeLink:
			if policy == rejectLinks {
				return links, fmt.Errorf("links are not permitted in vulnerability database archives")
			}
			links++
			continue
		case tar.TypeReg:
			total += h.Size
			if total > totalLimit {
				return links, fmt.Errorf("archive exceeds size limit")
			}
			if e = writeMemberLimited(p, r, h.Size, memberLimit); e != nil {
				return links, e
			}
		default:
			return links, fmt.Errorf("unsupported archive member %s", h.Name)
		}
	}
}

func artifactVersion(ctx context.Context, artifact string, run func(context.Context, string, string, ...string) ([]byte, error)) (string, error) {
	var data []byte
	var err error
	if strings.EqualFold(filepath.Ext(artifact), ".rpm") {
		data, err = run(ctx, "", "rpm", "-qp", "--queryformat", "%{VERSION}", "--", artifact)
	} else {
		data, err = run(ctx, "", "dpkg-deb", "--field", "--", artifact, "Version")
	}
	return strings.TrimSpace(string(data)), err
}
