// SPDX-License-Identifier: Apache-2.0

package gate

import (
	"archive/tar"
	"bufio"
	"compress/bzip2"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/klauspost/compress/zstd"
	rpmutils "github.com/sassoftware/go-rpmutils"
	"github.com/ulikunitz/xz"
	"github.com/ulikunitz/xz/lzma"
)

const (
	memberLimit = 1 << 30
	totalLimit  = 4 << 30
)

// extractRPM writes an RPM's regular files and directories under root and returns the
// header VERSION. Symlinks and hard-link placeholders are skipped and counted in links.
func extractRPM(ctx context.Context, path, root string, links *int) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	pkg, err := rpmutils.ReadRpm(f)
	if err != nil {
		return "", fmt.Errorf("rpm header: %w", err)
	}
	version, err := pkg.Header.GetString(rpmutils.VERSION)
	if err != nil {
		return "", fmt.Errorf("rpm version: %w", err)
	}
	infos, err := pkg.Header.GetFiles()
	if err != nil {
		return "", fmt.Errorf("rpm file list: %w", err)
	}
	payload, err := rpmPayload(f, pkg.Header)
	if err != nil {
		return "", err
	}
	var total int64
	skipped := 0
	err = walkCpio(ctx, payload, infos, func(fi rpmutils.FileInfo, body io.Reader) error {
		if fi == nil {
			skipped++ // hard link without content
			return nil
		}
		name := strings.TrimPrefix(strings.TrimPrefix(fi.Name(), "."), "/")
		p, err := target(root, name)
		if err != nil {
			return err
		}
		switch fi.Mode() & 0o170000 {
		case 0o040000:
			return os.MkdirAll(p, 0o700)
		case 0o120000:
			skipped++
			return nil
		case 0o100000:
			if total += fi.Size(); total > totalLimit {
				return fmt.Errorf("archive exceeds size limit")
			}
			return writeMemberLimited(p, body, fi.Size(), memberLimit)
		}
		return fmt.Errorf("unsupported archive member %s", name)
	})
	if links != nil {
		*links += skipped
	}
	return strings.TrimSpace(version), err
}

// rpmPayload decompresses the cpio payload that follows an RPM header.
func rpmPayload(r io.Reader, hdr *rpmutils.RpmHeader) (io.Reader, error) {
	if hdr.HasTag(rpmutils.PAYLOADFORMAT) {
		if f, err := hdr.GetString(rpmutils.PAYLOADFORMAT); err == nil && f != "cpio" {
			return nil, fmt.Errorf("unsupported rpm payload format %q", f)
		}
	}
	comp := "gzip"
	if hdr.HasTag(rpmutils.PAYLOADCOMPRESSOR) {
		c, err := hdr.GetString(rpmutils.PAYLOADCOMPRESSOR)
		if err != nil {
			return nil, err
		}
		comp = c
	}
	switch comp {
	case "gzip":
		return gzip.NewReader(r)
	case "bzip2":
		return bzip2.NewReader(r), nil
	case "xz":
		return xz.NewReader(r)
	case "lzma":
		return lzma.NewReader(r)
	case "zstd":
		d, err := zstd.NewReader(r)
		if err != nil {
			return nil, err
		}
		return d.IOReadCloser(), nil
	case "", "identity":
		return r, nil
	}
	return nil, fmt.Errorf("unsupported rpm payload compressor %q", comp)
}

// cpioCounter tracks bytes read for cpio's four-byte alignment.
type cpioCounter struct {
	r *bufio.Reader
	n int64
}

func (c *cpioCounter) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

func (c *cpioCounter) skip(n int64) error {
	if m, err := io.CopyN(io.Discard, c, n); err != nil || m != n {
		return fmt.Errorf("truncated rpm payload: %w", errors.Join(err, io.ErrUnexpectedEOF))
	}
	return nil
}

func (c *cpioCounter) align() error { return c.skip((4 - c.n%4) % 4) }

// walkCpio reads a newc cpio archive as RPM writes it, including RPM's stripped entries
// ("07070X" plus an index into files, written by RPM 6 and for files over 4 GiB), whose
// name and size come from the header. visit gets nil metadata for hard-link entries that
// carry no content.
func walkCpio(ctx context.Context, r io.Reader, files []rpmutils.FileInfo, visit func(rpmutils.FileInfo, io.Reader) error) error {
	byName := make(map[string]int, len(files))
	for i, fi := range files {
		byName[fi.Name()] = i
	}
	c := &cpioCounter{r: bufio.NewReaderSize(r, 64<<10)}
	magic := make([]byte, 6)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		if _, err := io.ReadFull(c, magic); err != nil {
			return fmt.Errorf("rpm payload entry: %w", err)
		}
		var fi rpmutils.FileInfo
		var size int64
		switch string(magic) {
		case "07070X":
			idx, err := cpioField(c)
			if err != nil {
				return err
			}
			if idx < 0 || idx >= int64(len(files)) {
				return fmt.Errorf("rpm payload refers to file %d of %d", idx, len(files))
			}
			fi = files[idx]
			if t := fi.Mode() & 0o170000; t == 0o100000 || t == 0o120000 {
				size = fi.Size() // directories and other types carry no content
			}
		case "070701":
			var fields [13]int64
			for i := range fields {
				v, err := cpioField(c)
				if err != nil {
					return err
				}
				fields[i] = v
			}
			var namesize int64
			size, namesize = fields[6], fields[11]
			if namesize < 1 || namesize > 4096 || size < 0 {
				return fmt.Errorf("rpm payload entry has name size %d and file size %d", namesize, size)
			}
			raw := make([]byte, namesize)
			if _, err := io.ReadFull(c, raw); err != nil {
				return fmt.Errorf("rpm payload entry name: %w", err)
			}
			name := strings.TrimPrefix(strings.TrimSuffix(string(raw), "\x00"), ".")
			if name == "TRAILER!!!" {
				return nil
			}
			idx, ok := byName[name]
			if !ok {
				return fmt.Errorf("rpm payload entry %q is not in the header", name)
			}
			fi = files[idx]
			// Directories carry a header size but no content, so only regular files are
			// checked: a hard link set stores content once, on its last entry.
			if fi.Mode()&0o170000 == 0o100000 {
				switch {
				case size == 0 && fi.Size() > 0:
					fi = nil
				case size != fi.Size():
					return fmt.Errorf("rpm payload entry %s is %d bytes, header says %d", name, size, fi.Size())
				}
			}
		default:
			return fmt.Errorf("rpm payload has bad entry magic %q", magic)
		}
		if err := c.align(); err != nil {
			return err
		}
		start := c.n
		if err := visit(fi, io.LimitReader(c, size)); err != nil {
			return err
		}
		if err := c.skip(size - (c.n - start)); err != nil {
			return err
		}
		if err := c.align(); err != nil {
			return err
		}
	}
}

func cpioField(r io.Reader) (int64, error) {
	b := make([]byte, 8)
	if _, err := io.ReadFull(r, b); err != nil {
		return 0, fmt.Errorf("rpm payload header: %w", err)
	}
	v, err := strconv.ParseInt(string(b), 16, 64)
	if err != nil {
		return 0, fmt.Errorf("rpm payload header field %q", b)
	}
	return v, nil
}

// extractDEB writes a .deb's ar members under root, then extracts the unique data archive
// there. It returns the raw control Version field.
func extractDEB(ctx context.Context, path, root string, links *int) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	br := bufio.NewReader(f)
	magic := make([]byte, 8)
	if _, err := io.ReadFull(br, magic); err != nil || string(magic) != "!<arch>\n" {
		return "", fmt.Errorf("not a deb archive")
	}
	var control, data []string
	var total int64
	for {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		name, size, err := arMember(br)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return "", err
		}
		p, err := target(root, name)
		if err != nil {
			return "", err
		}
		if total += size; total > totalLimit {
			return "", fmt.Errorf("archive exceeds size limit")
		}
		if err := writeMemberLimited(p, br, size, memberLimit); err != nil {
			return "", err
		}
		if size%2 == 1 {
			if _, err := br.Discard(1); err != nil && !errors.Is(err, io.EOF) {
				return "", err
			}
		}
		switch {
		case strings.HasPrefix(name, "control.tar"):
			control = append(control, p)
		case strings.HasPrefix(name, "data.tar"):
			data = append(data, p)
		}
	}
	if len(control) != 1 {
		return "", fmt.Errorf("deb has no unique control archive")
	}
	if len(data) != 1 {
		return "", fmt.Errorf("deb has no unique data archive")
	}
	version, err := debVersion(control[0])
	if err != nil {
		return "", err
	}
	n, err := withTarStream(data[0], func(r io.Reader) (int, error) {
		return extractTarCoverage(ctx, r, root, memberLimit, totalLimit)
	})
	if links != nil {
		*links += n
	}
	return version, err
}

// arMember reads one 60-byte ar member header.
func arMember(r io.Reader) (string, int64, error) {
	h := make([]byte, 60)
	if _, err := io.ReadFull(r, h); err != nil {
		if errors.Is(err, io.ErrUnexpectedEOF) {
			return "", 0, fmt.Errorf("truncated deb member header")
		}
		return "", 0, err
	}
	if string(h[58:60]) != "`\n" {
		return "", 0, fmt.Errorf("bad deb member header")
	}
	size, err := strconv.ParseInt(strings.TrimSpace(string(h[48:58])), 10, 64)
	if err != nil || size < 0 {
		return "", 0, fmt.Errorf("bad deb member size %q", h[48:58])
	}
	return strings.TrimSuffix(strings.TrimSpace(string(h[:16])), "/"), size, nil
}

// withTarStream opens a tar file, decompressing it by suffix, and passes the stream to fn.
func withTarStream(path string, fn func(io.Reader) (int, error)) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer func() { _ = f.Close() }()
	var r io.Reader
	switch name := filepath.Base(path); {
	case strings.HasSuffix(name, ".gz"):
		r, err = gzip.NewReader(f)
	case strings.HasSuffix(name, ".xz"):
		r, err = xz.NewReader(f)
	case strings.HasSuffix(name, ".zst"):
		var d *zstd.Decoder
		if d, err = zstd.NewReader(f); err == nil {
			defer d.Close()
			r = d
		}
	case strings.HasSuffix(name, ".bz2"):
		r = bzip2.NewReader(f)
	case strings.HasSuffix(name, ".tar"):
		r = f
	default:
		return 0, fmt.Errorf("unsupported deb member compression %s", name)
	}
	if err != nil {
		return 0, err
	}
	return fn(r)
}

// debVersion reads the Version field of the control file in a control archive.
func debVersion(path string) (string, error) {
	var version string
	_, err := withTarStream(path, func(r io.Reader) (int, error) {
		tr := tar.NewReader(r)
		for {
			h, err := tr.Next()
			if errors.Is(err, io.EOF) {
				return 0, fmt.Errorf("deb control archive has no control file")
			}
			if err != nil {
				return 0, err
			}
			if strings.TrimPrefix(h.Name, "./") != "control" {
				continue
			}
			sc := bufio.NewScanner(io.LimitReader(tr, 1<<20))
			for sc.Scan() {
				if k, v, ok := strings.Cut(sc.Text(), ":"); ok && strings.EqualFold(strings.TrimSpace(k), "Version") {
					version = strings.TrimSpace(v)
					return 0, nil
				}
			}
			return 0, fmt.Errorf("deb control file has no Version")
		}
	})
	return version, err
}
