// SPDX-License-Identifier: Apache-2.0

package gate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	v6 "github.com/anchore/grype/grype/db/v6"
	"github.com/anchore/grype/grype/db/v6/distribution"
	"github.com/klauspost/compress/zstd"
	"github.com/wagoodman/go-progress"
)

// Grype's distribution API has no context parameter; this client keeps downloads cancellable.
type databaseClient struct {
	ctx       context.Context
	latestURL string
	http      *http.Client
}

func (c databaseClient) Latest() (*distribution.LatestDocument, error) {
	ctx, cancel := context.WithTimeout(c.ctx, 30*time.Second)
	defer cancel()
	r, e := c.get(ctx, c.latestURL)
	if e != nil {
		return nil, e
	}
	defer func() { _ = r.Body.Close() }()
	doc, e := distribution.NewLatestFromReader(io.LimitReader(r.Body, 1<<20))
	if e != nil {
		return nil, e
	}
	if doc == nil || !doc.SchemaVersion.Valid() || doc.SchemaVersion.Model != v6.ModelVersion || doc.Path == "" || doc.Built.IsZero() {
		return nil, fmt.Errorf("invalid vulnerability database listing")
	}
	return doc, nil
}

func (c databaseClient) IsUpdateAvailable(current *v6.Description) (*distribution.Archive, error) {
	latest, e := c.Latest()
	if e != nil {
		return nil, e
	}
	if current == nil || (!current.Built.Equal(latest.Built.Time) && latest.Built.After(current.Built.Time)) {
		return &latest.Archive, nil
	}
	return nil, nil
}

func (c databaseClient) ResolveArchiveURL(archive distribution.Archive) (string, error) {
	u, e := url.Parse(c.latestURL)
	if e != nil {
		return "", e
	}
	u.Path = path.Join(path.Dir(u.Path), archive.Path)
	query := u.Query()
	query.Set("checksum", archive.Checksum)
	u.RawQuery = query.Encode()
	return u.String(), nil
}

func (c databaseClient) get(ctx context.Context, address string) (*http.Response, error) {
	req, e := http.NewRequestWithContext(ctx, http.MethodGet, address, nil)
	if e != nil {
		return nil, e
	}
	req.Header.Set("User-Agent", "rdy embedded-grype/0.119.0")
	r, e := c.http.Do(req)
	if e != nil {
		return nil, e
	}
	if r.StatusCode != http.StatusOK {
		_ = r.Body.Close()
		return nil, fmt.Errorf("database HTTP %d", r.StatusCode)
	}
	return r, nil
}

func (c databaseClient) Download(address, dest string, monitor *progress.Manual) (result string, err error) {
	if monitor != nil {
		defer monitor.SetCompleted()
	}
	u, err := url.Parse(address)
	if err != nil {
		return "", err
	}
	checksum := u.Query().Get("checksum")
	if !strings.HasPrefix(checksum, "sha256:") {
		return "", fmt.Errorf("database archive requires SHA256 checksum")
	}
	expected, err := hex.DecodeString(strings.TrimPrefix(checksum, "sha256:"))
	if err != nil || len(expected) != sha256.Size {
		return "", fmt.Errorf("invalid database archive checksum")
	}
	query := u.Query()
	query.Del("checksum")
	u.RawQuery = query.Encode()
	downloadCtx, pulse, stop := watchProgress(c.ctx, 2*time.Minute, func(d time.Duration, f func()) idleTimer { return time.AfterFunc(d, f) })
	defer stop()
	response, err := c.get(downloadCtx, u.String())
	if err != nil {
		return "", err
	}
	defer func() { _ = response.Body.Close() }()
	if err = os.MkdirAll(dest, 0o700); err != nil {
		return "", err
	}
	scratch, err := os.MkdirTemp(dest, "rdy-db-download-")
	if err != nil {
		return "", err
	}
	defer func() {
		if err != nil {
			_ = os.RemoveAll(scratch)
		}
	}()
	archive, err := os.Create(filepath.Join(scratch, "archive.tar.zst"))
	if err != nil {
		return "", err
	}
	hash := sha256.New()
	_, copyErr := io.Copy(io.MultiWriter(archive, hash), io.LimitReader(progressReader{response.Body, pulse}, 4<<30))
	closeErr := archive.Close()
	stop()
	if copyErr != nil {
		return "", copyErr
	}
	if closeErr != nil {
		return "", closeErr
	}
	if !strings.EqualFold(hex.EncodeToString(hash.Sum(nil)), hex.EncodeToString(expected)) {
		return "", fmt.Errorf("database archive checksum mismatch")
	}
	archive, err = os.Open(filepath.Join(scratch, "archive.tar.zst"))
	if err != nil {
		return "", err
	}
	defer func() { _ = archive.Close() }()
	decoder, err := zstd.NewReader(archive)
	if err != nil {
		return "", err
	}
	defer decoder.Close()
	payload := scratch
	if err = os.MkdirAll(payload, 0o700); err != nil {
		return "", err
	}
	if err = extractTarLimited(c.ctx, decoder, payload, 8<<30, 8<<30); err != nil {
		return "", err
	}
	decoder.Close()
	if err = archive.Close(); err != nil {
		return "", err
	}
	if err = os.Remove(filepath.Join(scratch, "archive.tar.zst")); err != nil {
		return "", err
	}
	return payload, nil
}
