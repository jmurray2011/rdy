// SPDX-License-Identifier: Apache-2.0

package gate

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type idleTimer interface {
	Reset(time.Duration) bool
	Stop() bool
}

func watchProgress(parent context.Context, idle time.Duration, after func(time.Duration, func()) idleTimer) (context.Context, func(), func()) {
	ctx, cancel := context.WithCancel(parent)
	var mu sync.Mutex
	done := false
	timer := after(idle, func() {
		mu.Lock()
		defer mu.Unlock()
		if !done {
			done = true
			cancel()
		}
	})
	pulse := func() {
		mu.Lock()
		defer mu.Unlock()
		if !done {
			timer.Reset(idle)
		}
	}
	stop := func() { mu.Lock(); defer mu.Unlock(); done = true; timer.Stop(); cancel() }
	return ctx, pulse, stop
}

func databaseHTTPClient() *http.Client {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.DialContext = (&net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}).DialContext
	tr.ResponseHeaderTimeout = 30 * time.Second
	tr.TLSHandshakeTimeout = 10 * time.Second
	return &http.Client{Transport: tr}
}

type progressReader struct {
	reader io.Reader
	pulse  func()
}

func (r progressReader) Read(p []byte) (int, error) {
	n, e := r.reader.Read(p)
	if n > 0 {
		r.pulse()
	}
	return n, e
}

// Only abandoned directories older than a day are removed. A live download updates
// its archive mtime; links and unrelated directories are never traversed.
func cleanupDatabaseScratch(ctx context.Context, root string, now time.Time) error {
	base, err := filepath.Abs(root)
	if err != nil {
		return err
	}
	info, err := os.Stat(base)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("database scratch cache root is not a directory")
	}
	entries, err := os.ReadDir(base)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return err
		}
		if !strings.HasPrefix(entry.Name(), "rdy-db-download-") || !entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
			continue
		}
		p := filepath.Join(base, entry.Name())
		rel, err := filepath.Rel(base, p)
		if err != nil || filepath.IsAbs(rel) || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return fmt.Errorf("scratch path outside database cache")
		}
		info, err := entry.Info()
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return err
		}
		newest := info.ModTime()
		children, err := os.ReadDir(p)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return err
		}
		for _, child := range children {
			info, err := child.Info()
			if os.IsNotExist(err) {
				continue
			}
			if err != nil {
				return err
			}
			if info.ModTime().After(newest) {
				newest = info.ModTime()
			}
		}
		if newest.Before(now.Add(-24 * time.Hour)) {
			if err := os.RemoveAll(p); err != nil {
				return err
			}
		}
	}
	return nil
}

func databaseScratchWarnings(ctx context.Context, root string, now time.Time) ([]Warning, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	err := cleanupDatabaseScratch(ctx, root, now)
	if err == nil || os.IsNotExist(err) {
		return nil, nil
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return []Warning{{ID: "db-cleanup-failed", Message: "database scratch cleanup failed: " + err.Error()}}, nil
}
