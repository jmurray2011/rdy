// SPDX-License-Identifier: Apache-2.0

package gate

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type fakeIdleTimer struct {
	reset   int
	stopped bool
}

func (f *fakeIdleTimer) Reset(_ time.Duration) bool { f.reset++; return true }
func (f *fakeIdleTimer) Stop() bool                 { f.stopped = true; return true }
func TestProgressTimeoutAndHTTPTransport(t *testing.T) {
	var expire func()
	ft := &fakeIdleTimer{}
	ctx, pulse, stop := watchProgress(context.Background(), time.Minute, func(_ time.Duration, f func()) idleTimer { expire = f; return ft })
	defer stop()
	for i := 0; i < 100; i++ {
		pulse()
	}
	if ctx.Err() != nil || ft.reset != 100 {
		t.Fatal("live progress interrupted")
	}
	expire()
	if ctx.Err() == nil {
		t.Fatal("idle download not canceled")
	}
	stop()
	if !ft.stopped {
		t.Fatal("timer leaked")
	}
	client := databaseHTTPClient()
	if client.Timeout != 0 {
		t.Fatal("whole-download timeout")
	}
	tr := client.Transport.(*http.Transport)
	if tr.DialContext == nil || tr.ResponseHeaderTimeout == 0 || tr.TLSHandshakeTimeout == 0 {
		t.Fatal("connection/header timeout missing")
	}
}

func TestStaleScratchCleanupKeepsActiveAndUnrelated(t *testing.T) {
	root := t.TempDir()
	now := time.Date(2099, 1, 3, 0, 0, 0, 0, time.UTC)
	old := now.Add(-48 * time.Hour)
	for _, n := range []string{"rdy-db-download-old", "rdy-db-download-live", "other"} {
		p := filepath.Join(root, n)
		if err := os.Mkdir(p, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(p, old, old); err != nil {
			t.Fatal(err)
		}
	}
	live := filepath.Join(root, "rdy-db-download-live", "archive.tar.zst")
	if err := os.WriteFile(live, []byte("progress"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(live, now, now); err != nil {
		t.Fatal(err)
	}
	if err := cleanupDatabaseScratch(context.Background(), root, now); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "rdy-db-download-old")); !os.IsNotExist(err) {
		t.Fatal("stale retained")
	}
	for _, n := range []string{"rdy-db-download-live", "other"} {
		if _, err := os.Stat(filepath.Join(root, n)); err != nil {
			t.Fatal(err)
		}
	}
}
