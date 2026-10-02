// SPDX-License-Identifier: Apache-2.0

package gate

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDatabaseHTTPContextAndChecksum(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/latest.json" {
			_, _ = w.Write([]byte(`{"status":"active","schemaVersion":"v6.0.0","built":"2099-01-01T00:00:00Z","path":"db.tar.zst","checksum":"sha256:0000000000000000000000000000000000000000000000000000000000000000"}`))
			return
		}
		_, _ = w.Write([]byte("corrupt archive"))
	}))
	defer server.Close()
	c := databaseClient{ctx: context.Background(), latestURL: server.URL + "/latest.json", http: server.Client()}
	latest, e := c.Latest()
	if e != nil {
		t.Fatal(e)
	}
	if latest.Path != "db.tar.zst" {
		t.Fatal("missing archive")
	}
	url, e := c.ResolveArchiveURL(latest.Archive)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = c.Download(url, t.TempDir(), nil); e == nil || !strings.Contains(e.Error(), "checksum") {
		t.Fatalf("checksum: %v", e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	c.ctx = ctx
	if _, e = c.Latest(); !errors.Is(e, context.Canceled) {
		t.Fatalf("cancel: %v", e)
	}
}
