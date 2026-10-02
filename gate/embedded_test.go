// SPDX-License-Identifier: Apache-2.0

package gate_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jmurray2011/rdy/gate"
)

func TestEmbeddedCatalogWithoutExecutables(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("PATH", t.TempDir())
	if e := os.WriteFile(filepath.Join(dir, "bundle.cdx.json"), []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"components":[{"type":"library","name":"fictional-bundle","version":"1","purl":"pkg:npm/fictional-bundle@1","bom-ref":"pkg:npm/fictional-bundle@1"}]}`), 0o600); e != nil {
		t.Fatal(e)
	}
	s := gate.NewEmbedded(gate.EmbeddedOptions{DBCache: t.TempDir(), Offline: true})
	b, e := s.Generate(context.Background(), dir)
	if e != nil {
		t.Fatal(e)
	}
	if !strings.Contains(string(b), "pkg:npm/fictional-bundle@1") {
		t.Fatalf("embedded SBOM lost: %s", b)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e = s.Generate(ctx, dir); !errors.Is(e, context.Canceled) {
		t.Fatalf("cancellation: %v", e)
	}
}

func TestEmbeddedOfflineMissingDatabase(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "input.cdx.json")
	if e := os.WriteFile(path, []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"components":[]}`), 0o600); e != nil {
		t.Fatal(e)
	}
	s := gate.NewEmbedded(gate.EmbeddedOptions{DBCache: t.TempDir(), Offline: true})
	if _, e := s.Scan(context.Background(), path); e == nil {
		t.Fatal("missing DB must not read clean")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := s.Scan(ctx, path); !errors.Is(e, context.Canceled) {
		t.Fatalf("cancellation: %v", e)
	}
}
