// SPDX-License-Identifier: Apache-2.0

package gate_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/jmurray2011/rdy/gate"
)

func TestWriteEmbeddedBundle(t *testing.T) {
	dir := t.TempDir()
	stats := filepath.Join(dir, "stats.json")
	lock := filepath.Join(dir, "lock.json")
	out := filepath.Join(dir, "bundle.cdx.json")
	if e := os.WriteFile(stats, []byte(`{"modules":[{"name":"./node_modules/sample/dist/index.js"}]}`), 0o600); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(lock, []byte(`{"lockfileVersion":2,"packages":{"node_modules/sample":{"version":"1"}}}`), 0o600); e != nil {
		t.Fatal(e)
	}
	if e := gate.WriteBundle(context.Background(), stats, lock, out); e != nil {
		t.Fatal(e)
	}
	if _, e := os.Stat(stats); !os.IsNotExist(e) {
		t.Fatal("stats must be removed before packaging")
	}
	if _, e := os.Stat(lock); e != nil {
		t.Fatal(e)
	}
	b, e := os.ReadFile(out)
	if e != nil {
		t.Fatal(e)
	}
	if len(b) == 0 {
		t.Fatal("missing bundle SBOM")
	}
}

func TestBundleOutputHardlinksPreserveInputs(t *testing.T) {
	for _, which := range []string{"stats", "lock"} {
		t.Run(which, func(t *testing.T) {
			dir := t.TempDir()
			stats, lock, out := filepath.Join(dir, "stats.json"), filepath.Join(dir, "lock.json"), filepath.Join(dir, "bundle.cdx.json")
			sb, lb := []byte(`{"modules":[]}`), []byte(`{"lockfileVersion":3,"packages":{}}`)
			if e := os.WriteFile(stats, sb, 0o600); e != nil {
				t.Fatal(e)
			}
			if e := os.WriteFile(lock, lb, 0o600); e != nil {
				t.Fatal(e)
			}
			input := stats
			if which == "lock" {
				input = lock
			}
			if e := os.Link(input, out); e != nil {
				t.Fatal(e)
			}
			if e := gate.WriteBundle(context.Background(), stats, lock, out); e == nil {
				t.Fatal("accepted output alias")
			}
			for p, want := range map[string][]byte{stats: sb, lock: lb} {
				got, e := os.ReadFile(p)
				if e != nil || string(got) != string(want) {
					t.Fatalf("input changed: %s %v", p, e)
				}
			}
		})
	}
}
