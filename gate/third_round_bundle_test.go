// SPDX-License-Identifier: Apache-2.0

package gate

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBundleHelperRejectsUnsupportedOrEmptyEvidence(t *testing.T) {
	for _, tc := range []struct{ name, stats, lock, want string }{{"empty", `{"modules":[]}`, `{"lockfileVersion":3,"packages":{}}`, "0 components"}, {"lock", `{"modules":[]}`, `{"lockfileVersion":1}`, "npm package-lock v2/v3"}, {"stats", `{"fictional":true}`, `{"lockfileVersion":3,"packages":{}}`, "webpack module graph"}} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			stats, lock := filepath.Join(dir, "fixture-stats.json"), filepath.Join(dir, "fictional-lock.json")
			if e := os.WriteFile(stats, []byte(tc.stats), 0o600); e != nil {
				t.Fatal(e)
			}
			if e := os.WriteFile(lock, []byte(tc.lock), 0o600); e != nil {
				t.Fatal(e)
			}
			e := WriteBundle(context.Background(), stats, lock, filepath.Join(dir, "bundle.cdx.json"))
			if e == nil || !strings.Contains(e.Error(), tc.want) || !strings.Contains(e.Error(), stats) || !strings.Contains(e.Error(), lock) {
				t.Fatalf("helper error %v", e)
			}
			if _, err := os.Stat(stats); err != nil {
				t.Fatal("failed helper consumed stats")
			}
		})
	}
}

func TestTagPatternsIgnorePrereleases(t *testing.T) {
	r, e := tagVersions([]string{"fictional-v2026.10.2", "fictional-v2026.10.2-rc1"}, `^fictional-v([0-9]+(?:\.[0-9]+)*)(?:-rc[0-9]+)?$`)
	if e != nil || len(r.versions) != 1 || len(r.ignored) != 1 {
		t.Fatalf("tags=%+v err=%v", r, e)
	}
	for _, pattern := range []string{`^[0-9]+$`, `^(fictional)-([0-9]+)$`} {
		if _, e := tagVersions(nil, pattern); e == nil {
			t.Fatal("capture count not validated")
		}
	}
}
