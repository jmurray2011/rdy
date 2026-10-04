// SPDX-License-Identifier: Apache-2.0

package gate

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNativeVersionNormalization(t *testing.T) {
	for _, tc := range []struct{ raw, source, want string }{{"1:2.4.0-3", "dpkg control", "2.4.0"}, {"2.4.0-1", "dpkg control", "2.4.0"}, {"2.4.0~rc1", "rpm header", "2.4.0"}, {"2.4.0^git1", "rpm header", "2.4.0"}, {"v2.4.0", "manifest", "v2.4.0"}} {
		if got := normalizeDeclared(tc.raw, tc.source); got != tc.want {
			t.Fatalf("normalize %s: %s", tc.raw, got)
		}
	}
}

func TestJavaScriptWithoutPackageMetadata(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"node_modules/unknown/a.js", "node_modules/unknown/a.mjs", "node_modules/unknown/a.cjs", "node_modules/known/dist/a.js"} {
		path := filepath.Join(root, filepath.FromSlash(name))
		if e := os.MkdirAll(filepath.Dir(path), 0o700); e != nil {
			t.Fatal(e)
		}
		if e := os.WriteFile(path, []byte("fixture"), 0o600); e != nil {
			t.Fatal(e)
		}
	}
	if e := os.WriteFile(filepath.Join(root, "node_modules", "known", "package.json"), []byte(`{"name":"known","version":"1"}`), 0o600); e != nil {
		t.Fatal(e)
	}
	n, e := javascriptFiles(context.Background(), root)
	if e != nil || n != 3 {
		t.Fatalf("count=%d err=%v", n, e)
	}
}

func TestUnsupportedExtractNamesInput(t *testing.T) {
	input := "fictional/image:latest"
	_, e := Extract(context.Background(), input, t.TempDir())
	if e == nil || !strings.Contains(e.Error(), input) || !strings.Contains(e.Error(), ".jar .war .rpm .deb, or --sbom") {
		t.Fatalf("extract error %v", e)
	}
}
