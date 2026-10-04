// SPDX-License-Identifier: Apache-2.0

package gate

import (
	"archive/tar"
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestTarCoverageAndBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name    string
		headers []*tar.Header
		bad     bool
		links   int
	}{
		{"traversal", []*tar.Header{{Name: "../outside", Typeflag: tar.TypeReg}}, true, 0},
		{"absolute", []*tar.Header{{Name: "/outside", Typeflag: tar.TypeReg}}, true, 0},
		{"oversize", []*tar.Header{{Name: "huge", Typeflag: tar.TypeReg, Size: 9}}, true, 0},
		{"links", []*tar.Header{{Name: "sym", Typeflag: tar.TypeSymlink, Linkname: "../outside"}, {Name: "hard", Typeflag: tar.TypeLink, Linkname: "missing"}}, false, 2},
		{"device", []*tar.Header{{Name: "dev", Typeflag: tar.TypeChar}}, true, 0},
		{"duplicate", []*tar.Header{{Name: "same", Typeflag: tar.TypeReg}, {Name: "same", Typeflag: tar.TypeReg}}, true, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var b bytes.Buffer
			w := tar.NewWriter(&b)
			for _, h := range tc.headers {
				if err := w.WriteHeader(h); err != nil {
					t.Fatal(err)
				}
				if h.Size > 0 {
					_, _ = w.Write(make([]byte, h.Size))
				}
			}
			if err := w.Close(); err != nil {
				t.Fatal(err)
			}
			root := t.TempDir()
			n, err := extractTarCoverage(context.Background(), &b, root, 8, 16)
			if (err != nil) != tc.bad || n != tc.links {
				t.Fatalf("links=%d err=%v", n, err)
			}
			for _, name := range []string{"sym", "hard"} {
				if _, err := os.Lstat(filepath.Join(root, name)); !os.IsNotExist(err) {
					t.Fatal("link created")
				}
			}
		})
	}
}

func TestJavaMatcherAuditUsesActualConfiguration(t *testing.T) {
	c := defaultMatcherConfig()
	if c.Java.UseCPEs {
		t.Fatal("Java CPE matching enabled")
	}
	if scannerAudit(c, false)["match"].(map[string]any)["java"].(map[string]bool)["using-cpes"] {
		t.Fatal("audit enabled")
	}
	c.Java.UseCPEs = true
	if !scannerAudit(c, false)["match"].(map[string]any)["java"].(map[string]bool)["using-cpes"] {
		t.Fatal("audit does not reflect configuration")
	}
}
