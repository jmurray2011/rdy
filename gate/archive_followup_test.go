// SPDX-License-Identifier: Apache-2.0

package gate

import (
	"archive/tar"
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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

func TestUppercaseRPMVersionRoute(t *testing.T) {
	called := ""
	v, err := artifactVersion(context.Background(), "APP.RPM", func(_ context.Context, _ string, name string, args ...string) ([]byte, error) {
		called = name
		return []byte("2.4.0"), nil
	})
	if err != nil || called != "rpm" || v != "2.4.0" {
		t.Fatalf("called=%s version=%s err=%v", called, v, err)
	}
}

func TestRealRPMWithSkippedSymlink(t *testing.T) {
	for _, name := range []string{"rpmbuild", "rpm", "bsdtar"} {
		if _, err := exec.LookPath(name); err != nil {
			t.Skipf("real RPM fixture requires %s on PATH", name)
		}
	}
	top := t.TempDir()
	for _, d := range []string{"BUILD", "BUILDROOT", "RPMS", "SOURCES", "SPECS", "SRPMS"} {
		if err := os.Mkdir(filepath.Join(top, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	spec := filepath.Join(top, "SPECS", "fictional.spec")
	body := `Name: fictional-gate-fixture
Version: 2.4.0
Release: 1
Summary: Fictional gate test
License: MIT
BuildArch: noarch
%description
Fictional fixture.
%install
mkdir -p %{buildroot}/usr/share/fictional
printf fixture > %{buildroot}/usr/share/fictional/data.txt
ln -s data.txt %{buildroot}/usr/share/fictional/current
%files
/usr/share/fictional
`
	if err := os.WriteFile(spec, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := command(context.Background(), "", "rpmbuild", "--define", "_topdir "+top, "-bb", spec); err != nil {
		t.Fatal(err)
	}
	files, err := filepath.Glob(filepath.Join(top, "RPMS", "noarch", "*.rpm"))
	if err != nil || len(files) != 1 {
		t.Fatal("no unique fixture RPM")
	}
	upper := filepath.Join(top, "APP.RPM")
	if err := os.Rename(files[0], upper); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(top, "out")
	links := 0
	version, err := extract(context.Background(), upper, root, &links)
	if err != nil || version != "2.4.0" || links != 1 {
		t.Fatalf("version=%s links=%d err=%v", version, links, err)
	}
	data, err := os.ReadFile(filepath.Join(root, "usr", "share", "fictional", "data.txt"))
	if err != nil || !strings.Contains(string(data), "fixture") {
		t.Fatal("payload absent")
	}
}
