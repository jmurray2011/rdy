// SPDX-License-Identifier: Apache-2.0

package gate

import (
	"context"
	"os"
	"os/exec"
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

func TestDPKGArtifactArgumentSeparator(t *testing.T) {
	_, e := artifactVersion(context.Background(), "-fictional.deb", func(_ context.Context, _ string, name string, args ...string) ([]byte, error) {
		if name != "dpkg-deb" || strings.Join(args, " ") != "--field -- -fictional.deb Version" {
			t.Fatalf("unsafe args %v", args)
		}
		return []byte("1:2.4.0-3"), nil
	})
	if e != nil {
		t.Fatal(e)
	}
}

func TestRealDEBWithEpochRevisionAndSymlink(t *testing.T) {
	for _, name := range []string{"dpkg-deb", "bsdtar"} {
		if _, e := exec.LookPath(name); e != nil {
			t.Skipf("real DEB fixture requires %s on PATH", name)
		}
	}
	root := t.TempDir()
	pkg := filepath.Join(root, "package")
	control := filepath.Join(pkg, "DEBIAN")
	payload := filepath.Join(pkg, "usr", "share", "fictional")
	if e := os.MkdirAll(control, 0o755); e != nil {
		t.Fatal(e)
	}
	if e := os.MkdirAll(payload, 0o700); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(filepath.Join(control, "control"), []byte("Package: fictional-gate-fixture\nVersion: 1:2.4.0-3\nArchitecture: all\nMaintainer: Fixture <fixture@example.invalid>\nDescription: Fictional fixture\n"), 0o600); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(filepath.Join(payload, "data.txt"), []byte("fixture"), 0o600); e != nil {
		t.Fatal(e)
	}
	if e := os.Symlink("data.txt", filepath.Join(payload, "current")); e != nil {
		t.Fatal(e)
	}
	artifact := filepath.Join(root, "fixture.deb")
	if _, e := command(context.Background(), "", "dpkg-deb", "--build", pkg, artifact); e != nil {
		t.Fatal(e)
	}
	links := 0
	raw, e := extract(context.Background(), artifact, filepath.Join(root, "out"), &links)
	if e != nil || raw != "1:2.4.0-3" || normalizeDeclared(raw, "dpkg control") != "2.4.0" || links != 1 {
		t.Fatalf("raw=%s links=%d err=%v", raw, links, e)
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
