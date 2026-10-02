// SPDX-License-Identifier: Apache-2.0

package gate_test

import (
	"archive/zip"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jmurray2011/rdy/gate"
)

func git(t *testing.T, dir string, args ...string) string {
	t.Helper()
	c := exec.CommandContext(context.Background(), "git", args...)
	c.Dir = dir
	b, e := c.CombinedOutput()
	if e != nil {
		t.Fatalf("git %v: %s: %v", args, b, e)
	}
	return strings.TrimSpace(string(b))
}

func commit(t *testing.T, dir, file, value string) {
	t.Helper()
	if e := os.WriteFile(filepath.Join(dir, file), []byte(value), 0o600); e != nil {
		t.Fatal(e)
	}
	git(t, dir, "add", file)
	git(t, dir, "commit", "-m", value)
}

func TestMissingPatches(t *testing.T) {
	for _, mode := range []string{"missing", "cherry-picked", "later-merge"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			git(t, dir, "init", "-b", "main")
			git(t, dir, "config", "user.email", "fixture@example.invalid")
			git(t, dir, "config", "user.name", "Fixture")
			commit(t, dir, "base", "base")
			git(t, dir, "tag", "1.0.2")
			git(t, dir, "branch", "candidate")
			commit(t, dir, "fix", "fix")
			fix := git(t, dir, "rev-parse", "HEAD")
			if mode == "later-merge" {
				git(t, dir, "checkout", "-b", "side")
				commit(t, dir, "side", "side")
				git(t, dir, "checkout", "main")
				git(t, dir, "merge", "--no-ff", "side", "-m", "merge")
			}
			git(t, dir, "tag", "1.0.3")
			git(t, dir, "checkout", "candidate")
			if mode != "missing" {
				commit(t, dir, "candidate", "candidate")
				git(t, dir, "cherry-pick", fix)
				if mode == "later-merge" {
					git(t, dir, "cherry-pick", "side")
				}
			}
			got, e := gate.Missing(context.Background(), dir, "candidate", "1.0.3")
			if e != nil {
				t.Fatal(e)
			}
			want := 0
			if mode == "missing" {
				want = 1
			}
			if len(got) != want {
				t.Fatalf("missing %v, want %d", got, want)
			}
		})
	}
}

func TestJarExtraction(t *testing.T) {
	for _, unsafe := range []bool{false, true} {
		t.Run(map[bool]string{false: "valid", true: "traversal"}[unsafe], func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "app.jar")
			f, e := os.Create(path)
			if e != nil {
				t.Fatal(e)
			}
			z := zip.NewWriter(f)
			name := "META-INF/MANIFEST.MF"
			if unsafe {
				name = "../escape"
			}
			w, e := z.Create(name)
			if e != nil {
				t.Fatal(e)
			}
			if _, e = w.Write([]byte("Manifest-Version: 1.0\r\nImplementation-Version: 1.0.2\r\n\r\n")); e != nil {
				t.Fatal(e)
			}
			if e = z.Close(); e != nil {
				t.Fatal(e)
			}
			if e = f.Close(); e != nil {
				t.Fatal(e)
			}
			version, e := gate.Extract(context.Background(), path, filepath.Join(dir, "out"))
			if unsafe {
				if e == nil {
					t.Fatal("accepted traversal")
				}
				return
			}
			if e != nil || version != "1.0.2" {
				t.Fatalf("%s %v", version, e)
			}
		})
	}
}
