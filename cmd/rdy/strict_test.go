// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jmurray2011/rdy/core"
	"github.com/jmurray2011/rdy/gate"
)

func TestStrictUnknownWarningUsage(t *testing.T) {
	for _, args := range [][]string{{"--strict", "--allow-warning", "fictional-unknown"}, {"--allow-warning", "fictional-unknown"}} {
		var out, stderr bytes.Buffer
		code := run(context.Background(), args, &out, &stderr)
		if code != 2 {
			t.Fatal(code)
		}
		for _, id := range gate.WarningIDs() {
			if !strings.Contains(stderr.String(), id) {
				t.Fatalf("missing %s: %s", id, &stderr)
			}
		}
	}
}

func TestStrictVerdictExit(t *testing.T) {
	for _, pass := range []bool{false, true} {
		var out, stderr bytes.Buffer
		r := gate.Result{Pass: pass, Line: "fictional verdict"}
		code := finish(context.Background(), "", t.TempDir(), r, &out, &stderr)
		want := 1
		if pass {
			want = 0
		}
		if code != want || !strings.Contains(out.String(), r.Line) {
			t.Fatalf("%d %s", code, &out)
		}
	}
}

func TestStrictRepeatableFlags(t *testing.T) {
	var out, stderr bytes.Buffer
	code := run(context.Background(), []string{"--strict", "--allow-warning", "tags-ignored,frontend-not-covered", "--allow-warning", "commit-not-asserted"}, &out, &stderr)
	if code != 2 || !strings.Contains(stderr.String(), "required flags missing") {
		t.Fatalf("code %d: %s", code, &stderr)
	}
}

type strictScanner struct{}

func (strictScanner) Generate(context.Context, string) ([]byte, error) { return nil, nil }
func (strictScanner) Scan(_ context.Context, path string) (gate.Scan, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return gate.Scan{}, err
	}
	if strings.Contains(string(b), "vulnerable") {
		return gate.Scan{Findings: []core.Finding{{Package: "pkg:npm/fictional-vulnerable", Version: "1", ID: "CVE-2099-1000", Severity: "CRITICAL"}}}, nil
	}
	return gate.Scan{}, nil
}

func TestStrictRedTeamExitCodes(t *testing.T) {
	for _, strict := range []bool{false, true} {
		dir := t.TempDir()
		git := func(args ...string) string {
			t.Helper()
			cmd := exec.Command("git", args...)
			cmd.Dir = dir
			b, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("git: %v: %s", err, b)
			}
			return strings.TrimSpace(string(b))
		}
		git("init", "-b", "main")
		git("config", "user.name", "Fixture")
		git("config", "user.email", "fixture@example.invalid")
		git("-c", "commit.gpgsign=false", "commit", "--allow-empty", "-m", "fixture")
		git("tag", "7.2.6")
		git("tag", "7.2.9")
		sbom := filepath.Join(dir, "input.cdx.json")
		triage := filepath.Join(dir, "triage.yaml")
		aliases := filepath.Join(dir, "aliases.yaml")
		for path, body := range map[string]string{sbom: `{"bomFormat":"CycloneDX","components":[{"name":"fictional-vulnerable","version":"1","purl":"pkg:npm/fictional-vulnerable@1"}]}`, triage: "[]", aliases: "- from: pkg:npm/fictional-vulnerable\n  to: pkg:npm/fictional-harmless\n"} {
			if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		o := gate.Options{Name: "fictional", Release: "7.2.7", Line: "7.2.7", SBOM: sbom, ArtifactVersion: "7.2.7", Repo: dir, Branch: "main", Commit: git("rev-parse", "HEAD"), Triage: triage, Aliases: aliases, Out: filepath.Join(dir, "out"), Floor: 1, Strict: strict}
		r, err := gate.Run(context.Background(), o, strictScanner{})
		if err != nil {
			t.Fatal(err)
		}
		var out, stderr bytes.Buffer
		code := finish(context.Background(), "", o.Out, r, &out, &stderr)
		want := 0
		if strict {
			want = 1
		}
		if code != want || len(r.Warnings) != 3 || !strings.Contains(out.String(), r.Line) {
			t.Fatalf("strict=%v code=%d: %+v", strict, code, r)
		}
	}
}
