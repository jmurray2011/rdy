// SPDX-License-Identifier: Apache-2.0

package gate_test

import (
	"archive/zip"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jmurray2011/rdy/core"
	"github.com/jmurray2011/rdy/gate"
)

type scanner struct{ findings []core.Finding }

func (s scanner) Generate(_ context.Context, _ string) ([]byte, error) {
	return []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"components":[{"type":"library","name":"runtime","version":"1","purl":"pkg:maven/org.example/runtime@1"}]}`), nil
}

func (s scanner) Scan(_ context.Context, _ string) (gate.Scan, error) {
	return gate.Scan{Findings: s.findings, Sources: []string{"fictional-advisories"}}, nil
}

func jar(t *testing.T, dir, version string) string {
	t.Helper()
	path := filepath.Join(dir, "app.jar")
	f, e := os.Create(path)
	if e != nil {
		t.Fatal(e)
	}
	z := zip.NewWriter(f)
	w, e := z.Create("META-INF/MANIFEST.MF")
	if e != nil {
		t.Fatal(e)
	}
	if _, e = w.Write([]byte("Implementation-Version: " + version + "\n\n")); e != nil {
		t.Fatal(e)
	}
	if e = z.Close(); e != nil {
		t.Fatal(e)
	}
	if e = f.Close(); e != nil {
		t.Fatal(e)
	}
	return path
}

func TestReleaseFixtures(t *testing.T) {
	for _, name := range []string{"widget-service", "gizmo-api", "example-app-critical", "example-app-pass"} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			git(t, dir, "init", "-b", "main")
			git(t, dir, "config", "user.email", "fixture@example.invalid")
			git(t, dir, "config", "user.name", "Fixture")
			commit(t, dir, "base", "base")
			git(t, dir, "tag", "1.0.2")
			git(t, dir, "branch", "candidate")
			release, declared := "1.0.4", "1.0.4"
			var findings []core.Finding
			if name == "widget-service" {
				declared = "1.0.2"
				commit(t, dir, "fix", "fix")
				git(t, dir, "tag", "1.0.3")
			}
			if name == "gizmo-api" {
				git(t, dir, "tag", "1.0.11")
			}
			if name == "example-app-critical" || name == "example-app-pass" {
				release, declared = "2.4.0", "2.4.0"
				findings = append(findings, core.Finding{Package: "pkg:maven/org.example/runtime", ID: "CVE-2099-2", Severity: "HIGH"})
				if name == "example-app-critical" {
					findings = append(findings, core.Finding{Package: "pkg:maven/org.example/runtime", ID: "CVE-2099-1", Severity: "CRITICAL"})
				}
			}
			triage := filepath.Join(dir, "triage.yaml")
			if e := os.WriteFile(triage, []byte("- package: pkg:maven/org.example/runtime\n  cve: CVE-2099-2\n  status: accepted\n  reason: Reviewed exposure\n"), 0o600); e != nil {
				t.Fatal(e)
			}
			result, e := gate.Run(context.Background(), gate.Options{Name: name, Release: release, Artifact: jar(t, dir, declared), Repo: dir, Branch: "candidate", Triage: triage, Out: filepath.Join(dir, "report"), Floor: 1}, scanner{findings})
			if e != nil {
				t.Fatal(e)
			}
			want := name == "example-app-pass"
			if result.Pass != want {
				t.Fatalf("verdict %+v", result)
			}
			if name == "widget-service" && len(result.Problems) != 2 {
				t.Fatalf("expected version and missing patch: %+v", result.Problems)
			}
			for _, file := range []string{"report.md", "findings.json", "triage.vex.json", "candidate.cdx.json"} {
				if _, e := os.Stat(filepath.Join(dir, "report", file)); e != nil {
					t.Fatal(e)
				}
			}
		})
	}
}

// Runtime advisories must be found through explicit identities, without CPE matching.
type runtimeScanner struct{}

func (runtimeScanner) Generate(_ context.Context, _ string) ([]byte, error) {
	return []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"components":[{"type":"library","name":"server-core","group":"org.example.server","version":"4.0.0","purl":"pkg:maven/org.example.server/server-core@4.0.0","properties":[{"name":"syft:metadata:-:groupID","value":"org.example.server"},{"name":"syft:metadata:-:artifactID","value":"server-core"},{"name":"fixture:keep","value":"preserved"}]}]}`), nil
}

func (runtimeScanner) Scan(_ context.Context, path string) (gate.Scan, error) {
	b, e := os.ReadFile(path)
	if e != nil {
		return gate.Scan{}, e
	}
	if !strings.Contains(string(b), "pkg:maven/org.example.server.embed/server-embed-core@4.0.0") {
		return gate.Scan{}, nil
	}
	var doc struct {
		Components []struct {
			Properties []struct {
				Name  string `json:"name"`
				Value string `json:"value"`
			} `json:"properties"`
		} `json:"components"`
	}
	if e = json.Unmarshal(b, &doc); e != nil {
		return gate.Scan{}, e
	}
	validGroup, validArtifact, preserved := false, false, false
	for _, component := range doc.Components {
		for _, p := range component.Properties {
			if p.Name == "syft:metadata:-:groupID" && p.Value == "org.example.server.embed" {
				validGroup = true
			}
			if p.Name == "syft:metadata:-:artifactID" && p.Value == "server-embed-core" {
				validArtifact = true
			}
			if p.Name == "fixture:keep" && p.Value == "preserved" {
				preserved = true
			}
		}
	}
	if !validGroup || !validArtifact || !preserved {
		return gate.Scan{}, nil
	}
	return gate.Scan{Findings: []core.Finding{{ID: "CVE-2099-CRITICAL", Package: "pkg:maven/org.example.server.embed/server-embed-core", Version: "4.0.0", Severity: "CRITICAL"}}, Sources: []string{"fictional-runtime-advisories"}}, nil
}

func TestRuntimeAliasGate(t *testing.T) {
	dir := t.TempDir()
	git(t, dir, "init", "-b", "main")
	git(t, dir, "config", "user.email", "fixture@example.invalid")
	git(t, dir, "config", "user.name", "Fixture")
	commit(t, dir, "base", "base")
	triage := filepath.Join(dir, "triage.yaml")
	if e := os.WriteFile(triage, []byte("[]"), 0o600); e != nil {
		t.Fatal(e)
	}
	aliases := filepath.Join(dir, "aliases.yaml")
	if e := os.WriteFile(aliases, []byte("- from: pkg:maven/org.example.server/server-core\n  to: pkg:maven/org.example.server.embed/server-embed-core\n"), 0o600); e != nil {
		t.Fatal(e)
	}
	r, e := gate.Run(context.Background(), gate.Options{Name: "runtime-app", Release: "4.0.0", Artifact: jar(t, dir, "4.0.0"), Repo: dir, Branch: "main", Triage: triage, Out: filepath.Join(dir, "out"), Aliases: aliases, Floor: 1}, runtimeScanner{})
	if e != nil {
		t.Fatal(e)
	}
	if r.Pass || len(r.Untriaged) != 1 || r.Untriaged[0].Severity != "CRITICAL" {
		t.Fatalf("runtime blind spot: %+v", r)
	}
}

func TestDeclaredFallbackAndBaseline(t *testing.T) {
	dir := t.TempDir()
	git(t, dir, "init", "-b", "main")
	git(t, dir, "config", "user.email", "fixture@example.invalid")
	git(t, dir, "config", "user.name", "Fixture")
	commit(t, dir, "base", "base")
	triage := filepath.Join(dir, "triage.yaml")
	if e := os.WriteFile(triage, []byte("[]"), 0o600); e != nil {
		t.Fatal(e)
	}
	dev := filepath.Join(dir, "dev.json")
	sbom := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"components":[{"type":"library","name":"bundled-transitive","version":"1","purl":"pkg:npm/bundled-transitive@1","scope":"optional"}]}`)
	if e := os.WriteFile(dev, sbom, 0o600); e != nil {
		t.Fatal(e)
	}
	fake := scanner{[]core.Finding{{Package: "pkg:npm/bundled-transitive", ID: "CVE-2099-1", Version: "1", Severity: "HIGH"}}}
	o := gate.Options{Name: "fallback-app", Release: "1.0.0", Artifact: jar(t, dir, "1.0.0"), Repo: dir, Branch: "main", Triage: triage, Out: filepath.Join(dir, "out"), DevSBOM: dev, Baseline: dev, Deployed: "0.9.0", Floor: 1}
	r, e := gate.Run(context.Background(), o, fake)
	if e != nil {
		t.Fatal(e)
	}
	if r.Pass || len(r.Untriaged) != 1 || r.Untriaged[0].Origin != "declared, not verified shipped" || r.Components != 2 {
		t.Fatalf("fallback: %+v", r)
	}
	if r.Baseline == nil || len(r.Added)+len(r.Cleared) != 0 {
		t.Fatal("baseline comparison")
	}
	o.Floor = 3
	r, e = gate.Run(context.Background(), o, scanner{})
	if e != nil {
		t.Fatal(e)
	}
	if r.Pass || len(r.Problems) != 1 {
		t.Fatal("thin SBOM must fail")
	}
}

func TestTriageRejectsAdditionalDocuments(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "triage.yaml")
	if e := os.WriteFile(path, []byte("[]\n---\n- package: x\n  cve: y\n  status: invalid\n  reason: r\n"), 0o600); e != nil {
		t.Fatal(e)
	}
	_, e := gate.Run(context.Background(), gate.Options{Name: "sample", Release: "1", Artifact: "unused.jar", Repo: dir, Branch: "main", Triage: path, Out: filepath.Join(dir, "out"), Floor: 1}, scanner{})
	if e == nil || !strings.Contains(e.Error(), "one YAML document") {
		t.Fatalf("additional document was ignored: %v", e)
	}
}

func TestKEVReleasePolicies(t *testing.T) {
	dir := t.TempDir()
	git(t, dir, "init", "-b", "main")
	git(t, dir, "config", "user.email", "fixture@example.invalid")
	git(t, dir, "config", "user.name", "Fixture")
	commit(t, dir, "base", "base")
	triage := filepath.Join(dir, "triage.yaml")
	if e := os.WriteFile(triage, []byte("[]"), 0o600); e != nil {
		t.Fatal(e)
	}
	artifact := jar(t, dir, "1.0.0")
	fake := scanner{[]core.Finding{{Package: "pkg:maven/org.example/runtime", Version: "1", ID: "CVE-2099-KEV", Severity: "MEDIUM", KnownExploited: []core.Exploitation{{CVE: "CVE-2099-KEV", DateAdded: "2099-01-01", DueDate: "2099-02-01", Action: "Apply fix", Ransomware: "Known"}}}}}
	for _, name := range []string{"block", "report"} {
		policy, e := core.ParseKEVPolicy(name)
		if e != nil {
			t.Fatal(e)
		}
		o := gate.Options{Name: "kev-app", Release: "1.0.0", Artifact: artifact, Repo: dir, Branch: "main", Triage: triage, Out: filepath.Join(dir, name), Floor: 1, KEVPolicy: policy}
		r, e := gate.Run(context.Background(), o, fake)
		if e != nil {
			t.Fatal(e)
		}
		if r.Pass != (name == "report") {
			t.Fatalf("%s: %+v", name, r)
		}
		b, e := os.ReadFile(filepath.Join(o.Out, "report.md"))
		if e != nil {
			t.Fatal(e)
		}
		if !strings.Contains(string(b), "CVE-2099-KEV") || !strings.Contains(string(b), "2099-02-01") {
			t.Fatal("missing KEV context")
		}
	}
}

type versionsScanner struct{}

func (versionsScanner) Generate(_ context.Context, _ string) ([]byte, error) {
	return []byte(`{"bomFormat":"CycloneDX","components":[{"name":"sample","version":"1","purl":"pkg:npm/sample@1"},{"name":"sample","version":"2","purl":"pkg:npm/sample@2"}]}`), nil
}

func (versionsScanner) Scan(_ context.Context, _ string) (gate.Scan, error) {
	return gate.Scan{Findings: []core.Finding{{Package: "pkg:npm/sample", Version: "1", ID: "CVE-2099-1", Severity: "HIGH"}}}, nil
}

func TestCoverageCountsEachInstalledVersion(t *testing.T) {
	dir := t.TempDir()
	git(t, dir, "init", "-b", "main")
	git(t, dir, "config", "user.email", "fixture@example.invalid")
	git(t, dir, "config", "user.name", "Fixture")
	commit(t, dir, "base", "base")
	triage := filepath.Join(dir, "triage.yaml")
	if e := os.WriteFile(triage, []byte("[]"), 0o600); e != nil {
		t.Fatal(e)
	}
	r, e := gate.Run(context.Background(), gate.Options{Name: "sample", Release: "1", Artifact: jar(t, dir, "1"), Repo: dir, Branch: "main", Triage: triage, Out: filepath.Join(dir, "out"), Floor: 1}, versionsScanner{})
	if e != nil {
		t.Fatal(e)
	}
	if r.Unmatched["npm"] != 1 {
		t.Fatalf("version 2 has no advisory match: %+v", r.Unmatched)
	}
}
