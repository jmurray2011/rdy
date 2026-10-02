// SPDX-License-Identifier: Apache-2.0

package gate_test

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jmurray2011/rdy/core"
	"github.com/jmurray2011/rdy/gate"
)

func jarWith(t *testing.T, dir, version string, files map[string]string) string {
	t.Helper()
	path := filepath.Join(dir, "app.jar")
	f, e := os.Create(path)
	if e != nil {
		t.Fatal(e)
	}
	z := zip.NewWriter(f)
	files["META-INF/MANIFEST.MF"] = "Implementation-Version: " + version + "\n\n"
	for name, body := range files {
		w, err := z.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = w.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if e = z.Close(); e != nil {
		t.Fatal(e)
	}
	if e = f.Close(); e != nil {
		t.Fatal(e)
	}
	return path
}

func repo(t *testing.T) (dir, triage string) {
	t.Helper()
	dir = t.TempDir()
	git(t, dir, "init", "-b", "main")
	git(t, dir, "config", "user.email", "fixture@example.invalid")
	git(t, dir, "config", "user.name", "Fixture")
	commit(t, dir, "base", "base")
	triage = filepath.Join(dir, "triage.yaml")
	if e := os.WriteFile(triage, []byte("[]"), 0o600); e != nil {
		t.Fatal(e)
	}
	return dir, triage
}

func TestUncoveredFrontendIsWarned(t *testing.T) {
	dir, triage := repo(t)
	artifact := jarWith(t, dir, "1.0.0", map[string]string{"static/js/main.abc123.js": "!function(){}();"})
	r, e := gate.Run(context.Background(), gate.Options{Name: "web-app", Release: "1.0.0", Artifact: artifact, Repo: dir, Branch: "main", Triage: triage, Out: filepath.Join(dir, "out"), Floor: 1}, scanner{})
	if e != nil {
		t.Fatal(e)
	}
	if !strings.Contains(strings.Join(warningMessages(r.Warnings), "\n"), "JavaScript") {
		t.Fatalf("silent frontend gap: %+v", r.Warnings)
	}
	if !strings.Contains(r.Line, "4 warnings") {
		t.Fatalf("warning missing from verdict line: %s", r.Line)
	}
	if !r.Pass {
		t.Fatal("a coverage warning alone must not fail the release")
	}
	report, e := os.ReadFile(filepath.Join(dir, "out", "report.md"))
	if e != nil || !strings.Contains(string(report), "## Warnings") {
		t.Fatalf("report lacks coverage warnings: %v", e)
	}
}

func TestNoWarningWithoutJavaScript(t *testing.T) {
	dir, triage := repo(t)
	r, e := gate.Run(context.Background(), gate.Options{Name: "service", Release: "1.0.0", Artifact: jar(t, dir, "1.0.0"), Repo: dir, Branch: "main", Triage: triage, Out: filepath.Join(dir, "out"), Floor: 1}, scanner{})
	if e != nil {
		t.Fatal(e)
	}
	if strings.Contains(strings.Join(warningMessages(r.Warnings), "\n"), "JavaScript") {
		t.Fatalf("unexpected warning %+v", r.Warnings)
	}
}

type twinRuntimeScanner struct{}

func (twinRuntimeScanner) Generate(_ context.Context, _ string) ([]byte, error) {
	return []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"components":[{"type":"library","name":"server-core","group":"org.example.server","version":"4.0.0","purl":"pkg:maven/org.example.server/server-core@4.0.0"},{"type":"library","name":"server-core","group":"org.example.server","version":"4.0.0","purl":"pkg:maven/org.example.server/server-core@4.0.0?type=jar"}]}`), nil
}

func (twinRuntimeScanner) Scan(_ context.Context, _ string) (gate.Scan, error) {
	return gate.Scan{Sources: []string{"fictional-advisories"}}, nil
}

func TestAppliedAliasesAreListedOnce(t *testing.T) {
	dir, triage := repo(t)
	aliases := filepath.Join(dir, "aliases.yaml")
	if e := os.WriteFile(aliases, []byte("- from: pkg:maven/org.example.server/server-core\n  to: pkg:maven/org.example.server.embed/server-embed-core\n"), 0o600); e != nil {
		t.Fatal(e)
	}
	r, e := gate.Run(context.Background(), gate.Options{Name: "runtime-app", Release: "1.0.0", Artifact: jar(t, dir, "1.0.0"), Repo: dir, Branch: "main", Triage: triage, Out: filepath.Join(dir, "out"), Aliases: aliases, Floor: 1}, twinRuntimeScanner{})
	if e != nil {
		t.Fatal(e)
	}
	if len(r.Aliases) != 1 {
		t.Fatalf("aliases listed %d times: %+v", len(r.Aliases), r.Aliases)
	}
}

func TestRelatedIdentifiersParsed(t *testing.T) {
	data := []byte(`{"matches":[{"vulnerability":{"id":"GHSA-aaaa-bbbb-cccc","severity":"High","namespace":"github:language:java","fix":{"versions":["2"]}},"relatedVulnerabilities":[{"id":"CVE-2099-0007"},{"id":"GHSA-aaaa-bbbb-cccc"}],"artifact":{"purl":"pkg:maven/org.example/parser@1","version":"1"}}],"descriptor":{"name":"grype","version":"0.100.0","db":{"status":{"built":"2099-01-01T00:00:00Z","valid":true},"providers":{"github":{},"kev":{"captured":"2099-01-01T00:00:00Z"}}}}}`)
	got, e := gate.ParseScan(data)
	if e != nil {
		t.Fatal(e)
	}
	f := got.Findings[0]
	if f.ID != "GHSA-aaaa-bbbb-cccc" || len(f.Aliases) != 1 || f.Aliases[0] != "CVE-2099-0007" {
		t.Fatalf("related identifiers %+v", f)
	}
	pending, _ := core.Triage(got.Findings, []core.Entry{{Package: "pkg:maven/org.example/parser", CVE: "CVE-2099-0007", Status: "not_affected", Reason: "r"}})
	if len(pending) != 0 {
		t.Fatal("CVE triage missed the scanned GHSA finding")
	}
}

func TestMaintenanceLineHotfix(t *testing.T) {
	dir, triage := repo(t)
	git(t, dir, "tag", "1.0.0")
	git(t, dir, "branch", "release/1.0")
	commit(t, dir, "feature", "feature")
	git(t, dir, "tag", "1.1.0")
	git(t, dir, "checkout", "-q", "release/1.0")
	commit(t, dir, "hotfix", "hotfix")
	o := gate.Options{Name: "line-app", Release: "1.0.1", Artifact: jar(t, dir, "1.0.1"), Repo: dir, Branch: "release/1.0", Triage: triage, Out: filepath.Join(dir, "out"), Floor: 1}
	r, e := gate.Run(context.Background(), o, scanner{})
	if e != nil {
		t.Fatal(e)
	}
	if !r.Pass || len(r.Problems) != 0 {
		t.Fatalf("maintenance hotfix flagged: %+v", r.Problems)
	}
	o.Line, o.Out = "1", filepath.Join(dir, "out-wide")
	if r, e = gate.Run(context.Background(), o, scanner{}); e != nil {
		t.Fatal(e)
	}
	if r.Pass || len(r.Problems) != 1 || !strings.Contains(r.Problems[0], "1.1.0") {
		t.Fatalf("explicit wider line must report the newer release: %+v", r.Problems)
	}
	o.Line = "2"
	if _, e = gate.Run(context.Background(), o, scanner{}); e == nil {
		t.Fatal("accepted a line that does not contain the release")
	}
}

type emptyScanner struct{}

func (emptyScanner) Generate(_ context.Context, _ string) ([]byte, error) {
	return []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","version":1}`), nil
}

func (emptyScanner) Scan(_ context.Context, _ string) (gate.Scan, error) {
	return gate.Scan{Sources: []string{"fictional-advisories"}}, nil
}

func TestEmptySBOMFailsTheFloor(t *testing.T) {
	dir, triage := repo(t)
	r, e := gate.Run(context.Background(), gate.Options{Name: "empty-app", Release: "1.0.0", Artifact: jar(t, dir, "1.0.0"), Repo: dir, Branch: "main", Triage: triage, Out: filepath.Join(dir, "out"), Floor: 1}, emptyScanner{})
	if e != nil {
		t.Fatalf("an SBOM without components is a thin SBOM, not a tool error: %v", e)
	}
	if r.Pass || r.Components != 0 || len(r.Problems) != 1 || !strings.Contains(r.Problems[0], "thin candidate SBOM") {
		t.Fatalf("%+v", r.Problems)
	}
}

func TestPrebuiltCountSurvivesEmbeddedSBOM(t *testing.T) {
	dir, triage := repo(t)
	stats, lock, bundle := filepath.Join(dir, "stats.json"), filepath.Join(dir, "lock.json"), filepath.Join(dir, "bundle.cdx.json")
	if e := os.WriteFile(stats, []byte(`{"modules":[{"name":"./node_modules/plain/dist/a.js"},{"name":"./node_modules/plain/dist/b.js"}]}`), 0o600); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(lock, []byte(`{"lockfileVersion":3,"packages":{"node_modules/plain":{"version":"1"}}}`), 0o600); e != nil {
		t.Fatal(e)
	}
	if e := gate.WriteBundle(context.Background(), stats, lock, bundle); e != nil {
		t.Fatal(e)
	}
	data, e := os.ReadFile(bundle)
	if e != nil {
		t.Fatal(e)
	}
	artifact := jarWith(t, dir, "1.0.0", map[string]string{"one/bundle.cdx.json": string(data), "two/bundle.cdx.json": string(data)})
	r, e := gate.Run(context.Background(), gate.Options{Name: "app", Release: "1.0.0", Artifact: artifact, Repo: dir, Branch: "main", Triage: triage, Out: filepath.Join(dir, "out"), Floor: 1}, prebuiltScanner{})
	if e != nil {
		t.Fatal(e)
	}
	sum := sha256.Sum256(data)
	for _, key := range []string{"embedded_sbom:one/bundle.cdx.json", "embedded_sbom:two/bundle.cdx.json"} {
		if r.InputSHA256[key] != hex.EncodeToString(sum[:]) {
			t.Fatalf("embedded hash %s: %v", key, r.InputSHA256)
		}
	}
	if r.PrebuiltWithoutVendoringEvidence != 1 || len(r.Opaque) != 0 {
		t.Fatalf("result %+v", r)
	}
	report, e := os.ReadFile(filepath.Join(dir, "out", "report.md"))
	if e != nil {
		t.Fatal(e)
	}
	if !strings.Contains(string(report), "1 packages ship prebuilt dist code with no evidence of vendoring; not counted as opaque") {
		t.Fatalf("report %s", report)
	}
	findings, e := os.ReadFile(filepath.Join(dir, "out", "findings.json"))
	if e != nil {
		t.Fatal(e)
	}
	var value map[string]any
	if e = json.Unmarshal(findings, &value); e != nil {
		t.Fatal(e)
	}
	if value["prebuilt_without_vendoring_evidence"] != float64(1) {
		t.Fatalf("count %v", value)
	}
	baseline, err := gate.Run(context.Background(), gate.Options{Name: "app", Release: "1.0.0", Artifact: artifact, Repo: dir, Branch: "main", Triage: triage, Out: filepath.Join(dir, "baseline-out"), Baseline: filepath.Join(dir, "out", "candidate.cdx.json"), Floor: 1}, prebuiltScanner{})
	if err != nil {
		t.Fatal(err)
	}
	if baseline.Baseline == nil || baseline.Baseline.PrebuiltWithoutVendoringEvidence != 1 {
		t.Fatalf("baseline count %+v", baseline.Baseline)
	}
}

type prebuiltScanner struct{}

func (prebuiltScanner) Generate(context.Context, string) ([]byte, error) {
	return []byte(`{"bomFormat":"CycloneDX","components":[{"name":"plain","version":"1","purl":"pkg:npm/plain@1"}]}`), nil
}

func (prebuiltScanner) Scan(context.Context, string) (gate.Scan, error) {
	return gate.Scan{Sources: []string{"fictional"}}, nil
}
