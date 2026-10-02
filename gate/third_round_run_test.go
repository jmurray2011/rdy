// SPDX-License-Identifier: Apache-2.0

package gate_test

import (
	"context"
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jmurray2011/rdy/core"
	"github.com/jmurray2011/rdy/gate"
)

func thirdOptions(t *testing.T) gate.Options {
	t.Helper()
	dir, triage := repo(t)
	return gate.Options{Name: "fictional", Release: "7.2.7", Artifact: jar(t, dir, "7.2.7"), Repo: dir, Branch: "main", Triage: triage, Out: filepath.Join(dir, "out"), Floor: 1, Now: fixedTime}
}

func TestThirdRoundNarrowedLineAndIgnoredTags(t *testing.T) {
	o := thirdOptions(t)
	git(t, o.Repo, "tag", "7.2.9")
	git(t, o.Repo, "tag", "7.2.6")
	for _, tag := range []string{"v1.2.3-rc1", "api-v1.2.3", "7.2.9-1"} {
		git(t, o.Repo, "tag", tag)
	}
	o.Line = "7.2.7"
	r, e := gate.Run(context.Background(), o, scanner{})
	if e != nil {
		t.Fatal(e)
	}
	s := strings.Join(warningMessages(r.Warnings), " ")
	if !r.Pass || !strings.Contains(r.Line, "source checks skipped (1)") || strings.Contains(r.Line, "source ok") || !strings.Contains(s, "outside") || !strings.Contains(s, "7.2.9") || !strings.Contains(s, "ignored 3") || !strings.Contains(s, "no --commit supplied") || r.ComparedTags.Count != 5 || r.ComparedTags.PreviousCommit == "" {
		t.Fatalf("visibility %+v", r)
	}
}

func TestThirdRoundNoNumericTags(t *testing.T) {
	o := thirdOptions(t)
	git(t, o.Repo, "tag", "fictional-rc1")
	r, e := gate.Run(context.Background(), o, scanner{})
	if e != nil {
		t.Fatal(e)
	}
	if r.ComparedTags.Latest != "" || !strings.Contains(strings.Join(warningMessages(r.Warnings), " "), "no numeric release tags") || !strings.Contains(r.Line, "source checks skipped (2)") {
		t.Fatalf("skips %+v", r)
	}
}

func TestThirdRoundTagPatternAndSBOM(t *testing.T) {
	o := thirdOptions(t)
	git(t, o.Repo, "tag", "api-v7.2.6")
	o.TagPattern = `^api-v([0-9]+(?:\.[0-9]+)*)$`
	o.SBOM = filepath.Join(o.Repo, "input.cdx.json")
	o.Artifact = ""
	o.ArtifactVersion = "7.2.7"
	if e := os.WriteFile(o.SBOM, []byte(`{"bomFormat":"CycloneDX","components":[{"name":"fictional","version":"1","purl":"pkg:npm/fictional@1"}]}`), 0o600); e != nil {
		t.Fatal(e)
	}
	r, e := gate.Run(context.Background(), o, scanner{findings: []core.Finding{{Package: "pkg:npm/fictional", ID: "CVE-2099-1000", Version: "1", Severity: "LOW"}}})
	if e != nil {
		t.Fatal(e)
	}
	if r.ComparedTags.Previous != "api-v7.2.6" || r.ComparedTags.LatestCommit == "" || r.Untriaged[0].Origin != "declared SBOM, not extracted" {
		t.Fatalf("adoption %+v", r)
	}
	o.Artifact = "also.jar"
	if _, e := gate.Run(context.Background(), o, scanner{}); e == nil || !strings.Contains(e.Error(), "exclusive") {
		t.Fatalf("exclusive %v", e)
	}
	o.Artifact = ""
	o.TagPattern = `^(api)-(.*)$`
	if _, e := gate.Run(context.Background(), o, scanner{}); e == nil || !strings.Contains(e.Error(), "one capture") {
		t.Fatalf("pattern %v", e)
	}
}

func TestThirdRoundExpiredTriageAtRunBoundary(t *testing.T) {
	for _, expires := range []string{"2099-01-02", "2099-01-03"} {
		t.Run(expires, func(t *testing.T) {
			o := thirdOptions(t)
			entry := "- package: pkg:maven/org.example/runtime\n  cve: CVE-2099-1000\n  status: accepted\n  reason: fixture\n  expires: " + expires + "\n"
			if e := os.WriteFile(o.Triage, []byte(entry), 0o600); e != nil {
				t.Fatal(e)
			}
			r, e := gate.Run(context.Background(), o, scanner{findings: []core.Finding{{Package: "pkg:maven/org.example/runtime", ID: "CVE-2099-1000", Severity: "HIGH", Version: "1"}}})
			if e != nil {
				t.Fatal(e)
			}
			expired := expires == "2099-01-02"
			if !r.Pass || !strings.Contains(r.Line, "1 triaged (0 Critical, 1 High, 0 KEV)") || strings.Contains(strings.Join(warningMessages(r.Warnings), " "), "triage entry expired") != expired || strings.Contains(r.Line, "1 expired triage entry still in force") != expired {
				t.Fatalf("boundary %+v", r)
			}
		})
	}
}

type aliasHidingScanner struct{}

func (aliasHidingScanner) Generate(context.Context, string) ([]byte, error) {
	return []byte(`{"bomFormat":"CycloneDX","components":[{"type":"library","group":"org.fictional","name":"vulnerable","version":"1","purl":"pkg:maven/org.fictional/vulnerable@1"}]}`), nil
}

func (aliasHidingScanner) Scan(_ context.Context, path string) (gate.Scan, error) {
	b, e := os.ReadFile(path)
	if e != nil {
		return gate.Scan{}, e
	}
	var doc struct{ Components []core.Component }
	if e = json.Unmarshal(b, &doc); e != nil {
		return gate.Scan{}, e
	}
	r := gate.Scan{}
	for _, c := range doc.Components {
		if c.Name == "vulnerable" {
			r.Findings = append(r.Findings, core.Finding{Package: core.PackageID(c.PURL), Version: c.Version, ID: "CVE-2099-1000", Severity: "CRITICAL", KnownExploited: []core.Exploitation{{CVE: "CVE-2099-1000"}}})
		}
	}
	return r, nil
}

func TestThirdRoundAliasRemovedCriticalVisible(t *testing.T) {
	o := thirdOptions(t)
	o.Aliases = filepath.Join(o.Repo, "aliases.yaml")
	if e := os.WriteFile(o.Aliases, []byte("- from: pkg:maven/org.fictional/vulnerable\n  to: pkg:maven/org.fictional/harmless\n"), 0o600); e != nil {
		t.Fatal(e)
	}
	r, e := gate.Run(context.Background(), o, aliasHidingScanner{})
	if e != nil {
		t.Fatal(e)
	}
	if !r.Pass || len(r.RemovedByAliases) != 1 || !strings.Contains(r.Line, "1 aliases applied (1 components)") || !strings.Contains(strings.Join(warningMessages(r.Warnings), " "), "alias removed") {
		t.Fatalf("alias visibility %+v", r)
	}
}

func TestThirdRoundUnstampedAndMissingBundle(t *testing.T) {
	for _, embed := range []bool{false, true} {
		t.Run(string(rune('a'+boolIndex(embed))), func(t *testing.T) {
			o := thirdOptions(t)
			files := map[string]string{"static/app.js": "fixture"}
			if embed {
				files["frontend/bundle.cdx.json"] = `{"bomFormat":"CycloneDX","components":[{"name":"plain","version":"1","purl":"pkg:npm/plain@1"}]}`
			}
			o.Artifact = jarWith(t, o.Repo, "7.2.7", files)
			r, e := gate.Run(context.Background(), o, prebuiltScanner{})
			if e != nil {
				t.Fatal(e)
			}
			want := "no bundle.cdx.json embedded"
			if embed {
				want = "unstamped bundle SBOM"
			}
			if !r.Pass || !strings.Contains(strings.Join(warningMessages(r.Warnings), " "), want) {
				t.Fatalf("frontend %+v", r)
			}
			if embed && (len(r.Bundles) != 1 || r.Bundles[0].Components != 1) {
				t.Fatal("missing per-bundle evidence")
			}
		})
	}
}

func boolIndex(b bool) int {
	if b {
		return 1
	}
	return 0
}

func TestThirdRoundKEVReportWarning(t *testing.T) {
	o := thirdOptions(t)
	policy, e := core.ParseKEVPolicy("report")
	if e != nil {
		t.Fatal(e)
	}
	o.KEVPolicy = policy
	r, e := gate.Run(context.Background(), o, scanner{findings: []core.Finding{{Package: "pkg:maven/org.example/runtime", ID: "CVE-2099-1000", Version: "1", Severity: "LOW", KnownExploited: []core.Exploitation{{CVE: "CVE-2099-1000"}}}}})
	if e != nil {
		t.Fatal(e)
	}
	if !r.Pass || !strings.Contains(strings.Join(warningMessages(r.Warnings), " "), "--kev-policy report allows 1") {
		t.Fatalf("KEV bypass %+v", r)
	}
}

func TestThirdRoundShallowClone(t *testing.T) {
	o := thirdOptions(t)
	clone := filepath.Join(t.TempDir(), "clone")
	path := filepath.ToSlash(o.Repo)
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	address := (&url.URL{Scheme: "file", Path: path}).String()
	git(t, o.Repo, "clone", "--depth", "1", "--no-local", address, clone)
	o.Repo = clone
	r, e := gate.Run(context.Background(), o, scanner{})
	if e != nil {
		t.Fatal(e)
	}
	if !r.Shallow || !strings.Contains(strings.Join(warningMessages(r.Warnings), " "), "repository is shallow") {
		t.Fatalf("shallow %+v", r)
	}
}

func TestThirdRoundUnsupportedAndDeclaredMessages(t *testing.T) {
	o := thirdOptions(t)
	o.Artifact = "fictional/image:latest"
	if _, e := gate.Run(context.Background(), o, scanner{}); e == nil || !strings.Contains(e.Error(), "supported types: .jar .war .rpm .deb, or --sbom") {
		t.Fatalf("unsupported %v", e)
	}
	for _, tc := range []struct{ version, want string }{{"", "manifest has no Implementation-Version"}, {"fixture", "declared version fixture is not purely numeric"}, {"7.2.6", "declared version 7.2.6 differs from release 7.2.7"}} {
		o := thirdOptions(t)
		o.Artifact = jar(t, o.Repo, tc.version)
		r, e := gate.Run(context.Background(), o, scanner{})
		if e != nil {
			t.Fatal(e)
		}
		if r.Pass || !strings.Contains(strings.Join(r.Problems, " "), tc.want) || r.VersionSource != "manifest" {
			t.Fatalf("declared %+v", r)
		}
	}
}
