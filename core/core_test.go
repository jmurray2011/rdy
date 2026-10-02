// SPDX-License-Identifier: Apache-2.0

package core_test

import (
	"testing"

	"github.com/jmurray2011/rdy/core"
)

func TestVersions(t *testing.T) {
	for _, pair := range [][2]string{{"1.0.11", "1.0.4"}, {"v7.3.2.1", "7.3.2"}} {
		a, err := core.ParseVersion(pair[0])
		if err != nil {
			t.Fatal(err)
		}
		b, err := core.ParseVersion(pair[1])
		if err != nil {
			t.Fatal(err)
		}
		if a.Compare(b) <= 0 {
			t.Fatalf("%s must exceed %s", pair[0], pair[1])
		}
	}
	if _, err := core.ParseVersion("release-1.0"); err == nil {
		t.Fatal("accepted non-release")
	}
	latest, previous := core.SelectTags([]string{"v1.0.11", "1.0.3", "nightly"}, "1.0.4")
	if latest != "v1.0.11" || previous != "1.0.3" {
		t.Fatalf("tags %s %s", latest, previous)
	}
}

func TestMerge(t *testing.T) {
	artifact := []core.Component{{PURL: "pkg:maven/org.example/runtime@1", Name: "runtime"}}
	dev := []core.Component{{PURL: "pkg:npm/frontend@1", Scope: "required"}, {PURL: "pkg:npm/tool@1", Scope: "optional"}, {PURL: "pkg:maven/hidden@1", Scope: "required"}}
	got := core.Merge(artifact, dev)
	if len(got) != 3 || len(artifact) != 1 || len(dev) != 3 {
		t.Fatalf("merge: %+v", got)
	}
}

func TestTriageAndVerdict(t *testing.T) {
	entries := []core.Entry{{Package: "pkg:npm/frontend", CVE: "CVE-2099-1", Status: "accepted", Reason: "Exposure reviewed"}}
	if err := core.ValidateTriage(entries); err != nil {
		t.Fatal(err)
	}
	findings := []core.Finding{{ID: "CVE-2099-1", Package: "pkg:npm/frontend", Version: "2", Severity: "HIGH"}, {ID: "CVE-2099-1", Package: "pkg:npm/other", Severity: "CRITICAL"}}
	pending, triaged := core.Triage(findings, entries)
	if len(pending) != 1 || len(triaged) != 1 {
		t.Fatal("triage must match package and CVE across versions")
	}
	if core.Pass(nil, pending) {
		t.Fatal("critical must fail")
	}
	if !core.Pass(nil, nil) || core.Pass([]string{"wrong version"}, nil) {
		t.Fatal("source verdict")
	}
	if err := core.ValidateTriage([]core.Entry{{Package: "x", CVE: "y", Status: "unknown", Reason: "r"}}); err == nil {
		t.Fatal("invalid status")
	}
	if err := core.ValidateTriage([]core.Entry{{Package: "x", CVE: "y", Status: "accepted"}}); err == nil {
		t.Fatal("missing reason")
	}
	line := core.Line("example-app", "2.4.0", nil, pending, "", 0, 0)
	if line != "example-app 2.4.0  FAIL | source ok | 1 Critical, 0 High untriaged | 0 Medium | 0 KEV untriaged" {
		t.Fatal(line)
	}
	added, cleared := core.Diff(findings, []core.Finding{{ID: "CVE-2099-1", Package: "pkg:npm/frontend", Version: "1"}})
	if len(added) != 1 || len(cleared) != 0 {
		t.Fatal("diff includes installed version")
	}
}

func TestKEVPolicy(t *testing.T) {
	findings := []core.Finding{{ID: "CVE-2099-1", Package: "pkg:npm/sample", Severity: "MEDIUM", KnownExploited: []core.Exploitation{{CVE: "CVE-2099-1"}}}}
	block, e := core.ParseKEVPolicy("block")
	if e != nil {
		t.Fatal(e)
	}
	report, e := core.ParseKEVPolicy("report")
	if e != nil {
		t.Fatal(e)
	}
	if core.PassWithPolicy(nil, findings, block) {
		t.Fatal("untriaged medium KEV must block under block policy")
	}
	if !core.PassWithPolicy(nil, findings, report) {
		t.Fatal("report policy must retain severity rule")
	}
	if _, e = core.ParseKEVPolicy("ignore"); e == nil {
		t.Fatal("unknown policy")
	}
	pending, triaged := core.Triage(findings, []core.Entry{{Package: "pkg:npm/sample", CVE: "CVE-2099-1", Status: "accepted", Reason: "Reviewed exploitation risk"}})
	if len(triaged) != 1 || !core.PassWithPolicy(nil, pending, block) {
		t.Fatal("triage must resolve KEV")
	}
}
