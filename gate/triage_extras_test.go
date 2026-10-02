// SPDX-License-Identifier: Apache-2.0

package gate

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jmurray2011/rdy/core"
)

func TestTriageExtrasAndMatchedVEX(t *testing.T) {
	e := core.Entry{Package: "pkg:npm/fictional", CVE: "CVE-2099-1000", Status: "not_affected", Reason: "fixture", ReviewedBy: "Fixture", ReviewedOn: "2099-01-01", Expires: "2099-01-02", Justification: "code_not_reachable"}
	unused := core.Entry{Package: "pkg:npm/unused", CVE: "CVE-2099-1001", Status: "accepted", Reason: "fixture"}
	d := core.Decision{Entry: e, Finding: core.Finding{Package: e.Package, ID: e.CVE, Version: "1.2.3"}}
	r := Result{Line: "fixture PASS", Timestamp: "2099-01-03T00:00:00Z", Version: "test", EffectiveOptions: Options{Artifact: "fictional.jar", Release: "1.0.0"}, InputSHA256: map[string]string{"artifact": strings.Repeat("a", 64)}, Triaged: []core.Decision{d}}
	triageExtras(&r, []core.Entry{e, unused}, "2099-01-03")
	if r.UnusedTriageCount != 1 || len(r.Warnings) != 1 {
		t.Fatalf("extras: %+v", r)
	}
	out := t.TempDir()
	if err := writeReports(out, r, []core.Entry{e, unused}); err != nil {
		t.Fatal(err)
	}
	report, _ := os.ReadFile(filepath.Join(out, "report.md"))
	for _, want := range []string{"Triage entries with no match in this run", "Fixture", "2099-01-02"} {
		if !strings.Contains(string(report), want) {
			t.Fatalf("report missing %s", want)
		}
	}
	b, _ := os.ReadFile(filepath.Join(out, "triage.vex.json"))
	var v struct {
		Metadata        json.RawMessage
		Components      []core.Component
		Vulnerabilities []struct {
			Analysis struct{ Justification string }
		}
	}
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	if len(v.Components) != 1 || v.Components[0].Version != "1.2.3" || len(v.Vulnerabilities) != 1 || v.Vulnerabilities[0].Analysis.Justification != e.Justification || !strings.Contains(string(v.Metadata), "fictional.jar") || !strings.Contains(string(v.Metadata), r.Timestamp) {
		t.Fatalf("VEX %s", b)
	}
}

func TestReportOrderingAndEmptySections(t *testing.T) {
	r := Result{Line: "fixture FAIL", Problems: []string{"artifact version differs"}, Untriaged: []core.Finding{{ID: "CVE-2099-1000"}}, Warnings: []Warning{{ID: "tags-ignored", Message: "fixture warning"}}}
	out := t.TempDir()
	if err := writeReports(out, r, nil); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(out, "report.md"))
	s := string(b)
	last := -1
	for _, title := range []string{"fixture FAIL", "## Source problems", "## Untriaged", "## Warnings", "Database build date"} {
		i := strings.Index(s, title)
		if i <= last {
			t.Fatalf("ordering %s", s)
		}
		last = i
	}
	for _, title := range []string{"## Opaque bundled code", "## Triaged", "## Added", "## Cleared", "## Known exploited"} {
		if strings.Contains(s, title) {
			t.Fatalf("empty section %s", title)
		}
	}
	if !strings.Contains(s, "Fix:") {
		t.Fatal("no source fix hint")
	}
}

func TestFixedInMarkerAndOptionalVEXJustification(t *testing.T) {
	e := core.Entry{Package: "pkg:npm/fictional", CVE: "CVE-2099-1000", Status: "fixed_in", Reason: "reviewed assertion"}
	r := Result{Triaged: []core.Decision{{Entry: e, Finding: core.Finding{Package: e.Package, ID: e.CVE, Version: "1.0.0"}}}}
	out := t.TempDir()
	if err := writeReports(out, r, []core.Entry{e}); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(out, "report.md"))
	if err != nil || !strings.Contains(string(b), "fixed_in (scanner still reports this version)") {
		t.Fatal("missing fixed_in qualifier")
	}
	r.Triaged[0].Entry.Status = "not_affected"
	if err := writeVEX(filepath.Join(out, "vex.json"), r); err != nil {
		t.Fatal(err)
	}
	b, err = os.ReadFile(filepath.Join(out, "vex.json"))
	if err != nil || strings.Contains(string(b), "justification") {
		t.Fatal("invented justification")
	}
}

func TestProviderNamesExcludeAdvisoryURLs(t *testing.T) {
	names := providerNames(json.RawMessage(`{"db":{"providers":{"fictional-osv":{},"fictional-nvd":{}}}}`), []string{"https://fictional.invalid/advisory/secret", "java:fictional"})
	if strings.Join(names, ",") != "fictional-nvd,fictional-osv" {
		t.Fatalf("providers %v", names)
	}
}
