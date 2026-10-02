// SPDX-License-Identifier: Apache-2.0

package gate

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jmurray2011/rdy/core"
)

func TestDatabaseRejectsLinksPayloadSkips(t *testing.T) {
	var b bytes.Buffer
	w := tar.NewWriter(&b)
	_ = w.WriteHeader(&tar.Header{Name: "link", Typeflag: tar.TypeSymlink, Linkname: "../outside"})
	_ = w.Close()
	if err := extractTarLimited(context.Background(), bytes.NewReader(b.Bytes()), t.TempDir(), 8, 16); err == nil {
		t.Fatal("database accepted link")
	}
	n, e := extractTarCoverage(context.Background(), bytes.NewReader(b.Bytes()), t.TempDir(), 8, 16)
	if e != nil || n != 1 {
		t.Fatalf("payload %d %v", n, e)
	}
}

func TestThirdRoundVEXAssertions(t *testing.T) {
	e := core.Entry{Package: "pkg:npm/fictional", CVE: "CVE-2099-1000", Status: "fixed_in", Reason: "scanner still reports"}
	r := Result{Triaged: []core.Decision{{Entry: e, Finding: core.Finding{Package: e.Package, Version: "1", ID: e.CVE}}}}
	path := filepath.Join(t.TempDir(), "vex.json")
	if err := writeVEX(path, r); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(path)
	if !strings.Contains(string(b), "in_triage") || strings.Contains(string(b), "resolved") {
		t.Fatalf("VEX %s", b)
	}
	r.Triaged[0].Entry.Status = "not_affected"
	r.Triaged[0].Entry.Justification = "fictional unsupported text"
	if err := writeVEX(path, r); err != nil {
		t.Fatal(err)
	}
	b, _ = os.ReadFile(path)
	if strings.Contains(string(b), `"justification"`) || !strings.Contains(string(b), "fictional unsupported text") {
		t.Fatalf("invalid enum %s", b)
	}
}

func TestBaselineTriageCountsAsUsed(t *testing.T) {
	e := core.Entry{Package: "pkg:npm/fictional", CVE: "CVE-2099-1000", Status: "accepted", Reason: "fixture"}
	r := Result{Baseline: &Evidence{Triaged: []core.Decision{{Entry: e}}}}
	triageExtras(&r, []core.Entry{e}, "2099-01-03")
	if r.UnusedTriageCount != 0 {
		t.Fatal("baseline entry listed unused")
	}
}

func TestScratchCleanupBestEffort(t *testing.T) {
	root := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(root, []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	warnings, err := databaseScratchWarnings(context.Background(), root, time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC))
	if err != nil || len(warnings) != 1 {
		t.Fatalf("warning=%v err=%v", warnings, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = databaseScratchWarnings(ctx, root, time.Time{})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel=%v", err)
	}
}

func TestThirdRoundReportLayout(t *testing.T) {
	r := Result{Line: "fixture", Untriaged: []core.Finding{{ID: "CVE-2099-1000", KnownExploited: []core.Exploitation{{CVE: "CVE-2099-1000"}}}}, Warnings: []Warning{{ID: "tags-ignored", Message: "fixture"}}, Triaged: []core.Decision{{Entry: core.Entry{Status: "accepted"}, Finding: core.Finding{Severity: "HIGH"}}}, Baseline: &Evidence{Unmatched: map[string]int{"npm": 3}}}
	dir := t.TempDir()
	if err := writeReports(dir, r, nil); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(dir, "report.md"))
	s := string(b)
	last := -1
	for _, v := range []string{"## Untriaged", "## Known exploited", "## Warnings", "## Triaged", "## Evidence header"} {
		i := strings.Index(s, v)
		if i <= last {
			t.Fatalf("layout %s", s)
		}
		last = i
	}
	if strings.Contains(s, "map[") || !strings.Contains(s, "- npm: 3") {
		t.Fatal("baseline map syntax")
	}
	var result map[string]any
	b, _ = os.ReadFile(filepath.Join(dir, "findings.json"))
	_ = json.Unmarshal(b, &result)
}

func TestAliasRemovalRetainsVersionSpecificEvidence(t *testing.T) {
	before := core.Finding{Package: "pkg:npm/fictional", Version: "2", ID: "CVE-2099-1000"}
	after := []core.Finding{{Package: before.Package, Version: "1", ID: before.ID}}
	if !aliasFindingRemoved(before, after) {
		t.Fatal("another installed version hid a removed finding")
	}
}

func TestVEXUnsupportedJustificationRetainedForEveryStatus(t *testing.T) {
	for _, status := range []string{"accepted", "fixed_in", "not_affected"} {
		r := Result{Triaged: []core.Decision{{Entry: core.Entry{Package: "pkg:npm/fictional", CVE: "CVE-2099-1000", Status: status, Reason: "fixture", Justification: "unsupported fictional rationale"}, Finding: core.Finding{Version: "1"}}}}
		path := filepath.Join(t.TempDir(), "vex.json")
		if e := writeVEX(path, r); e != nil {
			t.Fatal(e)
		}
		b, e := os.ReadFile(path)
		if e != nil || !strings.Contains(string(b), "unsupported fictional rationale") || strings.Contains(string(b), `"justification"`) {
			t.Fatalf("status=%s VEX=%s err=%v", status, b, e)
		}
	}
}
