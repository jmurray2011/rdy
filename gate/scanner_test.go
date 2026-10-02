// SPDX-License-Identifier: Apache-2.0

package gate_test

import (
	"testing"

	"github.com/jmurray2011/rdy/gate"
)

func TestNormalizeScan(t *testing.T) {
	data := []byte(`{"matches":[{"vulnerability":{"id":"CVE-2099-1","severity":"High","namespace":"fictional:java","dataSource":"https://example.invalid/advisory","fix":{"versions":["2"]}},"artifact":{"purl":"pkg:maven/org.example/runtime@1?type=jar","version":"1"}},{"vulnerability":{"id":"CVE-2099-1","severity":"High","namespace":"fictional:java","fix":{"versions":["2"]}},"artifact":{"purl":"pkg:maven/org.example/runtime@1","version":"1"}}],"descriptor":{"name":"grype","version":"0.100.0","db":{"status":{"built":"2099-01-01T00:00:00Z","valid":true},"providers":{"github":{},"nvd":{},"kev":{"captured":"2099-01-01T00:00:00Z"}}}}}`)
	got, e := gate.ParseScan(data)
	if e != nil {
		t.Fatal(e)
	}
	if len(got.Findings) != 1 || got.Findings[0].Package != "pkg:maven/org.example/runtime" || got.Findings[0].Fixed != "2" {
		t.Fatalf("%+v", got)
	}
	if got.DBDate != "2099-01-01T00:00:00Z" {
		t.Fatal("missing database build date")
	}
	found := false
	for _, source := range got.Sources {
		if source == "github" {
			found = true
		}
	}
	if !found {
		t.Fatal("missing full provider set")
	}
	for _, bad := range []string{`{"matches":[],"descriptor":{"name":"grype","version":"0.100.0"}}`, `{"matches":[],"descriptor":{"configuration":{"match":{"java":{"using-cpes":true}}}}}`, `{}`, `{"matches":null}`, `{"matches":[{"vulnerability":{"id":"x","severity":"mystery"},"artifact":{"purl":"pkg:npm/a@1"}}]}`, `{"matches":[],"ignoredMatches":[{}]}`} {
		if _, e = gate.ParseScan([]byte(bad)); e == nil {
			t.Fatalf("accepted %s", bad)
		}
	}
}

func TestKEVMetadata(t *testing.T) {
	data := []byte(`{"matches":[{"vulnerability":{"id":"GHSA-fictional-advisory","severity":"Medium","knownExploited":[{"cve":"CVE-2099-1","dateAdded":"2099-01-01","dueDate":"2099-02-01","requiredAction":"Apply the fix","knownRansomwareCampaignUse":"Known"}]},"artifact":{"purl":"pkg:npm/sample@1","version":"1"}},{"vulnerability":{"id":"GHSA-fictional-advisory","severity":"Medium"},"relatedVulnerabilities":[{"id":"CVE-2099-1","knownExploited":[{"cve":"CVE-2099-1","dateAdded":"2099-01-01","dueDate":"2099-02-01","requiredAction":"Apply the fix","knownRansomwareCampaignUse":"Known"}]}],"artifact":{"purl":"pkg:npm/sample@1","version":"1"}}],"descriptor":{"name":"grype","version":"0.100.0","db":{"status":{"built":"2099-01-02T00:00:00Z","valid":true},"providers":{"github":{},"kev":{"captured":"2099-01-01T00:00:00Z","input":"fixture-digest"}}}}}`)
	got, e := gate.ParseScan(data)
	if e != nil {
		t.Fatal(e)
	}
	if len(got.Findings) != 1 || len(got.Findings[0].KnownExploited) != 1 {
		t.Fatalf("KEV lost in dedup/related IDs: %+v", got)
	}
	kev := got.Findings[0].KnownExploited[0]
	if kev.CVE != "CVE-2099-1" || kev.DueDate != "2099-02-01" || kev.Ransomware != "Known" {
		t.Fatalf("%+v", kev)
	}
	if got.KEVCaptured != "2099-01-01T00:00:00Z" {
		t.Fatal("KEV provenance missing")
	}
}
