// SPDX-License-Identifier: Apache-2.0

package core_test

import (
	"testing"

	"github.com/jmurray2011/rdy/core"
)

func TestTriageMatchesRelatedIdentifier(t *testing.T) {
	findings := []core.Finding{{Package: "pkg:maven/org.example/parser", ID: "GHSA-aaaa-bbbb-cccc", Aliases: []string{"CVE-2099-0007"}, Severity: "HIGH"}}
	entries := []core.Entry{{Package: "pkg:maven/org.example/parser", CVE: "CVE-2099-0007", Status: "not_affected", Reason: "unreachable"}}
	pending, decisions := core.Triage(findings, entries)
	if len(pending) != 0 || len(decisions) != 1 {
		t.Fatalf("CVE-keyed triage missed GHSA finding: pending %+v", pending)
	}
	entries[0].CVE = "GHSA-aaaa-bbbb-cccc"
	if pending, _ = core.Triage(findings, entries); len(pending) != 0 {
		t.Fatal("primary identifier no longer matches")
	}
	entries[0].Package = "pkg:maven/org.example/other"
	if pending, _ = core.Triage(findings, entries); len(pending) != 1 {
		t.Fatal("related identifier matched another package")
	}
}

func TestDiffMatchesAcrossIdentifiers(t *testing.T) {
	candidate := []core.Finding{{Package: "pkg:npm/widget", ID: "CVE-2099-0008"}}
	baseline := []core.Finding{{Package: "pkg:npm/widget", ID: "GHSA-dddd-eeee-ffff", Aliases: []string{"CVE-2099-0008"}}}
	added, cleared := core.Diff(candidate, baseline)
	if len(added)+len(cleared) != 0 {
		t.Fatalf("identifier change read as churn: added %+v cleared %+v", added, cleared)
	}
	added, cleared = core.Diff([]core.Finding{{Package: "pkg:npm/widget", ID: "CVE-2099-0009"}}, baseline)
	if len(added) != 1 || len(cleared) != 1 {
		t.Fatal("distinct advisories collapsed")
	}
}

func TestOpaqueRequiresUnaccountedDependencies(t *testing.T) {
	stats := []byte(`{"modules":[{"name":"./node_modules/plain/dist/plain.js"},{"name":"./node_modules/partner/dist/partner.min.js"},{"name":"./node_modules/shared/index.js"},{"name":"./node_modules/bundler/dist/bundler.min.js"}]}`)
	lock := []byte(`{"lockfileVersion":3,"packages":{"node_modules/plain":{"version":"1.0.0"},"node_modules/partner":{"version":"1.0.0","dependencies":{"shared":"^1"}},"node_modules/shared":{"version":"1.2.0"},"node_modules/bundler":{"version":"2.0.0","dependencies":{"inlined-a":"^1","shared":"^1","inlined-b":"^3"}},"node_modules/inlined-a":{"version":"1.0.0"},"node_modules/inlined-b":{"version":"3.0.0"}}}`)
	got, e := core.BuildBundle(stats, lock)
	if e != nil {
		t.Fatal(e)
	}
	if len(got.Opaque) != 1 || got.Opaque[0].Package != "bundler" {
		t.Fatalf("opaque %+v", got.Opaque)
	}
	if u := got.Opaque[0].Unaccounted; len(u) != 2 || u[0] != "inlined-a" || u[1] != "inlined-b" {
		t.Fatalf("unaccounted %v", u)
	}
	if len(got.Prebuilt) != 2 {
		t.Fatalf("prebuilt packages %+v", got.Prebuilt)
	}
	if len(got.Components) != 4 {
		t.Fatalf("components %+v", got.Components)
	}
}

func TestDistVendoredNestedModulesAreOpaque(t *testing.T) {
	stats := []byte(`{"modules":[{"name":"./node_modules/host/dist/node_modules/inner/lib/x.js"},{"name":"./node_modules/host/dist/host.js"}]}`)
	lock := []byte(`{"lockfileVersion":3,"packages":{"node_modules/host":{"version":"4.0.0"}}}`)
	got, e := core.BuildBundle(stats, lock)
	if e != nil {
		t.Fatalf("vendored dist path must not require a lockfile entry: %v", e)
	}
	if len(got.Prebuilt) != 0 {
		t.Fatalf("opaque host counted as prebuilt without evidence: %+v", got.Prebuilt)
	}
	if len(got.Components) != 1 || got.Components[0].PURL != "pkg:npm/host@4.0.0" {
		t.Fatalf("components %+v", got.Components)
	}
	if len(got.Opaque) != 1 || got.Opaque[0].Package != "host" || got.Opaque[0].Path != "node_modules/host/dist/node_modules/inner/lib/x.js" {
		t.Fatalf("opaque %+v", got.Opaque)
	}
}
