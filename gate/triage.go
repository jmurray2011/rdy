// SPDX-License-Identifier: Apache-2.0

package gate

import (
	"fmt"
	"path/filepath"

	"github.com/jmurray2011/rdy/core"
)

func triageExtras(r *Result, entries []core.Entry, date string) {
	r.TriageEntries = entries
	used := map[string]bool{}
	for _, d := range r.Triaged {
		used[d.Entry.Package+"\x00"+d.Entry.CVE] = true
	}
	if r.Baseline != nil {
		for _, d := range r.Baseline.Triaged {
			used[d.Entry.Package+"\x00"+d.Entry.CVE] = true
		}
	}
	for _, e := range entries {
		if !used[e.Package+"\x00"+e.CVE] {
			r.UnusedTriageEntries = append(r.UnusedTriageEntries, e)
		}
		if e.Expires != "" && e.Expires < date {
			r.Warnings = append(r.Warnings, Warning{ID: "triage-expired", Message: fmt.Sprintf("triage entry expired on %s: %s %s", e.Expires, e.Package, e.CVE)})
		}
	}
	r.UnusedTriageCount = len(r.UnusedTriageEntries)
}

func triageStatus(e core.Entry) string {
	if e.Status == "fixed_in" {
		return "fixed_in (scanner still reports this version)"
	}
	return e.Status
}

func vexMetadata(r Result) any {
	input, key := r.EffectiveOptions.Artifact, "artifact"
	if r.EffectiveOptions.SBOM != "" {
		input, key = r.EffectiveOptions.SBOM, "sbom"
	}
	return map[string]any{"timestamp": r.Timestamp, "tools": map[string]any{"components": []map[string]string{{"type": "application", "name": "rdy", "version": r.Version}}}, "component": map[string]any{"type": "application", "name": filepath.Base(input), "version": r.EffectiveOptions.Release, "hashes": []map[string]string{{"alg": "SHA-256", "content": r.InputSHA256[key]}}}}
}

func cdxJustification(s string) bool {
	switch s {
	case "code_not_present", "code_not_reachable", "requires_configuration", "requires_dependency", "requires_environment", "protected_by_compiler", "protected_at_runtime", "protected_at_perimeter", "protected_by_mitigating_control":
		return true
	}
	return false
}
