// SPDX-License-Identifier: Apache-2.0

package gate

import (
	"fmt"
	"sort"
	"strings"
)

// Warning identifies a stable, independently allowlisted advisory signal.
type Warning struct {
	ID      string `json:"id"`
	Message string `json:"message"`
	Allowed bool   `json:"allowed,omitempty"`
}

// WarningIDs returns the complete stable warning vocabulary in sorted order.
func WarningIDs() []string {
	return []string{"alias-removed-finding", "archive-links-skipped", "bundle-unstamped", "commit-not-asserted", "db-cleanup-failed", "db-update-failed", "frontend-not-covered", "kev-not-blocking", "line-override", "shallow-repo", "source-check-skipped", "tags-ignored", "triage-expired"}
}

// NormalizeAllowedWarnings validates repeatable and comma-separated allowlists.
func NormalizeAllowedWarnings(values []string) ([]string, error) {
	valid := WarningIDs()
	result := []string{}
	seen := map[string]bool{}
	for _, value := range values {
		for _, id := range strings.Split(value, ",") {
			id = strings.TrimSpace(id)
			i := sort.SearchStrings(valid, id)
			if i == len(valid) || valid[i] != id {
				return nil, fmt.Errorf("unknown warning ID %q; valid IDs: %s", id, strings.Join(valid, ", "))
			}
			if !seen[id] {
				result = append(result, id)
				seen[id] = true
			}
		}
	}
	sort.Strings(result)
	return result, nil
}

func strictVerdict(r *Result, o Options) {
	if !o.Strict {
		return
	}
	allowed := map[string]bool{}
	for _, id := range o.AllowWarnings {
		allowed[id] = true
	}
	blocking := 0
	for i, w := range r.Warnings {
		r.Warnings[i].Allowed = allowed[w.ID]
		if !allowed[w.ID] {
			blocking++
		}
	}
	if blocking > 0 {
		if r.Pass {
			prefix := fmt.Sprintf("%s %s  PASS", o.Name, o.Release)
			r.Line = fmt.Sprintf("%s %s  FAIL", o.Name, o.Release) + strings.TrimPrefix(r.Line, prefix)
		}
		r.Pass = false
		r.Line += fmt.Sprintf(" | strict: %d blocking warnings", blocking)
	}
}
