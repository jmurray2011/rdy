// SPDX-License-Identifier: Apache-2.0

package core

import (
	"fmt"
	"sort"
)

// Exploitation preserves CISA KEV context supplied by the scanner database.
type Exploitation struct {
	CVE        string   `json:"cve"`
	DateAdded  string   `json:"dateAdded,omitempty"`
	DueDate    string   `json:"dueDate,omitempty"`
	Action     string   `json:"requiredAction,omitempty"`
	Ransomware string   `json:"knownRansomwareCampaignUse,omitempty"`
	URLs       []string `json:"urls,omitempty"`
}

// KEVPolicy is a validated KEV gating policy; its zero value blocks unresolved KEV.
type KEVPolicy struct{ reportOnly bool }

// ParseKEVPolicy accepts block or report.
func ParseKEVPolicy(s string) (KEVPolicy, error) {
	switch s {
	case "block":
		return KEVPolicy{}, nil
	case "report":
		return KEVPolicy{reportOnly: true}, nil
	default:
		return KEVPolicy{}, fmt.Errorf("invalid KEV policy %q: use block or report", s)
	}
}

// String returns the stable policy name.
func (p KEVPolicy) String() string {
	if p.reportOnly {
		return "report"
	}
	return "block"
}

// PassWithPolicy applies source, severity and the selected KEV rule.
func PassWithPolicy(problems []string, pending []Finding, policy KEVPolicy) bool {
	if len(problems) > 0 {
		return false
	}
	for _, f := range pending {
		if f.Severity == "CRITICAL" || f.Severity == "HIGH" || (!policy.reportOnly && len(f.KnownExploited) > 0) {
			return false
		}
	}
	return true
}

// MergeExploitation unions KEV records by CVE, retaining exploitation context.
func MergeExploitation(a, b []Exploitation) []Exploitation {
	records := map[string]Exploitation{}
	for _, e := range append(append([]Exploitation(nil), a...), b...) {
		old := records[e.CVE]
		if old.CVE != "" {
			if e.DateAdded == "" || (old.DateAdded != "" && old.DateAdded < e.DateAdded) {
				e.DateAdded = old.DateAdded
			}
			if e.DueDate == "" || (old.DueDate != "" && old.DueDate < e.DueDate) {
				e.DueDate = old.DueDate
			}
			if e.Action == "" {
				e.Action = old.Action
			}
			if old.Ransomware == "Known" || e.Ransomware == "" {
				e.Ransomware = old.Ransomware
			}
			urls := map[string]bool{}
			for _, u := range append(append([]string(nil), old.URLs...), e.URLs...) {
				urls[u] = true
			}
			e.URLs = nil
			for u := range urls {
				e.URLs = append(e.URLs, u)
			}
			sort.Strings(e.URLs)
		}
		records[e.CVE] = e
	}
	keys := make([]string, 0, len(records))
	for k := range records {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var out []Exploitation
	for _, k := range keys {
		out = append(out, records[k])
	}
	return out
}
