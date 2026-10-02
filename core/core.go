// SPDX-License-Identifier: Apache-2.0

// Package core implements deterministic release decisions without I/O.
package core

import (
	"fmt"
	"math/big"
	"sort"
	"strings"
	"time"
)

// Version is a validated numeric release version.
type Version struct{ parts []*big.Int }

// ParseVersion parses numeric tags with an optional v prefix.
func ParseVersion(s string) (Version, error) {
	s = strings.TrimPrefix(s, "v")
	var v Version
	for _, p := range strings.Split(s, ".") {
		if p == "" {
			return Version{}, fmt.Errorf("invalid release version %q", s)
		}
		for _, c := range p {
			if c < '0' || c > '9' {
				return Version{}, fmt.Errorf("invalid release version %q", s)
			}
		}
		n, ok := new(big.Int).SetString(p, 10)
		if !ok {
			return Version{}, fmt.Errorf("invalid version %q", s)
		}
		v.parts = append(v.parts, n)
	}
	return v, nil
}

// Compare compares versions, padding missing trailing parts with zero.
func (v Version) Compare(w Version) int {
	for i := 0; i < len(v.parts) || i < len(w.parts); i++ {
		a, b := new(big.Int), new(big.Int)
		if i < len(v.parts) {
			a = v.parts[i]
		}
		if i < len(w.parts) {
			b = w.parts[i]
		}
		if c := a.Cmp(b); c != 0 {
			return c
		}
	}
	return 0
}

// SelectTags selects tags on the release's default line (its version without the last part).
func SelectTags(tags []string, release string) (latest, previous string) {
	latest, previous, _ = SelectTagsInLine(tags, release, "")
	return latest, previous
}

// SelectTagsInLine returns the highest release tag on the line and the highest tag on
// the line below the release. A line is a numeric version prefix: parallel maintenance
// lines do not see each other, so a 7.2.x hotfix is not "backwards" against 7.3.x. An
// empty line defaults to the release without its last part. When the line has no tag
// below the release (the first release of a new line), previous falls back to the
// highest tag below the release in the whole repository.
func SelectTagsInLine(tags []string, release, line string) (latest, previous string, err error) {
	r, err := ParseVersion(release)
	if err != nil {
		return "", "", err
	}
	prefix := Version{parts: r.parts[:len(r.parts)-1]}
	if line != "" {
		if prefix, err = ParseVersion(line); err != nil {
			return "", "", fmt.Errorf("invalid release line %q", line)
		}
		if !r.within(prefix) {
			return "", "", fmt.Errorf("release %s is not on line %s", release, line)
		}
	}
	tags = append([]string(nil), tags...)
	sort.Strings(tags)
	var lv, pv, fv Version
	var fallback string
	for _, tag := range tags {
		v, e := ParseVersion(tag)
		if e != nil {
			continue
		}
		if v.Compare(r) < 0 && (fallback == "" || v.Compare(fv) > 0) {
			fallback, fv = tag, v
		}
		if !v.within(prefix) {
			continue
		}
		if latest == "" || v.Compare(lv) > 0 {
			latest, lv = tag, v
		}
		if v.Compare(r) < 0 && (previous == "" || v.Compare(pv) > 0) {
			previous, pv = tag, v
		}
	}
	if previous == "" {
		previous = fallback
	}
	return latest, previous, nil
}

// within reports whether v starts with the line's parts, treating missing parts as zero.
func (v Version) within(line Version) bool {
	for i, p := range line.parts {
		part := new(big.Int)
		if i < len(v.parts) {
			part = v.parts[i]
		}
		if part.Cmp(p) != 0 {
			return false
		}
	}
	return true
}

// Component is the CycloneDX component data used by the merge.
type Component struct {
	Type    string `json:"type,omitempty"`
	Name    string `json:"name"`
	Group   string `json:"group,omitempty"`
	Version string `json:"version,omitempty"`
	PURL    string `json:"purl,omitempty"`
	Scope   string `json:"scope,omitempty"`
	Ref     string `json:"bom-ref,omitempty"`
}

// Merge adds declared npm fallback components without trusting build scope.
func Merge(artifact, dev []Component) []Component {
	out := append([]Component(nil), artifact...)
	seen := map[string]bool{}
	for _, c := range out {
		seen[c.PURL] = true
	}
	for _, c := range dev {
		if strings.HasPrefix(c.PURL, "pkg:npm/") && !seen[c.PURL] {
			out = append(out, c)
			seen[c.PURL] = true
		}
	}
	return out
}

// Finding is a normalized scanner result.
type Finding struct {
	ID             string         `json:"id"`
	Aliases        []string       `json:"aliases,omitempty"`
	Package        string         `json:"package"`
	Version        string         `json:"installed_version"`
	Severity       string         `json:"severity"`
	Fixed          string         `json:"fixed_version"`
	Origin         string         `json:"evidence,omitempty"`
	KnownExploited []Exploitation `json:"knownExploited,omitempty"`
}

// Entry is a persistent triage decision keyed by package and vulnerability.
type Entry struct {
	ReviewedBy    string `json:"reviewed_by,omitempty" yaml:"reviewed_by,omitempty"`
	ReviewedOn    string `json:"reviewed_on,omitempty" yaml:"reviewed_on,omitempty"`
	Expires       string `json:"expires,omitempty" yaml:"expires,omitempty"`
	Justification string `json:"justification,omitempty" yaml:"justification,omitempty"`
	Package       string `json:"package" yaml:"package"`
	CVE           string `json:"cve" yaml:"cve"`
	Status        string `json:"status" yaml:"status"`
	Reason        string `json:"reason" yaml:"reason"`
}

// Decision joins a finding with its triage rationale.
type Decision struct {
	Finding Finding `json:"finding"`
	Entry   Entry   `json:"triage"`
}

// ValidateTriage rejects invalid and conflicting decisions.
func ValidateTriage(entries []Entry) error {
	seen := map[string]bool{}
	for _, e := range entries {
		for field, value := range map[string]string{"reviewed_on": e.ReviewedOn, "expires": e.Expires} {
			if value != "" {
				if _, err := time.Parse(time.DateOnly, value); err != nil {
					return fmt.Errorf("invalid triage %s %q: expected YYYY-MM-DD", field, value)
				}
			}
		}
		if strings.TrimSpace(e.Package) == "" || strings.TrimSpace(e.CVE) == "" || strings.TrimSpace(e.Reason) == "" {
			return fmt.Errorf("triage package, cve and reason are mandatory")
		}
		switch e.Status {
		case "not_affected", "fixed_in", "accepted":
		default:
			return fmt.Errorf("invalid triage status %q", e.Status)
		}
		key := e.Package + "\x00" + e.CVE
		if seen[key] {
			return fmt.Errorf("duplicate triage decision for %s %s", e.Package, e.CVE)
		}
		seen[key] = true
	}
	return nil
}

// Identifiers returns the advisory identifier followed by its related identifiers.
func (f Finding) Identifiers() []string {
	return append([]string{f.ID}, f.Aliases...)
}

// Triage matches package and any advisory identifier without considering installed version.
func Triage(findings []Finding, entries []Entry) (pending []Finding, decisions []Decision) {
	index := map[string]Entry{}
	for _, e := range entries {
		index[e.Package+"\x00"+e.CVE] = e
	}
	for _, f := range findings {
		matched := false
		for _, id := range f.Identifiers() {
			if e, ok := index[f.Package+"\x00"+id]; ok {
				decisions = append(decisions, Decision{f, e})
				matched = true
				break
			}
		}
		if !matched {
			pending = append(pending, f)
		}
	}
	return pending, decisions
}

// Diff compares package and advisory identities; related identifiers are the same advisory.
func Diff(candidate, baseline []Finding) (added, cleared []Finding) {
	return unmatched(candidate, baseline), unmatched(baseline, candidate)
}

func unmatched(from, against []Finding) []Finding {
	known := map[string]bool{}
	for _, f := range against {
		for _, id := range f.Identifiers() {
			known[f.Package+"\x00"+id] = true
		}
	}
	var out []Finding
	reported := map[string]bool{}
	for _, f := range from {
		k := f.Package + "\x00" + f.ID
		if reported[k] {
			continue
		}
		found := false
		for _, id := range f.Identifiers() {
			if known[f.Package+"\x00"+id] {
				found = true
				break
			}
		}
		if !found {
			out = append(out, f)
			reported[k] = true
		}
	}
	return out
}

// Pass decides whether all blocking issues have been resolved.
func Pass(problems []string, pending []Finding) bool {
	return PassWithPolicy(problems, pending, KEVPolicy{})
}

// Line formats the human-readable verdict.
func Line(name, release string, problems []string, pending []Finding, deployed string, added, cleared int) string {
	return LineWithPolicy(name, release, problems, pending, deployed, added, cleared, KEVPolicy{})
}

// LineWithPolicy formats a verdict using the selected KEV policy.
func LineWithPolicy(name, release string, problems []string, pending []Finding, deployed string, added, cleared int, policy KEVPolicy) string {
	verdict, source := "PASS", "source ok"
	if !PassWithPolicy(problems, pending, policy) {
		verdict = "FAIL"
	}
	if len(problems) > 0 {
		source = fmt.Sprintf("%d source problems", len(problems))
	}
	counts := map[string]int{}
	for _, f := range pending {
		counts[f.Severity]++
	}
	s := fmt.Sprintf("%s %s  %s | %s | %d Critical, %d High untriaged | %d Medium", name, release, verdict, source, counts["CRITICAL"], counts["HIGH"], counts["MEDIUM"])
	kev := 0
	for _, f := range pending {
		if len(f.KnownExploited) > 0 {
			kev++
		}
	}
	s += fmt.Sprintf(" | %d KEV untriaged", kev)
	if deployed != "" {
		s += fmt.Sprintf(" | +%d / -%d vs deployed %s", added, cleared, deployed)
	}
	return s
}
