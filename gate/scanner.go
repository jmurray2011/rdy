// SPDX-License-Identifier: Apache-2.0

package gate

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/jmurray2011/rdy/core"
)

// ParseScan validates and normalizes Grype JSON, rejecting ignored findings.
func ParseScan(data []byte) (Scan, error) {
	var doc struct {
		Matches    json.RawMessage   `json:"matches"`
		Ignored    []json.RawMessage `json:"ignoredMatches"`
		Descriptor json.RawMessage   `json:"descriptor"`
	}
	if e := json.Unmarshal(data, &doc); e != nil {
		return Scan{}, e
	}
	if len(doc.Matches) == 0 || string(doc.Matches) == "null" {
		return Scan{}, fmt.Errorf("scanner output has no matches array")
	}
	if len(doc.Ignored) > 0 {
		return Scan{}, fmt.Errorf("scanner ignored findings; use the triage file instead")
	}
	var matches []struct {
		Vulnerability struct {
			KnownExploited []core.Exploitation `json:"knownExploited"`
			ID             string              `json:"id"`
			Severity       string              `json:"severity"`
			Namespace      string              `json:"namespace"`
			Source         string              `json:"dataSource"`
			Fix            struct {
				Versions []string `json:"versions"`
			} `json:"fix"`
		} `json:"vulnerability"`
		Related []struct {
			ID             string              `json:"id"`
			KnownExploited []core.Exploitation `json:"knownExploited"`
		} `json:"relatedVulnerabilities"`
		Artifact struct {
			PURL    string `json:"purl"`
			Version string `json:"version"`
		} `json:"artifact"`
	}
	if e := json.Unmarshal(doc.Matches, &matches); e != nil {
		return Scan{}, e
	}
	result := Scan{Metadata: doc.Descriptor}
	var descriptor struct {
		Name    string `json:"name"`
		Version string `json:"version"`
		DB      struct {
			Status struct {
				Built string `json:"built"`
				Valid bool   `json:"valid"`
			} `json:"status"`
			Providers map[string]json.RawMessage `json:"providers"`
		} `json:"db"`
		Configuration struct {
			Match struct {
				Java struct {
					CPE bool `json:"using-cpes"`
				} `json:"java"`
			} `json:"match"`
		} `json:"configuration"`
	}
	if len(doc.Descriptor) > 0 {
		if e := json.Unmarshal(doc.Descriptor, &descriptor); e != nil {
			return Scan{}, e
		}
	}
	if descriptor.Name != "grype" || descriptor.Version == "" || !descriptor.DB.Status.Valid || descriptor.DB.Status.Built == "" || len(descriptor.DB.Providers) == 0 {
		return Scan{}, fmt.Errorf("scanner database provenance missing or invalid")
	}
	if descriptor.Configuration.Match.Java.CPE {
		return Scan{}, fmt.Errorf("global Java CPE matching is forbidden; configure identity aliases")
	}
	result.DBDate = descriptor.DB.Status.Built
	sources := map[string]bool{}
	kevProvider, ok := descriptor.DB.Providers["kev"]
	if !ok {
		return Scan{}, fmt.Errorf("scanner database lacks the KEV provider")
	}
	var kevCapture struct {
		Captured string `json:"captured"`
	}
	if e := json.Unmarshal(kevProvider, &kevCapture); e != nil {
		return Scan{}, e
	}
	result.KEVCaptured = kevCapture.Captured
	for provider := range descriptor.DB.Providers {
		sources[provider] = true
	}
	dedup := map[string]core.Finding{}
	for _, m := range matches {
		v := m.Vulnerability
		severity := strings.ToUpper(v.Severity)
		switch severity {
		case "CRITICAL", "HIGH", "MEDIUM", "LOW", "NEGLIGIBLE":
		case "UNKNOWN":
			return Scan{}, fmt.Errorf("unknown severity for %s", v.ID)
		default:
			return Scan{}, fmt.Errorf("invalid severity %q", v.Severity)
		}
		if v.ID == "" || !strings.HasPrefix(m.Artifact.PURL, "pkg:") {
			return Scan{}, fmt.Errorf("scanner finding missing vulnerability id or package purl")
		}
		sort.Strings(v.Fix.Versions)
		f := core.Finding{ID: v.ID, Package: core.PackageID(m.Artifact.PURL), Version: m.Artifact.Version, Severity: severity, Fixed: strings.Join(v.Fix.Versions, ", ")}
		f.KnownExploited = core.MergeExploitation(nil, v.KnownExploited)
		for _, related := range m.Related {
			f.KnownExploited = core.MergeExploitation(f.KnownExploited, related.KnownExploited)
			f.Aliases = append(f.Aliases, related.ID)
		}
		for _, kev := range f.KnownExploited {
			if kev.CVE == "" {
				return Scan{}, fmt.Errorf("KEV record missing CVE")
			}
		}
		key := f.Package + "\x00" + f.ID + "\x00" + f.Version
		if old, ok := dedup[key]; ok {
			f.KnownExploited = core.MergeExploitation(old.KnownExploited, f.KnownExploited)
			f.Aliases = append(f.Aliases, old.Aliases...)
			ranks := map[string]int{"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "NEGLIGIBLE": 1}
			if ranks[old.Severity] > ranks[f.Severity] {
				f.Severity = old.Severity
			}
			fixed := map[string]bool{}
			for _, s := range strings.Split(old.Fixed+", "+f.Fixed, ", ") {
				if s != "" {
					fixed[s] = true
				}
			}
			var versions []string
			for s := range fixed {
				versions = append(versions, s)
			}
			sort.Strings(versions)
			f.Fixed = strings.Join(versions, ", ")
		}
		f.Aliases = relatedIDs(f.ID, f.Aliases)
		dedup[key] = f
		if v.Namespace != "" {
			sources[v.Namespace] = true
		}
		if v.Source != "" {
			sources[v.Source] = true
		}
	}
	keys := make([]string, 0, len(dedup))
	for k := range dedup {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		result.Findings = append(result.Findings, dedup[k])
	}
	for s := range sources {
		result.Sources = append(result.Sources, s)
	}
	sort.Strings(result.Sources)
	if len(result.Sources) == 0 {
		result.Sources = []string{"Grype database (see scanner_metadata for database identity; no matched advisory sources)"}
	}
	return result, nil
}

// relatedIDs returns the sorted, distinct related identifiers other than the primary.
func relatedIDs(primary string, ids []string) []string {
	seen := map[string]bool{primary: true, "": true}
	var out []string
	for _, id := range ids {
		if !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	sort.Strings(out)
	return out
}
