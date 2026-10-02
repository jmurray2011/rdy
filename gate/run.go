// SPDX-License-Identifier: Apache-2.0

package gate

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/jmurray2011/rdy/core"

	"go.yaml.in/yaml/v3"
)

// Options configures one release evaluation.
type Options struct {
	Strict          bool             `json:"strict"`
	AllowWarnings   []string         `json:"allow_warning"`
	SBOM            string           `json:"sbom,omitempty"`
	ArtifactVersion string           `json:"artifact_version,omitempty"`
	TagPattern      string           `json:"tag_pattern,omitempty"`
	Offline         bool             `json:"offline"`
	DBCache         string           `json:"db_cache,omitempty"`
	Version         string           `json:"version"`
	Now             func() time.Time `json:"-"`

	Name            string         `json:"name"`
	Release         string         `json:"release"`
	Line            string         `json:"line"`
	Artifact        string         `json:"artifact"`
	Repo            string         `json:"repo"`
	Branch          string         `json:"branch"`
	Commit          string         `json:"commit"`
	DevSBOM         string         `json:"dev_sbom"`
	Triage          string         `json:"triage"`
	Baseline        string         `json:"baseline"`
	BaselineDevSBOM string         `json:"baseline_dev_sbom"`
	Deployed        string         `json:"deployed"`
	Out             string         `json:"out"`
	Aliases         string         `json:"aliases"`
	Floor           int            `json:"min_components"`
	KEVPolicy       core.KEVPolicy `json:"kev_policy"`
}

// Scan is the normalized result and scanner provenance.
type Scan struct {
	Warnings    []Warning
	DBUpdate    DatabaseUpdate
	Findings    []core.Finding
	Sources     []string
	KEVCaptured string
	DBDate      string
	Metadata    json.RawMessage
}

// Scanner is the generation and vulnerability scanning boundary.
type Scanner interface {
	Generate(context.Context, string) ([]byte, error)
	Scan(context.Context, string) (Scan, error)
}

// Result contains the verdict and report evidence.
type Result struct {
	JavaScriptFiles                  int                 `json:"javascript_files"`
	DeclaredVersion                  string              `json:"artifact_declared_version"`
	VersionSource                    string              `json:"artifact_version_source"`
	SourceChecksSkipped              int                 `json:"source_checks_skipped"`
	SkippedChecks                    []string            `json:"skipped_source_checks"`
	Shallow                          bool                `json:"shallow_repository"`
	RemovedByAliases                 []core.Finding      `json:"findings_removed_by_aliases"`
	AliasComponents                  int                 `json:"alias_component_count"`
	AliasVersions                    map[string][]string `json:"alias_versions"`
	Bundles                          []BundleInfo        `json:"bundles"`
	ExpiredTriageCount               int                 `json:"expired_triage_count"`
	TriageEntries                    []core.Entry        `json:"triage_entries"`
	UnusedTriageEntries              []core.Entry        `json:"unused_triage_entries"`
	UnusedTriageCount                int                 `json:"unused_triage_count"`
	ComparedTags                     ComparedTags        `json:"compared_tags"`
	DBAge                            string              `json:"database_age"`
	DBUpdate                         DatabaseUpdate      `json:"database_update"`
	InputSHA256                      map[string]string   `json:"input_sha256"`
	Version                          string              `json:"tool_version"`
	Timestamp                        string              `json:"timestamp"`
	EffectiveOptions                 Options             `json:"effective_options"`
	Pass                             bool                `json:"pass"`
	Line                             string              `json:"line"`
	Branch                           string              `json:"branch"`
	Commit                           string              `json:"commit"`
	Problems                         []string            `json:"source_problems"`
	Warnings                         []Warning           `json:"warnings"`
	Missing                          []string            `json:"missing_commits"`
	Untriaged                        []core.Finding      `json:"untriaged"`
	Triaged                          []core.Decision     `json:"triaged"`
	Added                            []core.Finding      `json:"added"`
	Cleared                          []core.Finding      `json:"cleared"`
	Components                       int                 `json:"component_count"`
	Unmatched                        map[string]int      `json:"components_without_vulnerability_match"`
	Sources                          []string            `json:"vulnerability_sources"`
	ScannerMetadata                  json.RawMessage     `json:"scanner_metadata"`
	PrebuiltWithoutVendoringEvidence int                 `json:"prebuilt_without_vendoring_evidence"`
	Opaque                           []core.Opaque       `json:"opaque_bundled_code"`
	Aliases                          []core.Alias        `json:"applied_aliases"`
	DBDate                           string              `json:"database_build_date"`
	KEVCaptured                      string              `json:"kev_feed_captured"`
	KEVPolicy                        string              `json:"kev_policy"`
	Baseline                         *Evidence           `json:"baseline,omitempty"`
}

// Evidence records baseline findings, triage and coverage.
type Evidence struct {
	Warnings                         []Warning           `json:"warnings"`
	Bundles                          []BundleInfo        `json:"bundles"`
	RemovedByAliases                 []core.Finding      `json:"findings_removed_by_aliases"`
	AliasComponents                  int                 `json:"alias_component_count"`
	AliasVersions                    map[string][]string `json:"alias_versions"`
	SkippedLinks                     int                 `json:"skipped_archive_links"`
	DBUpdate                         DatabaseUpdate      `json:"database_update"`
	InputSHA256                      map[string]string   `json:"input_sha256"`
	Findings                         []core.Finding      `json:"findings"`
	Untriaged                        []core.Finding      `json:"untriaged"`
	Triaged                          []core.Decision     `json:"triaged"`
	Components                       int                 `json:"component_count"`
	Unmatched                        map[string]int      `json:"components_without_vulnerability_match"`
	Sources                          []string            `json:"vulnerability_sources"`
	PrebuiltWithoutVendoringEvidence int                 `json:"prebuilt_without_vendoring_evidence"`
	Opaque                           []core.Opaque       `json:"opaque_bundled_code"`
	Aliases                          []core.Alias        `json:"applied_aliases"`
	DBDate                           string              `json:"database_build_date"`
	KEVCaptured                      string              `json:"kev_feed_captured"`
	Metadata                         json.RawMessage     `json:"scanner_metadata"`
	Scripts                          int                 `json:"javascript_files"`
	NPM                              int                 `json:"npm_components"`
}

func readSBOM(data []byte) (map[string]json.RawMessage, []core.Component, error) {
	var doc map[string]json.RawMessage
	if e := json.Unmarshal(data, &doc); e != nil {
		return nil, nil, e
	}
	var format string
	if e := json.Unmarshal(doc["bomFormat"], &format); e != nil || format != "CycloneDX" {
		return nil, nil, fmt.Errorf("expected CycloneDX JSON")
	}
	if len(doc["components"]) == 0 {
		// An empty artifact yields no components key; the component floor decides it.
		doc["components"] = json.RawMessage("[]")
	}
	var components []core.Component
	if e := json.Unmarshal(doc["components"], &components); e != nil {
		return nil, nil, fmt.Errorf("invalid components: %w", e)
	}
	return doc, components, nil
}

func coverage(components []core.Component, findings []core.Finding) map[string]int {
	matches := map[string]bool{}
	for _, f := range findings {
		matches[f.Package+"\x00"+f.Version] = true
	}
	counts := map[string]int{}
	for _, c := range components {
		identity := core.PackageID(c.PURL)
		if matches[identity+"\x00"+c.Version] {
			continue
		}
		ecosystem := "unknown"
		if rest, ok := strings.CutPrefix(c.PURL, "pkg:"); ok {
			ecosystem, _, _ = strings.Cut(rest, "/")
		}
		counts[ecosystem]++
	}
	return counts
}

// Run evaluates a candidate, writes reports, and returns errors separately from FAIL.
func Run(ctx context.Context, o Options, s Scanner) (Result, error) {
	allowed, err := NormalizeAllowedWarnings(o.AllowWarnings)
	if err != nil {
		return Result{}, err
	}
	o.AllowWarnings = allowed
	now := time.Now().UTC()
	if o.Now != nil {
		now = o.Now().UTC()
	}
	if o.Version == "" {
		o.Version = "dev"
	}
	r := Result{Version: o.Version, Timestamp: now.Format(time.RFC3339), EffectiveOptions: o, Branch: o.Branch, KEVPolicy: o.KEVPolicy.String()}
	if o.Name == "" || o.Release == "" || (o.Artifact == "" && o.SBOM == "") || o.Repo == "" || o.Branch == "" || o.Triage == "" || o.Out == "" || o.Floor < 1 {
		return r, fmt.Errorf("required flags missing or component floor below one")
	}
	if err := validateCandidate(o); err != nil {
		return r, err
	}
	if _, err := tagVersions(nil, o.TagPattern); err != nil {
		return r, err
	}
	if strings.HasPrefix(o.Branch, "-") {
		return r, fmt.Errorf("branch cannot begin with -")
	}
	version, e := core.ParseVersion(o.Release)
	if e != nil {
		return r, e
	}
	aliases, e := core.NewAliases(nil)
	if e != nil {
		return r, e
	}
	if o.Aliases != "" {
		data, err := os.ReadFile(o.Aliases)
		if err != nil {
			return r, err
		}
		var entries []core.Alias
		d := yaml.NewDecoder(bytes.NewReader(data))
		d.KnownFields(true)
		if err = d.Decode(&entries); err != nil {
			return r, err
		}
		var extra any
		if err = d.Decode(&extra); err != io.EOF {
			return r, fmt.Errorf("aliases require one YAML document")
		}
		aliases, err = core.NewAliases(entries)
		if err != nil {
			return r, err
		}
	}
	b, e := os.ReadFile(o.Triage)
	if e != nil {
		return r, e
	}
	var entries []core.Entry
	decoder := yaml.NewDecoder(bytes.NewReader(b))
	decoder.KnownFields(true)
	if e = decoder.Decode(&entries); e != nil {
		return r, e
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return r, fmt.Errorf("triage requires one YAML document")
	}
	for i := range entries {
		entries[i].Package = aliases.Canonical(entries[i].Package)
	}
	if e = core.ValidateTriage(entries); e != nil {
		return r, e
	}
	hashes, err := hashInputs(ctx, o)
	if err != nil {
		return r, err
	}
	r.InputSHA256 = hashes
	b, e = command(ctx, o.Repo, "git", "rev-parse", "--verify", o.Branch+"^{commit}")
	if e != nil {
		return r, e
	}
	r.Commit = strings.TrimSpace(string(b))
	if o.Commit != "" && o.Commit != r.Commit {
		r.Problems = append(r.Problems, "declared source commit differs from branch commit")
	}
	b, e = command(ctx, o.Repo, "git", "tag", "--list")
	if e != nil {
		return r, e
	}
	tags := strings.Fields(string(b))
	latest, previous, err := sourceTags(ctx, o, tags, &r)
	if err != nil {
		return r, err
	}
	if latest != "" {
		v, err := core.ParseVersion(latest)
		if err != nil {
			return r, err
		}
		if version.Compare(v) < 0 {
			r.Problems = append(r.Problems, "version goes backwards: latest tag is "+r.ComparedTags.Latest)
		}
	}
	r.Missing, e = Missing(ctx, o.Repo, r.Commit, r.ComparedTags.Previous)
	if e != nil {
		return r, e
	}
	if len(r.Missing) > 0 {
		r.Problems = append(r.Problems, fmt.Sprintf("%d missing patches from %s", len(r.Missing), previous))
	}
	if e = os.MkdirAll(o.Out, 0o700); e != nil {
		return r, e
	}
	input := o.Artifact
	declaredInput := false
	if o.SBOM != "" {
		input = o.SBOM
		declaredInput = true
	}
	candidate, declared, e := process(ctx, input, o.DevSBOM, filepath.Join(o.Out, "candidate.cdx.json"), declaredInput, s, aliases)
	if e != nil {
		return r, e
	}
	if o.SBOM != "" {
		declared = o.ArtifactVersion
	}
	r.DeclaredVersion, r.VersionSource = declared, versionSource(o.Artifact, o.SBOM)
	normalized := normalizeDeclared(declared, r.VersionSource)
	declaredVersion, declaredErr := core.ParseVersion(normalized)
	switch {
	case declared == "" && r.VersionSource == "manifest":
		r.Problems = append(r.Problems, "manifest has no Implementation-Version")
	case declaredErr != nil:
		r.Problems = append(r.Problems, fmt.Sprintf("declared version %s is not purely numeric", declared))
	case declaredVersion.Compare(version) != 0:
		r.Problems = append(r.Problems, fmt.Sprintf("declared version %s differs from release %s", declared, o.Release))
	}
	if o.Commit == "" {
		r.Warnings = append(r.Warnings, Warning{ID: "commit-not-asserted", Message: "no --commit supplied; source identity not asserted"})
	}
	r.JavaScriptFiles = candidate.Scripts
	r.RemovedByAliases, r.AliasComponents, r.AliasVersions, r.Bundles = candidate.RemovedByAliases, candidate.AliasComponents, candidate.AliasVersions, candidate.Bundles
	r.Warnings = append(r.Warnings, candidate.Warnings...)
	aliasWarnings(&r, candidate, "")
	for _, bundle := range candidate.Bundles {
		if !bundle.Stamped {
			r.Warnings = append(r.Warnings, Warning{ID: "bundle-unstamped", Message: "unstamped bundle SBOM: " + bundle.Path})
		}
	}
	if candidate.Components < o.Floor {
		r.Problems = append(r.Problems, fmt.Sprintf("thin candidate SBOM: %d components below floor %d", candidate.Components, o.Floor))
	}
	if candidate.SkippedLinks > 0 {
		r.Warnings = append(r.Warnings, Warning{ID: "archive-links-skipped", Message: fmt.Sprintf("%d archive links skipped; linked files are not covered", candidate.SkippedLinks)})
	}
	r.PrebuiltWithoutVendoringEvidence = candidate.PrebuiltWithoutVendoringEvidence
	r.Opaque, r.Aliases, r.DBDate = candidate.Opaque, candidate.Aliases, candidate.DBDate
	r.KEVCaptured = candidate.KEVCaptured
	r.DBUpdate = candidate.DBUpdate
	r.DBAge = databaseAge(candidate.DBDate, now)
	if candidate.DBUpdate.Outcome == "failed" {
		r.Warnings = append(r.Warnings, Warning{ID: "db-update-failed", Message: "database update failed; using cached database: " + candidate.DBUpdate.Reason})
	}
	for key, value := range candidate.InputSHA256 {
		r.InputSHA256["embedded_sbom:"+key] = value
	}
	candidateHash, err := hashFile(ctx, filepath.Join(o.Out, "candidate.cdx.json"))
	if err != nil {
		return r, err
	}
	r.InputSHA256["candidate_sbom"] = candidateHash
	r.Components, r.Unmatched, r.Sources, r.ScannerMetadata = candidate.Components, candidate.Unmatched, candidate.Sources, candidate.Metadata
	if candidate.Scripts > 0 && len(candidate.Bundles) == 0 {
		r.Warnings = append(r.Warnings, Warning{ID: "frontend-not-covered", Message: fmt.Sprintf("%d JavaScript files shipped; no bundle.cdx.json embedded; frontend dependencies are not covered", candidate.Scripts)})
	}
	if o.SBOM != "" {
		for i := range candidate.Findings {
			candidate.Findings[i].Origin = "declared SBOM, not extracted"
		}
	}
	r.Untriaged, r.Triaged = core.Triage(candidate.Findings, entries)
	if o.Baseline != "" {
		baseline, _, err := process(ctx, o.Baseline, o.BaselineDevSBOM, filepath.Join(o.Out, "baseline.cdx.json"), true, s, aliases)
		if err != nil {
			return r, err
		}
		baseline.Untriaged, baseline.Triaged = core.Triage(baseline.Findings, entries)
		if baseline.DBUpdate.Outcome == "failed" {
			r.Warnings = append(r.Warnings, Warning{ID: "db-update-failed", Message: "baseline database update failed; using cached database: " + baseline.DBUpdate.Reason})
		}
		if baseline.SkippedLinks > 0 {
			r.Warnings = append(r.Warnings, Warning{ID: "archive-links-skipped", Message: fmt.Sprintf("baseline: %d archive links skipped; linked files are not covered", baseline.SkippedLinks)})
		}
		r.Warnings = append(r.Warnings, baseline.Warnings...)
		aliasWarnings(&r, baseline, "baseline: ")
		r.Baseline = &baseline
		for key, value := range baseline.InputSHA256 {
			r.InputSHA256["baseline_embedded_sbom:"+key] = value
		}
		r.Added, r.Cleared = core.Diff(candidate.Findings, baseline.Findings)
		if o.Deployed == "" {
			o.Deployed = "baseline"
		}
	}
	r.EffectiveOptions.Deployed = o.Deployed
	triageExtras(&r, entries, now.Format(time.DateOnly))
	r.Pass = core.PassWithPolicy(r.Problems, r.Untriaged, o.KEVPolicy)
	r.Line = core.LineWithPolicy(o.Name, o.Release, r.Problems, r.Untriaged, o.Deployed, len(r.Added), len(r.Cleared), o.KEVPolicy)
	visibleHeadline(&r, o)
	strictVerdict(&r, o)
	switch n := len(r.Warnings); {
	case n == 1:
		r.Line += " | 1 warning"
	case n > 1:
		r.Line += fmt.Sprintf(" | %d warnings", n)
	}
	if e = writeReports(o.Out, r, entries); e != nil {
		return r, e
	}
	return r, nil
}

func saveJSON(path string, value any) error {
	b, e := json.MarshalIndent(value, "", "  ")
	if e != nil {
		return e
	}
	return os.WriteFile(path, append(b, '\n'), 0o600)
}

func cell(s string) string {
	s = strings.ReplaceAll(s, "|", "\\|")
	s = strings.ReplaceAll(s, "\r", " ")
	return strings.ReplaceAll(s, "\n", " ")
}

func table(b *strings.Builder, title string, findings []core.Finding) {
	if len(findings) == 0 {
		return
	}
	fmt.Fprintf(b, "\n## %s\n\n| CVE | Package | Installed | Severity | Fixed | Evidence | KEV CVEs |\n| --- | --- | --- | --- | --- | --- | --- |\n", title)
	for _, f := range findings {
		var cves []string
		for _, kev := range f.KnownExploited {
			cves = append(cves, kev.CVE)
		}
		fmt.Fprintf(b, "| %s | %s | %s | %s | %s | %s | %s |\n", cell(f.ID), cell(f.Package), cell(f.Version), cell(f.Severity), cell(f.Fixed), cell(f.Origin), cell(strings.Join(cves, ", ")))
	}
}

func writeReports(out string, r Result, entries []core.Entry) error {
	if e := saveJSON(filepath.Join(out, "findings.json"), r); e != nil {
		return e
	}
	var b strings.Builder
	fmt.Fprintf(&b, "# Release gate\n\n%s\n", cell(r.Line))
	if len(r.Problems) > 0 || len(r.Missing) > 0 {
		b.WriteString("\n## Source problems\n\n")
		for _, p := range r.Problems {
			fmt.Fprintf(&b, "- %s - Fix: %s\n", cell(p), cell(sourceFix(p)))
		}
		if len(r.Missing) > 0 {
			b.WriteString("\n### Missing commits\n\n")
			for _, p := range r.Missing {
				fmt.Fprintf(&b, "- %s\n", cell(p))
			}
		}
	}
	table(&b, "Untriaged", r.Untriaged)
	hasKEV := false
	for _, f := range r.Untriaged {
		hasKEV = hasKEV || len(f.KnownExploited) > 0
	}
	for _, d := range r.Triaged {
		hasKEV = hasKEV || len(d.Finding.KnownExploited) > 0
	}
	if hasKEV {
		b.WriteString("\n## Known exploited vulnerabilities\n\nCISA due dates are catalog context; the gate uses membership, not deadlines.\n\n| Advisory | Package | CVE | Added | Due | Ransomware use | Required action | Triage |\n| --- | --- | --- | --- | --- | --- | --- | --- |\n")
		for _, f := range r.Untriaged {
			kevRows(&b, f, "untriaged")
		}
		for _, d := range r.Triaged {
			kevRows(&b, d.Finding, triageStatus(d.Entry)+": "+d.Entry.Reason)
		}
	}
	if len(r.Warnings) > 0 || (!r.EffectiveOptions.Strict && len(r.EffectiveOptions.AllowWarnings) > 0) {
		b.WriteString("\n## Warnings\n\n")
		if !r.EffectiveOptions.Strict && len(r.EffectiveOptions.AllowWarnings) > 0 {
			b.WriteString("--allow-warning has no effect without --strict.\n\n")
		}
		for _, w := range r.Warnings {
			suffix := ""
			if w.Allowed {
				suffix = " (allowed)"
			}
			fmt.Fprintf(&b, "- [%s] %s%s\n", cell(w.ID), cell(w.Message), suffix)
		}
	}
	fmt.Fprintf(&b, "\n%d packages ship prebuilt dist code with no evidence of vendoring; not counted as opaque\n", r.PrebuiltWithoutVendoringEvidence)
	if len(r.Opaque) > 0 {
		b.WriteString("\n## Opaque bundled code\n\nTransitive contents are unknown and are not counted as covered.\n\n| Parent package | Version | Path | Dependencies not in the module graph |\n| --- | --- | --- | --- |\n")
		for _, o := range r.Opaque {
			fmt.Fprintf(&b, "| %s | %s | %s | %s |\n", cell(o.Package), cell(o.Version), cell(o.Path), cell(strings.Join(o.Unaccounted, ", ")))
		}
	}
	if len(r.Aliases) > 0 {
		b.WriteString("\n## Applied identity aliases\n\n")
		for _, a := range r.Aliases {
			fmt.Fprintf(&b, "- %s -> %s\n", cell(a.From), cell(a.To))
			fmt.Fprintf(&b, "  - Rewritten versions: %s\n", cell(strings.Join(r.AliasVersions[a.From+" -> "+a.To], ", ")))
		}
	}
	table(&b, "Findings removed by aliases", r.RemovedByAliases)
	if len(r.Bundles) > 0 {
		b.WriteString("\n## Embedded frontend bundles\n\n| Path | Components | Opaque modules | Evidence stamped |\n| --- | --- | --- | --- |\n")
		for _, v := range r.Bundles {
			fmt.Fprintf(&b, "| %s | %d | %d | %t |\n", cell(v.Path), v.Components, v.Opaque, v.Stamped)
		}
	}
	if len(r.Unmatched) > 0 {
		b.WriteString("\n## Components with no vulnerability match\n\nNo match is not evidence of safety.\n\n")
		keys := make([]string, 0, len(r.Unmatched))
		for k := range r.Unmatched {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Fprintf(&b, "- %s: %d\n", cell(k), r.Unmatched[k])
		}
	}
	if len(r.Triaged) > 0 {
		b.WriteString("\n## Triaged\n\n")
		for _, d := range r.Triaged {
			fmt.Fprintf(&b, "- %s / %s (%s), %s: %s - %s [%s]", cell(d.Finding.Package), cell(d.Finding.ID), cell(d.Finding.Version), cell(d.Finding.Severity), cell(triageStatus(d.Entry)), cell(d.Entry.Reason), cell(d.Finding.Origin))
			if len(r.Timestamp) >= 10 && d.Entry.Expires != "" && d.Entry.Expires < r.Timestamp[:10] {
				b.WriteString(" (expired)")
			}
			for _, f := range []struct{ k, v string }{{"reviewed_by", d.Entry.ReviewedBy}, {"reviewed_on", d.Entry.ReviewedOn}, {"expires", d.Entry.Expires}} {
				if f.v != "" {
					fmt.Fprintf(&b, "; %s: %s", f.k, cell(f.v))
				}
			}
			b.WriteByte('\n')
		}
	}
	if len(r.UnusedTriageEntries) > 0 {
		b.WriteString("\n## Triage entries with no match in this run\n\n")
		for _, e := range r.UnusedTriageEntries {
			fmt.Fprintf(&b, "- %s / %s: %s - %s\n", cell(e.Package), cell(e.CVE), cell(e.Status), cell(e.Reason))
		}
	}
	if r.Baseline != nil {
		table(&b, "Added", r.Added)
		table(&b, "Cleared", r.Cleared)
		fmt.Fprintf(&b, "\nBaseline database build date: %s\n\nBaseline KEV feed captured: %s\n", cell(r.Baseline.DBDate), cell(r.Baseline.KEVCaptured))
		fmt.Fprintf(&b, "\nBaseline components: %d\n\nBaseline sources: %s\n\n", r.Baseline.Components, cell(strings.Join(providerNames(r.Baseline.Metadata, r.Baseline.Sources), ", ")))
		if len(r.Baseline.Unmatched) > 0 {
			b.WriteString("\nBaseline unmatched:\n\n")
			keys := make([]string, 0, len(r.Baseline.Unmatched))
			for k := range r.Baseline.Unmatched {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				fmt.Fprintf(&b, "- %s: %d\n", cell(k), r.Baseline.Unmatched[k])
			}
		}
	}
	b.WriteByte('\n')
	fmt.Fprintf(&b, "## Evidence header\n\nBranch: %s\n\nResolved commit: %s\n\nVulnerability sources: %s\n\nComponents: %d\n", cell(r.Branch), r.Commit, cell(strings.Join(providerNames(r.ScannerMetadata, r.Sources), ", ")), r.Components)
	fmt.Fprintf(&b, "\nDatabase build date: %s\n\nDatabase age: %s\n\nDatabase update: %s\n\nCompared tags: line=%s; latest-in-line=%s; previous=%s\n\nTool version: %s\n\nTimestamp (UTC): %s\n", cell(r.DBDate), cell(r.DBAge), cell(r.DBUpdate.String()), cell(r.ComparedTags.Line), cell(r.ComparedTags.Latest), cell(r.ComparedTags.Previous), cell(r.Version), cell(r.Timestamp))
	fmt.Fprintf(&b, "\nArtifact declared version: %s (source: %s)\n", cell(r.DeclaredVersion), cell(r.VersionSource))
	keysSHA := make([]string, 0, len(r.InputSHA256))
	for key := range r.InputSHA256 {
		keysSHA = append(keysSHA, key)
	}
	sort.Strings(keysSHA)
	for _, key := range keysSHA {
		fmt.Fprintf(&b, "\nSHA256 %s: %s\n", cell(key), r.InputSHA256[key])
	}
	effective, _ := json.Marshal(r.EffectiveOptions)
	fmt.Fprintf(&b, "\nEffective options: %s\n", cell(string(effective)))
	fmt.Fprintf(&b, "\nKEV policy: %s\n\nKEV feed captured: %s\n", cell(r.KEVPolicy), cell(r.KEVCaptured))
	if e := os.WriteFile(filepath.Join(out, "report.md"), []byte(b.String()), 0o600); e != nil {
		return e
	}
	return writeVEX(filepath.Join(out, "triage.vex.json"), r)
}

func writeVEX(path string, r Result) error {
	type analysis struct {
		Justification string   `json:"justification,omitempty"`
		State         string   `json:"state"`
		Detail        string   `json:"detail"`
		Response      []string `json:"response,omitempty"`
	}
	type affect struct {
		Ref string `json:"ref"`
	}
	type vulnerability struct {
		ID       string   `json:"id"`
		Affects  []affect `json:"affects"`
		Analysis analysis `json:"analysis"`
	}
	var components []core.Component
	var vulnerabilities []vulnerability
	seen := map[string]bool{}
	for _, d := range r.Triaged {
		e := d.Entry
		ref := e.Package + "@" + url.PathEscape(d.Finding.Version)
		if !seen[ref] {
			components = append(components, core.Component{Type: "library", Name: e.Package, Version: d.Finding.Version, PURL: ref, Ref: ref})
			seen[ref] = true
		}
		a := analysis{Detail: e.Reason}
		if e.Justification != "" && (e.Status != "not_affected" || !cdxJustification(e.Justification)) {
			a.Detail += "; justification: " + e.Justification
		}
		switch e.Status {
		case "not_affected":
			a.State = "not_affected"
			if cdxJustification(e.Justification) {
				a.Justification = e.Justification
			}
		case "fixed_in":
			a.State = "in_triage"
		case "accepted":
			a.State = "exploitable"
			a.Response = []string{"will_not_fix"}
		}
		vulnerabilities = append(vulnerabilities, vulnerability{e.CVE, []affect{{ref}}, a})
	}
	return saveJSON(path, struct {
		Format          string           `json:"bomFormat"`
		Spec            string           `json:"specVersion"`
		Version         int              `json:"version"`
		Metadata        any              `json:"metadata"`
		Components      []core.Component `json:"components,omitempty"`
		Vulnerabilities []vulnerability  `json:"vulnerabilities,omitempty"`
	}{"CycloneDX", "1.6", 1, vexMetadata(r), components, vulnerabilities})
}

func kevRows(b *strings.Builder, f core.Finding, triage string) {
	for _, kev := range f.KnownExploited {
		fmt.Fprintf(b, "| %s | %s | %s | %s | %s | %s | %s | %s |\n", cell(f.ID), cell(f.Package), cell(kev.CVE), cell(kev.DateAdded), cell(kev.DueDate), cell(kev.Ransomware), cell(kev.Action), cell(triage))
	}
}

// MarshalJSON records a policy name instead of the opaque policy implementation.
func (o Options) MarshalJSON() ([]byte, error) {
	type plain Options
	return json.Marshal(struct {
		plain
		Policy string `json:"kev_policy"`
	}{plain(o), o.KEVPolicy.String()})
}
