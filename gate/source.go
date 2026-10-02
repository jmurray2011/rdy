// SPDX-License-Identifier: Apache-2.0

package gate

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/jmurray2011/rdy/core"
)

type parsedTags struct {
	versions []string
	names    map[string]string
	ignored  []string
}

func tagVersions(tags []string, pattern string) (parsedTags, error) {
	r := parsedTags{names: map[string]string{}}
	var re *regexp.Regexp
	if pattern != "" {
		var err error
		re, err = regexp.Compile(pattern)
		if err != nil {
			return r, fmt.Errorf("tag-pattern: %w", err)
		}
		if re.NumSubexp() != 1 {
			return r, fmt.Errorf("tag-pattern requires exactly one capture group")
		}
	}
	sort.Strings(tags)
	for _, tag := range tags {
		v := tag
		if re != nil {
			indices := re.FindStringSubmatchIndex(tag)
			if len(indices) != 4 || indices[0] != 0 || indices[1] != len(tag) || indices[3] != len(tag) {
				r.ignored = append(r.ignored, tag)
				continue
			}
			v = tag[indices[2]:indices[3]]
		}
		if _, err := core.ParseVersion(v); err != nil {
			r.ignored = append(r.ignored, tag)
			continue
		}
		r.versions = append(r.versions, v)
		if _, ok := r.names[v]; !ok {
			r.names[v] = tag
		}
	}
	return r, nil
}

func sourceTags(ctx context.Context, o Options, tags []string, r *Result) (string, string, error) {
	p, e := tagVersions(tags, o.TagPattern)
	if e != nil {
		return "", "", e
	}
	latest, previous, e := core.SelectTagsInLine(p.versions, o.Release, o.Line)
	if e != nil {
		return "", "", e
	}
	r.ComparedTags = ComparedTags{Line: releaseLine(o.Release, o.Line), Latest: p.names[latest], Previous: p.names[previous], Count: len(tags), Ignored: p.ignored}
	r.EffectiveOptions.Line = r.ComparedTags.Line
	if latest == "" {
		why := "latest-in-line is empty; version-backwards check not run"
		if len(p.versions) == 0 {
			why = "no numeric release tags; latest-in-line is empty; version-backwards check not run"
		}
		r.SkippedChecks = append(r.SkippedChecks, why)
		r.Warnings = append(r.Warnings, Warning{ID: "source-check-skipped", Message: why})
	}
	if previous == "" {
		why := "no previous release tag; missing-patch check not run"
		r.SkippedChecks = append(r.SkippedChecks, why)
		r.Warnings = append(r.Warnings, Warning{ID: "source-check-skipped", Message: why})
	}
	r.SourceChecksSkipped = len(r.SkippedChecks)
	if len(p.ignored) > 0 {
		names := p.ignored
		if len(names) > 5 {
			names = names[:5]
		}
		r.Warnings = append(r.Warnings, Warning{ID: "tags-ignored", Message: fmt.Sprintf("ignored %d unparseable tags: %s", len(p.ignored), strings.Join(names, ", "))})
	}
	if o.Line != "" {
		release, _ := core.ParseVersion(o.Release)
		var outside []string
		for _, v := range p.versions {
			version, _ := core.ParseVersion(v)
			if version.Compare(release) > 0 {
				l, _, err := core.SelectTagsInLine([]string{v}, o.Release, o.Line)
				if err != nil {
					return "", "", err
				}
				if l == "" {
					outside = append(outside, p.names[v])
				}
			}
		}
		if len(outside) > 0 {
			r.Warnings = append(r.Warnings, Warning{ID: "line-override", Message: "--line excludes numeric tags above the release outside the line: " + strings.Join(outside, ", ")})
		}
	}
	b, e := command(ctx, o.Repo, "git", "rev-parse", "--is-shallow-repository")
	if e != nil {
		return "", "", e
	}
	r.Shallow = strings.TrimSpace(string(b)) == "true"
	if r.Shallow {
		r.Warnings = append(r.Warnings, Warning{ID: "shallow-repo", Message: "repository is shallow; tags and missing-patch history may be incomplete"})
	}
	for _, entry := range []struct {
		tag    string
		target *string
	}{{r.ComparedTags.Latest, &r.ComparedTags.LatestCommit}, {r.ComparedTags.Previous, &r.ComparedTags.PreviousCommit}} {
		tag, target := entry.tag, entry.target
		if tag != "" {
			b, e := command(ctx, o.Repo, "git", "rev-parse", "--verify", "--end-of-options", tag+"^{commit}")
			if e != nil {
				return "", "", e
			}
			*target = strings.TrimSpace(string(b))
		}
	}
	return latest, r.ComparedTags.Previous, nil
}

func validateCandidate(o Options) error {
	if o.SBOM != "" {
		if o.Artifact != "" {
			return fmt.Errorf("--sbom and --artifact are mutually exclusive")
		}
		if o.ArtifactVersion == "" {
			return fmt.Errorf("--sbom requires --artifact-version")
		}
		return nil
	}
	if o.ArtifactVersion != "" {
		return fmt.Errorf("--artifact-version requires --sbom")
	}
	switch strings.ToLower(filepath.Ext(o.Artifact)) {
	case ".jar", ".war", ".rpm", ".deb":
		if info, e := os.Stat(o.Artifact); e == nil && info.IsDir() {
			break
		}
		return nil
	}
	return fmt.Errorf("unsupported artifact %q; supported types: .jar .war .rpm .deb, or --sbom", o.Artifact)
}

func versionSource(artifact, sbom string) string {
	if sbom != "" {
		return "--artifact-version"
	}
	switch strings.ToLower(filepath.Ext(artifact)) {
	case ".rpm":
		return "rpm header"
	case ".deb":
		return "dpkg control"
	default:
		return "manifest"
	}
}

func normalizeDeclared(v, source string) string {
	switch source {
	case "dpkg control":
		if _, rest, ok := strings.Cut(v, ":"); ok {
			v = rest
		}
		if i := strings.LastIndex(v, "-"); i >= 0 {
			v = v[:i]
		}
	case "rpm header":
		if i := strings.IndexAny(v, "~^"); i >= 0 {
			v = v[:i]
		}
	}
	return v
}

func aliasWarnings(r *Result, e Evidence, prefix string) {
	for _, f := range e.RemovedByAliases {
		if f.Severity == "CRITICAL" || f.Severity == "HIGH" || len(f.KnownExploited) > 0 {
			r.Warnings = append(r.Warnings, Warning{ID: "alias-removed-finding", Message: prefix + "alias removed a Critical, High or KEV finding: " + f.Package + " " + f.ID})
		}
	}
}

func visibleHeadline(r *Result, o Options) {
	if r.SourceChecksSkipped > 0 {
		msg := fmt.Sprintf("source checks skipped (%d)", r.SourceChecksSkipped)
		if len(r.Problems) == 0 {
			r.Line = strings.Replace(r.Line, "source ok", msg, 1)
		} else {
			r.Line += " | " + msg
		}
	}
	if len(r.Aliases) > 0 {
		r.Line += fmt.Sprintf(" | %d aliases applied (%d components)", len(r.Aliases), r.AliasComponents)
	}
	if len(r.Triaged) > 0 {
		c, h, k := 0, 0, 0
		expired := map[string]bool{}
		for _, d := range r.Triaged {
			if d.Finding.Severity == "CRITICAL" {
				c++
			}
			if d.Finding.Severity == "HIGH" {
				h++
			}
			if len(d.Finding.KnownExploited) > 0 {
				k++
			}
			if d.Entry.Expires != "" && len(r.Timestamp) >= 10 && d.Entry.Expires < r.Timestamp[:10] {
				expired[d.Entry.Package+"\x00"+d.Entry.CVE] = true
			}
		}
		r.Line += fmt.Sprintf(" | %d triaged (%d Critical, %d High, %d KEV)", len(r.Triaged), c, h, k)
		r.ExpiredTriageCount = len(expired)
		if len(expired) > 0 {
			r.Line += fmt.Sprintf(" | %d expired triage entry still in force", len(expired))
		}
	}
	if o.KEVPolicy.String() == "report" {
		n := 0
		for _, f := range r.Untriaged {
			if len(f.KnownExploited) > 0 {
				n++
			}
		}
		if n > 0 {
			r.Warnings = append(r.Warnings, Warning{ID: "kev-not-blocking", Message: fmt.Sprintf("--kev-policy report allows %d untriaged KEV findings without KEV blocking", n)})
		}
	}
}
