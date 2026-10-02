// SPDX-License-Identifier: Apache-2.0

package gate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/jmurray2011/rdy/core"
)

// WriteBundle writes an embedded CycloneDX bundle SBOM and consumes successful stats.
func WriteBundle(ctx context.Context, statsPath, lockPath, outPath string) error {
	if e := ctx.Err(); e != nil {
		return e
	}
	if statsPath == "" || lockPath == "" || outPath == "" || filepath.Base(outPath) != "bundle.cdx.json" {
		return fmt.Errorf("bundle step requires stats, lockfile and output named bundle.cdx.json")
	}
	out, e := filepath.Abs(outPath)
	if e != nil {
		return e
	}
	outInfo, err := os.Stat(out)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	for _, p := range []string{statsPath, lockPath} {
		input, e := filepath.Abs(p)
		if e != nil {
			return e
		}
		inputInfo, err := os.Stat(input)
		if err != nil {
			return err
		}
		if strings.EqualFold(out, input) || (outInfo != nil && os.SameFile(outInfo, inputInfo)) {
			return fmt.Errorf("bundle output conflicts with input")
		}
	}
	stats, e := os.ReadFile(statsPath)
	if e != nil {
		return e
	}
	lock, e := os.ReadFile(lockPath)
	if e != nil {
		return e
	}
	bundle, e := core.BuildBundle(stats, lock)
	if e != nil {
		return fmt.Errorf("bundle inputs %s (webpack module graph), %s (npm package-lock v2/v3): %w", statsPath, lockPath, e)
	}
	if len(bundle.Components) == 0 {
		return fmt.Errorf("webpack stats %s resolves 0 components against npm package-lock v2/v3 %s", statsPath, lockPath)
	}
	opaque, e := json.Marshal(bundle.Opaque)
	if e != nil {
		return e
	}
	doc := struct {
		Format     string           `json:"bomFormat"`
		Spec       string           `json:"specVersion"`
		Version    int              `json:"version"`
		Components []core.Component `json:"components"`
		Properties []property       `json:"properties"`
	}{"CycloneDX", "1.6", 1, bundle.Components, []property{{"rdy:opaque-bundled-code", string(opaque)}, {"rdy:prebuilt-without-vendoring-evidence", prebuiltJSON(bundle.Prebuilt)}, {"rdy:frontend-evidence", "webpack module graph + exact npm lockfile paths"}}}
	if e = ctx.Err(); e != nil {
		return e
	}
	if e = os.MkdirAll(filepath.Dir(outPath), 0o700); e != nil {
		return e
	}
	if e = saveJSON(outPath, doc); e != nil {
		return e
	}
	return os.Remove(statsPath)
}

type property struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

func opaqueFrom(doc map[string]json.RawMessage) ([]core.Opaque, error) {
	if len(doc["properties"]) == 0 {
		return nil, nil
	}
	var props []property
	if e := json.Unmarshal(doc["properties"], &props); e != nil {
		return nil, e
	}
	var out []core.Opaque
	for _, p := range props {
		if p.Name == "rdy:opaque-bundled-code" {
			var values []core.Opaque
			if e := json.Unmarshal([]byte(p.Value), &values); e != nil {
				return nil, e
			}
			out = append(out, values...)
		}
	}
	return out, nil
}

// BundleInfo summarizes one embedded frontend evidence document.
type BundleInfo struct {
	Path       string `json:"path"`
	Components int    `json:"component_count"`
	Opaque     int    `json:"opaque_count"`
	Stamped    bool   `json:"stamped"`
}

type bundleEvidence struct {
	bundles  []BundleInfo
	hashes   map[string]string
	opaque   []core.Opaque
	prebuilt []string
}

func embedded(ctx context.Context, root string) ([]core.Component, bundleEvidence, error) {
	var components []core.Component
	var opaque []core.Opaque
	var prebuilt []string
	hashes := map[string]string{}
	var bundles []BundleInfo
	e := filepath.WalkDir(root, func(path string, d fs.DirEntry, e error) error {
		if e != nil {
			return e
		}
		if e = ctx.Err(); e != nil {
			return e
		}
		if d.IsDir() || d.Name() != "bundle.cdx.json" {
			return nil
		}
		b, e := os.ReadFile(path)
		if e != nil {
			return e
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(b)
		hashes[filepath.ToSlash(rel)] = hex.EncodeToString(sum[:])
		doc, c, e := readSBOM(b)
		if e != nil {
			return e
		}
		o, e := opaqueFrom(doc)
		if e != nil {
			return e
		}
		stamped := false
		var props []property
		if len(doc["properties"]) > 0 {
			if e = json.Unmarshal(doc["properties"], &props); e != nil {
				return e
			}
			for _, p := range props {
				if p.Name == "rdy:frontend-evidence" && p.Value != "" {
					stamped = true
				}
			}
		}
		bundles = append(bundles, BundleInfo{filepath.ToSlash(rel), len(c), len(o), stamped})
		components = append(components, c...)
		opaque = append(opaque, o...)
		ids, err := prebuiltFrom(doc)
		if err != nil {
			return err
		}
		prebuilt = append(prebuilt, ids...)
		return nil
	})
	return components, bundleEvidence{bundles: bundles, hashes: hashes, opaque: opaque, prebuilt: prebuilt}, e
}

func process(ctx context.Context, input, dev, out string, baseline bool, s Scanner, aliases core.Aliases) (Evidence, string, error) {
	var data []byte
	var declared string
	var expected []core.Component
	var opaque []core.Opaque
	var prebuilt []string
	inputHashes := map[string]string{}
	var scripts, links int
	var bundles []BundleInfo
	var e error
	if baseline && strings.EqualFold(filepath.Ext(input), ".json") {
		data, e = os.ReadFile(input)
	} else {
		root, err := os.MkdirTemp("", "rdy-")
		if err != nil {
			return Evidence{}, "", err
		}
		defer func() { _ = os.RemoveAll(root) }()
		declared, e = extract(ctx, input, root, &links)
		if e == nil {
			var bundled bundleEvidence
			expected, bundled, e = embedded(ctx, root)
			opaque, prebuilt = bundled.opaque, bundled.prebuilt
			inputHashes = bundled.hashes
			bundles = bundled.bundles
		}
		if e == nil {
			scripts, e = javascriptFiles(ctx, root)
		}
		if e == nil {
			data, e = s.Generate(ctx, root)
		}
	}
	if e != nil {
		return Evidence{}, "", e
	}
	doc, components, e := readSBOM(data)
	if e != nil {
		return Evidence{}, "", e
	}
	fromDoc, e := opaqueFrom(doc)
	if e != nil {
		return Evidence{}, "", e
	}
	opaque = append(opaque, fromDoc...)
	ids, err := prebuiltFrom(doc)
	if err != nil {
		return Evidence{}, "", err
	}
	prebuilt = append(prebuilt, ids...)
	unique := map[string]bool{}
	for _, id := range prebuilt {
		unique[id] = true
	}
	for _, o := range opaque {
		delete(unique, "pkg:npm/"+strings.ReplaceAll(o.Package, "@", "%40")+"@"+url.PathEscape(o.Version))
	}
	prebuilt = prebuilt[:0]
	for id := range unique {
		prebuilt = append(prebuilt, id)
	}
	sort.Strings(prebuilt)
	seen := map[string]bool{}
	for _, c := range components {
		seen[c.PURL] = true
	}
	for _, c := range expected {
		if !seen[c.PURL] {
			return Evidence{}, "", fmt.Errorf("syft omitted embedded bundle component %s", c.PURL)
		}
	}
	var raw []json.RawMessage
	if e = json.Unmarshal(doc["components"], &raw); e != nil {
		return Evidence{}, "", e
	}
	declaredKeys := map[string]bool{}
	if dev != "" {
		b, err := os.ReadFile(dev)
		if err != nil {
			return Evidence{}, "", err
		}
		_, extra, err := readSBOM(b)
		if err != nil {
			return Evidence{}, "", err
		}
		merged := core.Merge(components, extra)
		for _, c := range merged[len(components):] {
			canonical := aliases.Canonical(core.PackageID(c.PURL))
			declaredKeys[canonical+"\x00"+c.Version] = true
			b, err = json.Marshal(c)
			if err != nil {
				return Evidence{}, "", err
			}
			raw = append(raw, b)
		}
		components = merged
	}
	doc["components"], e = json.Marshal(raw)
	if e != nil {
		return Evidence{}, "", e
	}
	preAlias, e := json.MarshalIndent(doc, "", "  ")
	if e != nil {
		return Evidence{}, "", e
	}
	canonical := aliases.Apply(components)
	aliasComponents := 0
	aliasVersions := map[string][]string{}
	var changes []core.Alias
	applied := map[core.Alias]bool{}
	for i, c := range canonical {
		if c.PURL == components[i].PURL {
			continue
		}
		aliasComponents++
		change := core.Alias{From: core.PackageID(components[i].PURL), To: core.PackageID(c.PURL)}
		key := change.From + " -> " + change.To
		aliasVersions[key] = append(aliasVersions[key], components[i].Version)
		if !applied[change] {
			applied[change] = true
			changes = append(changes, change)
		}
		var value map[string]json.RawMessage
		if e = json.Unmarshal(raw[i], &value); e != nil {
			return Evidence{}, "", e
		}
		for key, v := range map[string]string{"purl": c.PURL, "name": c.Name, "group": c.Group} {
			value[key], e = json.Marshal(v)
			if e != nil {
				return Evidence{}, "", e
			}
		}
		if len(value["properties"]) > 0 {
			var props []property
			if e = json.Unmarshal(value["properties"], &props); e != nil {
				return Evidence{}, "", e
			}
			for j, p := range props {
				switch p.Name {
				case "syft:metadata:-:groupID":
					props[j].Value = c.Group
				case "syft:metadata:-:artifactID", "syft:package:name":
					props[j].Value = c.Name
				}
			}
			value["properties"], e = json.Marshal(props)
			if e != nil {
				return Evidence{}, "", e
			}
		}
		raw[i], e = json.Marshal(value)
		if e != nil {
			return Evidence{}, "", e
		}
	}
	components = canonical
	doc["components"], e = json.Marshal(raw)
	if e != nil {
		return Evidence{}, "", e
	}
	opaqueJSON, e := json.Marshal(opaque)
	if e != nil {
		return Evidence{}, "", e
	}
	var props []property
	if len(doc["properties"]) > 0 {
		if e = json.Unmarshal(doc["properties"], &props); e != nil {
			return Evidence{}, "", e
		}
	}
	filtered := props[:0]
	for _, p := range props {
		if p.Name != "rdy:opaque-bundled-code" && p.Name != "rdy:prebuilt-without-vendoring-evidence" {
			filtered = append(filtered, p)
		}
	}
	props = append(filtered, property{"rdy:opaque-bundled-code", string(opaqueJSON)}, property{"rdy:prebuilt-without-vendoring-evidence", prebuiltJSON(prebuilt)})
	doc["properties"], e = json.Marshal(props)
	if e != nil {
		return Evidence{}, "", e
	}
	data, e = json.MarshalIndent(doc, "", "  ")
	if e != nil {
		return Evidence{}, "", e
	}
	if e = os.WriteFile(out, data, 0o600); e != nil {
		return Evidence{}, "", e
	}
	var before Scan
	if len(changes) > 0 {
		path := filepath.Join(filepath.Dir(out), "pre-alias-"+filepath.Base(out))
		if e = os.WriteFile(path, preAlias, 0o600); e != nil {
			return Evidence{}, "", e
		}
		before, e = s.Scan(ctx, path)
		if e != nil {
			return Evidence{}, "", e
		}
	}
	scan, e := s.Scan(ctx, out)
	if e != nil {
		return Evidence{}, "", e
	}
	for i, f := range scan.Findings {
		scan.Findings[i].Package = aliases.Canonical(f.Package)
		scan.Findings[i].Origin = "artifact"
		if declaredKeys[scan.Findings[i].Package+"\x00"+f.Version] {
			scan.Findings[i].Origin = "declared, not verified shipped"
		}
	}
	var removed []core.Finding
	for _, f := range before.Findings {
		comparison := f
		comparison.Package = aliases.Canonical(f.Package)
		if aliasFindingRemoved(comparison, scan.Findings) {
			f.Origin = "pre-alias SBOM"
			removed = append(removed, f)
		}
	}
	for key, versions := range aliasVersions {
		sort.Strings(versions)
		unique := versions[:0]
		for _, v := range versions {
			if len(unique) == 0 || unique[len(unique)-1] != v {
				unique = append(unique, v)
			}
		}
		aliasVersions[key] = unique
	}
	npm := 0
	for _, c := range components {
		if strings.HasPrefix(c.PURL, "pkg:npm/") {
			npm++
		}
	}
	return Evidence{Warnings: scan.Warnings, Bundles: bundles, RemovedByAliases: removed, AliasComponents: aliasComponents, AliasVersions: aliasVersions, InputSHA256: inputHashes, DBUpdate: scan.DBUpdate, PrebuiltWithoutVendoringEvidence: len(prebuilt), Scripts: scripts, SkippedLinks: links, NPM: npm, Findings: scan.Findings, Components: len(components), Unmatched: coverage(components, scan.Findings), Sources: scan.Sources, Metadata: scan.Metadata, Opaque: opaque, Aliases: changes, DBDate: scan.DBDate, KEVCaptured: scan.KEVCaptured}, declared, nil
}

// javascriptFiles counts scripts without npm package metadata, including vendored trees.
func javascriptFiles(ctx context.Context, root string) (int, error) {
	count := 0
	e := filepath.WalkDir(root, func(path string, d fs.DirEntry, e error) error {
		if e != nil {
			return e
		}
		if e = ctx.Err(); e != nil {
			return e
		}
		if d.IsDir() {
			return nil
		}
		switch strings.ToLower(filepath.Ext(d.Name())) {
		case ".js", ".mjs", ".cjs":
			known, err := catalogableJavaScript(root, path)
			if err != nil {
				return err
			}
			if !known {
				count++
			}
		}
		return nil
	})
	return count, e
}

func prebuiltJSON(ids []string) string { b, _ := json.Marshal(ids); return string(b) }
func prebuiltFrom(doc map[string]json.RawMessage) ([]string, error) {
	if len(doc["properties"]) == 0 {
		return nil, nil
	}
	var props []property
	if e := json.Unmarshal(doc["properties"], &props); e != nil {
		return nil, e
	}
	var ids []string
	for _, p := range props {
		if p.Name == "rdy:prebuilt-without-vendoring-evidence" {
			var values []string
			if e := json.Unmarshal([]byte(p.Value), &values); e != nil {
				return nil, e
			}
			ids = append(ids, values...)
		}
	}
	return ids, nil
}

func aliasFindingRemoved(f core.Finding, after []core.Finding) bool {
	sameVersion := make([]core.Finding, 0, len(after))
	for _, v := range after {
		if v.Version == f.Version {
			sameVersion = append(sameVersion, v)
		}
	}
	removed, _ := core.Diff([]core.Finding{f}, sameVersion)
	return len(removed) > 0
}

func catalogableJavaScript(root, path string) (bool, error) {
	rel, e := filepath.Rel(root, path)
	if e != nil {
		return false, e
	}
	parts := strings.Split(filepath.ToSlash(rel), "/")
	last := -1
	for i, p := range parts {
		if p == "node_modules" {
			last = i
		}
	}
	if last < 0 || last+1 >= len(parts) {
		return false, nil
	}
	end := last + 2
	if strings.HasPrefix(parts[last+1], "@") {
		end++
	}
	if end > len(parts) {
		return false, nil
	}
	manifest := filepath.Join(root, filepath.FromSlash(strings.Join(parts[:end], "/")), "package.json")
	info, e := os.Stat(manifest)
	if os.IsNotExist(e) {
		return false, nil
	}
	if e != nil {
		return false, e
	}
	return !info.IsDir(), nil
}
