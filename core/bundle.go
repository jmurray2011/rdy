// SPDX-License-Identifier: Apache-2.0

package core

import (
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"
)

// Opaque identifies a prebuilt module whose transitive contents are unknown.
type (
	Opaque struct {
		Package     string   `json:"package"`
		Version     string   `json:"version"`
		Path        string   `json:"path"`
		Unaccounted []string `json:"unaccounted_dependencies,omitempty"`
	}
	// Bundle contains packages proven present in the bundler graph and opaque modules.
	Bundle struct {
		Components []Component `json:"components"`
		Opaque     []Opaque    `json:"opaque"`
		// Prebuilt holds distinct package PURLs for count-only reporting.
		Prebuilt []string `json:"-"`
	}
)

// BuildBundle resolves webpack module paths against exact npm lockfile v2/v3 paths.
func BuildBundle(stats, lock []byte) (Bundle, error) {
	var graph struct {
		Modules  []module      `json:"modules"`
		Children []compilation `json:"children"`
		Chunks   []compilation `json:"chunks"`
	}
	if e := json.Unmarshal(stats, &graph); e != nil {
		return Bundle{}, e
	}
	var packages struct {
		Version  int `json:"lockfileVersion"`
		Packages map[string]struct {
			Name         string            `json:"name"`
			Version      string            `json:"version"`
			Link         bool              `json:"link"`
			Dependencies map[string]string `json:"dependencies"`
		} `json:"packages"`
	}
	if e := json.Unmarshal(lock, &packages); e != nil {
		return Bundle{}, e
	}
	if (packages.Version != 2 && packages.Version != 3) || packages.Packages == nil {
		return Bundle{}, fmt.Errorf("package-lock v2/v3 packages required")
	}
	if graph.Modules == nil && graph.Children == nil && graph.Chunks == nil {
		return Bundle{}, fmt.Errorf("webpack stats have no module graph")
	}
	var paths []string
	collectModules(graph.Modules, &paths)
	for _, c := range append(graph.Children, graph.Chunks...) {
		collectCompilation(c, &paths)
	}
	components := map[string]Component{}
	present := map[string]bool{}
	type candidate struct {
		opaque   Opaque
		declared map[string]string
		vendored bool
		identity string
	}
	candidates := map[string]candidate{}
	for _, path := range paths {
		normalized := strings.ReplaceAll(path, "\\", "/")
		if i := strings.LastIndex(normalized, "!"); i >= 0 {
			normalized = normalized[i+1:]
		}
		normalized, _, _ = strings.Cut(normalized, "?")
		start := strings.Index(normalized, "node_modules/")
		for start > 0 && normalized[start-1] != '/' {
			next := strings.Index(normalized[start+1:], "node_modules/")
			if next < 0 {
				start = -1
				break
			}
			start += next + 1
		}
		if start < 0 {
			continue
		}
		relative := normalized[start:]
		key, name, remainder, vendored, e := packagePath(relative)
		if e != nil {
			return Bundle{}, fmt.Errorf("invalid module path %q", path)
		}
		pkg, ok := packages.Packages[key]
		if !ok || pkg.Version == "" || pkg.Link {
			return Bundle{}, fmt.Errorf("module %q has no exact resolved lockfile package %q", path, key)
		}
		if pkg.Name != "" {
			name = pkg.Name
		}
		present[name] = true
		escaped := strings.ReplaceAll(name, "@", "%40")
		purl := "pkg:npm/" + escaped + "@" + url.PathEscape(pkg.Version)
		components[purl] = Component{Type: "library", Name: name, Version: pkg.Version, PURL: purl, Ref: purl}
		if vendored || prebuilt(remainder) {
			candidates[relative] = candidate{Opaque{Package: name, Version: pkg.Version, Path: relative}, pkg.Dependencies, vendored, purl}
		}
	}
	opaque := map[string]Opaque{}
	prebuiltPackages := map[string]bool{}
	opaquePackages := map[string]bool{}
	for path, c := range candidates {
		for dep := range c.declared {
			if !present[dep] {
				c.opaque.Unaccounted = append(c.opaque.Unaccounted, dep)
			}
		}
		sort.Strings(c.opaque.Unaccounted)
		if c.vendored || len(c.opaque.Unaccounted) > 0 {
			opaque[path] = c.opaque
			opaquePackages[c.identity] = true
		} else {
			prebuiltPackages[c.identity] = true
		}
	}
	result := Bundle{Components: []Component{}, Opaque: []Opaque{}}
	keys := make([]string, 0, len(components))
	for k := range components {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		result.Components = append(result.Components, components[k])
	}
	keys = keys[:0]
	for k := range opaque {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		result.Opaque = append(result.Opaque, opaque[k])
	}
	for id := range prebuiltPackages {
		if !opaquePackages[id] {
			result.Prebuilt = append(result.Prebuilt, id)
		}
	}
	sort.Strings(result.Prebuilt)
	return result, nil
}

// prebuilt reports whether a path inside a package is a dist output or minified file.
func prebuilt(remainder string) bool {
	return remainder == "dist" || strings.HasPrefix(remainder, "dist/") || strings.Contains(remainder, "/dist/") || strings.HasSuffix(remainder, "/dist") || strings.HasSuffix(remainder, ".min.js")
}

// packagePath resolves the innermost lockfile package of a node_modules path. A
// node_modules tree inside a package's dist/ is that package's prebuilt output, so
// resolution stops at the outer package and the module is reported as vendored.
func packagePath(relative string) (key, name, remainder string, vendored bool, err error) {
	segments := strings.Split(strings.TrimPrefix(relative, "node_modules/"), "/node_modules/")
	for i, segment := range segments {
		parts := strings.Split(segment, "/")
		count := 1
		if strings.HasPrefix(parts[0], "@") {
			count = 2
		}
		if len(parts) < count || parts[0] == "" {
			return "", "", "", false, fmt.Errorf("invalid module path")
		}
		name = strings.Join(parts[:count], "/")
		if key == "" {
			key = "node_modules/" + name
		} else {
			key += "/node_modules/" + name
		}
		remainder = strings.Join(parts[count:], "/")
		if i < len(segments)-1 && prebuilt(remainder) {
			return key, name, remainder, true, nil
		}
	}
	return key, name, remainder, false, nil
}

type (
	module struct {
		Name       string   `json:"name"`
		Identifier string   `json:"identifier"`
		Modules    []module `json:"modules"`
	}
	compilation struct {
		Modules  []module      `json:"modules"`
		Children []compilation `json:"children"`
		Chunks   []compilation `json:"chunks"`
	}
)

func collectModules(modules []module, paths *[]string) {
	for _, m := range modules {
		if m.Identifier != "" {
			*paths = append(*paths, m.Identifier)
		} else if m.Name != "" {
			*paths = append(*paths, m.Name)
		}
		collectModules(m.Modules, paths)
	}
}

func collectCompilation(c compilation, paths *[]string) {
	collectModules(c.Modules, paths)
	for _, child := range append(c.Children, c.Chunks...) {
		collectCompilation(child, paths)
	}
}

// Alias maps a versionless package identity to its advisory identity.
type (
	Alias struct {
		From string `json:"from" yaml:"from"`
		To   string `json:"to" yaml:"to"`
	}
	// Aliases is a validated, acyclic package identity table.
	Aliases struct{ targets map[string]string }
)

// PackageID removes PURL version, qualifiers and subpath for persistent matching.
func PackageID(purl string) string {
	purl, _, _ = strings.Cut(purl, "#")
	purl, _, _ = strings.Cut(purl, "?")
	if i := strings.LastIndex(purl, "@"); i > strings.LastIndex(purl, "/") {
		purl = strings.TrimRight(purl[:i], "@")
	}
	return purl
}

// NewAliases validates an explicit alias table and resolves chains.
func NewAliases(entries []Alias) (Aliases, error) {
	targets := map[string]string{}
	for _, e := range entries {
		if !strings.HasPrefix(e.From, "pkg:") || !strings.HasPrefix(e.To, "pkg:") || PackageID(e.From) != e.From || PackageID(e.To) != e.To || strings.Count(e.From, "/") < 1 || strings.Count(e.To, "/") < 1 {
			return Aliases{}, fmt.Errorf("aliases require versionless PURLs")
		}
		if e.From == e.To {
			return Aliases{}, fmt.Errorf("self alias %s", e.From)
		}
		if _, ok := targets[e.From]; ok {
			return Aliases{}, fmt.Errorf("duplicate alias %s", e.From)
		}
		targets[e.From] = e.To
	}
	resolved := map[string]string{}
	for from := range targets {
		seen := map[string]bool{from: true}
		to := targets[from]
		for targets[to] != "" {
			if seen[to] {
				return Aliases{}, fmt.Errorf("alias cycle at %s", to)
			}
			seen[to] = true
			to = targets[to]
		}
		if seen[to] {
			return Aliases{}, fmt.Errorf("alias cycle at %s", to)
		}
		resolved[from] = to
	}
	return Aliases{resolved}, nil
}

// Canonical returns the final package identity, leaving unknown identities intact.
func (a Aliases) Canonical(identity string) string {
	if target, ok := a.targets[identity]; ok {
		return target
	}
	return identity
}

// Apply rewrites matching component identities without mutating input.
func (a Aliases) Apply(input []Component) []Component {
	out := append([]Component(nil), input...)
	for i, c := range out {
		id := PackageID(c.PURL)
		canonical := a.Canonical(id)
		if canonical == id {
			continue
		}
		out[i].PURL = canonical + strings.TrimPrefix(c.PURL, id)
		tail := strings.TrimPrefix(canonical, "pkg:")
		_, tail, _ = strings.Cut(tail, "/")
		if slash := strings.LastIndex(tail, "/"); slash >= 0 {
			out[i].Group = tail[:slash]
			out[i].Name = tail[slash+1:]
		} else {
			out[i].Group = ""
			out[i].Name = tail
		}
	}
	return out
}
