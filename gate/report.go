// SPDX-License-Identifier: Apache-2.0

package gate

import (
	"encoding/json"
	"sort"
	"strings"
)

func sourceFix(p string) string {
	switch {
	case strings.Contains(p, "backwards"):
		return "Choose a release version at least as new as the latest tag."
	case strings.Contains(p, "commit"):
		return "Build the selected branch commit and update the declared commit."
	case strings.Contains(p, "missing patches"):
		return "Merge or cherry-pick the listed missing commits, then rebuild."
	case strings.Contains(p, "artifact version") || strings.Contains(p, "declared version") || strings.Contains(p, "Implementation-Version"):
		return "Rebuild with a numeric artifact version matching --release."
	case strings.Contains(p, "thin"):
		return "Check artifact contents and SBOM coverage; set a justified component floor."
	default:
		return "Correct the source evidence and rebuild."
	}
}

func providerNames(metadata json.RawMessage, fallback []string) []string {
	var doc struct {
		DB struct {
			Providers map[string]json.RawMessage `json:"providers"`
		} `json:"db"`
	}
	_ = json.Unmarshal(metadata, &doc)
	names := map[string]bool{}
	for k := range doc.DB.Providers {
		names[k] = true
	}
	if len(names) == 0 {
		for _, s := range fallback {
			if !strings.ContainsAny(s, "/:") {
				names[s] = true
			}
		}
	}
	out := make([]string, 0, len(names))
	for k := range names {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
