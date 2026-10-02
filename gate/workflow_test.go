// SPDX-License-Identifier: Apache-2.0

package gate

import (
	"os"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

func TestReleaseWorkflowBoundaries(t *testing.T) {
	b, err := os.ReadFile("../.github/workflows/release.yml")
	if err != nil {
		t.Fatal(err)
	}
	var w struct {
		On   map[string]any `yaml:"on"`
		Jobs map[string]struct {
			Needs       any               `yaml:"needs"`
			Uses        string            `yaml:"uses"`
			Permissions map[string]string `yaml:"permissions"`
			Steps       []struct {
				Uses string
				Run  string
			} `yaml:"steps"`
		} `yaml:"jobs"`
	}
	if err := yaml.Unmarshal(b, &w); err != nil {
		t.Fatal(err)
	}
	if len(w.On) != 1 || w.On["push"] == nil {
		t.Fatal("release must be tag-triggered only")
	}
	j := w.Jobs["release"]
	needs, ok := j.Needs.([]any)
	if !ok || len(needs) != 2 || needs[0] != "validate" || needs[1] != "build" || w.Jobs["validate"].Uses != "./.github/workflows/ci.yml" {
		t.Fatal("release can publish before validation succeeds")
	}
	if j.Permissions["contents"] != "write" || j.Permissions["id-token"] != "write" {
		t.Fatal("release permissions missing")
	}
	for _, step := range j.Steps {
		if step.Uses != "" {
			_, sha, ok := strings.Cut(step.Uses, "@")
			if !ok || len(sha) != 40 {
				t.Fatal("action not pinned")
			}
		}
	}
	for _, want := range []string{"CGO_ENABLED=0", "darwin", "windows", "attestations: write", "THIRD_PARTY_NOTICES", "merge-base --is-ancestor", "scripts/release-notes", "SHA256SUMS", "cosign sign-blob", "gh release create"} {
		if !strings.Contains(string(b), want) {
			t.Fatalf("missing release operation %s", want)
		}
	}
}

func TestThirdRoundCIAndReleaseProbe(t *testing.T) {
	b, e := os.ReadFile("../.github/workflows/ci.yml")
	if e != nil {
		t.Fatal(e)
	}
	if !strings.Contains(string(b), "libarchive-tools") || !strings.Contains(string(b), "rpm") {
		t.Fatal("native fixture tools absent")
	}
	var w struct {
		On map[string]any `yaml:"on"`
	}
	if e := yaml.Unmarshal(b, &w); e != nil {
		t.Fatalf("CI push must filter branches to avoid a second tag run: %v", e)
	}
	push, ok := w.On["push"].(map[string]any)
	if !ok || push["branches"] == nil {
		t.Fatal("CI runs twice on tags")
	}
	b, e = os.ReadFile("../.github/workflows/release.yml")
	if e != nil {
		t.Fatal(e)
	}
	probe := strings.Index(string(b), "./build/rdy-linux-amd64 --version")
	sign := strings.Index(string(b), "cosign sign-blob")
	if probe < 0 || probe > sign {
		t.Fatal("no built binary probe before signing")
	}
}
