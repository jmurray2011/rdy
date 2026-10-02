// SPDX-License-Identifier: Apache-2.0

package gate_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/jmurray2011/rdy/gate"
)

func TestStrictWarningIDs(t *testing.T) {
	want := []string{"alias-removed-finding", "archive-links-skipped", "bundle-unstamped", "commit-not-asserted", "db-cleanup-failed", "db-update-failed", "frontend-not-covered", "kev-not-blocking", "line-override", "shallow-repo", "source-check-skipped", "tags-ignored", "triage-expired"}
	if !reflect.DeepEqual(gate.WarningIDs(), want) {
		t.Fatalf("warning IDs: %v", gate.WarningIDs())
	}
}

func TestStrictRedTeam(t *testing.T) {
	for _, strict := range []bool{false, true} {
		o := thirdOptions(t)
		o.Strict = strict
		o.Line = "7.2.7"
		git(t, o.Repo, "tag", "7.2.9")
		git(t, o.Repo, "tag", "7.2.6")
		o.Commit = strings.TrimSpace(git(t, o.Repo, "rev-parse", "HEAD"))
		o.Aliases = filepath.Join(o.Repo, "aliases.yaml")
		if err := os.WriteFile(o.Aliases, []byte("- from: pkg:maven/org.fictional/vulnerable\n  to: pkg:maven/org.fictional/harmless\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		r, err := gate.Run(context.Background(), o, aliasHidingScanner{})
		if err != nil {
			t.Fatal(err)
		}
		if r.Pass == strict || len(r.Warnings) != 3 || strings.Contains(r.Line, "strict: 3 blocking warnings") != strict {
			t.Fatalf("strict=%v: %+v", strict, r)
		}
		want := []string{"source-check-skipped", "line-override", "alias-removed-finding"}
		for i, w := range r.Warnings {
			if w.ID != want[i] {
				t.Fatalf("warning: %+v", w)
			}
		}
	}
}

func TestStrictCleanAndAllowed(t *testing.T) {
	for _, mode := range []string{"clean", "allowed", "blocked", "default-allowed"} {
		t.Run(mode, func(t *testing.T) {
			o := thirdOptions(t)
			o.Strict = mode != "default-allowed"
			o.Commit = strings.TrimSpace(git(t, o.Repo, "rev-parse", "HEAD"))
			git(t, o.Repo, "tag", "7.2.6")
			git(t, o.Repo, "tag", "7.2.7")
			if mode != "clean" {
				git(t, o.Repo, "tag", "fictional-rc1")
			}
			if mode == "allowed" || mode == "default-allowed" {
				o.AllowWarnings = []string{"tags-ignored,tags-ignored"}
			}
			r, err := gate.Run(context.Background(), o, scanner{})
			if err != nil {
				t.Fatal(err)
			}
			if r.Pass != (mode != "blocked") {
				t.Fatalf("%s: %+v", mode, r)
			}
			report, err := os.ReadFile(filepath.Join(o.Out, "report.md"))
			if err != nil {
				t.Fatal(err)
			}
			if mode == "allowed" && (!strings.Contains(string(report), "[tags-ignored]") || !strings.Contains(string(report), "(allowed)")) {
				t.Fatalf("report: %s", report)
			}
			if mode == "default-allowed" && (strings.Count(string(report), "--allow-warning has no effect without --strict") != 1 || strings.Contains(string(report), "(allowed)")) {
				t.Fatalf("report: %s", report)
			}
			data, err := os.ReadFile(filepath.Join(o.Out, "findings.json"))
			if err != nil {
				t.Fatal(err)
			}
			var saved struct {
				Warnings         []gate.Warning `json:"warnings"`
				EffectiveOptions struct {
					Strict        bool     `json:"strict"`
					AllowWarnings []string `json:"allow_warning"`
				} `json:"effective_options"`
				Pass bool `json:"pass"`
			}
			if err = json.Unmarshal(data, &saved); err != nil {
				t.Fatal(err)
			}
			if saved.Pass != r.Pass || saved.EffectiveOptions.Strict != o.Strict || !reflect.DeepEqual(saved.Warnings, r.Warnings) {
				t.Fatalf("JSON: %s", data)
			}
			if mode == "allowed" && !reflect.DeepEqual(r.EffectiveOptions.AllowWarnings, []string{"tags-ignored"}) {
				t.Fatal(r.EffectiveOptions)
			}
		})
	}
}

func warningMessages(warnings []gate.Warning) []string {
	result := make([]string, len(warnings))
	for i, w := range warnings {
		result[i] = w.Message
	}
	return result
}
