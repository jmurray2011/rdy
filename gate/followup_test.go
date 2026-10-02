// SPDX-License-Identifier: Apache-2.0

package gate_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jmurray2011/rdy/core"
	"github.com/jmurray2011/rdy/gate"
)

func fixedTime() time.Time { return time.Date(2099, 1, 3, 0, 0, 0, 0, time.UTC) }
func TestComparedTagsAndSkippedChecks(t *testing.T) {
	dir, triage := repo(t)
	o := gate.Options{Name: "app", Release: "2.4.0", Artifact: jar(t, dir, "2.4.0"), Repo: dir, Branch: "main", Triage: triage, Out: filepath.Join(dir, "out"), Floor: 1}
	r, e := gate.Run(context.Background(), o, scanner{})
	if e != nil {
		t.Fatal(e)
	}
	if r.ComparedTags.Line != "2.4" || !strings.Contains(strings.Join(warningMessages(r.Warnings), " "), "no previous release tag; missing-patch check not run") {
		t.Fatalf("skip evidence %+v", r)
	}
	git(t, dir, "tag", "2.4.0")
	o.Release = "2.4.1"
	o.Artifact = jar(t, dir, "2.4.1")
	r, e = gate.Run(context.Background(), o, scanner{})
	if e != nil {
		t.Fatal(e)
	}
	if r.ComparedTags.Latest != "2.4.0" || r.ComparedTags.Previous != "2.4.0" {
		t.Fatalf("tags %+v", r.ComparedTags)
	}
}

type staleUpdateScanner struct{ scanner }

func (staleUpdateScanner) Scan(context.Context, string) (gate.Scan, error) {
	return gate.Scan{DBDate: "2099-01-02T00:00:00Z", DBUpdate: gate.DatabaseUpdate{Outcome: "failed", Reason: "fixture update failed"}, Sources: []string{"fixture"}}, nil
}

func TestCachedDatabaseWarning(t *testing.T) {
	dir, triage := repo(t)
	r, e := gate.Run(context.Background(), gate.Options{Name: "app", Release: "1.0.0", Artifact: jar(t, dir, "1.0.0"), Repo: dir, Branch: "main", Triage: triage, Out: filepath.Join(dir, "out"), Floor: 1, Now: fixedTime}, staleUpdateScanner{})
	if e != nil {
		t.Fatal(e)
	}
	if !r.Pass || r.DBAge != "24h0m0s" || !strings.Contains(strings.Join(warningMessages(r.Warnings), " "), "fixture update failed") {
		t.Fatalf("freshness %+v", r)
	}
}

func TestInputBindings(t *testing.T) {
	dir, triage := repo(t)
	embedded := `{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"components":[{"type":"library","name":"plain","version":"1","purl":"pkg:npm/plain@1"}]}`
	artifact := jarWith(t, dir, "1.0.0", map[string]string{"frontend/bundle.cdx.json": embedded})
	baseline, aliases, dev := filepath.Join(dir, "baseline.jar"), filepath.Join(dir, "aliases.yaml"), filepath.Join(dir, "developer.json")
	data, err := os.ReadFile(artifact)
	if err != nil {
		t.Fatal(err)
	}
	for path, body := range map[string][]byte{baseline: data, aliases: []byte("[]"), dev: []byte(embedded)} {
		if err := os.WriteFile(path, body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	o := gate.Options{Name: "app", Release: "1.0.0", Artifact: artifact, Repo: dir, Branch: "main", Triage: triage, Out: filepath.Join(dir, "out"), Floor: 1, Now: fixedTime, Version: "fixture-build", Baseline: baseline, Aliases: aliases, DevSBOM: dev, BaselineDevSBOM: dev}
	r, e := gate.Run(context.Background(), o, prebuiltScanner{})
	if e != nil {
		t.Fatal(e)
	}
	for key, path := range map[string]string{"artifact": artifact, "triage": triage, "baseline": baseline, "aliases": aliases, "dev_sbom": dev, "baseline_dev_sbom": dev, "candidate_sbom": filepath.Join(o.Out, "candidate.cdx.json")} {
		b, e := os.ReadFile(path)
		if e != nil {
			t.Fatal(e)
		}
		sum := sha256.Sum256(b)
		if r.InputSHA256[key] != hex.EncodeToString(sum[:]) {
			t.Fatalf("hash %s", key)
		}
	}
	sum := sha256.Sum256([]byte(embedded))
	for _, key := range []string{"embedded_sbom:frontend/bundle.cdx.json", "baseline_embedded_sbom:frontend/bundle.cdx.json"} {
		if r.InputSHA256[key] != hex.EncodeToString(sum[:]) {
			t.Fatalf("hash %s", key)
		}
	}
	if r.Timestamp != "2099-01-03T00:00:00Z" || r.Version != "fixture-build" {
		t.Fatalf("identity %+v", r)
	}
	b, e := json.Marshal(r.EffectiveOptions)
	if e != nil {
		t.Fatal(e)
	}
	if strings.Contains(string(b), "webhook") {
		t.Fatal("secret option exposed")
	}
}

func TestDeclaredVersionNumericComparison(t *testing.T) {
	for _, c := range []struct {
		declared string
		pass     bool
	}{{"v2.4.0", true}, {"2.4", true}, {"2.4.1", false}, {"invalid", false}} {
		t.Run(c.declared, func(t *testing.T) {
			dir, triage := repo(t)
			r, e := gate.Run(context.Background(), gate.Options{Name: "app", Release: "2.4.0", Artifact: jar(t, dir, c.declared), Repo: dir, Branch: "main", Triage: triage, Out: filepath.Join(dir, "out"), Floor: 1}, scanner{})
			if e != nil {
				t.Fatal(e)
			}
			if r.Pass != c.pass {
				t.Fatalf("problems %v", r.Problems)
			}
			if !c.pass && !strings.Contains(strings.Join(r.Problems, " "), c.declared) {
				t.Fatal("declared version missing")
			}
		})
	}
}

func TestEffectiveOptionsPolicyAndDefaults(t *testing.T) {
	dir, triage := repo(t)
	policy, err := core.ParseKEVPolicy("report")
	if err != nil {
		t.Fatal(err)
	}
	r, err := gate.Run(context.Background(), gate.Options{Name: "fictional", Release: "2.4.0", Artifact: jar(t, dir, "2.4.0"), Repo: dir, Branch: "main", Triage: triage, Out: filepath.Join(dir, "out"), Floor: 1, KEVPolicy: policy}, scanner{})
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(r.EffectiveOptions)
	if err != nil {
		t.Fatal(err)
	}
	var v map[string]any
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	if v["kev_policy"] != "report" || v["line"] != "2.4" {
		t.Fatalf("effective options %s", b)
	}
}
