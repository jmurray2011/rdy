// SPDX-License-Identifier: Apache-2.0

package gate

import (
	"strings"
	"testing"
)

func TestStrictContributesToExistingFailure(t *testing.T) {
	r := Result{Pass: false, Line: "fictional FAIL | 1 High", Warnings: []Warning{{ID: "kev-not-blocking", Message: "fixture"}, {ID: "tags-ignored", Message: "fixture"}}}
	strictVerdict(&r, Options{Strict: true, AllowWarnings: []string{"tags-ignored"}})
	if r.Pass || !strings.Contains(r.Line, "strict: 1 blocking warnings") || !r.Warnings[1].Allowed {
		t.Fatalf("%+v", r)
	}
}

func TestStrictPreservesDisplayName(t *testing.T) {
	r := Result{Pass: true, Line: "fictional PASS 1.2  PASS | source ok", Warnings: []Warning{{ID: "tags-ignored", Message: "fixture"}}}
	strictVerdict(&r, Options{Name: "fictional PASS", Release: "1.2", Strict: true})
	if !strings.HasPrefix(r.Line, "fictional PASS 1.2  FAIL |") {
		t.Fatal(r.Line)
	}
}
