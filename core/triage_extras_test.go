// SPDX-License-Identifier: Apache-2.0

package core

import "testing"

func TestOptionalTriageDates(t *testing.T) {
	e := Entry{Package: "pkg:npm/fictional", CVE: "CVE-2099-1000", Status: "accepted", Reason: "fixture"}
	if err := ValidateTriage([]Entry{e}); err != nil {
		t.Fatal(err)
	}
	e.ReviewedBy = "Fixture"
	e.ReviewedOn = "2099-01-02"
	e.Expires = "2099-02-03"
	if err := ValidateTriage([]Entry{e}); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"2099-2-03", "2099-02-30", "yesterday"} {
		e.Expires = bad
		if ValidateTriage([]Entry{e}) == nil {
			t.Fatalf("accepted %s", bad)
		}
	}
}
