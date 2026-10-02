// SPDX-License-Identifier: Apache-2.0

package core_test

import (
	"testing"

	"github.com/jmurray2011/rdy/core"
)

func TestReleaseLines(t *testing.T) {
	parallel := []string{"7.2.5", "7.2.6", "7.3.4", "7.3.5", "7.3.6", "nightly"}
	for _, c := range []struct {
		name, release, line string
		tags                []string
		latest, previous    string
	}{
		{"maintenance hotfix ignores the newer line", "7.2.7", "", parallel, "7.2.6", "7.2.6"},
		{"current line", "7.3.7", "", parallel, "7.3.6", "7.3.6"},
		{"backwards within the line", "7.3.3", "", parallel, "7.3.6", ""},
		{"first release of a new line falls back to the previous release", "7.4.0", "", parallel, "", "7.3.6"},
		{"four-part hotfix stays on its base release", "7.3.2.2", "", []string{"7.3.2", "7.3.2.1", "7.3.5"}, "7.3.2.1", "7.3.2.1"},
		{"explicit wider line restores repository-wide ordering", "7.2.7", "7", parallel, "7.3.6", "7.2.6"},
		{"single-part releases use every tag", "5", "", []string{"3", "4", "6"}, "6", "4"},
	} {
		t.Run(c.name, func(t *testing.T) {
			latest, previous, e := core.SelectTagsInLine(c.tags, c.release, c.line)
			if e != nil {
				t.Fatal(e)
			}
			if latest != c.latest {
				t.Fatalf("latest %q, want %q", latest, c.latest)
			}
			if c.previous != "" && previous != c.previous {
				t.Fatalf("previous %q, want %q", previous, c.previous)
			}
		})
	}
	if _, _, e := core.SelectTagsInLine(parallel, "7.2.7", "7.3"); e == nil {
		t.Fatal("accepted a line that is not a prefix of the release")
	}
	if _, _, e := core.SelectTagsInLine(parallel, "7.2.7", "7.x"); e == nil {
		t.Fatal("accepted a non-numeric line")
	}
}
