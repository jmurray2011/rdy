// SPDX-License-Identifier: Apache-2.0

package core

import (
	"testing"
)

func TestPackageIDFinalSlash(t *testing.T) {
	for _, input := range []string{"pkg:npm/@fictional/sample@@1", "pkg:maven/group@scope/sample@1"} {
		id := PackageID(input)
		if PackageID(id) != id {
			t.Fatalf("not idempotent: %s -> %s", input, id)
		}
	}
	if got := PackageID("pkg:maven/group@scope/sample"); got != "pkg:maven/group@scope/sample" {
		t.Fatal(got)
	}
}

func TestBundleModuleBoundary(t *testing.T) {
	stats := []byte(`{"modules":[{"name":"./fake_node_modules/fictional/index.js"},{"name":"./node_modules/real/index.js"}]}`)
	lock := []byte(`{"lockfileVersion":3,"packages":{"node_modules/real":{"version":"1"}}}`)
	b, err := BuildBundle(stats, lock)
	if err != nil || len(b.Components) != 1 {
		t.Fatalf("%+v %v", b, err)
	}
}
