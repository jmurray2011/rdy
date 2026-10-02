// SPDX-License-Identifier: Apache-2.0

package main

import (
	"runtime/debug"
	"strings"
	"testing"
)

func TestVersionFallback(t *testing.T) {
	for _, tc := range []struct{ linked, module, want string }{{"dev", "v1.2.3", "1.2.3"}, {"dev", "(devel)", "dev"}, {"0.1.0", "v9.9.9", "0.1.0"}, {"dev", "", "dev"}} {
		info := &debug.BuildInfo{Main: debug.Module{Version: tc.module}, GoVersion: "go1.99.0", Settings: []debug.BuildSetting{{Key: "vcs.revision", Value: "fictional-sha"}}}
		version, line := versionDetails(tc.linked, info)
		if version != tc.want || !strings.HasPrefix(line, "rdy "+tc.want) || !strings.Contains(line, "fictional-sha") || !strings.Contains(line, "go1.99.0") {
			t.Fatalf("%s %s", version, line)
		}
	}
	version, line := versionDetails("dev", nil)
	if version != "dev" || line != "rdy dev" {
		t.Fatal(version, line)
	}
}
