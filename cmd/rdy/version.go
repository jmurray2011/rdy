// SPDX-License-Identifier: Apache-2.0

package main

import (
	"runtime/debug"
	"strings"
)

func versionDetails(linked string, info *debug.BuildInfo) (string, string) {
	version := linked
	if version == "dev" && info != nil && info.Main.Version != "" && info.Main.Version != "(devel)" {
		version = strings.TrimPrefix(info.Main.Version, "v")
	}
	line := "rdy " + version
	if info != nil {
		for _, s := range info.Settings {
			if s.Key == "vcs.revision" && s.Value != "" {
				line += " commit " + s.Value
				break
			}
		}
		if info.GoVersion != "" {
			line += " " + info.GoVersion
		}
	}
	return version, line
}
