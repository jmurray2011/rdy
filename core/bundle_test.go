// SPDX-License-Identifier: Apache-2.0

package core_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/jmurray2011/rdy/core"
)

func TestBundleGraph(t *testing.T) {
	stats := []byte(`{"modules":[{"name":"./node_modules/alpha/index.js"},{"modules":[{"identifier":"loader!/work/node_modules/alpha/node_modules/beta/dist/beta.min.js"}]},{"name":"./node_modules/@example/ui/index.js"}]}`)
	lock := []byte(`{"lockfileVersion":3,"packages":{"node_modules/alpha":{"version":"1.0.0"},"node_modules/alpha/node_modules/beta":{"version":"2.0.0","dev":true,"dependencies":{"gamma":"^1"}},"node_modules/@example/ui":{"version":"3.0.0"},"node_modules/test-tool":{"version":"9.0.0","dev":true}}}`)
	got, e := core.BuildBundle(stats, lock)
	if e != nil {
		t.Fatal(e)
	}
	if len(got.Components) != 3 || len(got.Opaque) != 1 {
		t.Fatalf("%+v", got)
	}
	b, e := json.Marshal(got)
	if e != nil {
		t.Fatal(e)
	}
	s := string(b)
	if !strings.Contains(s, "pkg:npm/beta@2.0.0") || strings.Contains(s, "test-tool") {
		t.Fatal(s)
	}
	if got.Opaque[0].Package != "beta" || got.Opaque[0].Version != "2.0.0" {
		t.Fatal(got.Opaque)
	}
	if _, e = core.BuildBundle(stats, []byte(`{"lockfileVersion":1}`)); e == nil {
		t.Fatal("accepted lockfile v1")
	}
	if _, e = core.BuildBundle([]byte(`{"modules":[{"name":"./node_modules/missing/index.js"}]}`), lock); e == nil {
		t.Fatal("unresolved graph package")
	}
}

func TestIdentityAliases(t *testing.T) {
	aliases, e := core.NewAliases([]core.Alias{{From: "pkg:maven/org.example.server/server-core", To: "pkg:maven/org.example.server.embed/server-embed-core"}, {From: "pkg:maven/org.example.old/parser", To: "pkg:maven/org.example/parser"}})
	if e != nil {
		t.Fatal(e)
	}
	input := []core.Component{{Name: "server-core", Group: "org.example.server", Version: "4.0.0", PURL: "pkg:maven/org.example.server/server-core@4.0.0?type=jar"}}
	got := aliases.Apply(input)
	if got[0].PURL != "pkg:maven/org.example.server.embed/server-embed-core@4.0.0?type=jar" || got[0].Group != "org.example.server.embed" || input[0].Name != "server-core" {
		t.Fatalf("%+v", got)
	}
	a := aliases.Apply([]core.Component{{PURL: "pkg:maven/org.example.old/parser@1"}})
	b := aliases.Apply([]core.Component{{PURL: "pkg:maven/org.example/parser@2"}})
	added, cleared := core.Diff([]core.Finding{{Package: core.PackageID(a[0].PURL), ID: "CVE-2099-1"}}, []core.Finding{{Package: core.PackageID(b[0].PURL), ID: "CVE-2099-1"}})
	if len(added)+len(cleared) != 0 {
		t.Fatal("alias rename churn")
	}
	if _, e = core.NewAliases([]core.Alias{{From: "pkg:npm/a", To: "pkg:npm/b"}, {From: "pkg:npm/b", To: "pkg:npm/a"}}); e == nil {
		t.Fatal("alias cycle")
	}
}

func TestPrebuiltPackageCountDeduplicatesModules(t *testing.T) {
	b, e := core.BuildBundle([]byte(`{"modules":[{"name":"./node_modules/plain/dist/a.js"},{"name":"./node_modules/plain/dist/b.min.js"}]}`), []byte(`{"lockfileVersion":3,"packages":{"node_modules/plain":{"version":"1"}}}`))
	if e != nil {
		t.Fatal(e)
	}
	if len(b.Opaque) != 0 || len(b.Prebuilt) != 1 {
		t.Fatalf("bundle %+v", b)
	}
}
