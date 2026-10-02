// SPDX-License-Identifier: Apache-2.0

package gate

import (
	"testing"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/matcher"
	grypepkg "github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/search"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/syft/syft/cpe"
	syftpkg "github.com/anchore/syft/syft/pkg"
)

type cpeQueryProbe struct{ queries int }

func (p *cpeQueryProbe) PackageSearchNames(pkg grypepkg.Package) []string { return []string{pkg.Name} }

func (p *cpeQueryProbe) FindVulnerabilities(criteria ...vulnerability.Criteria) ([]vulnerability.Vulnerability, error) {
	for _, c := range criteria {
		if _, ok := c.(*search.CPECriteria); ok {
			p.queries++
		}
	}
	return nil, nil
}

func (p *cpeQueryProbe) VulnerabilityMetadata(vulnerability.Reference) (*vulnerability.Metadata, error) {
	return nil, nil
}
func (p *cpeQueryProbe) Close() error { return nil }
func TestActualJavaMatchersDoNotSearchCPEs(t *testing.T) {
	c, e := cpe.New("cpe:2.3:a:fictional:vulnerable:1:*:*:*:*:java:*:*", cpe.DeclaredSource)
	if e != nil {
		t.Fatal(e)
	}
	pkg := grypepkg.Package{Name: "vulnerable", Version: "1", Language: syftpkg.Java, Type: syftpkg.JavaPkg, PURL: "pkg:maven/org.fictional/vulnerable@1", CPEs: []cpe.CPE{c}, Metadata: grypepkg.JavaMetadata{PomGroupID: "org.fictional", PomArtifactID: "vulnerable"}}
	for _, enabled := range []bool{false, true} {
		cfg := defaultMatcherConfig()
		if enabled {
			cfg.Java.UseCPEs = true
		}
		probe := &cpeQueryProbe{}
		found := false
		for _, m := range matcher.NewDefaultMatchers(cfg) {
			if m.Type() == match.JavaMatcher {
				found = true
				if _, _, e := m.Match(probe, pkg); e != nil {
					t.Fatal(e)
				}
			}
		}
		if !found || (probe.queries > 0) != enabled {
			t.Fatalf("CPE enabled=%v queries=%d found=%v", enabled, probe.queries, found)
		}
	}
}
