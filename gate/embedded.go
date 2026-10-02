// SPDX-License-Identifier: Apache-2.0

package gate

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/anchore/clio"
	"github.com/anchore/grype/grype"
	v6 "github.com/anchore/grype/grype/db/v6"
	"github.com/anchore/grype/grype/db/v6/installation"
	"github.com/anchore/grype/grype/matcher"
	"github.com/anchore/grype/grype/matcher/rpm"
	"github.com/anchore/grype/grype/matcher/stock"
	grypepkg "github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/presenter/models"
	"github.com/anchore/grype/grype/version"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/cataloging"
	"github.com/anchore/syft/syft/format/cyclonedxjson"
)

// EmbeddedOptions controls vulnerability database storage and updates.
type (
	EmbeddedOptions struct {
		DBCache string
		Offline bool
	}
	// Embedded catalogs and scans with pinned Go libraries, without scanner executables.
	Embedded struct{ options EmbeddedOptions }
)

// NewEmbedded configures the embedded scanner; database access is deferred until scanning.
func NewEmbedded(options EmbeddedOptions) Embedded { return Embedded{options: options} }

// Generate catalogs extracted files and embedded bundle SBOMs using Syft.
func (s Embedded) Generate(ctx context.Context, root string) (data []byte, err error) {
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	source, err := syft.GetSource(ctx, root, syft.DefaultGetSourceConfig().WithSources("local-directory"))
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, source.Close()) }()
	cfg := syft.DefaultCreateSBOMConfig().WithTool("syft", "1.54.0").WithCatalogerSelection(cataloging.NewSelectionRequest().WithAdditions("sbom-cataloger"))
	bom, err := syft.CreateSBOM(ctx, source, cfg)
	if err != nil {
		return nil, err
	}
	encoder, err := cyclonedxjson.NewFormatEncoderWithConfig(cyclonedxjson.EncoderConfig{Version: "1.6", Pretty: true})
	if err != nil {
		return nil, err
	}
	var buffer bytes.Buffer
	if err = encoder.Encode(&buffer, *bom); err != nil {
		return nil, err
	}
	return buffer.Bytes(), ctx.Err()
}

// Scan reads only the merged SBOM, validates the database, and uses default matching.
func (s Embedded) Scan(ctx context.Context, path string) (result Scan, err error) {
	if err = ctx.Err(); err != nil {
		return result, err
	}
	input, err := os.Open(path)
	if err != nil {
		return result, err
	}
	defer func() { err = errors.Join(err, input.Close()) }()
	packages, pkgContext, _, err := grypepkg.ProvideFromReader(input, grypepkg.ProviderConfig{})
	if err != nil {
		return result, err
	}
	id := clio.Identification{Name: "grype", Version: "0.119.0"}
	cfg := installation.DefaultConfig(id)
	cfg.DBRootDir = s.options.DBCache
	if cfg.DBRootDir == "" {
		root, e := os.UserCacheDir()
		if e != nil {
			return result, e
		}
		cfg.DBRootDir = filepath.Join(root, "rdy", "db")
	}
	cleanupWarnings, err := databaseScratchWarnings(ctx, cfg.DBRootDir, time.Now())
	if err != nil {
		return result, err
	}
	client := databaseClient{ctx: ctx, latestURL: "https://grype.anchore.io/databases/v6/latest.json", http: databaseHTTPClient()}
	curator, err := installation.NewCurator(cfg, client)
	if err != nil {
		return result, err
	}
	var updateErr error
	if !s.options.Offline {
		_, updateErr = curator.Update()
		if err = ctx.Err(); err != nil {
			return result, err
		}
	}
	status := curator.Status()
	if status.Error != nil {
		return result, fmt.Errorf("vulnerability database unavailable: %w", errors.Join(status.Error, updateErr))
	}
	reader, err := curator.Reader()
	if err != nil {
		return result, err
	}
	provider := v6.NewVulnerabilityProvider(reader)
	defer func() { err = errors.Join(err, provider.Close()) }()
	provenance, ok := provider.(vulnerability.StoreMetadataProvider)
	if !ok {
		return result, fmt.Errorf("database does not expose provider provenance")
	}
	providers, err := provenance.DataProvenance()
	if err != nil {
		return result, err
	}
	matcherConfig := defaultMatcherConfig()
	engine := grype.VulnerabilityMatcher{VulnerabilityProvider: provider, Matchers: matcher.NewDefaultMatchers(matcherConfig)}
	matches, ignored, err := engine.FindMatchesContext(ctx, packages, pkgContext)
	if err != nil {
		return result, err
	}
	if err = ctx.Err(); err != nil {
		return result, err
	}
	database := struct {
		Status    *vulnerability.ProviderStatus           `json:"status"`
		Providers map[string]vulnerability.DataProvenance `json:"providers"`
	}{&status, providers}
	audit := scannerAudit(matcherConfig, s.options.Offline)
	if updateErr != nil {
		audit["database_update_error"] = updateErr.Error()
	}
	doc, err := models.NewDocument(id, packages, pkgContext, *matches, ignored, provider, audit, database, models.SortStrategy("package"), false, nil)
	if err != nil {
		return result, err
	}
	data, err := json.Marshal(doc)
	if err != nil {
		return result, err
	}
	result, err = ParseScan(data)
	result.Warnings = append(result.Warnings, cleanupWarnings...)
	result.DBUpdate = DatabaseUpdate{Outcome: "ok"}
	if s.options.Offline {
		result.DBUpdate = DatabaseUpdate{Outcome: "skipped", Reason: "offline"}
	} else if updateErr != nil {
		result.DBUpdate = DatabaseUpdate{Outcome: "failed", Reason: updateErr.Error()}
	}
	return result, err
}

func defaultMatcherConfig() matcher.Config {
	return matcher.Config{Rpm: rpm.MatcherConfig{MissingEpochStrategy: version.MissingEpochStrategyAuto}, Stock: stock.MatcherConfig{UseCPEs: true}}
}

func scannerAudit(c matcher.Config, offline bool) map[string]any {
	return map[string]any{"match": map[string]any{"java": map[string]bool{"using-cpes": c.Java.UseCPEs}}, "matcher_options": c, "offline": offline}
}
