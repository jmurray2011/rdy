// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"strings"
	"syscall"
	"time"

	"github.com/jmurray2011/rdy/core"
	"github.com/jmurray2011/rdy/gate"
)

// buildVersion is set by the release linker and never changed at runtime.
var buildVersion = "dev"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Stdout, os.Stderr))
}

func run(ctx context.Context, args []string, out, stderr io.Writer) int {
	fs := flag.NewFlagSet("rdy", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var o gate.Options
	fs.BoolVar(&o.Strict, "strict", false, "Fail on warnings unless their IDs are allowed")
	fs.Func("allow-warning", "Allowed warning ID (repeatable or comma-separated)", func(value string) error {
		ids, err := gate.NormalizeAllowedWarnings(append(o.AllowWarnings, value))
		if err != nil {
			return err
		}
		o.AllowWarnings = ids
		return nil
	})
	var webhook, dbCache string
	var offline bool
	var statsPath, lockPath, bundleOut string
	fs.StringVar(&statsPath, "bundle-stats", "", "Build step: webpack stats JSON (deleted on success)")
	fs.StringVar(&lockPath, "lockfile", "", "Build step: package-lock.json v2/v3")
	fs.StringVar(&bundleOut, "bundle-out", "", "Build step: output path named bundle.cdx.json")
	fs.StringVar(&o.Aliases, "aliases", "", "Runtime and rename identity aliases YAML")
	var kevPolicy string
	fs.StringVar(&kevPolicy, "kev-policy", "block", "KEV policy: block all untriaged KEV or report only")
	var showVersion bool
	fs.BoolVar(&showVersion, "version", false, "Print build version")
	fs.StringVar(&o.Name, "name", "", "Display name")
	fs.StringVar(&o.Release, "release", "", "Numeric candidate version")
	fs.StringVar(&o.SBOM, "sbom", "", "CycloneDX JSON alternative to --artifact")
	fs.StringVar(&o.ArtifactVersion, "artifact-version", "", "Declared version required with --sbom")
	fs.StringVar(&o.TagPattern, "tag-pattern", "", "Tag regex with one captured numeric version")
	fs.StringVar(&o.Artifact, "artifact", "", "RPM, DEB, JAR or WAR")
	fs.StringVar(&o.Repo, "repo", "", "Local Git clone")
	fs.StringVar(&o.Branch, "branch", "", "Source branch")
	fs.StringVar(&o.Commit, "commit", "", "Declared full source commit SHA (optional)")
	fs.StringVar(&o.DevSBOM, "dev-sbom", "", "Deprecated: declared npm fallback, not verified shipped")
	fs.StringVar(&o.Triage, "triage", "", "YAML triage list")
	fs.StringVar(&o.Baseline, "baseline", "", "Deployed artifact or CycloneDX JSON")
	fs.StringVar(&o.BaselineDevSBOM, "baseline-dev-sbom", "", "Baseline build CycloneDX JSON")
	fs.StringVar(&o.Deployed, "deployed", "", "Deployed label")
	fs.StringVar(&o.Line, "line", "", "Release line as a version prefix (default: release without its last part)")
	fs.StringVar(&o.Out, "out", "", "Report directory")
	fs.IntVar(&o.Floor, "min-components", 1, "Minimum candidate component count (>=1)")
	fs.StringVar(&webhook, "notify-webhook", "", "POST verdict JSON {text: line}")
	fs.StringVar(&dbCache, "db-cache", "", "Vulnerability database cache directory")
	fs.BoolVar(&offline, "offline", false, "Use cached vulnerability database without network updates")
	if e := fs.Parse(args); e != nil {
		if errors.Is(e, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	info, _ := debug.ReadBuildInfo()
	effectiveVersion, versionLine := versionDetails(buildVersion, info)
	if showVersion {
		if _, err := fmt.Fprintln(out, versionLine); err != nil {
			return toolError(stderr, err)
		}
		return 0
	}
	if fs.NArg() != 0 {
		return toolError(stderr, fmt.Errorf("unexpected positional arguments"))
	}
	if statsPath != "" || lockPath != "" || bundleOut != "" {
		if o.Artifact != "" || o.SBOM != "" || o.Out != "" || o.Triage != "" || o.Baseline != "" {
			return toolError(stderr, fmt.Errorf("bundle build step cannot be combined with gate inputs"))
		}
		if err := gate.WriteBundle(ctx, statsPath, lockPath, bundleOut); err != nil {
			return toolError(stderr, err)
		}
		if _, err := fmt.Fprintln(out, "Bundle SBOM written:", bundleOut); err != nil {
			return toolError(stderr, err)
		}
		return 0
	}
	webhook = webhookAddress(webhook)
	policy, err := core.ParseKEVPolicy(kevPolicy)
	if err != nil {
		return toolError(stderr, err)
	}
	o.KEVPolicy = policy
	if o.Baseline == "" && (o.BaselineDevSBOM != "" || o.Deployed != "") {
		return toolError(stderr, fmt.Errorf("baseline flags require --baseline"))
	}
	if o.Out != "" {
		for _, name := range []string{"report.md", "findings.json", "candidate.cdx.json", "baseline.cdx.json", "triage.vex.json", "notify-error.txt", "pre-alias-candidate.cdx.json", "pre-alias-baseline.cdx.json"} {
			output, err := filepath.Abs(filepath.Join(o.Out, name))
			if err != nil {
				return toolError(stderr, err)
			}
			outputInfo, _ := os.Stat(output)
			for _, input := range []string{o.Artifact, o.SBOM, o.Triage, o.DevSBOM, o.Baseline, o.BaselineDevSBOM, o.Aliases} {
				if input == "" {
					continue
				}
				absolute, err := filepath.Abs(input)
				if err != nil {
					return toolError(stderr, err)
				}
				inputInfo, _ := os.Stat(input)
				if strings.EqualFold(output, absolute) || (outputInfo != nil && inputInfo != nil && os.SameFile(outputInfo, inputInfo)) {
					return toolError(stderr, fmt.Errorf("input conflicts with report output %s", output))
				}
			}
		}
	}
	// Prevent old successful reports from being mistaken for the current run.
	if o.Out != "" {
		if e := os.MkdirAll(o.Out, 0o700); e != nil {
			return toolError(stderr, e)
		}
		for _, name := range []string{"report.md", "findings.json", "candidate.cdx.json", "baseline.cdx.json", "triage.vex.json", "notify-error.txt", "pre-alias-candidate.cdx.json", "pre-alias-baseline.cdx.json"} {
			e := os.Remove(filepath.Join(o.Out, name))
			if e != nil && !errors.Is(e, os.ErrNotExist) {
				return toolError(stderr, e)
			}
		}
	}
	if dbCache == "" {
		root, err := os.UserCacheDir()
		if err != nil {
			return toolError(stderr, recordError(o.Out, err))
		}
		dbCache = filepath.Join(root, "rdy", "db")
	}
	o.Version = effectiveVersion
	o.Offline = offline
	o.DBCache = dbCache
	r, e := gate.Run(ctx, o, gate.NewEmbedded(gate.EmbeddedOptions{DBCache: dbCache, Offline: offline}))
	if e != nil {
		return toolError(stderr, recordError(o.Out, e))
	}
	return finish(ctx, webhook, o.Out, r, out, stderr)
}

func finish(ctx context.Context, webhook, outDir string, r gate.Result, out, stderr io.Writer) int {
	if e := emitVerdict(out, outDir, r.Line); e != nil {
		return toolError(stderr, e)
	}
	if webhook != "" {
		if e := publish(ctx, webhook, outDir, r.Line); e != nil {
			_, _ = fmt.Fprintln(stderr, "rdy notification ERROR:", e)
			if r.Pass {
				return 3
			}
			return 1
		}
	}
	if r.Pass {
		return 0
	}
	return 1
}

// emitVerdict writes the verdict and replaces reports with ERROR if output fails.
func emitVerdict(out io.Writer, outDir, line string) error {
	if _, e := fmt.Fprintln(out, line); e != nil {
		return recordError(outDir, e)
	}
	return nil
}

func toolError(out io.Writer, e error) int {
	_, _ = fmt.Fprintln(out, "rdy ERROR:", e)
	return 2
}

// publish preserves verdict reports and saves a separate notification error.
func publish(ctx context.Context, url, outDir, line string) error {
	if e := notify(ctx, url, line); e != nil {
		if outDir != "" {
			if err := os.WriteFile(filepath.Join(outDir, "notify-error.txt"), []byte(e.Error()+"\n"), 0o600); err != nil {
				return errors.Join(e, err)
			}
		}
		return e
	}
	return nil
}

func notify(ctx context.Context, url, line string) error {
	if !strings.HasPrefix(url, "https://") && !strings.HasPrefix(url, "http://") {
		return fmt.Errorf("webhook must be HTTP(S)")
	}
	b, e := json.Marshal(struct {
		Text string `json:"text"`
	}{line})
	if e != nil {
		return e
	}
	req, e := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(b))
	if e != nil {
		return redactedNotificationError(e)
	}
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 15 * time.Second}
	resp, e := client.Do(req)
	if e != nil {
		return redactedNotificationError(e)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("webhook HTTP %d", resp.StatusCode)
	}
	return nil
}

func recordError(outDir string, cause error) error {
	if outDir == "" {
		return cause
	}
	if e := os.WriteFile(filepath.Join(outDir, "report.md"), []byte("# Release gate\n\nERROR: "+cause.Error()+"\n"), 0o600); e != nil {
		return errors.Join(cause, e)
	}
	b, e := json.Marshal(map[string]string{"verdict": "ERROR", "error": cause.Error()})
	if e != nil {
		return errors.Join(cause, e)
	}
	if e = os.WriteFile(filepath.Join(outDir, "findings.json"), b, 0o600); e != nil {
		return errors.Join(cause, e)
	}
	return cause
}

func webhookAddress(flagValue string) string {
	if flagValue != "" {
		return flagValue
	}
	return os.Getenv("RDY_WEBHOOK")
}

type notificationError struct {
	category string
	cause    error
}

func (e notificationError) Error() string { return "notify webhook: " + e.category }
func (e notificationError) Unwrap() error { return e.cause }
func redactedNotificationError(err error) error {
	original := err
	for {
		var e *url.Error
		if !errors.As(err, &e) {
			break
		}
		err = e.Err
	}
	category := "connect"
	var dns *net.DNSError
	var timeout net.Error
	var cert *tls.CertificateVerificationError
	var unknown x509.UnknownAuthorityError
	var header tls.RecordHeaderError
	switch {
	case errors.Is(err, context.Canceled):
		category = "canceled"
	case errors.Is(err, context.DeadlineExceeded):
		category = "timeout"
	case errors.As(err, &timeout) && timeout.Timeout():
		category = "timeout"
	case errors.As(err, &dns):
		category = "dns"
	case errors.As(err, &cert) || errors.As(err, &unknown) || errors.As(err, &header):
		category = "tls"
	}
	return notificationError{category, original}
}
