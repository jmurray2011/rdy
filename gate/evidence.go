// SPDX-License-Identifier: Apache-2.0

package gate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

// ComparedTags records the source comparisons, including checks that had no tag.
type ComparedTags struct {
	Count          int      `json:"tag_count"`
	Ignored        []string `json:"ignored_tags"`
	LatestCommit   string   `json:"latest_commit"`
	PreviousCommit string   `json:"previous_commit"`
	Line           string   `json:"line"`
	Latest         string   `json:"latest_in_line"`
	Previous       string   `json:"previous"`
}

// DatabaseUpdate records whether the advisory database update ran successfully.
type DatabaseUpdate struct {
	Outcome string `json:"outcome"`
	Reason  string `json:"reason,omitempty"`
}

// String formats the update outcome and optional reason.
func (d DatabaseUpdate) String() string {
	if d.Reason != "" {
		return d.Outcome + ": " + d.Reason
	}
	return d.Outcome
}

func releaseLine(release, line string) string {
	if line != "" {
		return strings.TrimPrefix(line, "v")
	}
	parts := strings.Split(strings.TrimPrefix(release, "v"), ".")
	return strings.Join(parts[:len(parts)-1], ".")
}

func databaseAge(built string, now time.Time) string {
	t, e := time.Parse(time.RFC3339, built)
	if e != nil {
		return "unknown"
	}
	age := now.Sub(t)
	if age < 0 {
		age = 0
	}
	return age.Round(time.Second).String()
}

func hashFile(ctx context.Context, path string) (string, error) {
	f, e := os.Open(path)
	if e != nil {
		return "", e
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, e = io.Copy(h, contextReader{ctx, f}); e != nil {
		return "", e
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func hashInputs(ctx context.Context, o Options) (map[string]string, error) {
	hashes := map[string]string{}
	for key, path := range map[string]string{"artifact": o.Artifact, "sbom": o.SBOM, "baseline": o.Baseline, "triage": o.Triage, "aliases": o.Aliases, "dev_sbom": o.DevSBOM, "baseline_dev_sbom": o.BaselineDevSBOM} {
		if path != "" {
			h, e := hashFile(ctx, path)
			if e != nil {
				return nil, fmt.Errorf("hash %s: %w", key, e)
			}
			hashes[key] = h
		}
	}
	return hashes, nil
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r contextReader) Read(b []byte) (int, error) {
	if e := r.ctx.Err(); e != nil {
		return 0, e
	}
	return r.reader.Read(b)
}
