// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jmurray2011/rdy/gate"
)

func TestUsage(t *testing.T) {
	for _, args := range [][]string{{}, {"--name", "sample"}, {"--unknown"}} {
		var out, err bytes.Buffer
		if code := run(context.Background(), args, &out, &err); code != 2 {
			t.Fatalf("code %d", code)
		}
		if strings.Contains(out.String(), "PASS") {
			t.Fatal("usage error reads as pass")
		}
	}
	var out, err bytes.Buffer
	if code := run(context.Background(), []string{"--help"}, &out, &err); code != 0 {
		t.Fatalf("help %d", code)
	}
}

func TestInputPreserved(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "findings.json")
	if e := os.WriteFile(path, []byte("input"), 0o600); e != nil {
		t.Fatal(e)
	}
	var out, stderr bytes.Buffer
	if code := run(context.Background(), []string{"--artifact", path, "--out", dir}, &out, &stderr); code != 2 {
		t.Fatal(code)
	}
	b, e := os.ReadFile(path)
	if e != nil || string(b) != "input" {
		t.Fatalf("input overwritten: %s %v", b, e)
	}
}

func TestBuildVersion(t *testing.T) {
	var out, stderr bytes.Buffer
	if code := run(context.Background(), []string{"--version"}, &out, &stderr); code != 0 {
		t.Fatalf("version exit %d: %s", code, stderr.String())
	}
	if !strings.Contains(out.String(), "rdy dev") {
		t.Fatalf("version %s", out.String())
	}
}

func TestErrorReportsReplaceSuccess(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"report.md", "findings.json"} {
		if e := os.WriteFile(filepath.Join(dir, name), []byte("PASS"), 0o600); e != nil {
			t.Fatal(e)
		}
	}
	if e := recordError(dir, errors.New("webhook failed")); e == nil {
		t.Fatal("lost error")
	}
	for _, name := range []string{"report.md", "findings.json"} {
		b, e := os.ReadFile(filepath.Join(dir, name))
		if e != nil {
			t.Fatal(e)
		}
		if strings.Contains(string(b), "PASS") || !strings.Contains(string(b), "ERROR") {
			t.Fatalf("stale success %s: %s", name, b)
		}
	}
}

func TestKEVPolicyFlag(t *testing.T) {
	var out, stderr bytes.Buffer
	if code := run(context.Background(), []string{"--kev-policy", "report", "--help"}, &out, &stderr); code != 0 {
		t.Fatalf("KEV policy flag missing: %d %s", code, stderr.String())
	}
}

func TestNotificationFailureExitThree(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"report.md", "findings.json"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("fixture PASS"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var out, stderr bytes.Buffer
	code := finish(ctx, "https://fictional.invalid/secret-hook?token=secret-token", dir, gate.Result{Pass: true, Line: "fixture PASS"}, &out, &stderr)
	if code != 3 || strings.Contains(stderr.String(), "secret-") {
		t.Fatalf("exit=%d stderr=%s", code, &stderr)
	}
	for _, name := range []string{"report.md", "findings.json"} {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil || string(b) != "fixture PASS" {
			t.Fatal("verdict changed")
		}
	}
}

func TestThirdRoundNotifyVerdictPrecedesPost(t *testing.T) {
	for _, pass := range []bool{false, true} {
		t.Run(fmt.Sprint(pass), func(t *testing.T) {
			var out, stderr bytes.Buffer
			posted := false
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				posted = true
				if !strings.Contains(out.String(), "fixture verdict") {
					t.Error("posted before stdout verdict")
				}
				w.WriteHeader(503)
			}))
			defer server.Close()
			code := finish(context.Background(), server.URL, t.TempDir(), gate.Result{Pass: pass, Line: "fixture verdict"}, &out, &stderr)
			want := 1
			if pass {
				want = 3
			}
			if code != want || !posted || out.String() != "fixture verdict\n" {
				t.Fatalf("exit=%d stdout=%q", code, &out)
			}
		})
	}
}

func TestThirdRoundTransportCategoriesHideHosts(t *testing.T) {
	for _, e := range []error{&net.DNSError{Name: "secret.fixture.invalid", Err: "fictional DNS failure"}, &net.OpError{Op: "dial", Net: "tcp", Addr: &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 443}, Err: errors.New("fixture")}} {
		s := redactedNotificationError(&url.Error{Op: "Post", URL: "https://secret.fixture.invalid/token", Err: e}).Error()
		if strings.Contains(s, "fixture") || strings.Contains(s, "192.0.2.1") || strings.Contains(s, "https") {
			t.Fatalf("transport leaked: %s", s)
		}
	}
}

func TestThirdRoundSBOMFlagsAreRecognized(t *testing.T) {
	var out, stderr bytes.Buffer
	code := run(context.Background(), []string{"--sbom", "fictional.cdx.json", "--artifact-version", "2.4.0", "--tag-pattern", `^fictional-v([0-9.]+)$`}, &out, &stderr)
	if code != 2 || strings.Contains(stderr.String(), "flag provided but not defined") {
		t.Fatalf("flags exit=%d stderr=%s", code, &stderr)
	}
}
