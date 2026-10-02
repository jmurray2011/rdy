// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFailedNotificationPreservesVerdict(t *testing.T) {
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	address := listener.Addr().String()
	if e = listener.Close(); e != nil {
		t.Fatal(e)
	}
	dir := t.TempDir()
	for _, name := range []string{"report.md", "findings.json"} {
		if e = os.WriteFile(filepath.Join(dir, name), []byte("app 1.0.0  FAIL"), 0o600); e != nil {
			t.Fatal(e)
		}
	}
	if e = publish(context.Background(), "http://"+address+"/secret-token?key=secret-value", dir, "app 1.0.0  FAIL"); e == nil {
		t.Fatal("unreachable webhook reported success")
	}
	for _, name := range []string{"report.md", "findings.json"} {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if string(b) != "app 1.0.0  FAIL" {
			t.Fatalf("%s kept the verdict after a notification error: %s", name, b)
		}
	}
}

type brokenVerdictWriter struct{}

func (brokenVerdictWriter) Write([]byte) (int, error) { return 0, os.ErrClosed }
func TestFailedVerdictOutputReplacesReports(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"report.md", "findings.json"} {
		if e := os.WriteFile(filepath.Join(dir, name), []byte("PASS"), 0o600); e != nil {
			t.Fatal(e)
		}
	}
	if e := emitVerdict(brokenVerdictWriter{}, dir, "sample PASS"); e == nil {
		t.Fatal("lost output error")
	}
	for _, name := range []string{"report.md", "findings.json"} {
		b, e := os.ReadFile(filepath.Join(dir, name))
		if e != nil {
			t.Fatal(e)
		}
		if strings.Contains(string(b), "PASS") || !strings.Contains(string(b), "ERROR") {
			t.Fatalf("stale verdict: %s", b)
		}
	}
}

func TestNotificationErrorIsRedactedAndSaved(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	dir := t.TempDir()
	url := "https://example.invalid/secret-token?key=secret-value"
	e := publish(ctx, url, dir, "PASS")
	if e == nil {
		t.Fatal("lost error")
	}
	b, re := os.ReadFile(filepath.Join(dir, "notify-error.txt"))
	if re != nil {
		t.Fatal(re)
	}
	for _, text := range []string{e.Error(), string(b)} {
		if strings.Contains(text, "secret-token") || strings.Contains(text, "secret-value") {
			t.Fatalf("secret leaked: %s", text)
		}
	}
}

func TestWebhookEnvironmentFallback(t *testing.T) {
	t.Setenv("RDY_WEBHOOK", "https://example.invalid/secret")
	if webhookAddress("") != "https://example.invalid/secret" || webhookAddress("https://example.invalid/override") != "https://example.invalid/override" {
		t.Fatal("webhook precedence")
	}
}
