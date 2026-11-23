package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestUIServesThePageAndKeepsTheAPI(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "index.html"), []byte("<!doctype html><h1>控制台</h1>"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "assets"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "assets", "app.js"), []byte("console.log(1)"), 0o644); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "secret.html")
	if err := os.WriteFile(outside, []byte("secret-outside"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "linked.html")); err != nil {
		t.Fatal(err)
	}
	handler := handlerFor("", nil, dir)

	page := get(t, handler, "/")
	if page.Code != http.StatusOK || !strings.Contains(page.Body.String(), "控制台") {
		t.Fatalf("page %d %s", page.Code, page.Body)
	}
	if !strings.Contains(page.Header().Get("Content-Security-Policy"), "default-src 'self'") {
		t.Fatalf("csp %q", page.Header().Get("Content-Security-Policy"))
	}
	script := get(t, handler, "/assets/app.js")
	if script.Code != http.StatusOK || script.Header().Get("Content-Type") != "text/javascript; charset=utf-8" {
		t.Fatalf("script %d %q", script.Code, script.Header().Get("Content-Type"))
	}
	for _, path := range []string{"/../secret.html", "/linked.html", "/assets/../linked.html", "/note.txt"} {
		got := get(t, handler, path)
		if got.Code != http.StatusNotFound || strings.Contains(got.Body.String(), "secret-outside") {
			t.Fatalf("%s %d %s", path, got.Code, got.Body)
		}
	}
	audit := get(t, handler, "/v1/audit")
	if audit.Code != http.StatusNotFound || !strings.Contains(audit.Body.String(), "not configured") {
		t.Fatalf("api %d %s", audit.Code, audit.Body)
	}
	revocation := get(t, handler, "/v1/revocations")
	if revocation.Code != http.StatusNotFound || !strings.Contains(revocation.Body.String(), "revoker is not configured") {
		t.Fatalf("revocation %d %s", revocation.Code, revocation.Body)
	}
	if _, err := uiFile(dir, "/"); err != nil {
		t.Fatal(err)
	}
}

func TestUIFlagRejectsAMissingDirectory(t *testing.T) {
	if code := run([]string{"--ui", filepath.Join(t.TempDir(), "missing")}, io.Discard, io.Discard); code != exitUsage {
		t.Fatalf("code %d", code)
	}
}

func TestRootStaysAnAPIWhenUIIsOmitted(t *testing.T) {
	response := httptest.NewRecorder()
	handlerFor("", nil, "").ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/", nil))
	if response.Code != http.StatusNotFound {
		t.Fatalf("status %d", response.Code)
	}
}
