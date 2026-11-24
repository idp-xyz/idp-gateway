package main

import (
	"context"
	"io"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAuthzStateFlagsAreAllOrNothing(t *testing.T) {
	h := newHarness(t)
	revocations := writePrivate(t, filepath.Join(t.TempDir(), "revocations.json"), nothingRevoked)
	base := append(h.args("127.0.0.1:0"), "--revocations", revocations, "--revoker-identity", revokerID)
	partial := append(append([]string{}, base...), "--authz-state-url", "https://state.idp.test")
	if _, err := parse(partial, io.Discard); err == nil || !strings.Contains(err.Error(), "go together") {
		t.Fatal(err)
	}
	httpURL := append(append([]string{}, base...),
		"--authz-state-url", "http://state.idp.test",
		"--authz-state-cert", h.peers["gateway"].CertFile,
		"--authz-state-key", h.peers["gateway"].KeyFile,
		"--authz-state-ca", h.ca.File(),
		"--authz-state-name", "state.idp.test")
	if _, err := parse(httpURL, io.Discard); err == nil || !strings.Contains(err.Error(), "https URL") {
		t.Fatal(err)
	}
	withQuery := append(append([]string{}, base...),
		"--authz-state-url", "https://user:pw@state.idp.test/state?x=1#f",
		"--authz-state-cert", "c", "--authz-state-key", "k", "--authz-state-ca", "ca", "--authz-state-name", "state.idp.test")
	if _, err := parse(withQuery, io.Discard); err == nil || !strings.Contains(err.Error(), "https URL") || strings.Contains(err.Error(), "user:pw") {
		t.Fatal(err)
	}
	noFile := append(h.args("127.0.0.1:0"),
		"--authz-state-url", "https://state.idp.test",
		"--authz-state-cert", "c", "--authz-state-key", "k", "--authz-state-ca", "ca", "--authz-state-name", "state.idp.test")
	if _, err := parse(noFile, io.Discard); err == nil || !strings.Contains(err.Error(), "needs --revocations") {
		t.Fatal(err)
	}
	if _, err := parse(base, io.Discard); err != nil {
		t.Fatal(err)
	}

	down := append(append([]string{}, base...),
		"--authz-state-url", "https://127.0.0.1:1",
		"--authz-state-cert", h.peers["gateway"].CertFile,
		"--authz-state-key", h.peers["gateway"].KeyFile,
		"--authz-state-ca", h.ca.File(),
		"--authz-state-name", "state.idp.test")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	err := run(ctx, down, io.Discard, nil)
	cancel()
	if err == nil || !strings.Contains(err.Error(), "authz state") || strings.Contains(err.Error(), "provider-token") {
		t.Fatal(err)
	}
}
