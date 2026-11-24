package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"go.idp.xyz/idp-gateway/internal/platform/workloadtls/tlstest"
)

const (
	serverName = "coord.idp.test"
	authzID    = "spiffe://idp.test/egress/gateway-authz"
	otherID    = "spiffe://idp.test/egress/other"
	leaseKey   = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	leaseToken = "coordinator-access-token"
)

type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

type harness struct {
	t      *testing.T
	ca     *tlstest.CA
	server tlstest.Leaf
	authz  tlstest.Leaf
	other  tlstest.Leaf
	file   string
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	ca := tlstest.NewCA(t, "workload CA")
	return &harness{
		t: t, ca: ca,
		server: ca.Issue("coordinator", []string{"spiffe://idp.test/sf-lease"}, serverName),
		authz:  ca.Issue("authz", []string{authzID}),
		other:  ca.Issue("other", []string{otherID}),
		file:   filepath.Join(t.TempDir(), "leases.json"),
	}
}

func (h *harness) args(listen string) []string {
	return []string{"--listen", listen, "--tls-cert", h.server.CertFile, "--tls-key", h.server.KeyFile,
		"--client-ca", h.ca.File(), "--authz-identity", authzID, "--lease-file", h.file}
}

func (h *harness) start() (string, *lockedBuffer, func()) {
	h.t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	logs := &lockedBuffer{}
	addrCh := make(chan net.Addr, 1)
	done := make(chan error, 1)
	go func() {
		done <- run(ctx, h.args("127.0.0.1:0"), logs, func(a net.Addr) { addrCh <- a })
	}()
	var addr net.Addr
	select {
	case addr = <-addrCh:
	case err := <-done:
		cancel()
		h.t.Fatalf("did not start: %v\n%s", err, logs.String())
	case <-time.After(10 * time.Second):
		cancel()
		h.t.Fatal("did not start")
	}
	stop := func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				h.t.Errorf("stop: %v", err)
			}
		case <-time.After(10 * time.Second):
			h.t.Error("did not stop")
		}
	}
	return addr.String(), logs, stop
}

func (h *harness) client(leaf tlstest.Leaf) *http.Client {
	return &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
		TLSClientConfig: tlstest.ClientConfig(h.ca, serverName, &leaf),
	}}
}

func (h *harness) post(addr string, leaf tlstest.Leaf, path, body string) (int, string) {
	h.t.Helper()
	req, err := http.NewRequest(http.MethodPost, "https://"+addr+path, strings.NewReader(body))
	if err != nil {
		h.t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := h.client(leaf).Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		h.t.Fatal(err)
	}
	return resp.StatusCode, string(raw)
}

func TestFlagsAreRequired(t *testing.T) {
	base := []string{"--listen", "127.0.0.1:9", "--tls-cert", "c", "--tls-key", "k", "--client-ca", "ca",
		"--authz-identity", authzID, "--lease-file", "leases.json"}
	if _, err := parse(base, io.Discard); err != nil {
		t.Fatal(err)
	}
	if _, err := parse(append(base, "nope"), io.Discard); err == nil || !strings.Contains(err.Error(), "unexpected") {
		t.Fatalf("extra arg: %v", err)
	}
	names := []string{"--listen", "--tls-cert", "--tls-key", "--client-ca", "--authz-identity", "--lease-file"}
	for _, name := range names {
		var args []string
		for i := 0; i < len(base); i += 2 {
			if base[i] != name {
				args = append(args, base[i], base[i+1])
			}
		}
		if _, err := parse(args, io.Discard); err == nil || !strings.Contains(err.Error(), name) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestLooseLeaseFileRefusesToStart(t *testing.T) {
	h := newHarness(t)
	body := []byte(`{"version":1,"leases":{"` + leaseKey + `":{"token":"` + leaseToken + `"}}}`)
	if err := os.WriteFile(h.file, body, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(h.file, 0o644); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	err := run(ctx, h.args("127.0.0.1:0"), io.Discard, nil)
	if err == nil || !strings.Contains(err.Error(), "mode") || strings.Contains(err.Error(), leaseToken) {
		t.Fatalf("%v", err)
	}
}

func TestMTLSStartStopWrongIdentityDuplicateHostAndRestart(t *testing.T) {
	h := newHarness(t)
	addr, logs, stop := h.start()

	healthReq, err := http.NewRequest(http.MethodGet, "https://"+addr+"/healthz", nil)
	if err != nil {
		t.Fatal(err)
	}
	healthResp, err := h.client(h.authz).Do(healthReq)
	if err != nil {
		t.Fatal(err)
	}
	healthBody, _ := io.ReadAll(healthResp.Body)
	healthResp.Body.Close()
	if healthResp.StatusCode != http.StatusOK || strings.TrimSpace(string(healthBody)) != `{"ok":true}` {
		t.Fatalf("health %d %s", healthResp.StatusCode, healthBody)
	}

	status, body := h.post(addr, h.other, "/v1/sf-leases/commit", `not-json `+leaseToken)
	if status != http.StatusUnauthorized || strings.Contains(body, leaseToken) {
		t.Fatalf("wrong identity %d %s", status, body)
	}

	conn, err := tls.Dial("tcp", addr, &tls.Config{
		Certificates: []tls.Certificate{h.authz.Certificate},
		RootCAs:      h.ca.Pool(),
		ServerName:   serverName,
		NextProtos:   []string{"http/1.1"},
		MinVersion:   tls.VersionTLS12,
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	_, err = io.WriteString(conn, "POST /v1/sf-leases/acquire HTTP/1.1\r\nHost: 127.0.0.1\r\nHost: evil.example\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}")
	if err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(conn).ReadString('\n')
	conn.Close()
	if err != nil || !strings.Contains(line, " 400 ") {
		t.Fatalf("duplicate host %q %v", line, err)
	}

	status, body = h.post(addr, h.authz, "/v1/sf-leases/acquire",
		`{"lease_key":"`+leaseKey+`","holder_id":"holder-a","refresh_lead_ms":0,"lock_ttl_ms":2000,"wait_ms":0}`)
	var fetched struct {
		State      string `json:"state"`
		FenceToken string `json:"fence_token"`
	}
	if status != http.StatusOK || json.Unmarshal([]byte(body), &fetched) != nil || fetched.State != "FETCH" {
		t.Fatalf("acquire %d %s", status, body)
	}
	expires := time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano)
	commit := `{"lease_key":"` + leaseKey + `","holder_id":"holder-a","fence_token":"` + fetched.FenceToken +
		`","token":"` + leaseToken + `","lifetime_ms":3600000,"expires_at":"` + expires + `"}`
	status, body = h.post(addr, h.authz, "/v1/sf-leases/commit", commit)
	if status != http.StatusOK {
		t.Fatalf("commit %d %s", status, body)
	}
	if strings.Contains(logs.String(), leaseToken) {
		t.Fatalf("logs contain the token: %s", logs.String())
	}
	stop()

	addr, logs, stop = h.start()
	defer stop()
	status, body = h.post(addr, h.authz, "/v1/sf-leases/acquire",
		`{"lease_key":"`+leaseKey+`","holder_id":"holder-z","refresh_lead_ms":600000,"lock_ttl_ms":0,"wait_ms":0}`)
	if status != http.StatusOK || !strings.Contains(body, `"state":"VALID"`) || !strings.Contains(body, leaseToken) {
		t.Fatalf("after restart %d %s", status, body)
	}
	if strings.Contains(logs.String(), leaseToken) {
		t.Fatalf("restart logs contain the token: %s", logs.String())
	}
}
