package main

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"go.idp.xyz/idp-gateway/internal/egressauthz/adapters/revokerclient"
	"go.idp.xyz/idp-gateway/internal/platform/audit"
	"go.idp.xyz/idp-gateway/internal/platform/workloadtls"
)

func TestListenMustBeLoopback(t *testing.T) {
	for _, addr := range []string{"127.0.0.1:19100", "[::1]:19100"} {
		if err := validateListen(addr); err != nil {
			t.Fatalf("%s: %v", addr, err)
		}
	}
	for _, addr := range []string{"0.0.0.0:19100", "10.1.2.3:19100", "localhost:19100", ":19100", "127.0.0.1", ""} {
		if err := validateListen(addr); err == nil {
			t.Fatalf("%s was accepted", addr)
		}
	}
	if code := run([]string{"--listen", "0.0.0.0:9"}, io.Discard, io.Discard); code != exitUsage {
		t.Fatalf("code %d", code)
	}
	if code := run([]string{"--authz", "127.0.0.1:1"}, io.Discard, io.Discard); code != exitUsage {
		t.Fatalf("partial authz code %d", code)
	}
}

func TestTwoHostHeadersAreRefusedBeforeTheHandler(t *testing.T) {
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		newConsole("", nil).ServeHTTP(w, r)
	}))
	defer server.Close()
	conn, err := net.Dial("tcp", server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_, err = io.WriteString(conn, "GET /v1/revocations HTTP/1.1\r\nHost: 127.0.0.1\r\nHost: evil.example\r\nConnection: close\r\n\r\n")
	if err != nil {
		t.Fatal(err)
	}
	status, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(status, " 400 ") {
		t.Fatalf("status %q", status)
	}
	if hits.Load() != 0 {
		t.Fatalf("handler was entered %d times", hits.Load())
	}
}

func TestHandlerRejectsASecondHostHeader(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "/v1/audit", nil)
	request.Header["Host"] = []string{"127.0.0.1", "evil.example"}
	response := httptest.NewRecorder()
	newConsole(t.TempDir()+"/missing", nil).ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status %d", response.Code)
	}
}

func TestAuditReadHidesSecretDetailsAndLooseFiles(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	sink, err := audit.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	err = sink.Write(audit.Record{
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		Service:   "idp-gateway-authz",
		EventType: "egress_decision",
		TraceID:   "trace-1",
		Outcome:   "ALLOW",
		Detail:    map[string]string{"api_key": "super-secret", "carrier_status": "200"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := sink.Close(); err != nil {
		t.Fatal(err)
	}
	response := get(t, newConsole(path, nil), "/v1/audit?trace_id=trace-1")
	if response.Code != http.StatusOK {
		t.Fatalf("status %d %s", response.Code, response.Body)
	}
	body := response.Body.String()
	if strings.Contains(body, "super-secret") || strings.Contains(body, "api_key") {
		t.Fatalf("secret survived: %s", body)
	}
	if !strings.Contains(body, "carrier_status") || !strings.Contains(body, "ALLOW") {
		t.Fatalf("body %s", body)
	}
	other := get(t, newConsole(path, nil), "/v1/audit?outcome=DENY")
	if other.Code != http.StatusOK || !strings.Contains(other.Body.String(), `"records":[]`) {
		t.Fatalf("filter %d %s", other.Code, other.Body)
	}

	loose := filepath.Join(dir, "loose.jsonl")
	if err := os.WriteFile(loose, []byte("{}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := get(t, newConsole(loose, nil), "/v1/audit"); got.Code != http.StatusForbidden || strings.Contains(got.Body.String(), loose) {
		t.Fatalf("loose %d %s", got.Code, got.Body)
	}
	link := filepath.Join(dir, "link.jsonl")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if got := get(t, newConsole(link, nil), "/v1/audit"); got.Code != http.StatusForbidden {
		t.Fatalf("symlink %d %s", got.Code, got.Body)
	}
	if got := get(t, newConsole(filepath.Join(dir, "missing.jsonl"), nil), "/v1/audit"); got.Code != http.StatusNotFound || strings.Contains(got.Body.String(), dir) {
		t.Fatalf("missing %d %s", got.Code, got.Body)
	}
	if got := get(t, newConsole("", nil), "/v1/audit"); got.Code != http.StatusNotFound || !strings.Contains(got.Body.String(), "not configured") {
		t.Fatalf("unset %d %s", got.Code, got.Body)
	}
	if got := get(t, newConsole("", nil), "/v1/revocations"); got.Code != http.StatusNotFound {
		t.Fatalf("mutation without a client %d", got.Code)
	}
}

func TestRevokeUsesTheRevokerCertificateAndIgnoresABadBody(t *testing.T) {
	var hits atomic.Int32
	var sawBody atomic.Value
	var sawURI atomic.Value
	standin := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		body, _ := io.ReadAll(io.LimitReader(r.Body, 4096))
		sawBody.Store(string(body))
		if r.TLS != nil && len(r.TLS.PeerCertificates) == 1 && len(r.TLS.PeerCertificates[0].URIs) == 1 {
			sawURI.Store(r.TLS.PeerCertificates[0].URIs[0].String())
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"account_id":"acct-1","revoked":true,"changed":true,"revocation_epoch":4}`)
	})
	address, files := startRevoker(t, standin)
	tlsConfig, err := workloadtls.ClientConfig(files.cert, files.key, files.ca, "authz.example")
	if err != nil {
		t.Fatal(err)
	}
	client, err := revokerclient.New(revokerclient.Config{Address: address, TLS: tlsConfig, Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	handler := newConsole("", client)
	bad := post(t, handler, "/v1/revocations", `{"account_id":"acct-1","revoked":true,"reason":"because","token":"nope"}`)
	if bad.Code != http.StatusBadRequest || hits.Load() != 0 {
		t.Fatalf("bad body %d hits %d %s", bad.Code, hits.Load(), bad.Body)
	}
	ok := post(t, handler, "/v1/revocations", `{"account_id":"acct-1","revoked":true,"reason":"operator"}`)
	if ok.Code != http.StatusOK || hits.Load() != 1 {
		t.Fatalf("revoke %d hits %d %s", ok.Code, hits.Load(), ok.Body)
	}
	var report map[string]any
	if err := json.Unmarshal(ok.Body.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if report["outcome"] != "REVOKED" || report["account_id"] != "acct-1" {
		t.Fatalf("report %#v", report)
	}
	if sawBody.Load().(string) != `{"account_id":"acct-1","revoked":true,"reason":"operator"}` {
		t.Fatalf("upstream body %q", sawBody.Load())
	}
	if sawURI.Load().(string) != "spiffe://idp.test/console/revoker" {
		t.Fatalf("client uri %#v", sawURI.Load())
	}
}

func get(t *testing.T, handler http.Handler, path string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodGet, path, nil)
	request.Host = "127.0.0.1"
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func post(t *testing.T, handler http.Handler, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	request.Host = "127.0.0.1"
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

type pemFiles struct{ cert, key, ca string }

func startRevoker(t *testing.T, handler http.Handler) (string, pemFiles) {
	t.Helper()
	dir := t.TempDir()
	caKey, caCert, caPEM := mintCA(t)
	serverPEM, serverKey := mintLeaf(t, caKey, caCert, "authz.example", x509.ExtKeyUsageServerAuth, nil)
	identity, err := url.Parse("spiffe://idp.test/console/revoker")
	if err != nil {
		t.Fatal(err)
	}
	clientPEM, clientKey := mintLeaf(t, caKey, caCert, "revoker", x509.ExtKeyUsageClientAuth, identity)
	files := pemFiles{
		cert: filepath.Join(dir, "client.crt"),
		key:  filepath.Join(dir, "client.key"),
		ca:   filepath.Join(dir, "ca.crt"),
	}
	writeFile(t, files.cert, clientPEM)
	writeFile(t, files.key, clientKey)
	writeFile(t, files.ca, caPEM)
	certificate, err := tls.X509KeyPair(serverPEM, serverKey)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		t.Fatal("ca")
	}
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{certificate},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pool,
	})
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close() })
	return listener.Addr().String(), files
}

func mintCA(t *testing.T) (*ecdsa.PrivateKey, *x509.Certificate, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: "console-ca"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return key, parsed, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func mintLeaf(t *testing.T, caKey *ecdsa.PrivateKey, caCert *x509.Certificate, name string, usage x509.ExtKeyUsage, identity *url.URL) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: name},
		NotBefore: caCert.NotBefore, NotAfter: caCert.NotAfter,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage},
	}
	if usage == x509.ExtKeyUsageServerAuth {
		template.DNSNames = []string{name}
	}
	if identity != nil {
		template.URIs = []*url.URL{identity}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, caCert, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
}

func writeFile(t *testing.T, path string, body []byte) {
	t.Helper()
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
}
