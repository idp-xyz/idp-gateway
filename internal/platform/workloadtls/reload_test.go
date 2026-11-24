package workloadtls_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.idp.xyz/idp-gateway/internal/platform/workloadtls"
	"go.idp.xyz/idp-gateway/internal/platform/workloadtls/tlstest"
)

const (
	rejectLog      = "still using the last one that loaded"
	garbageMarker  = "NOT-A-CERTIFICATE-BODY"
	rotatedSubject = "spiffe://idp.test/gateway-control/publisher-next"
)

func garbagePEM() []byte {
	return []byte("-----BEGIN PRIVATE KEY-----\n" + garbageMarker + "\n-----END PRIVATE KEY-----\n" +
		"-----BEGIN CERTIFICATE-----\n" + garbageMarker + "\n-----END CERTIFICATE-----\n")
}

type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

func testLogger(buf *lockedBuffer) *slog.Logger {
	return slog.New(slog.NewJSONHandler(buf, nil))
}

func readBytes(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func atomicWriteErr(dst string, data []byte) error {
	file, err := os.CreateTemp(filepath.Dir(dst), ".tls-*")
	if err != nil {
		return err
	}
	name := file.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = file.Close()
			_ = os.Remove(name)
		}
	}()
	if _, err := file.Write(data); err != nil {
		return err
	}
	if err := file.Chmod(0o600); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, dst); err != nil {
		return err
	}
	cleanup = false
	return nil
}

func atomicWrite(t *testing.T, dst string, data []byte) {
	t.Helper()
	if err := atomicWriteErr(dst, data); err != nil {
		t.Fatal(err)
	}
}

func startTLSServer(t *testing.T, cfg *tls.Config) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{
		TLSConfig: cfg,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			serial := ""
			if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 && r.TLS.PeerCertificates[0].SerialNumber != nil {
				serial = r.TLS.PeerCertificates[0].SerialNumber.String()
			}
			_, _ = io.WriteString(w, "peer="+workloadtls.PeerIdentity(r.TLS)+" serial="+serial)
		}),
		ReadHeaderTimeout: 5 * time.Second,
		ErrorLog:          log.New(io.Discard, "", 0),
	}
	go func() { _ = srv.ServeTLS(listener, "", "") }()
	t.Cleanup(func() { _ = srv.Close() })
	return listener.Addr().String()
}

func exchange(addr string, cfg *tls.Config) (body, serverSerial string, err error) {
	var leaf *x509.Certificate
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			DisableKeepAlives: true,
			DialTLSContext: func(ctx context.Context, network, address string) (net.Conn, error) {
				conn, dialErr := (&tls.Dialer{Config: cfg}).DialContext(ctx, network, address)
				if dialErr != nil {
					return nil, dialErr
				}
				tlsConn, ok := conn.(*tls.Conn)
				if !ok || len(tlsConn.ConnectionState().PeerCertificates) == 0 {
					_ = conn.Close()
					return nil, fmt.Errorf("no server certificate")
				}
				leaf = tlsConn.ConnectionState().PeerCertificates[0]
				return conn, nil
			},
		},
	}
	defer client.CloseIdleConnections()
	response, err := client.Get("https://" + addr + "/")
	if err != nil {
		return "", "", err
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return "", "", err
	}
	if leaf == nil || leaf.SerialNumber == nil {
		return "", "", fmt.Errorf("no server certificate")
	}
	return string(raw), leaf.SerialNumber.String(), nil
}

func mustExchange(t *testing.T, addr string, cfg *tls.Config) (body, serverSerial string) {
	t.Helper()
	body, serverSerial, err := exchange(addr, cfg)
	if err != nil {
		t.Fatal(err)
	}
	return body, serverSerial
}

func mustFail(t *testing.T, addr string, cfg *tls.Config) {
	t.Helper()
	if _, _, err := exchange(addr, cfg); err == nil {
		t.Fatal("handshake succeeded")
	}
}

func assertLogClean(t *testing.T, text string) {
	t.Helper()
	for _, forbidden := range []string{"PRIVATE KEY", "BEGIN CERTIFICATE", garbageMarker} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("log contains %q:\n%s", forbidden, text)
		}
	}
}

func certSerial(t *testing.T, path string) string {
	t.Helper()
	block, _ := pem.Decode(readBytes(t, path))
	if block == nil {
		t.Fatal("not pem")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return cert.SerialNumber.String()
}

func writeServerLeaf(t *testing.T, ca testCA, dnsName, certPath, keyPath string) string {
	t.Helper()
	block, _ := pem.Decode(readBytes(t, ca.keyPath))
	if block == nil {
		t.Fatal("ca key is not pem")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		t.Fatal("ca key cannot sign")
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatal(err)
	}
	if serial.Sign() == 0 {
		serial = big.NewInt(1)
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: dnsName},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{dnsName},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.cert, &leafKey.PublicKey, signer)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(leafKey)
	if err != nil {
		t.Fatal(err)
	}
	atomicWrite(t, certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	atomicWrite(t, keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
	return serial.String()
}

func TestServerLeafReloadsWithoutRestart(t *testing.T) {
	ca := tlstest.NewCA(t, "workload CA")
	first := ca.Issue("server", []string{"spiffe://idp.test/egress/authz"}, serverName)
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "server.crt"), filepath.Join(dir, "server.key")
	atomicWrite(t, certPath, readBytes(t, first.CertFile))
	atomicWrite(t, keyPath, readBytes(t, first.KeyFile))
	cfg, err := workloadtls.ServerConfig(certPath, keyPath, ca.File())
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MinVersion != tls.VersionTLS12 || cfg.ClientAuth != tls.RequireAndVerifyClientCert ||
		len(cfg.Certificates) != 1 || cfg.ClientCAs == nil || cfg.GetConfigForClient == nil {
		t.Fatalf("static server fields: %+v", cfg)
	}
	addr := startTLSServer(t, cfg)
	clientLeaf := ca.Issue("gateway", []string{gatewayID})
	client := tlstest.ClientConfig(ca, serverName, &clientLeaf)
	_, serial := mustExchange(t, addr, client)
	if serial != first.X509.SerialNumber.String() {
		t.Fatalf("serial %s", serial)
	}
	next := ca.Issue("server-next", []string{"spiffe://idp.test/egress/authz"}, serverName)
	atomicWrite(t, certPath, readBytes(t, next.CertFile))
	atomicWrite(t, keyPath, readBytes(t, next.KeyFile))
	_, serial = mustExchange(t, addr, client)
	if serial != next.X509.SerialNumber.String() {
		t.Fatalf("after rotation serial %s, want %s", serial, next.X509.SerialNumber)
	}
}

func TestServerClientCAReloadsWithoutRestart(t *testing.T) {
	ca1 := tlstest.NewCA(t, "clients 1")
	ca2 := tlstest.NewCA(t, "clients 2")
	server := ca1.Issue("server", nil, serverName)
	clientCA := filepath.Join(t.TempDir(), "clients.pem")
	atomicWrite(t, clientCA, readBytes(t, ca1.File()))
	cfg, err := workloadtls.ServerConfig(server.CertFile, server.KeyFile, clientCA)
	if err != nil {
		t.Fatal(err)
	}
	addr := startTLSServer(t, cfg)
	const id1, id2 = "spiffe://idp.test/egress/old", "spiffe://idp.test/egress/new"
	oldLeaf := ca1.Issue("old", []string{id1})
	newLeaf := ca2.Issue("new", []string{id2})
	oldClient := tlstest.ClientConfig(ca1, serverName, &oldLeaf)
	newClient := tlstest.ClientConfig(ca1, serverName, &newLeaf)
	body, _ := mustExchange(t, addr, oldClient)
	if body != "peer="+id1+" serial="+oldLeaf.X509.SerialNumber.String() {
		t.Fatal(body)
	}
	atomicWrite(t, clientCA, readBytes(t, ca2.File()))
	mustFail(t, addr, oldClient)
	body, _ = mustExchange(t, addr, newClient)
	if body != "peer="+id2+" serial="+newLeaf.X509.SerialNumber.String() {
		t.Fatal(body)
	}
}

func TestClientLeafReloadsWithIssuePublisherCert(t *testing.T) {
	ca := newTestCA(t)
	dir := t.TempDir()
	serverCert, serverKey := filepath.Join(dir, "server.crt"), filepath.Join(dir, "server.key")
	wantServer := writeServerLeaf(t, ca, serverName, serverCert, serverKey)
	outCert, outKey := filepath.Join(dir, "publisher.crt"), filepath.Join(dir, "publisher.key")
	id1 := publisherID
	issued, err := workloadtls.IssuePublisherCert(request(ca, outCert, outKey, id1, 30))
	if err != nil || issued.Outcome != workloadtls.PublisherIssued {
		t.Fatal(issued, err)
	}
	srv, err := workloadtls.ServerConfig(serverCert, serverKey, ca.certPath)
	if err != nil {
		t.Fatal(err)
	}
	addr := startTLSServer(t, srv)
	cli, err := workloadtls.ClientConfig(outCert, outKey, ca.certPath, serverName)
	if err != nil {
		t.Fatal(err)
	}
	body, serverSerial := mustExchange(t, addr, cli)
	if serverSerial != wantServer || body != "peer="+id1+" serial="+certSerial(t, outCert) {
		t.Fatalf("body %q server %s", body, serverSerial)
	}
	rotated, err := workloadtls.IssuePublisherCert(request(ca, outCert, outKey, rotatedSubject, 30))
	if err != nil || rotated.Outcome != workloadtls.PublisherRotated || rotated.Identity != rotatedSubject {
		t.Fatal(rotated, err)
	}
	body, serverSerial = mustExchange(t, addr, cli)
	if serverSerial != wantServer || body != "peer="+rotatedSubject+" serial="+certSerial(t, outCert) {
		t.Fatalf("after rotation body %q server %s", body, serverSerial)
	}
}

func TestClientServerCAReloadsWithoutRestart(t *testing.T) {
	ca1 := tlstest.NewCA(t, "servers 1")
	ca2 := tlstest.NewCA(t, "servers 2")
	dir := t.TempDir()
	serverCert, serverKey := filepath.Join(dir, "server.crt"), filepath.Join(dir, "server.key")
	serverCA := filepath.Join(dir, "server-ca.pem")
	first := ca1.Issue("server", nil, serverName)
	atomicWrite(t, serverCert, readBytes(t, first.CertFile))
	atomicWrite(t, serverKey, readBytes(t, first.KeyFile))
	atomicWrite(t, serverCA, readBytes(t, ca1.File()))
	clientLeaf := ca1.Issue("gateway", []string{gatewayID})
	srv, err := workloadtls.ServerConfig(serverCert, serverKey, ca1.File())
	if err != nil {
		t.Fatal(err)
	}
	addr := startTLSServer(t, srv)
	cli, err := workloadtls.ClientConfig(clientLeaf.CertFile, clientLeaf.KeyFile, serverCA, serverName)
	if err != nil {
		t.Fatal(err)
	}
	cloned := cli.Clone()
	if cli.ServerName != serverName || cli.RootCAs == nil || len(cli.Certificates) == 0 || cli.MinVersion != tls.VersionTLS12 ||
		!cli.InsecureSkipVerify || cli.VerifyConnection == nil || cli.GetClientCertificate == nil ||
		cloned.VerifyConnection == nil || cloned.GetClientCertificate == nil || !cloned.InsecureSkipVerify || cloned.RootCAs == nil {
		t.Fatal("client config lost the fields callers check, or Clone dropped the hooks")
	}
	body, serial := mustExchange(t, addr, cli)
	if serial != first.X509.SerialNumber.String() || body != "peer="+gatewayID+" serial="+clientLeaf.X509.SerialNumber.String() {
		t.Fatalf("body %q serial %s", body, serial)
	}
	next := ca2.Issue("server-ca2", nil, serverName)
	atomicWrite(t, serverCert, readBytes(t, next.CertFile))
	atomicWrite(t, serverKey, readBytes(t, next.KeyFile))
	mustFail(t, addr, cli)
	atomicWrite(t, serverCA, readBytes(t, ca2.File()))
	_, serial = mustExchange(t, addr, cli)
	if serial != next.X509.SerialNumber.String() {
		t.Fatalf("serial %s", serial)
	}
	wrong, err := workloadtls.ClientConfig(clientLeaf.CertFile, clientLeaf.KeyFile, serverCA, "other.idp.test")
	if err != nil {
		t.Fatal(err)
	}
	mustFail(t, addr, wrong)
}

func TestSplitReplacementKeepsThePreviousCertificate(t *testing.T) {
	ca := tlstest.NewCA(t, "workload CA")
	first := ca.Issue("server", nil, serverName)
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "server.crt"), filepath.Join(dir, "server.key")
	atomicWrite(t, certPath, readBytes(t, first.CertFile))
	atomicWrite(t, keyPath, readBytes(t, first.KeyFile))
	cfg, err := workloadtls.ServerConfig(certPath, keyPath, ca.File())
	if err != nil {
		t.Fatal(err)
	}
	addr := startTLSServer(t, cfg)
	clientLeaf := ca.Issue("gateway", []string{gatewayID})
	client := tlstest.ClientConfig(ca, serverName, &clientLeaf)
	_, serial := mustExchange(t, addr, client)
	if serial != first.X509.SerialNumber.String() {
		t.Fatal(serial)
	}
	next := ca.Issue("server-next", nil, serverName)
	atomicWrite(t, certPath, readBytes(t, next.CertFile))
	_, serial = mustExchange(t, addr, client)
	if serial != first.X509.SerialNumber.String() {
		t.Fatalf("mismatched pair replaced the live certificate: %s", serial)
	}
	atomicWrite(t, keyPath, readBytes(t, next.KeyFile))
	_, serial = mustExchange(t, addr, client)
	if serial != next.X509.SerialNumber.String() {
		t.Fatalf("after the key arrived serial %s, want %s", serial, next.X509.SerialNumber)
	}
}

func TestBadFilesKeepTheLastGoodMaterial(t *testing.T) {
	t.Run("server certificate", func(t *testing.T) {
		ca := tlstest.NewCA(t, "workload CA")
		first := ca.Issue("server", nil, serverName)
		dir := t.TempDir()
		certPath, keyPath := filepath.Join(dir, "server.crt"), filepath.Join(dir, "server.key")
		atomicWrite(t, certPath, readBytes(t, first.CertFile))
		atomicWrite(t, keyPath, readBytes(t, first.KeyFile))
		logs := &lockedBuffer{}
		cfg, err := workloadtls.ServerConfigWithLogger(certPath, keyPath, ca.File(), testLogger(logs))
		if err != nil {
			t.Fatal(err)
		}
		addr := startTLSServer(t, cfg)
		client := tlstest.ClientConfig(ca, serverName, ptrLeaf(ca.Issue("gateway", []string{gatewayID})))
		want := first.X509.SerialNumber.String()
		corruptAndKeep(t, addr, client, logs, certPath, want, "")
	})
	t.Run("server client CA", func(t *testing.T) {
		ca1 := tlstest.NewCA(t, "clients 1")
		ca2 := tlstest.NewCA(t, "clients 2")
		server := ca1.Issue("server", nil, serverName)
		clientCA := filepath.Join(t.TempDir(), "clients.pem")
		atomicWrite(t, clientCA, readBytes(t, ca1.File()))
		logs := &lockedBuffer{}
		cfg, err := workloadtls.ServerConfigWithLogger(server.CertFile, server.KeyFile, clientCA, testLogger(logs))
		if err != nil {
			t.Fatal(err)
		}
		addr := startTLSServer(t, cfg)
		goodLeaf := ca1.Issue("good", []string{gatewayID})
		rogueLeaf := ca2.Issue("rogue", []string{gatewayID})
		good := tlstest.ClientConfig(ca1, serverName, &goodLeaf)
		rogue := tlstest.ClientConfig(ca1, serverName, &rogueLeaf)
		body, _ := mustExchange(t, addr, good)
		if body != "peer="+gatewayID+" serial="+goodLeaf.X509.SerialNumber.String() {
			t.Fatal(body)
		}
		mustFail(t, addr, rogue)
		for _, step := range []func(){
			func() { atomicWrite(t, clientCA, garbagePEM()) },
			func() {
				if err := os.WriteFile(clientCA, nil, 0o600); err != nil {
					t.Fatal(err)
				}
			},
			func() {
				if err := os.Remove(clientCA); err != nil {
					t.Fatal(err)
				}
			},
		} {
			before := strings.Count(logs.String(), rejectLog)
			step()
			body, _ = mustExchange(t, addr, good)
			if body != "peer="+gatewayID+" serial="+goodLeaf.X509.SerialNumber.String() {
				t.Fatal(body)
			}
			mustExchange(t, addr, good)
			mustFail(t, addr, rogue)
			if got := strings.Count(logs.String(), rejectLog); got != before+1 {
				t.Fatalf("reject logs %d, want %d\n%s", got, before+1, logs.String())
			}
		}
		assertLogClean(t, logs.String())
	})
	t.Run("client certificate", func(t *testing.T) {
		ca := tlstest.NewCA(t, "workload CA")
		server := ca.Issue("server", nil, serverName)
		leaf := ca.Issue("gateway", []string{gatewayID})
		dir := t.TempDir()
		certPath, keyPath := filepath.Join(dir, "client.crt"), filepath.Join(dir, "client.key")
		atomicWrite(t, certPath, readBytes(t, leaf.CertFile))
		atomicWrite(t, keyPath, readBytes(t, leaf.KeyFile))
		logs := &lockedBuffer{}
		cli, err := workloadtls.ClientConfigWithLogger(certPath, keyPath, ca.File(), serverName, testLogger(logs))
		if err != nil {
			t.Fatal(err)
		}
		addr := startTLSServer(t, mustServer(t, server.CertFile, server.KeyFile, ca.File()))
		wantBody := "peer=" + gatewayID + " serial=" + leaf.X509.SerialNumber.String()
		corruptWatched(t, addr, cli, logs, certPath, "", wantBody)
	})
	t.Run("client server CA", func(t *testing.T) {
		ca1 := tlstest.NewCA(t, "servers 1")
		ca2 := tlstest.NewCA(t, "servers 2")
		goodServer := ca1.Issue("server", nil, serverName)
		rogueServer := ca2.Issue("rogue-server", nil, serverName)
		leaf := ca1.Issue("gateway", []string{gatewayID})
		serverCA := filepath.Join(t.TempDir(), "server-ca.pem")
		atomicWrite(t, serverCA, readBytes(t, ca1.File()))
		logs := &lockedBuffer{}
		cli, err := workloadtls.ClientConfigWithLogger(leaf.CertFile, leaf.KeyFile, serverCA, serverName, testLogger(logs))
		if err != nil {
			t.Fatal(err)
		}
		goodAddr := startTLSServer(t, mustServer(t, goodServer.CertFile, goodServer.KeyFile, ca1.File()))
		rogueAddr := startTLSServer(t, mustServer(t, rogueServer.CertFile, rogueServer.KeyFile, ca1.File()))
		want := goodServer.X509.SerialNumber.String()
		_, serial := mustExchange(t, goodAddr, cli)
		if serial != want {
			t.Fatal(serial)
		}
		mustFail(t, rogueAddr, cli)
		for _, step := range []func(){
			func() { atomicWrite(t, serverCA, garbagePEM()) },
			func() {
				if err := os.WriteFile(serverCA, nil, 0o600); err != nil {
					t.Fatal(err)
				}
			},
			func() {
				if err := os.Remove(serverCA); err != nil {
					t.Fatal(err)
				}
			},
		} {
			before := strings.Count(logs.String(), rejectLog)
			step()
			_, serial = mustExchange(t, goodAddr, cli)
			if serial != want {
				t.Fatal(serial)
			}
			mustExchange(t, goodAddr, cli)
			mustFail(t, rogueAddr, cli)
			if got := strings.Count(logs.String(), rejectLog); got != before+1 {
				t.Fatalf("reject logs %d, want %d\n%s", got, before+1, logs.String())
			}
		}
		assertLogClean(t, logs.String())
	})
}

func ptrLeaf(leaf tlstest.Leaf) *tlstest.Leaf { return &leaf }

func mustServer(t *testing.T, cert, key, ca string) *tls.Config {
	t.Helper()
	cfg, err := workloadtls.ServerConfig(cert, key, ca)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func corruptAndKeep(t *testing.T, addr string, client *tls.Config, logs *lockedBuffer, path, wantSerial, wantBody string) {
	t.Helper()
	body, serial := mustExchange(t, addr, client)
	if serial != wantSerial || (wantBody != "" && body != wantBody) {
		t.Fatalf("body %q serial %s", body, serial)
	}
	corruptWatched(t, addr, client, logs, path, wantSerial, wantBody)
}

func corruptWatched(t *testing.T, addr string, client *tls.Config, logs *lockedBuffer, path, wantSerial, wantBody string) {
	t.Helper()
	for _, step := range []func(){
		func() { atomicWrite(t, path, garbagePEM()) },
		func() {
			if err := os.WriteFile(path, nil, 0o600); err != nil {
				t.Fatal(err)
			}
		},
		func() {
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
		},
	} {
		before := strings.Count(logs.String(), rejectLog)
		step()
		body, serial := mustExchange(t, addr, client)
		if (wantSerial != "" && serial != wantSerial) || (wantBody != "" && body != wantBody) {
			t.Fatalf("body %q serial %s", body, serial)
		}
		body, serial = mustExchange(t, addr, client)
		if (wantSerial != "" && serial != wantSerial) || (wantBody != "" && body != wantBody) {
			t.Fatalf("second handshake body %q serial %s", body, serial)
		}
		if got := strings.Count(logs.String(), rejectLog); got != before+1 {
			t.Fatalf("reject logs %d, want %d\n%s", got, before+1, logs.String())
		}
	}
	assertLogClean(t, logs.String())
}

func TestEstablishedConnectionIsNotCutWhenFilesChange(t *testing.T) {
	ca := tlstest.NewCA(t, "workload CA")
	first := ca.Issue("server", nil, serverName)
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "server.crt"), filepath.Join(dir, "server.key")
	atomicWrite(t, certPath, readBytes(t, first.CertFile))
	atomicWrite(t, keyPath, readBytes(t, first.KeyFile))
	addr := startTLSServer(t, mustServer(t, certPath, keyPath, ca.File()))
	clientLeaf := ca.Issue("gateway", []string{gatewayID})
	var dials atomic.Int32
	var mu sync.Mutex
	var serials []string
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			DialTLSContext: func(ctx context.Context, network, address string) (net.Conn, error) {
				conn, err := (&tls.Dialer{Config: tlstest.ClientConfig(ca, serverName, &clientLeaf)}).DialContext(ctx, network, address)
				if err != nil {
					return nil, err
				}
				dials.Add(1)
				state := conn.(*tls.Conn).ConnectionState()
				mu.Lock()
				serials = append(serials, state.PeerCertificates[0].SerialNumber.String())
				mu.Unlock()
				return conn, nil
			},
		},
	}
	get := func() error {
		response, err := client.Get("https://" + addr + "/")
		if err != nil {
			return err
		}
		defer response.Body.Close()
		_, err = io.Copy(io.Discard, response.Body)
		return err
	}
	if err := get(); err != nil {
		t.Fatal(err)
	}
	next := ca.Issue("server-next", nil, serverName)
	atomicWrite(t, certPath, readBytes(t, next.CertFile))
	atomicWrite(t, keyPath, readBytes(t, next.KeyFile))
	if err := get(); err != nil {
		t.Fatal(err)
	}
	if dials.Load() != 1 {
		t.Fatalf("the existing connection was replaced, dials=%d", dials.Load())
	}
	client.CloseIdleConnections()
	if err := get(); err != nil {
		t.Fatal(err)
	}
	if dials.Load() != 2 {
		t.Fatalf("dials=%d", dials.Load())
	}
	mu.Lock()
	defer mu.Unlock()
	if len(serials) != 2 || serials[0] != first.X509.SerialNumber.String() || serials[1] != next.X509.SerialNumber.String() {
		t.Fatal(serials)
	}
}

func TestConcurrentHandshakesDuringRotation(t *testing.T) {
	ca := tlstest.NewCA(t, "workload CA")
	dir := t.TempDir()
	serverCert, serverKey := filepath.Join(dir, "server.crt"), filepath.Join(dir, "server.key")
	clientCert, clientKey := filepath.Join(dir, "client.crt"), filepath.Join(dir, "client.key")
	firstServer := ca.Issue("server", nil, serverName)
	firstClient := ca.Issue("client", []string{gatewayID})
	atomicWrite(t, serverCert, readBytes(t, firstServer.CertFile))
	atomicWrite(t, serverKey, readBytes(t, firstServer.KeyFile))
	atomicWrite(t, clientCert, readBytes(t, firstClient.CertFile))
	atomicWrite(t, clientKey, readBytes(t, firstClient.KeyFile))
	addr := startTLSServer(t, mustServer(t, serverCert, serverKey, ca.File()))
	cli, err := workloadtls.ClientConfig(clientCert, clientKey, ca.File(), serverName)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		for i := 0; i < 20; i++ {
			select {
			case <-done:
				return
			default:
			}
			server := ca.Issue(fmt.Sprintf("server-%d", i), nil, serverName)
			if err := atomicWriteErr(serverCert, readBytes(t, server.CertFile)); err != nil {
				return
			}
			if err := atomicWriteErr(serverKey, readBytes(t, server.KeyFile)); err != nil {
				return
			}
			client := ca.Issue(fmt.Sprintf("client-%d", i), []string{fmt.Sprintf("spiffe://idp.test/egress/client-%d", i)})
			if err := atomicWriteErr(clientCert, readBytes(t, client.CertFile)); err != nil {
				return
			}
			if err := atomicWriteErr(clientKey, readBytes(t, client.KeyFile)); err != nil {
				return
			}
		}
	}()
	var wg sync.WaitGroup
	var mu sync.Mutex
	var failures []string
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 12 {
				if _, _, err := exchange(addr, cli); err != nil {
					mu.Lock()
					if len(failures) < 3 {
						failures = append(failures, err.Error())
					}
					mu.Unlock()
					return
				}
			}
		}()
	}
	wg.Wait()
	close(done)
	<-finished
	if len(failures) > 0 {
		t.Fatal(failures)
	}
}

func TestStartupRejectsOversizedMaterial(t *testing.T) {
	ca := tlstest.NewCA(t, "workload CA")
	leaf := ca.Issue("server", nil, serverName)
	big := filepath.Join(t.TempDir(), "big.pem")
	if err := os.WriteFile(big, bytes.Repeat([]byte{'A'}, (4<<20)+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := workloadtls.ServerConfig(big, leaf.KeyFile, ca.File()); err == nil {
		t.Fatal("oversized certificate was accepted")
	}
	if _, err := workloadtls.ServerConfig(leaf.CertFile, big, ca.File()); err == nil {
		t.Fatal("oversized key was accepted")
	}
	if _, err := workloadtls.ServerConfig(leaf.CertFile, leaf.KeyFile, big); err == nil {
		t.Fatal("oversized CA was accepted")
	}
	if _, err := workloadtls.ClientConfig(leaf.CertFile, leaf.KeyFile, big, serverName); err == nil {
		t.Fatal("oversized client CA was accepted")
	}
}
