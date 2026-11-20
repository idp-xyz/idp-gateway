package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const publisherIdentity = "spiffe://idp.test/gateway-control/publisher"

type commandCA struct {
	certPath string
	keyPath  string
	cert     *x509.Certificate
}

func newCommandCA(t *testing.T) commandCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "publisher CA"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	ca := commandCA{certPath: filepath.Join(dir, "ca.crt"), keyPath: filepath.Join(dir, "ca.key"), cert: cert}
	writeCommandPEM(t, ca.certPath, "CERTIFICATE", der)
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	writeCommandPEM(t, ca.keyPath, "PRIVATE KEY", keyDER)
	return ca
}

func writeCommandPEM(t *testing.T, path, blockType string, der []byte) {
	t.Helper()
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
}

func runIssuePublisher(t *testing.T, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errb bytes.Buffer
	code = run(context.Background(), append([]string{commandIssuePublisherCert}, args...), &out, &errb, nil)
	return code, out.String(), errb.String()
}

func issueArgs(ca commandCA, identity, certPath, keyPath string, extra ...string) []string {
	args := []string{
		"--ca-cert", ca.certPath, "--ca-key", ca.keyPath,
		"--identity", identity, "--out-cert", certPath, "--out-key", keyPath,
	}
	return append(args, extra...)
}

type issuedLine struct {
	Outcome  string `json:"outcome"`
	Identity string `json:"identity"`
	NotAfter string `json:"not_after"`
}

func decodeIssued(t *testing.T, stdout string) issuedLine {
	t.Helper()
	dec := json.NewDecoder(strings.NewReader(stdout))
	dec.DisallowUnknownFields()
	var line issuedLine
	if err := dec.Decode(&line); err != nil {
		t.Fatal(err)
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		t.Fatalf("extra output: %v", err)
	}
	if strings.Contains(stdout, "PRIVATE") || strings.Contains(stdout, "BEGIN CERTIFICATE") {
		t.Fatal("stdout contains key or certificate material")
	}
	return line
}

func leafChains(t *testing.T, certPath string, ca *x509.Certificate, identity string) *x509.Certificate {
	t.Helper()
	raw, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(raw)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatal("not a certificate")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		t.Fatal(err)
	}
	if len(leaf.URIs) != 1 || leaf.URIs[0].String() != identity || len(leaf.DNSNames) != 0 || leaf.IsCA {
		t.Fatalf("uri %v dns %v ca %v", leaf.URIs, leaf.DNSNames, leaf.IsCA)
	}
	return leaf
}

func filePerm(t *testing.T, path string) os.FileMode {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return info.Mode().Perm()
}

func TestIssuePublisherCertCommandChainsToTheCA(t *testing.T) {
	ca := newCommandCA(t)
	dir := t.TempDir()
	certPath := filepath.Join(dir, "publisher.crt")
	keyPath := filepath.Join(dir, "publisher.key")
	code, stdout, stderr := runIssuePublisher(t, issueArgs(ca, publisherIdentity, certPath, keyPath)...)
	if code != exitActive || stderr != "" {
		t.Fatalf("code %d stderr %q stdout %q", code, stderr, stdout)
	}
	line := decodeIssued(t, stdout)
	leaf := leafChains(t, certPath, ca.cert, publisherIdentity)
	if line.Outcome != "ISSUED" || line.Identity != publisherIdentity || !strings.HasSuffix(line.NotAfter, "Z") {
		t.Fatalf("%+v", line)
	}
	if line.NotAfter != leaf.NotAfter.UTC().Format(time.RFC3339) {
		t.Fatalf("not_after %s cert %s", line.NotAfter, leaf.NotAfter.UTC().Format(time.RFC3339))
	}
	if filePerm(t, certPath) != 0o644 || filePerm(t, keyPath) != 0o600 {
		t.Fatalf("modes %o %o", filePerm(t, certPath), filePerm(t, keyPath))
	}
	raw, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(raw)
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	ec, ok := key.(*ecdsa.PrivateKey)
	if !ok || ec.Curve.Params().Name != "P-256" {
		t.Fatalf("key type %T", key)
	}
	if _, err := os.Stat(certPath + ".previous"); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("previous file exists after issuance")
	}
}

func TestIssuePublisherCertCommandRotates(t *testing.T) {
	ca := newCommandCA(t)
	dir := t.TempDir()
	certPath := filepath.Join(dir, "publisher.crt")
	keyPath := filepath.Join(dir, "publisher.key")
	if code, stdout, stderr := runIssuePublisher(t, issueArgs(ca, publisherIdentity, certPath, keyPath)...); code != exitActive {
		t.Fatalf("issue %d %s %s", code, stdout, stderr)
	}
	first, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr := runIssuePublisher(t, issueArgs(ca, publisherIdentity, certPath, keyPath)...)
	if code != exitActive || stderr != "" {
		t.Fatalf("rotate %d %s %s", code, stdout, stderr)
	}
	line := decodeIssued(t, stdout)
	if line.Outcome != "ROTATED" || line.Identity != publisherIdentity {
		t.Fatalf("%+v", line)
	}
	second, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatal(err)
	}
	previous, err := os.ReadFile(certPath + ".previous")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(first, second) || !bytes.Equal(first, previous) {
		t.Fatal("previous leaf was not kept")
	}
	leafChains(t, certPath, ca.cert, publisherIdentity)
	leafChains(t, certPath+".previous", ca.cert, publisherIdentity)
	if filePerm(t, keyPath) != 0o600 || filePerm(t, keyPath+".previous") != 0o600 {
		t.Fatalf("key modes %o %o", filePerm(t, keyPath), filePerm(t, keyPath+".previous"))
	}
	if _, err := os.Stat(keyPath + ".previous"); err != nil {
		t.Fatal(err)
	}
}

func TestIssuePublisherCertCommandRefusesANonCA(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "not a ca"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	caCert := filepath.Join(dir, "not-ca.crt")
	caKey := filepath.Join(dir, "not-ca.key")
	writeCommandPEM(t, caCert, "CERTIFICATE", der)
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	writeCommandPEM(t, caKey, "PRIVATE KEY", keyDER)
	out := t.TempDir()
	outCert := filepath.Join(out, "publisher.crt")
	outKey := filepath.Join(out, "publisher.key")
	code, stdout, stderr := runIssuePublisher(t, "--ca-cert", caCert, "--ca-key", caKey, "--identity", publisherIdentity, "--out-cert", outCert, "--out-key", outKey)
	if code != exitError || stdout != "" || !strings.Contains(stderr, "not a CA") {
		t.Fatalf("code %d stdout %q stderr %q", code, stdout, stderr)
	}
	if entries, readErr := os.ReadDir(out); readErr != nil || len(entries) != 0 {
		t.Fatalf("output %v %v", entries, readErr)
	}
}

func TestIssuePublisherCertCommandRefusesNonSPIFFEIdentity(t *testing.T) {
	ca := newCommandCA(t)
	for _, identity := range []string{"publisher.idp.test", "https://idp.test/gateway-control/publisher"} {
		t.Run(identity, func(t *testing.T) {
			dir := t.TempDir()
			outCert := filepath.Join(dir, "publisher.crt")
			outKey := filepath.Join(dir, "publisher.key")
			code, stdout, stderr := runIssuePublisher(t, issueArgs(ca, identity, outCert, outKey)...)
			if code != exitError || stdout != "" || !strings.Contains(stderr, "spiffe") {
				t.Fatalf("code %d stdout %q stderr %q", code, stdout, stderr)
			}
			if entries, err := os.ReadDir(dir); err != nil || len(entries) != 0 {
				t.Fatalf("%v %v", entries, err)
			}
		})
	}
}

func TestIssuePublisherCertCommandUsageAndRefusals(t *testing.T) {
	ca := newCommandCA(t)
	dir := t.TempDir()
	certPath := filepath.Join(dir, "publisher.crt")
	keyPath := filepath.Join(dir, "publisher.key")
	code, stdout, stderr := runIssuePublisher(t)
	if code != exitUsage || stdout != "" || !strings.Contains(stderr, "missing required flags") {
		t.Fatalf("usage %d %q %q", code, stdout, stderr)
	}
	code, stdout, stderr = runIssuePublisher(t, append(issueArgs(ca, publisherIdentity, certPath, keyPath), "extra")...)
	if code != exitUsage || !strings.Contains(stderr, "unexpected argument") {
		t.Fatalf("extra %d %q", code, stderr)
	}
	var usage bytes.Buffer
	if code := run(context.Background(), []string{"no-such"}, io.Discard, &usage, nil); code != exitUsage || !strings.Contains(usage.String(), "issue-publisher-cert") {
		t.Fatalf("usage list %d %q", code, usage.String())
	}

	code, stdout, stderr = runIssuePublisher(t, append(issueArgs(ca, publisherIdentity, certPath, keyPath), "--days", "0")...)
	if code != exitError || stdout != "" || !strings.Contains(stderr, "days") {
		t.Fatalf("days 0: %d %q %q", code, stdout, stderr)
	}
	code, _, stderr = runIssuePublisher(t, append(issueArgs(ca, publisherIdentity, certPath, keyPath), "--days", "826")...)
	if code != exitError || !strings.Contains(stderr, "days") {
		t.Fatalf("days 826: %d %q", code, stderr)
	}
	if _, err := os.Stat(certPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("days refusal created a certificate")
	}

	envCert := filepath.Join(dir, "${HOME}.crt")
	code, stdout, stderr = runIssuePublisher(t, issueArgs(ca, publisherIdentity, envCert, keyPath)...)
	if code != exitError || stdout != "" || !strings.Contains(stderr, "environment") {
		t.Fatalf("env %d %q %q", code, stdout, stderr)
	}
	if _, err := os.Stat(envCert); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("environment path was created")
	}
}
