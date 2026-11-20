package workloadtls_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"go.idp.xyz/idp-gateway/internal/platform/workloadtls"
)

const publisherID = "spiffe://idp.test/gateway-control/publisher"

type testCA struct {
	certPath string
	keyPath  string
	cert     *x509.Certificate
}

func newTestCA(t *testing.T) testCA {
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
	ca := testCA{certPath: filepath.Join(dir, "ca.crt"), keyPath: filepath.Join(dir, "ca.key"), cert: cert}
	writePEM(t, ca.certPath, "CERTIFICATE", der)
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	writePEM(t, ca.keyPath, "PRIVATE KEY", keyDER)
	return ca
}

func writePEM(t *testing.T, path, blockType string, der []byte) {
	t.Helper()
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
}

func selfSignedNonCA(t *testing.T) (certPath, keyPath string) {
	t.Helper()
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
	certPath = filepath.Join(dir, "leaf.crt")
	keyPath = filepath.Join(dir, "leaf.key")
	writePEM(t, certPath, "CERTIFICATE", der)
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	writePEM(t, keyPath, "PRIVATE KEY", keyDER)
	return certPath, keyPath
}

func request(ca testCA, certPath, keyPath, identity string, days int) workloadtls.PublisherCertRequest {
	return workloadtls.PublisherCertRequest{
		CACertFile: ca.certPath, CAKeyFile: ca.keyPath,
		Identity: identity, OutCert: certPath, OutKey: keyPath, Days: days,
	}
}

func chainToCA(t *testing.T, certPath string, ca *x509.Certificate, identity string) *x509.Certificate {
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
	if len(leaf.URIs) != 1 || leaf.URIs[0].String() != identity {
		t.Fatalf("uri %v", leaf.URIs)
	}
	if len(leaf.DNSNames) != 0 || leaf.IsCA {
		t.Fatalf("dns %v ca %v", leaf.DNSNames, leaf.IsCA)
	}
	if len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		t.Fatalf("eku %v", leaf.ExtKeyUsage)
	}
	if leaf.KeyUsage&x509.KeyUsageCertSign != 0 {
		t.Fatal("leaf can sign certificates")
	}
	return leaf
}

func perm(t *testing.T, path string) os.FileMode {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return info.Mode().Perm()
}

func assertP256(t *testing.T, keyPath string) {
	t.Helper()
	raw, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(raw)
	if block == nil || block.Type != "PRIVATE KEY" {
		t.Fatal("key is not PKCS8")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	ec, ok := key.(*ecdsa.PrivateKey)
	if !ok || ec.Curve.Params().Name != "P-256" {
		t.Fatalf("key type %T", key)
	}
}

func TestIssuePublisherCertChainsToTheRequestedURI(t *testing.T) {
	ca := newTestCA(t)
	dir := t.TempDir()
	certPath := filepath.Join(dir, "publisher.crt")
	keyPath := filepath.Join(dir, "publisher.key")
	result, err := workloadtls.IssuePublisherCert(request(ca, certPath, keyPath, publisherID, 30))
	if err != nil {
		t.Fatal(err)
	}
	if result.Outcome != workloadtls.PublisherIssued || result.Identity != publisherID {
		t.Fatalf("%+v", result)
	}
	leaf := chainToCA(t, certPath, ca.cert, publisherID)
	if !leaf.NotAfter.Equal(result.NotAfter) {
		t.Fatalf("not after %s vs %s", leaf.NotAfter, result.NotAfter)
	}
	remaining := time.Until(leaf.NotAfter)
	if remaining < 30*24*time.Hour-time.Minute || remaining > 30*24*time.Hour {
		t.Fatalf("remaining %s", remaining)
	}
	if perm(t, certPath) != 0o644 || perm(t, keyPath) != 0o600 {
		t.Fatalf("modes %o %o", perm(t, certPath), perm(t, keyPath))
	}
	assertP256(t, keyPath)
	if id, err := workloadtls.CertificateIdentity(certPath); err != nil || id != publisherID {
		t.Fatalf("identity %q %v", id, err)
	}
	if _, err := os.Stat(certPath + ".previous"); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("previous certificate exists after issuance")
	}
}

func TestRotatePublisherCertKeepsThePreviousPair(t *testing.T) {
	ca := newTestCA(t)
	dir := t.TempDir()
	certPath := filepath.Join(dir, "publisher.crt")
	keyPath := filepath.Join(dir, "publisher.key")
	if _, err := workloadtls.IssuePublisherCert(request(ca, certPath, keyPath, publisherID, 30)); err != nil {
		t.Fatal(err)
	}
	first, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatal(err)
	}
	firstKey, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	result, err := workloadtls.IssuePublisherCert(request(ca, certPath, keyPath, publisherID, 30))
	if err != nil {
		t.Fatal(err)
	}
	if result.Outcome != workloadtls.PublisherRotated || result.Identity != publisherID {
		t.Fatalf("%+v", result)
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
		t.Fatal("rotation did not keep the previous leaf")
	}
	secondKey, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	previousKey, err := os.ReadFile(keyPath + ".previous")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(firstKey, secondKey) || !bytes.Equal(firstKey, previousKey) {
		t.Fatal("rotation did not keep the previous key")
	}
	chainToCA(t, certPath, ca.cert, publisherID)
	chainToCA(t, certPath+".previous", ca.cert, publisherID)
	if perm(t, keyPath) != 0o600 || perm(t, keyPath+".previous") != 0o600 {
		t.Fatalf("key modes %o %o", perm(t, keyPath), perm(t, keyPath+".previous"))
	}
	assertP256(t, keyPath)

	// 再轮换一次：上一对仍在，是刚换下去的那一对，没有被删掉。
	again, err := workloadtls.IssuePublisherCert(request(ca, certPath, keyPath, publisherID, 30))
	if err != nil || again.Outcome != workloadtls.PublisherRotated {
		t.Fatal(err, again.Outcome)
	}
	kept, err := os.ReadFile(certPath + ".previous")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(kept, second) {
		t.Fatal("the immediate previous leaf was deleted")
	}
	chainToCA(t, certPath, ca.cert, publisherID)
	chainToCA(t, certPath+".previous", ca.cert, publisherID)
	if perm(t, keyPath+".previous") != 0o600 {
		t.Fatalf("previous key mode %o", perm(t, keyPath+".previous"))
	}
}

func TestIssuePublisherCertRefusesANonCA(t *testing.T) {
	certPath, keyPath := selfSignedNonCA(t)
	dir := t.TempDir()
	outCert := filepath.Join(dir, "publisher.crt")
	outKey := filepath.Join(dir, "publisher.key")
	_, err := workloadtls.IssuePublisherCert(workloadtls.PublisherCertRequest{
		CACertFile: certPath, CAKeyFile: keyPath,
		Identity: publisherID, OutCert: outCert, OutKey: outKey, Days: 30,
	})
	if err == nil {
		t.Fatal("non-CA was accepted")
	}
	if entries, readErr := os.ReadDir(dir); readErr != nil || len(entries) != 0 {
		t.Fatalf("output directory: %v %v", entries, readErr)
	}
}

func TestIssuePublisherCertRefusesNonSPIFFEIdentity(t *testing.T) {
	ca := newTestCA(t)
	for _, identity := range []string{"publisher.idp.test", "https://idp.test/gateway-control/publisher", "SPIFFE://idp.test/publisher"} {
		dir := t.TempDir()
		outCert := filepath.Join(dir, "publisher.crt")
		outKey := filepath.Join(dir, "publisher.key")
		_, err := workloadtls.IssuePublisherCert(request(ca, outCert, outKey, identity, 30))
		if err == nil {
			t.Fatalf("%s was accepted", identity)
		}
		if entries, readErr := os.ReadDir(dir); readErr != nil || len(entries) != 0 {
			t.Fatalf("%s created %v %v", identity, entries, readErr)
		}
	}
}

func TestIssuePublisherCertRefusesMismatchedKeyDaysAndEnvRefs(t *testing.T) {
	ca := newTestCA(t)
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherDER, err := x509.MarshalPKCS8PrivateKey(other)
	if err != nil {
		t.Fatal(err)
	}
	otherKey := filepath.Join(t.TempDir(), "other.key")
	writePEM(t, otherKey, "PRIVATE KEY", otherDER)

	dir := t.TempDir()
	outCert := filepath.Join(dir, "publisher.crt")
	outKey := filepath.Join(dir, "publisher.key")
	req := request(ca, outCert, outKey, publisherID, 30)
	req.CAKeyFile = otherKey
	if _, err := workloadtls.IssuePublisherCert(req); err == nil {
		t.Fatal("mismatched key was accepted")
	}

	for _, days := range []int{0, -1, 826} {
		if _, err := workloadtls.IssuePublisherCert(request(ca, outCert, outKey, publisherID, days)); err == nil {
			t.Fatalf("days %d was accepted", days)
		}
	}
	envCert := filepath.Join(dir, "${HOME}.crt")
	envKey := filepath.Join(dir, "$KEY.key")
	if _, err := workloadtls.IssuePublisherCert(request(ca, envCert, envKey, publisherID, 30)); err == nil {
		t.Fatal("environment reference was accepted")
	}
	if _, err := os.Stat(envCert); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("env cert path was created")
	}
	if _, err := os.Stat(envKey); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("env key path was created")
	}
	if _, err := os.Stat(outCert); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("output was created after refusals")
	}

	if _, err := workloadtls.IssuePublisherCert(request(ca, outCert, outKey, publisherID, 1)); err != nil {
		t.Fatal(err)
	}
	leaf := chainToCA(t, outCert, ca.cert, publisherID)
	remaining := time.Until(leaf.NotAfter)
	if remaining < 24*time.Hour-time.Minute || remaining > 24*time.Hour {
		t.Fatalf("one day remaining %s", remaining)
	}
	if _, err := workloadtls.IssuePublisherCert(request(ca, outCert, outKey, publisherID, 825)); err != nil {
		t.Fatal(err)
	}
	leaf = chainToCA(t, outCert, ca.cert, publisherID)
	remaining = time.Until(leaf.NotAfter)
	if remaining < 825*24*time.Hour-time.Minute || remaining > 825*24*time.Hour {
		t.Fatalf("825 days remaining %s", remaining)
	}
}

func TestIssuePublisherCertRefusesAPartialPair(t *testing.T) {
	ca := newTestCA(t)
	dir := t.TempDir()
	certPath := filepath.Join(dir, "publisher.crt")
	keyPath := filepath.Join(dir, "publisher.key")
	if err := os.WriteFile(certPath, []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := workloadtls.IssuePublisherCert(request(ca, certPath, keyPath, publisherID, 30))
	if err == nil {
		t.Fatal("partial pair was accepted")
	}
	got, err := os.ReadFile(certPath)
	if err != nil || string(got) != "keep" {
		t.Fatalf("certificate changed: %q %v", got, err)
	}
	if _, err := os.Stat(keyPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("key was created")
	}
}
