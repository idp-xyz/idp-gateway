// Package tlstest 给测试签发一次性的 CA 与工作负载证书。只供 *_test.go 使用，
// 产品代码不得导入（internal/architecture 有测试守着）。
package tlstest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// CA 是一个测试用的签发者。
type CA struct {
	t    *testing.T
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	dir  string
	n    int64
}

// NewCA 生成一个自签 CA，文件写在测试的临时目录里。
func NewCA(t *testing.T, commonName string) *CA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: commonName},
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
	ca := &CA{t: t, cert: cert, key: key, dir: t.TempDir(), n: 1}
	ca.write("ca.crt", "CERTIFICATE", der)
	return ca
}

// File 返回 CA 证书文件的路径。
func (ca *CA) File() string { return filepath.Join(ca.dir, "ca.crt") }

// Pool 返回只含这个 CA 的证书池。
func (ca *CA) Pool() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(ca.cert)
	return pool
}

// Leaf 是一张叶子证书及其文件。
type Leaf struct {
	CertFile, KeyFile string
	Certificate       tls.Certificate
	X509              *x509.Certificate
}

// Issue 签发一张叶子证书。identities 写入 subjectAltName 的 URI；dnsNames 非空时
// 是服务端证书，否则是客户端证书。
func (ca *CA) Issue(name string, identities []string, dnsNames ...string) Leaf {
	ca.t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		ca.t.Fatal(err)
	}
	ca.n++
	usage := x509.ExtKeyUsageClientAuth
	if len(dnsNames) > 0 {
		usage = x509.ExtKeyUsageServerAuth
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(ca.n),
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{usage},
		DNSNames:     dnsNames,
	}
	for _, identity := range identities {
		uri, err := url.Parse(identity)
		if err != nil {
			ca.t.Fatal(err)
		}
		template.URIs = append(template.URIs, uri)
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		ca.t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		ca.t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		ca.t.Fatal(err)
	}
	leaf := Leaf{
		CertFile:    ca.write(name+".crt", "CERTIFICATE", der),
		KeyFile:     ca.write(name+".key", "PRIVATE KEY", keyDER),
		Certificate: tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key},
		X509:        parsed,
	}
	return leaf
}

func (ca *CA) write(name, blockType string, der []byte) string {
	ca.t.Helper()
	path := filepath.Join(ca.dir, name)
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der}), 0o600); err != nil {
		ca.t.Fatal(err)
	}
	return path
}

// ClientConfig 构造一个信任 ca、为 serverName 验证服务端证书的客户端配置；
// leaf 为 nil 时不出示客户端证书。
func ClientConfig(ca *CA, serverName string, leaf *Leaf) *tls.Config {
	config := &tls.Config{RootCAs: ca.Pool(), ServerName: serverName, MinVersion: tls.VersionTLS12}
	if leaf != nil {
		config.Certificates = []tls.Certificate{leaf.Certificate}
	}
	return config
}

// PeerState 伪造一个握手已完成、对端出示了 leaf 的连接状态，供不走网络的处理器测试使用。
func PeerState(leaf Leaf) *tls.ConnectionState {
	return &tls.ConnectionState{
		Version:           tls.VersionTLS13,
		HandshakeComplete: true,
		PeerCertificates:  []*x509.Certificate{leaf.X509},
		VerifiedChains:    [][]*x509.Certificate{{leaf.X509}},
	}
}
