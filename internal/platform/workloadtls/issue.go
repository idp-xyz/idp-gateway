package workloadtls

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"time"
)

const (
	// PublisherIssued 是两个输出路径原先都不存在、这一次新建的。
	PublisherIssued = "ISSUED"
	// PublisherRotated 是两个输出路径原先都在，这一次换成了新叶子。
	PublisherRotated = "ROTATED"

	publisherCertMinDays = 1
	publisherCertMaxDays = 825
)

// PublisherCertRequest 是签发或轮换发布器叶子的参数。叶子是 gateway-control 出示给
// 网关回读口的客户端证书。CA 是网关已经信任的那一张，所以换叶子不用改网关配置。
type PublisherCertRequest struct {
	CACertFile string
	CAKeyFile  string
	Identity   string
	OutCert    string
	OutKey     string
	Days       int
}

// PublisherCertResult 是写成之后的结局。NotAfter 是叶子证书里的到期时间。
type PublisherCertResult struct {
	Outcome  string
	Identity string
	NotAfter time.Time
}

// IssuePublisherCert 签发或轮换发布器的叶子，把文件写到磁盘上。
// 正在跑的进程仍然只在启动时读一次证书，这里不重载 TLS；下一次进程读新文件。
//
// 两个输出路径都不存在时是签发：证书 0644，私钥 0600。
// 两个都存在时是轮换：新的一对先写到同目录的临时文件，确认新叶子能由这张 CA 验证、
// 并且只有请求的那一个 URI 之后，才把原来的一对留成 <路径>.previous（私钥 0600），
// 再把新的一对改名换上去。不删除 .previous，以便人手放回去。
//
// 身份不是单个 spiffe:// URI、天数不在 1 到 825、CA 私钥与证书不配对、CA 证书不是 CA、
// 输出路径里有环境变量引用（${ 或 $NAME），或两个输出只存在一个时，拒绝，不写输出文件。
func IssuePublisherCert(req PublisherCertRequest) (PublisherCertResult, error) {
	if err := refuseEnvPath(req.OutCert); err != nil {
		return PublisherCertResult{}, err
	}
	if err := refuseEnvPath(req.OutKey); err != nil {
		return PublisherCertResult{}, err
	}
	if req.CACertFile == "" || req.CAKeyFile == "" || req.OutCert == "" || req.OutKey == "" {
		return PublisherCertResult{}, errors.New("publisher certificate: path is required")
	}
	if req.OutCert == req.OutKey || req.OutCert+".previous" == req.OutKey || req.OutKey+".previous" == req.OutCert {
		return PublisherCertResult{}, errors.New("output path: certificate and key must be different files")
	}
	if req.Days < publisherCertMinDays || req.Days > publisherCertMaxDays {
		return PublisherCertResult{}, errors.New("days: must be from 1 to 825")
	}
	uri, err := parseSPIFFE(req.Identity)
	if err != nil {
		return PublisherCertResult{}, err
	}
	caCert, caKey, err := loadCA(req.CACertFile, req.CAKeyFile)
	if err != nil {
		return PublisherCertResult{}, err
	}
	rotate, err := outputState(req.OutCert, req.OutKey)
	if err != nil {
		return PublisherCertResult{}, err
	}
	certPEM, keyPEM, err := mint(caCert, caKey, uri, req.Days)
	if err != nil {
		return PublisherCertResult{}, err
	}
	tmpCert, err := writeTemp(filepath.Dir(req.OutCert), certPEM, 0o644)
	if err != nil {
		return PublisherCertResult{}, err
	}
	defer os.Remove(tmpCert)
	tmpKey, err := writeTemp(filepath.Dir(req.OutKey), keyPEM, 0o600)
	if err != nil {
		return PublisherCertResult{}, err
	}
	defer os.Remove(tmpKey)
	leaf, err := verifyIssued(tmpCert, tmpKey, caCert, req.Identity)
	if err != nil {
		return PublisherCertResult{}, err
	}
	if err := install(req.OutCert, req.OutKey, tmpCert, tmpKey, rotate); err != nil {
		return PublisherCertResult{}, err
	}
	outcome := PublisherIssued
	if rotate {
		outcome = PublisherRotated
	}
	return PublisherCertResult{Outcome: outcome, Identity: req.Identity, NotAfter: leaf.NotAfter.UTC()}, nil
}

func refuseEnvPath(path string) error {
	if containsEnvRef(path) {
		return errors.New("output path: contains an environment variable reference")
	}
	return nil
}

// containsEnvRef 报告路径里有没有 ${ 或 $NAME。$$ 本身不是引用。
func containsEnvRef(path string) bool {
	for i := 0; i < len(path); i++ {
		if path[i] != '$' || i+1 >= len(path) {
			continue
		}
		next := path[i+1]
		if next == '{' || next == '_' || (next >= 'A' && next <= 'Z') || (next >= 'a' && next <= 'z') {
			return true
		}
	}
	return false
}

func parseSPIFFE(identity string) (*url.URL, error) {
	const refused = "identity: must be a single spiffe:// URI"
	u, err := url.Parse(identity)
	if err != nil || u.Scheme != "spiffe" || u.Host == "" || u.Opaque != "" || u.User != nil ||
		u.Port() != "" || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New(refused)
	}
	if !hasWorkloadPath(u.Path) || u.String() != identity {
		return nil, errors.New(refused)
	}
	return u, nil
}

func hasWorkloadPath(path string) bool {
	if len(path) < 2 || path[0] != '/' || path[len(path)-1] == '/' {
		return false
	}
	for i := 0; i < len(path)-1; i++ {
		if path[i] == '/' && path[i+1] == '/' {
			return false
		}
	}
	return true
}

func loadCA(certFile, keyFile string) (*x509.Certificate, crypto.Signer, error) {
	cert, err := readCert(certFile)
	if err != nil {
		return nil, nil, err
	}
	if !cert.IsCA {
		return nil, nil, errors.New("ca certificate: not a CA")
	}
	key, err := readSigner(keyFile)
	if err != nil {
		return nil, nil, err
	}
	if !publicKeyMatches(cert.PublicKey, key.Public()) {
		return nil, nil, errors.New("ca key: does not match the certificate")
	}
	return cert, key, nil
}

func readCert(path string) (*x509.Certificate, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("ca certificate: %w", err)
	}
	rest := raw
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return nil, errors.New("ca certificate: no certificate found in " + path)
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("ca certificate: %w", err)
		}
		return cert, nil
	}
}

func readSigner(path string) (crypto.Signer, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("ca key: %w", err)
	}
	rest := raw
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return nil, errors.New("ca key: no private key found in " + path)
		}
		key, err := parseKeyBlock(block)
		if err != nil {
			return nil, err
		}
		if key == nil {
			continue
		}
		signer, ok := key.(crypto.Signer)
		if !ok {
			return nil, errors.New("ca key: cannot sign")
		}
		return signer, nil
	}
}

func parseKeyBlock(block *pem.Block) (any, error) {
	switch block.Type {
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("ca key: %w", err)
		}
		return key, nil
	case "EC PRIVATE KEY":
		key, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("ca key: %w", err)
		}
		return key, nil
	case "RSA PRIVATE KEY":
		key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("ca key: %w", err)
		}
		return key, nil
	default:
		return nil, nil
	}
}

func publicKeyMatches(certPub, keyPub crypto.PublicKey) bool {
	eq, ok := certPub.(interface{ Equal(crypto.PublicKey) bool })
	return ok && eq.Equal(keyPub)
}

func mint(ca *x509.Certificate, signer crypto.Signer, uri *url.URL, days int) (certPEM, keyPEM []byte, err error) {
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("publisher certificate: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, fmt.Errorf("publisher certificate: %w", err)
	}
	if serial.Sign() == 0 {
		serial = big.NewInt(1)
	}
	now := time.Now().UTC().Truncate(time.Second)
	template := &x509.Certificate{
		SerialNumber:          serial,
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(time.Duration(days) * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		URIs:                  []*url.URL{uri},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca, &leafKey.PublicKey, signer)
	if err != nil {
		return nil, nil, fmt.Errorf("publisher certificate: %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(leafKey)
	if err != nil {
		return nil, nil, fmt.Errorf("publisher certificate: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), nil
}

func verifyIssued(certFile, keyFile string, ca *x509.Certificate, identity string) (*x509.Certificate, error) {
	pair, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("publisher certificate: %w", err)
	}
	if len(pair.Certificate) != 1 {
		return nil, errors.New("publisher certificate: expected one certificate")
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("publisher certificate: %w", err)
	}
	if leaf.IsCA || leaf.KeyUsage&x509.KeyUsageCertSign != 0 ||
		len(leaf.DNSNames) != 0 || len(leaf.EmailAddresses) != 0 || len(leaf.IPAddresses) != 0 ||
		len(leaf.URIs) != 1 || leaf.URIs[0].String() != identity {
		return nil, errors.New("publisher certificate: leaf constraints do not match")
	}
	clientAuth := false
	for _, usage := range leaf.ExtKeyUsage {
		if usage != x509.ExtKeyUsageClientAuth {
			return nil, errors.New("publisher certificate: leaf constraints do not match")
		}
		clientAuth = true
	}
	if !clientAuth {
		return nil, errors.New("publisher certificate: leaf constraints do not match")
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		return nil, fmt.Errorf("publisher certificate: %w", err)
	}
	return leaf, nil
}

func outputState(certPath, keyPath string) (rotate bool, err error) {
	certExists, err := regularFile(certPath)
	if err != nil {
		return false, err
	}
	keyExists, err := regularFile(keyPath)
	if err != nil {
		return false, err
	}
	if certExists != keyExists {
		return false, errors.New("output path: certificate and key must both exist or both be absent")
	}
	return certExists, nil
}

func regularFile(path string) (bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("publisher certificate: %w", err)
	}
	if !info.Mode().IsRegular() {
		return false, errors.New("output path: not a regular file")
	}
	return true, nil
}

func install(outCert, outKey, tmpCert, tmpKey string, rotate bool) error {
	if rotate {
		// 先留住原来的一对，再改名换上新的。失败时把证书从 .previous 抄回去，私钥还在原处。
		if err := copyRegular(outCert, outCert+".previous", 0o644); err != nil {
			return err
		}
		if err := copyRegular(outKey, outKey+".previous", 0o600); err != nil {
			return err
		}
	}
	if err := place(tmpCert, outCert, 0o644); err != nil {
		return err
	}
	if err := place(tmpKey, outKey, 0o600); err != nil {
		if rotate {
			if back := copyRegular(outCert+".previous", outCert, 0o644); back != nil {
				return fmt.Errorf("%w (restore certificate: %v)", err, back)
			}
			return err
		}
		_ = os.Remove(outCert)
		return err
	}
	return nil
}

func place(tmp, dst string, mode os.FileMode) error {
	if err := os.Chmod(tmp, mode); err != nil {
		return fmt.Errorf("publisher certificate: %w", err)
	}
	if err := os.Rename(tmp, dst); err != nil {
		return fmt.Errorf("publisher certificate: %w", err)
	}
	return nil
}

func copyRegular(src, dst string, mode os.FileMode) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return fmt.Errorf("publisher certificate: %w", err)
	}
	tmp, err := writeTemp(filepath.Dir(dst), data, mode)
	if err != nil {
		return err
	}
	if err := os.Rename(tmp, dst); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("publisher certificate: %w", err)
	}
	if err := os.Chmod(dst, mode); err != nil {
		return fmt.Errorf("publisher certificate: %w", err)
	}
	return nil
}

func writeTemp(dir string, data []byte, mode os.FileMode) (path string, err error) {
	file, err := os.CreateTemp(dir, ".publisher-*")
	if err != nil {
		return "", fmt.Errorf("publisher certificate: %w", err)
	}
	name := file.Name()
	ok := false
	defer func() {
		if !ok {
			_ = file.Close()
			_ = os.Remove(name)
		}
	}()
	if _, err := file.Write(data); err != nil {
		return "", fmt.Errorf("publisher certificate: %w", err)
	}
	if err := file.Chmod(mode); err != nil {
		return "", fmt.Errorf("publisher certificate: %w", err)
	}
	if err := file.Sync(); err != nil {
		return "", fmt.Errorf("publisher certificate: %w", err)
	}
	if err := file.Close(); err != nil {
		return "", fmt.Errorf("publisher certificate: %w", err)
	}
	ok = true
	return name, nil
}
