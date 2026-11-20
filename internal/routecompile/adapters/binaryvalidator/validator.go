// Package binaryvalidator 用锁定的 agentgateway 二进制做 --validate-only。
// 它不启动监听，校验失败时由调用方决定不写文件。
package binaryvalidator

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"go.idp.xyz/idp-gateway/internal/routecompile/ports"
)

// Validator 调用本机的 agentgateway。LockFile 非空时先核对二进制的 SHA-256。
type Validator struct {
	Binary   string
	LockFile string
}

var (
	resourceLine = regexp.MustCompile(`(?m)^[ \t]*(cert|key|root|file):[ \t]*(?:'([^']*)'|([^ \t#]+))`)
	hostnameLine = regexp.MustCompile(`(?m)^[ \t]*hostname:[ \t]*(?:'([^']*)'|([^ \t#]+))`)
)

// Validate 在临时目录里准备配置引用的证书和 JWKS，然后只跑 --validate-only。
func (v Validator) Validate(ctx context.Context, yamlBytes []byte, tlsDir string, jwksFile string) error {
	if v.Binary == "" {
		return errors.New("agentgateway binary path is empty")
	}
	if v.LockFile != "" {
		if err := checkLock(v.Binary, v.LockFile); err != nil {
			return err
		}
	}
	dir, err := os.MkdirTemp("", "routecompile-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), yamlBytes, 0o644); err != nil {
		return err
	}
	if err := materialize(dir, yamlBytes, tlsDir, jwksFile); err != nil {
		return err
	}
	cmd := exec.CommandContext(ctx, v.Binary, "--validate-only", "-f", "config.yaml")
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			msg := strings.TrimSpace(string(out))
			if msg == "" {
				msg = exitErr.Error()
			}
			return fmt.Errorf("%w: %s", ports.ErrRefused, msg)
		}
		return fmt.Errorf("agentgateway: %w", err)
	}
	return nil
}

func checkLock(binary, lockPath string) error {
	data, err := os.ReadFile(lockPath)
	if err != nil {
		return err
	}
	var lock struct {
		SHA256 map[string]string `json:"sha256"`
	}
	if err := json.Unmarshal(data, &lock); err != nil {
		return fmt.Errorf("lock file: %w", err)
	}
	if len(lock.SHA256) == 0 {
		return fmt.Errorf("%w: lock file has no sha256 entries", ports.ErrRefused)
	}
	got, err := fileSHA256(binary)
	if err != nil {
		return err
	}
	for _, want := range lock.SHA256 {
		if strings.EqualFold(strings.TrimSpace(want), got) {
			return nil
		}
	}
	return fmt.Errorf("%w: agentgateway sha256 %s does not match %s", ports.ErrRefused, got, lockPath)
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	sum := sha256.New()
	if _, err := io.Copy(sum, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(sum.Sum(nil)), nil
}

type resource struct {
	kind string
	path string
}

func materialize(dir string, yamlBytes []byte, tlsDir, jwksFile string) error {
	text := string(yamlBytes)
	var refs []resource
	for _, match := range resourceLine.FindAllStringSubmatch(text, -1) {
		path := match[2]
		if path == "" {
			path = match[3]
		}
		refs = append(refs, resource{kind: match[1], path: path})
	}
	if len(refs) == 0 {
		return nil
	}
	hosts := []string{"gateway.idp.test"}
	seenHost := map[string]struct{}{"gateway.idp.test": {}}
	for _, match := range hostnameLine.FindAllStringSubmatch(text, -1) {
		host := match[1]
		if host == "" {
			host = match[2]
		}
		if _, ok := seenHost[host]; ok || host == "" {
			continue
		}
		seenHost[host] = struct{}{}
		hosts = append(hosts, host)
	}
	caPEM, certPEM, keyPEM, jwks, err := mint(hosts)
	if err != nil {
		return err
	}
	written := map[string]struct{}{}
	for _, ref := range refs {
		if _, ok := written[ref.path]; ok {
			continue
		}
		written[ref.path] = struct{}{}
		var body []byte
		switch {
		case ref.kind == "file" || strings.HasSuffix(ref.path, ".json"):
			body = jwks
		case ref.kind == "root":
			body = caPEM
		case ref.kind == "key":
			body = keyPEM
		default:
			body = certPEM
		}
		dest := filepath.Join(dir, filepath.FromSlash(ref.path))
		if err := putFile(dest, findExternal(ref.path, tlsDir, jwksFile), body); err != nil {
			return err
		}
	}
	return nil
}

func findExternal(rel, tlsDir, jwksFile string) string {
	if jwksFile != "" && strings.HasSuffix(rel, ".json") {
		if st, err := os.Stat(jwksFile); err == nil && !st.IsDir() {
			return jwksFile
		}
	}
	if tlsDir == "" {
		return ""
	}
	for _, candidate := range []string{filepath.Join(tlsDir, filepath.FromSlash(rel)), filepath.Join(tlsDir, filepath.Base(rel))} {
		if st, err := os.Stat(candidate); err == nil && !st.IsDir() {
			return candidate
		}
	}
	return ""
}

func putFile(dest, external string, generated []byte) error {
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return err
	}
	if external != "" {
		abs, err := filepath.Abs(external)
		if err != nil {
			return err
		}
		if err := os.Symlink(abs, dest); err == nil {
			return nil
		}
		data, err := os.ReadFile(external)
		if err != nil {
			return err
		}
		generated = data
	}
	return os.WriteFile(dest, generated, 0o644)
}

func mint(hosts []string) (caPEM, certPEM, keyPEM, jwks []byte, err error) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	caTpl := &x509.Certificate{
		SerialNumber:          serial(),
		Subject:               pkix.Name{CommonName: "routecompile-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTpl, caTpl, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	leafTpl := &x509.Certificate{
		SerialNumber:          serial(),
		Subject:               pkix.Name{CommonName: hosts[0]},
		NotBefore:             caTpl.NotBefore,
		NotAfter:              caTpl.NotAfter,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		DNSNames:              hosts,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTpl, caTpl, &leafKey.PublicKey, caKey)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	caPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})
	keyDER, err := x509.MarshalPKCS8PrivateKey(leafKey)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	jwks, err = json.Marshal(map[string]any{
		"keys": []any{map[string]any{
			"kty": "RSA", "kid": "routecompile", "use": "sig", "alg": "RS256",
			"n": base64.RawURLEncoding.EncodeToString(rsaKey.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(rsaKey.E)).Bytes()),
		}},
	})
	return caPEM, certPEM, keyPEM, jwks, err
}

func serial() *big.Int {
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return big.NewInt(1)
	}
	return n
}
