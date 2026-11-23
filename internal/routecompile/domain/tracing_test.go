package domain

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
	"math"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

func TestTracingRefusals(t *testing.T) {
	bad := 1.5
	nan := math.NaN()
	cases := []struct {
		name string
		spec *TracingSpec
		env  string
	}{
		{"other ip", &TracingSpec{Host: "10.0.0.1:4318", ServiceName: "idp-egress-gateway"}, "TEST"},
		{"prod loopback", &TracingSpec{Host: "127.0.0.1:4318", ServiceName: "idp-egress-gateway"}, "PROD"},
		{"scheme", &TracingSpec{Host: "http://otel:4318", ServiceName: "idp-egress-gateway"}, "TEST"},
		{"bad protocol", &TracingSpec{Host: "otel-collector:4318", Protocol: "tcp", ServiceName: "idp-egress-gateway"}, "TEST"},
		{"grpc path", &TracingSpec{Host: "otel-collector:4318", Protocol: "grpc", Path: "/v1/traces", ServiceName: "idp-egress-gateway"}, "TEST"},
		{"path query", &TracingSpec{Host: "otel-collector:4318", Path: "/v1/traces?x=1", ServiceName: "idp-egress-gateway"}, "TEST"},
		{"service name", &TracingSpec{Host: "otel-collector:4318", ServiceName: "Bad"}, "TEST"},
		{"sampling", &TracingSpec{Host: "otel-collector:4318", ServiceName: "idp-egress-gateway", RandomSampling: &bad}, "TEST"},
		{"nan", &TracingSpec{Host: "otel-collector:4318", ServiceName: "idp-egress-gateway", ClientSampling: &nan}, "TEST"},
		{"port", &TracingSpec{Host: "otel-collector:70000", ServiceName: "idp-egress-gateway"}, "TEST"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			issues := tracingIssues(c.spec, c.env)
			if len(issues) == 0 || issues[0].Code != "TRACING" {
				t.Fatalf("issues %+v", issues)
			}
		})
	}
	quarter := 0.25
	ok := &TracingSpec{Host: "otel.idp.internal:4318", ServiceName: "idp-egress-gateway", RandomSampling: &quarter}
	if issues := tracingIssues(ok, "PROD"); len(issues) != 0 {
		t.Fatalf("valid prod dns: %+v", issues)
	}
	loop := &TracingSpec{Host: "127.0.0.1:4318", ServiceName: "idp-egress-gateway"}
	if issues := tracingIssues(loop, "TEST"); len(issues) != 0 {
		t.Fatalf("dev loopback: %+v", issues)
	}
}

func TestTracingOmittedStaysOutOfTheDocument(t *testing.T) {
	art, err := Compile(wanbSpec())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(art.GatewayYAML), "tracing:") {
		t.Fatal("nil tracing was emitted")
	}
	ingress, err := CompileIngress(loadIngressExample(t))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(ingress.GatewayYAML), "tracing:") {
		t.Fatal("ingress nil tracing was emitted")
	}
	ai, err := CompileAI(loadAIExample(t))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(ai.GatewayYAML), "tracing:") {
		t.Fatal("ai nil tracing was emitted")
	}
}

func TestTracingEmissionAndNativeValidation(t *testing.T) {
	quarter := 0.25
	tracing := &TracingSpec{Host: "otel-collector:4318", ServiceName: "idp-egress-gateway", RandomSampling: &quarter}
	spec := wanbSpec()
	plain, err := Compile(spec)
	if err != nil {
		t.Fatal(err)
	}
	spec.Pool.Tracing = tracing
	art, err := Compile(spec)
	if err != nil {
		t.Fatal(err)
	}
	if art.PolicySHA256 != plain.PolicySHA256 {
		t.Fatal("tracing changed the policy document")
	}
	block := tracingBlock(string(art.GatewayYAML))
	for _, needle := range []string{
		"host: 'otel-collector:4318'",
		"protocol: 'http'",
		"path: '/v1/traces'",
		"randomSampling: 0.25",
		"clientSampling: 1.0",
		`service.name: '"idp-egress-gateway"'`,
		"authz_decision_id:",
		"tenant_ref: 'jwt.tenant_id'",
	} {
		if !strings.Contains(block, needle) {
			t.Fatalf("egress tracing missing %s:\n%s", needle, block)
		}
	}
	validateLockedGateway(t, art.GatewayYAML)

	ingressSpec := loadIngressExample(t)
	ingressSpec.Pool.Tracing = &TracingSpec{Host: "otel-collector:4318", Protocol: "http", ServiceName: "idp-ingress-gateway"}
	ingress, err := CompileIngress(ingressSpec)
	if err != nil {
		t.Fatal(err)
	}
	ingressBlock := tracingBlock(string(ingress.GatewayYAML))
	if strings.Contains(ingressBlock, "authz_decision_id") || !strings.Contains(ingressBlock, "tenant_ref: 'jwt.tenant_id'") {
		t.Fatalf("ingress tracing:\n%s", ingressBlock)
	}
	validateLockedGateway(t, ingress.GatewayYAML)

	aiSpec := loadAIExample(t)
	aiSpec.Pool.Tracing = &TracingSpec{Host: "otel-collector:4317", Protocol: "grpc", ServiceName: "idp-ai-gateway"}
	ai, err := CompileAI(aiSpec)
	if err != nil {
		t.Fatal(err)
	}
	aiBlock := tracingBlock(string(ai.GatewayYAML))
	if strings.Contains(aiBlock, "path:") || !strings.Contains(aiBlock, "protocol: 'grpc'") || strings.Contains(aiBlock, "authz_decision_id") {
		t.Fatalf("ai tracing:\n%s", aiBlock)
	}
	validateLockedGateway(t, ai.GatewayYAML)
}

func tracingBlock(yaml string) string {
	const marker = "\n  tracing:\n"
	i := strings.Index(yaml, marker)
	if i < 0 {
		return ""
	}
	rest := yaml[i+1:]
	lines := strings.Split(rest, "\n")
	var b strings.Builder
	for n, line := range lines {
		if n > 0 && line != "" && !strings.HasPrefix(line, "    ") {
			break
		}
		b.WriteString(line)
		b.WriteByte('\n')
	}
	return b.String()
}

func validateLockedGateway(t *testing.T, yaml []byte) {
	t.Helper()
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(home, ".local", "opt", "agentgateway", "1.7.0", "agentgateway")
	if _, err := os.Stat(binary); err != nil {
		t.Skip("pinned agentgateway 1.7.0 is not installed")
	}
	root := repoRoot(t)
	lockPath := filepath.Join(root, "deploy", "agentgateway", "agentgateway.lock.json")
	if err := pinnedBinary(binary, lockPath); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), yaml, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := materializeTracingFixture(dir, yaml); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, "--validate-only", "-f", "config.yaml")
	cmd.Dir = dir
	cmd.Env = withoutProxy(os.Environ())
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("validate-only: %v\n%s", err, out)
	}
}

func pinnedBinary(binary, lockPath string) error {
	raw, err := os.ReadFile(lockPath)
	if err != nil {
		return err
	}
	var lock struct {
		SHA256 map[string]string `json:"sha256"`
	}
	if err := json.Unmarshal(raw, &lock); err != nil {
		return err
	}
	sum, err := fileSHA(binary)
	if err != nil {
		return err
	}
	for _, want := range lock.SHA256 {
		if strings.EqualFold(strings.TrimSpace(want), sum) {
			return nil
		}
	}
	return os.ErrInvalid
}

func fileSHA(path string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

func withoutProxy(env []string) []string {
	out := make([]string, 0, len(env))
	for _, item := range env {
		name, _, _ := strings.Cut(item, "=")
		switch strings.ToLower(name) {
		case "http_proxy", "https_proxy", "all_proxy", "no_proxy":
			continue
		default:
			out = append(out, item)
		}
	}
	return out
}

var (
	tracingResource = regexp.MustCompile(`(?m)^[ \t]*(cert|key|root|file):[ \t]*(?:'([^']*)'|([^ \t#]+))`)
	tracingHostname = regexp.MustCompile(`(?m)^[ \t]*hostname:[ \t]*(?:'([^']*)'|([^ \t#]+))`)
)

func materializeTracingFixture(dir string, yaml []byte) error {
	text := string(yaml)
	hosts := []string{"gateway.idp.test"}
	seen := map[string]struct{}{"gateway.idp.test": {}}
	for _, match := range tracingHostname.FindAllStringSubmatch(text, -1) {
		host := match[1]
		if host == "" {
			host = match[2]
		}
		if host == "" {
			continue
		}
		if _, ok := seen[host]; ok {
			continue
		}
		seen[host] = struct{}{}
		hosts = append(hosts, host)
	}
	caPEM, certPEM, keyPEM, jwks, err := mintTracingCerts(hosts)
	if err != nil {
		return err
	}
	written := map[string]struct{}{}
	for _, match := range tracingResource.FindAllStringSubmatch(text, -1) {
		path := match[2]
		if path == "" {
			path = match[3]
		}
		if _, ok := written[path]; ok {
			continue
		}
		written[path] = struct{}{}
		var body []byte
		switch {
		case match[1] == "file" || strings.HasSuffix(path, ".json"):
			body = jwks
		case match[1] == "root":
			body = caPEM
		case match[1] == "key":
			body = keyPEM
		default:
			body = certPEM
		}
		dest := filepath.Join(dir, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(dest, body, 0o644); err != nil {
			return err
		}
	}
	return nil
}

func mintTracingCerts(hosts []string) (caPEM, certPEM, keyPEM, jwks []byte, err error) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, nil, nil, err
	}
	caTpl := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: "routecompile-ca"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTpl, caTpl, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	leafSerial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, nil, nil, err
	}
	leafTpl := &x509.Certificate{
		SerialNumber: leafSerial, Subject: pkix.Name{CommonName: hosts[0]},
		NotBefore: caTpl.NotBefore, NotAfter: caTpl.NotAfter, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames: hosts,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTpl, caTpl, &leafKey.PublicKey, caKey)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(leafKey)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	jwks, err = json.Marshal(map[string]any{"keys": []any{map[string]any{
		"kty": "RSA", "kid": "routecompile", "use": "sig", "alg": "RS256",
		"n": base64.RawURLEncoding.EncodeToString(rsaKey.N.Bytes()),
		"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(rsaKey.E)).Bytes()),
	}}})
	if err != nil {
		return nil, nil, nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
		jwks, nil
}
