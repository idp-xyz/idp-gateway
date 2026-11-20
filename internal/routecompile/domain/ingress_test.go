package domain

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCompileIngressExample(t *testing.T) {
	spec := loadIngressExample(t)
	art, err := CompileIngress(spec)
	if err != nil {
		t.Fatal(err)
	}
	if art.RouteCount != 2 {
		t.Fatalf("routes %d", art.RouteCount)
	}
	text := string(art.GatewayYAML)
	for _, name := range []string{"public-shipments-get-get", "public-shipments-get-head"} {
		if !strings.Contains(text, "name: '"+name+"'") {
			t.Fatalf("missing route %s\n%s", name, text)
		}
	}
	if strings.Count(text, "- name: ") != 2 {
		t.Fatalf("route name count\n%s", text)
	}
	for _, needle := range []string{
		"api.cargopai.example",
		"https://issuer.example/ingress",
		"example-ingress",
		"shipment-api.example:443",
		"jwtAuth:",
		"backendTLS:",
		"method: 'GET'",
		"method: 'HEAD'",
		`request.path == "/v1/shipments"`,
		"mode: 'readOnly'",
		"tenant_ref: 'jwt.tenant_id'",
		`k in ["accept", "content-type", "traceparent"]`,
	} {
		if !strings.Contains(text, needle) {
			t.Fatalf("missing %s\n%s", needle, text)
		}
	}
	lower := strings.ToLower(text)
	for _, banned := range []string{"extauthz", "hc-owedeveloper", "credential_binding"} {
		if strings.Contains(lower, banned) {
			t.Fatalf("yaml contains %s\n%s", banned, text)
		}
	}
	if strings.Contains(text, `"authorization"`) {
		t.Fatal("authorization is forwarded")
	}
	if strings.Contains(text, "prefix:") {
		t.Fatalf("path rewrite leaked\n%s", text)
	}
	var policy struct {
		Version              string `json:"version"`
		DefaultDecision      string `json:"default_decision"`
		RegisteredOperations []any  `json:"registered_operations"`
		Notes                string `json:"notes"`
	}
	if err := json.Unmarshal(art.PolicyJSON, &policy); err != nil {
		t.Fatal(err)
	}
	if policy.Version != "ingress" || policy.DefaultDecision != "DENY" || policy.RegisteredOperations == nil || len(policy.RegisteredOperations) != 0 {
		t.Fatalf("policy %+v", policy)
	}
	if policy.Notes != spec.Pool.Notes {
		t.Fatalf("notes %q", policy.Notes)
	}
	rawPolicy := string(art.PolicyJSON)
	for _, banned := range []string{"provider_id", "credential_binding_ref", "accounts_by_tenant"} {
		if strings.Contains(rawPolicy, banned) {
			t.Fatalf("policy contains %s\n%s", banned, rawPolicy)
		}
	}
}

func TestCompileIngressRefusesIPLiteral(t *testing.T) {
	spec := loadIngressExample(t)
	spec.Backend.UpstreamHost = "127.0.0.1"
	_, err := CompileIngress(spec)
	if !refusalHas(err, "UPSTREAM_HOST") {
		t.Fatalf("ip literal upstream was not refused: %v", err)
	}
}

func TestParseSpecDoesNotDecodeIngress(t *testing.T) {
	root := repoRoot(t)
	ingress := readBytes(t, filepath.Join(root, "contracts/gateway/ingress-compile-spec.example.json"))
	egress := readBytes(t, filepath.Join(root, "deploy/providers/wanbexpress/compile-spec.json"))
	if !IngressDocument(ingress) {
		t.Fatal("example was not detected as ingress")
	}
	if IngressDocument(egress) {
		t.Fatal("egress spec was detected as ingress")
	}
	if _, err := ParseSpec(ingress); err == nil {
		t.Fatal("ParseSpec decoded an ingress document")
	}
	if _, err := ParseSpec(egress); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseIngressSpec(ingress); err != nil {
		t.Fatal(err)
	}
}

func loadIngressExample(t *testing.T) IngressSpec {
	t.Helper()
	spec, err := ParseIngressSpec(readBytes(t, filepath.Join(repoRoot(t), "contracts/gateway/ingress-compile-spec.example.json")))
	if err != nil {
		t.Fatal(err)
	}
	return spec
}

func readBytes(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
