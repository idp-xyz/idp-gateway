package domain

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

func TestCompileAIExample(t *testing.T) {
	spec := loadAIExample(t)
	art, err := CompileAI(spec)
	if err != nil {
		t.Fatal(err)
	}
	if art.RouteCount != 1 {
		t.Fatalf("models %d", art.RouteCount)
	}
	text := string(art.GatewayYAML)
	for _, needle := range []string{
		"ai.example",
		"https://issuer.example/ai",
		"example-ai",
		"pathPrefix: '/llm'",
		"provider: 'openai'",
		"baseUrl: 'https://api.openai.example:443/v1'",
		"file: 'tls/ai-api-key'",
		"name: 'example-model'",
		"reference: 'example'",
		"jwtAuth:",
		"mode: 'readOnly'",
		"name: 'read-back'",
	} {
		if !strings.Contains(text, needle) {
			t.Fatalf("missing %s\n%s", needle, text)
		}
	}
	for _, banned := range []string{"extAuthz", "Hc-OweDeveloper", "credential_binding", "not-a-real-key", "sk-"} {
		if strings.Contains(text, banned) {
			t.Fatalf("yaml contains %s\n%s", banned, text)
		}
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
	if policy.Version != "ai" || policy.DefaultDecision != "DENY" || len(policy.RegisteredOperations) != 0 {
		t.Fatalf("policy %+v", policy)
	}
	if policy.Notes != spec.Pool.Notes {
		t.Fatalf("notes %q", policy.Notes)
	}
}

func TestCompileAIRefusesPlainHTTPExceptLoopback(t *testing.T) {
	spec := loadAIExample(t)
	spec.Provider.BaseURL = "http://api.openai.example:80/v1"
	if err := compileAI(spec); err == nil || !refusalHas(err, "BASE_URL") {
		t.Fatalf("public http: %v", err)
	}
	spec.Pool.Environment = "PROD"
	spec.Provider.BaseURL = "http://127.0.0.1:19571/v1"
	if err := compileAI(spec); err == nil || !refusalHas(err, "BASE_URL") {
		t.Fatalf("prod loopback http: %v", err)
	}
	spec = loadAIExample(t)
	spec.Pool.Environment = "TEST"
	spec.Provider.BaseURL = "http://127.0.0.1:19571/v1"
	if _, err := CompileAI(spec); err != nil {
		t.Fatal(err)
	}
}

func TestCompileAIRefusesUnmeasuredProtocolsAndKeys(t *testing.T) {
	spec := loadAIExample(t)
	spec.Intent.AIProtocol = "MCP"
	if err := compileAI(spec); err == nil || !refusalHas(err, "AI_PROTOCOL") {
		t.Fatalf("mcp: %v", err)
	}
	spec = loadAIExample(t)
	spec.Provider.Kind = "not-a-provider"
	if err := compileAI(spec); err == nil || !refusalHas(err, "AI_PROVIDER") {
		t.Fatalf("kind: %v", err)
	}
	raw := readBytes(t, filepath.Join(repoRoot(t), "contracts/gateway/ai-compile-spec.example.json"))
	raw = []byte(strings.Replace(string(raw), `"kind"`, `"api_key": "secret", "kind"`, 1))
	if _, err := ParseAISpec(raw); err == nil || !refusalHas(err, "UNKNOWN_FIELD") && !refusalHas(err, "CREDENTIAL_VALUE_IN_INTENT") {
		t.Fatalf("inline key: %v", err)
	}
}

func TestParseSpecDoesNotDecodeAI(t *testing.T) {
	root := repoRoot(t)
	ai := readBytes(t, filepath.Join(root, "contracts/gateway/ai-compile-spec.example.json"))
	egress := readBytes(t, filepath.Join(root, "deploy/providers/wanbexpress/compile-spec.json"))
	if !AIDocument(ai) || AIDocument(egress) {
		t.Fatal("document detection")
	}
	if _, err := ParseSpec(ai); err == nil {
		t.Fatal("ParseSpec decoded an AI document")
	}
	if _, err := ParseAISpec(ai); err != nil {
		t.Fatal(err)
	}
}

func compileAI(spec AISpec) error {
	_, err := CompileAI(spec)
	return err
}

func loadAIExample(t *testing.T) AISpec {
	t.Helper()
	spec, err := ParseAISpec(readBytes(t, filepath.Join(repoRoot(t), "contracts/gateway/ai-compile-spec.example.json")))
	if err != nil {
		t.Fatal(err)
	}
	return spec
}
