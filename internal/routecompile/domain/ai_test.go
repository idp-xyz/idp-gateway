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

func TestCompileAIRefusesMixedBranchAndKeys(t *testing.T) {
	spec := loadAIExample(t)
	spec.Intent.AIProtocol = "MCP"
	if err := compileAI(spec); err == nil || !refusalHas(err, "AI_PROTOCOL") {
		t.Fatalf("llm document switched to MCP: %v", err)
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
	return loadAIFile(t, "ai-compile-spec.example.json")
}

func loadAIFile(t *testing.T, name string) AISpec {
	t.Helper()
	spec, err := ParseAISpec(readBytes(t, filepath.Join(repoRoot(t), "contracts/gateway", name)))
	if err != nil {
		t.Fatal(err)
	}
	return spec
}

func loadAIDoc(t *testing.T, name string) map[string]any {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal(readBytes(t, filepath.Join(repoRoot(t), "contracts/gateway", name)), &doc); err != nil {
		t.Fatal(err)
	}
	return doc
}

func compileAIDoc(t *testing.T, doc map[string]any) (CompiledArtifacts, error) {
	t.Helper()
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	spec, err := ParseAISpec(raw)
	if err != nil {
		return CompiledArtifacts{}, err
	}
	return CompileAI(spec)
}

func TestCompileAILLMPolicies(t *testing.T) {
	spec := loadAIExample(t)
	art, err := CompileAI(spec)
	if err != nil {
		t.Fatal(err)
	}
	if got := sha256Hex(art.PolicyJSON); got != "2b4196ee00a68a4885e1e751a9a27a9ca3aa2216ae6274e1524dca0cab5124ea" {
		t.Fatalf("llm policy json changed %s\n%s", got, art.PolicyJSON)
	}
	text := string(art.GatewayYAML)
	rule := `request.host == "ai.example" && ((request.method == "POST" && request.path == "/llm/v1/chat/completions") || (request.method == "GET" && request.path == "/llm/v1/models"))`
	for _, needle := range []string{
		"pathPrefix: '/llm'",
		rule,
		ingressHeaderFilter,
		"remove:\n        - 'location'\n        - 'set-cookie'",
	} {
		if !strings.Contains(text, needle) {
			t.Fatalf("missing %s\n%s", needle, text)
		}
	}
	policies := strings.Index(text, "policies:")
	providers := strings.Index(text, "providers:")
	models := strings.Index(text, "\n  models:")
	if policies < 0 || providers < 0 || models < 0 || !(policies < providers && providers < models) {
		t.Fatalf("llm key order\n%s", text)
	}
	spec.Pool.PublicHostname = "other.example"
	spec.Pool.PathPrefix = "/models"
	art, err = CompileAI(spec)
	if err != nil {
		t.Fatal(err)
	}
	text = string(art.GatewayYAML)
	other := `request.host == "other.example" && ((request.method == "POST" && request.path == "/models/v1/chat/completions") || (request.method == "GET" && request.path == "/models/v1/models"))`
	if !strings.Contains(text, other) || strings.Contains(text, `request.host == "ai.example"`) || strings.Contains(text, `"/llm/`) {
		t.Fatalf("rule did not follow the spec\n%s", text)
	}
}

func TestCompileAIMCPExample(t *testing.T) {
	art := mustCompileAIFile(t, "ai-compile-spec.mcp.example.json")
	if art.RouteCount != 1 {
		t.Fatalf("routes %d", art.RouteCount)
	}
	text := string(art.GatewayYAML)
	for _, needle := range []string{
		"name: 'ai-test-mcp'",
		"hostnames:\n  - 'mcp.example'",
		"pathPrefix: '/mcp'",
		"method: 'POST'",
		"method: 'GET'",
		"method: 'DELETE'",
		`request.path == "/mcp"`,
		"mcp-protocol-version",
		"mcp-session-id",
		"traceparent",
		"full: 'mcp-upstream.example'",
		"name: 'example'",
		"host: 'mcp-upstream.example'",
		"port: 443",
		"path: '/mcp'",
		"backendTLS:",
		"cert: 'tls/gateway.crt'",
		"key: 'tls/gateway.key'",
		"root: 'tls/ca.crt'",
		"hostname: 'mcp-upstream.example'",
		"remove:\n      - 'location'\n      - 'set-cookie'",
		"name: 'read-back'",
		"exact: '/config_dump'",
		"exact: '/api/runtime'",
	} {
		if !strings.Contains(text, needle) {
			t.Fatalf("missing %s\n%s", needle, text)
		}
	}
	if strings.Contains(text, "\nllm:") || strings.Contains(text, "a2a:") || strings.Contains(text, "requestTimeout: '5s'") {
		t.Fatalf("mcp yaml has llm, a2a, or a route timeout\n%s", text)
	}
	if strings.Count(text, "requestTimeout:") != 1 {
		t.Fatalf("mcp route must not add a timeout\n%s", text)
	}
	if strings.Index(text, "transformations:") > strings.Index(text, "backends:") {
		t.Fatalf("allowlist is not on the route\n%s", text)
	}
	assertAIPolicy(t, art)
}

func TestCompileAIA2AExample(t *testing.T) {
	art := mustCompileAIFile(t, "ai-compile-spec.a2a.example.json")
	if art.RouteCount != 1 {
		t.Fatalf("routes %d", art.RouteCount)
	}
	text := string(art.GatewayYAML)
	rule := `(request.method == "POST" && request.path == "/agent") || (request.method == "GET" && request.path == "/agent/.well-known/agent-card.json")`
	for _, needle := range []string{
		"name: 'ai-test-a2a'",
		"hostnames:\n  - 'a2a.example'",
		"pathPrefix: '/agent'",
		"method: 'GET'",
		"method: 'POST'",
		"a2a: {}",
		rule,
		"full: 'agent-upstream.example'",
		"prefix: '/'",
		"host: 'agent-upstream.example:443'",
		"requestTimeout: '5s'",
		"backendTLS:",
		"hostname: 'agent-upstream.example'",
		`request.headers.filterKeys(k, k in ["accept", "content-type", "traceparent"])`,
		"remove:\n      - 'location'\n      - 'set-cookie'",
		"name: 'read-back'",
	} {
		if !strings.Contains(text, needle) {
			t.Fatalf("missing %s\n%s", needle, text)
		}
	}
	if strings.Contains(text, "mcp-session-id") || strings.Contains(text, "\nllm:") {
		t.Fatalf("a2a yaml has an mcp allowlist or llm\n%s", text)
	}
	if strings.Count(text, "requestTimeout:") != 2 {
		t.Fatalf("a2a timeout count\n%s", text)
	}
	if strings.Index(text, "backends:") > strings.Index(text, "transformations:") {
		t.Fatalf("a2a allowlist is not on the backend\n%s", text)
	}
	assertAIPolicy(t, art)
}

func TestCompileAILoopbackShapes(t *testing.T) {
	spec := loadAIFile(t, "ai-compile-spec.mcp.example.json")
	spec.MCP.Target.Host = "127.0.0.1"
	spec.MCP.Target.Port = 27666
	spec.MCP.Target.TLSHostname = ""
	art, err := CompileAI(spec)
	if err != nil {
		t.Fatal(err)
	}
	text := string(art.GatewayYAML)
	if strings.Contains(text, "backendTLS") || !strings.Contains(text, "full: '127.0.0.1:27666'") {
		t.Fatalf("plain loopback\n%s", text)
	}
	spec.MCP.Target.TLSHostname = "mcp.standin.test"
	art, err = CompileAI(spec)
	if err != nil {
		t.Fatal(err)
	}
	text = string(art.GatewayYAML)
	if !strings.Contains(text, "hostname: 'mcp.standin.test'") || !strings.Contains(text, "full: 'mcp.standin.test'") || !strings.Contains(text, "host: '127.0.0.1'") {
		t.Fatalf("tls loopback\n%s", text)
	}
	spec = loadAIFile(t, "ai-compile-spec.mcp.example.json")
	spec.MCP.Target.TLSHostname = ""
	art, err = CompileAI(spec)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(art.GatewayYAML), "hostname: 'mcp-upstream.example'") {
		t.Fatalf("dns name without tls_hostname still uses TLS\n%s", art.GatewayYAML)
	}
	spec = loadAIFile(t, "ai-compile-spec.a2a.example.json")
	spec.A2A.Agent.Host = "127.0.0.1"
	spec.A2A.Agent.Port = 27667
	spec.A2A.Agent.TLSHostname = ""
	art, err = CompileAI(spec)
	if err != nil {
		t.Fatal(err)
	}
	text = string(art.GatewayYAML)
	if strings.Contains(text, "backendTLS") || !strings.Contains(text, "full: '127.0.0.1:27667'") || !strings.Contains(text, "host: '127.0.0.1:27667'") {
		t.Fatalf("a2a plain loopback\n%s", text)
	}
	if !strings.Contains(text, "transformations:") {
		t.Fatalf("a2a plain loopback still allowlists headers\n%s", text)
	}
}

func TestCompileAIRefusesOtherBranchFields(t *testing.T) {
	llm := loadAIDoc(t, "ai-compile-spec.example.json")
	llm["mcp"] = loadAIDoc(t, "ai-compile-spec.mcp.example.json")["mcp"]
	if _, err := compileAIDoc(t, llm); err == nil || !refusalHas(err, "AI_PROTOCOL") {
		t.Fatalf("llm with mcp: %v", err)
	}
	llm = loadAIDoc(t, "ai-compile-spec.example.json")
	llm["a2a"] = loadAIDoc(t, "ai-compile-spec.a2a.example.json")["a2a"]
	if _, err := compileAIDoc(t, llm); err == nil || !refusalHas(err, "AI_PROTOCOL") {
		t.Fatalf("llm with a2a: %v", err)
	}
	mcp := loadAIDoc(t, "ai-compile-spec.mcp.example.json")
	mcp["provider"] = loadAIDoc(t, "ai-compile-spec.example.json")["provider"]
	if _, err := compileAIDoc(t, mcp); err == nil || !refusalHas(err, "AI_PROTOCOL") {
		t.Fatalf("mcp with provider: %v", err)
	}
	mcp = loadAIDoc(t, "ai-compile-spec.mcp.example.json")
	mcp["models"] = loadAIDoc(t, "ai-compile-spec.example.json")["models"]
	if _, err := compileAIDoc(t, mcp); err == nil || !refusalHas(err, "AI_PROTOCOL") {
		t.Fatalf("mcp with models: %v", err)
	}
	mcp = loadAIDoc(t, "ai-compile-spec.mcp.example.json")
	mcp["a2a"] = loadAIDoc(t, "ai-compile-spec.a2a.example.json")["a2a"]
	if _, err := compileAIDoc(t, mcp); err == nil || !refusalHas(err, "AI_PROTOCOL") {
		t.Fatalf("mcp with a2a: %v", err)
	}
	mcp = loadAIDoc(t, "ai-compile-spec.mcp.example.json")
	mcp["provider"] = nil
	if _, err := compileAIDoc(t, mcp); err == nil || !refusalHas(err, "AI_PROTOCOL") {
		t.Fatalf("mcp with null provider: %v", err)
	}
	a2a := loadAIDoc(t, "ai-compile-spec.a2a.example.json")
	a2a["provider"] = loadAIDoc(t, "ai-compile-spec.example.json")["provider"]
	if _, err := compileAIDoc(t, a2a); err == nil || !refusalHas(err, "AI_PROTOCOL") {
		t.Fatalf("a2a with provider: %v", err)
	}
	a2a = loadAIDoc(t, "ai-compile-spec.a2a.example.json")
	a2a["models"] = loadAIDoc(t, "ai-compile-spec.example.json")["models"]
	if _, err := compileAIDoc(t, a2a); err == nil || !refusalHas(err, "AI_PROTOCOL") {
		t.Fatalf("a2a with models: %v", err)
	}
	a2a = loadAIDoc(t, "ai-compile-spec.a2a.example.json")
	a2a["mcp"] = loadAIDoc(t, "ai-compile-spec.mcp.example.json")["mcp"]
	if _, err := compileAIDoc(t, a2a); err == nil || !refusalHas(err, "AI_PROTOCOL") {
		t.Fatalf("a2a with mcp: %v", err)
	}
	llm = loadAIDoc(t, "ai-compile-spec.example.json")
	delete(llm, "provider")
	if _, err := compileAIDoc(t, llm); err == nil || !refusalHas(err, "AI_PROVIDER") {
		t.Fatalf("llm without provider: %v", err)
	}
	llm = loadAIDoc(t, "ai-compile-spec.example.json")
	delete(llm, "models")
	if _, err := compileAIDoc(t, llm); err == nil || !refusalHas(err, "NO_MODELS") {
		t.Fatalf("llm without models: %v", err)
	}
	mcp = loadAIDoc(t, "ai-compile-spec.mcp.example.json")
	delete(mcp, "mcp")
	if _, err := compileAIDoc(t, mcp); err == nil || !refusalHas(err, "MCP_TARGET") {
		t.Fatalf("mcp without target: %v", err)
	}
	a2a = loadAIDoc(t, "ai-compile-spec.a2a.example.json")
	delete(a2a, "a2a")
	if _, err := compileAIDoc(t, a2a); err == nil || !refusalHas(err, "A2A_AGENT") {
		t.Fatalf("a2a without agent: %v", err)
	}
}

func TestCompileAIRefusesUpstreamShapes(t *testing.T) {
	refuse := func(name, code string, edit func(AISpec) AISpec) {
		t.Helper()
		spec := edit(loadAIFile(t, name))
		if err := compileAI(spec); err == nil || !refusalHas(err, code) {
			t.Fatalf("%s: %v", code, err)
		}
	}
	refuse("ai-compile-spec.mcp.example.json", "UPSTREAM_HOST", func(spec AISpec) AISpec {
		spec.Pool.Environment = "PROD"
		spec.Pool.Name = "ai-prod"
		spec.MCP.Target.Host = "127.0.0.1"
		spec.MCP.Target.TLSHostname = "mcp.standin.test"
		return spec
	})
	refuse("ai-compile-spec.a2a.example.json", "UPSTREAM_HOST", func(spec AISpec) AISpec {
		spec.Pool.Environment = "PROD"
		spec.Pool.Name = "ai-prod"
		spec.A2A.Agent.Host = "127.0.0.1"
		spec.A2A.Agent.TLSHostname = ""
		return spec
	})
	for _, host := range []string{"localhost", "10.1.2.3", "192.0.2.1", "::1"} {
		host := host
		refuse("ai-compile-spec.mcp.example.json", "UPSTREAM_HOST", func(spec AISpec) AISpec {
			spec.MCP.Target.Host = host
			return spec
		})
	}
	refuse("ai-compile-spec.mcp.example.json", "TLS_HOSTNAME", func(spec AISpec) AISpec {
		spec.MCP.Target.TLSHostname = "not a host"
		return spec
	})
	refuse("ai-compile-spec.mcp.example.json", "TARGET_NAME", func(spec AISpec) AISpec {
		spec.MCP.Target.Name = "my_tool"
		return spec
	})
	refuse("ai-compile-spec.mcp.example.json", "TARGET_NAME", func(spec AISpec) AISpec {
		spec.MCP.Target.Name = "a"
		return spec
	})
	refuse("ai-compile-spec.mcp.example.json", "TARGET_PATH", func(spec AISpec) AISpec {
		spec.MCP.Target.Path = "/mcp/"
		return spec
	})
	refuse("ai-compile-spec.mcp.example.json", "UPSTREAM_PORT", func(spec AISpec) AISpec {
		spec.MCP.Target.Port = 0
		return spec
	})
	refuse("ai-compile-spec.a2a.example.json", "AGENT_PATH", func(spec AISpec) AISpec {
		spec.A2A.Agent.PathPrefix = "/agent/"
		return spec
	})
	refuse("ai-compile-spec.a2a.example.json", "AGENT_PATH", func(spec AISpec) AISpec {
		spec.A2A.Agent.PathPrefix = "agent"
		return spec
	})
	refuse("ai-compile-spec.a2a.example.json", "ROUTE_TIMEOUT", func(spec AISpec) AISpec {
		spec.A2A.Agent.RouteTimeout = "0s"
		return spec
	})
	spec := loadAIFile(t, "ai-compile-spec.a2a.example.json")
	spec.A2A.Agent.PathPrefix = "/"
	if _, err := CompileAI(spec); err != nil {
		t.Fatal(err)
	}
	spec.A2A.Agent.PathPrefix = "/a2a"
	if _, err := CompileAI(spec); err != nil {
		t.Fatal(err)
	}
	doc := loadAIDoc(t, "ai-compile-spec.mcp.example.json")
	doc["intent"].(map[string]any)["ai_protocol"] = "SSE"
	if _, err := compileAIDoc(t, doc); err == nil || !refusalHas(err, "AI_PROTOCOL") {
		t.Fatalf("unknown protocol: %v", err)
	}
	doc = loadAIDoc(t, "ai-compile-spec.mcp.example.json")
	target := doc["mcp"].(map[string]any)["target"].(map[string]any)
	target["api_key"] = "secret"
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseAISpec(raw); err == nil || !refusalHas(err, "UNKNOWN_FIELD") && !refusalHas(err, "CREDENTIAL_VALUE_IN_INTENT") {
		t.Fatalf("mcp api_key: %v", err)
	}
}

func mustCompileAIFile(t *testing.T, name string) CompiledArtifacts {
	t.Helper()
	art, err := CompileAI(loadAIFile(t, name))
	if err != nil {
		t.Fatal(err)
	}
	return art
}

func assertAIPolicy(t *testing.T, art CompiledArtifacts) {
	t.Helper()
	var policy struct {
		Version              string `json:"version"`
		DefaultDecision      string `json:"default_decision"`
		RegisteredOperations []any  `json:"registered_operations"`
	}
	if err := json.Unmarshal(art.PolicyJSON, &policy); err != nil {
		t.Fatal(err)
	}
	if policy.Version != "ai" || policy.DefaultDecision != "DENY" || len(policy.RegisteredOperations) != 0 {
		t.Fatalf("policy %+v", policy)
	}
}
