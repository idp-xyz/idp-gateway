package domain

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// 锁定的 1.7.0 在 llm.providers 上接受这些 provider 名字。来自该二进制内嵌的
// LocalBuiltinModelAIProvider 和 ProviderPreset，不是本仓库选定的一家模型商。
var aiProviderKinds = map[string]struct{}{
	"openai": {}, "openAI": {}, "gemini": {}, "vertex": {}, "anthropic": {},
	"bedrock": {}, "azure": {}, "copilot": {},
	"cohere": {}, "ollama": {}, "baseten": {}, "cerebras": {}, "deepinfra": {},
	"deepseek": {}, "groq": {}, "huggingface": {}, "mistral": {}, "openrouter": {},
	"togetherai": {}, "xai": {}, "fireworks": {}, "meta": {}, "perplexity": {}, "typesafe": {},
}

// AISpec 是 AI 池的编译输入。监听、JWT、上游地址和密钥文件都在这份文档里。
// 编译器不写死主机名，也不把密钥写进输出。
type AISpec struct {
	TrafficClass string     `json:"traffic_class"`
	Pool         AIPool     `json:"pool"`
	Intent       AIIntent   `json:"intent"`
	Provider     AIUpstream `json:"provider"`
	Models       []AIModel  `json:"models"`
}

// AIPool 是这个 AI 池的监听和调用方 JWT。path_prefix 挂在锁定二进制的标准 LLM 路径前面。
type AIPool struct {
	Name              string   `json:"name"`
	Environment       string   `json:"environment"`
	PublicHostname    string   `json:"public_hostname"`
	PathPrefix        string   `json:"path_prefix"`
	ListenPort        int      `json:"listen_port"`
	BindAddress       string   `json:"bind_address"`
	AdminAddr         string   `json:"admin_addr"`
	StatsAddr         string   `json:"stats_addr"`
	ReadinessAddr     string   `json:"readiness_addr"`
	ReadbackPort      int      `json:"readback_port"`
	PublisherIdentity string   `json:"publisher_identity"`
	TLSDir            string   `json:"tls_dir"`
	JWTIssuer         string   `json:"jwt_issuer"`
	JWTAudiences      []string `json:"jwt_audiences"`
	JWKSFile          string   `json:"jwks_file"`
	Notes             string   `json:"notes,omitempty"`
}

// AIIntent 是拼进预检的那一条 AI RouteIntent。协议目前只编译 LLM。
type AIIntent struct {
	IntentID           string `json:"intent_id"`
	AIProtocol         string `json:"ai_protocol"`
	AITargetRef        string `json:"ai_target_ref"`
	AuthzProfile       string `json:"authz_profile"`
	ApprovalRef        string `json:"approval_ref"`
	ExpectedGeneration int    `json:"expected_generation"`
	PolicyBundleRef    string `json:"policy_bundle_ref"`
}

// AIUpstream 是模型上游。api_key_file 是配置目录里的相对路径，文件内容不进编译结果。
// base_url 要带端口。https 的主机必须是 DNS 名。http 只允许 TEST 或 DEV 上的 127.0.0.1。
type AIUpstream struct {
	Name       string `json:"name"`
	Kind       string `json:"kind"`
	APIKeyFile string `json:"api_key_file"`
	BaseURL    string `json:"base_url"`
}

// AIModel 是调用方请求里的模型名。它引用同一份 provider，不另带密钥。
type AIModel struct {
	Name string `json:"name"`
}

// AIDocument 判断原始 JSON 是不是 AI 编译规格。
func AIDocument(data []byte) bool {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var doc map[string]any
	if err := dec.Decode(&doc); err != nil {
		return false
	}
	class, ok := doc["traffic_class"].(string)
	return ok && class == ClassAI
}

// ParseAISpec 解码 AI 编译规格。未知字段、环境变量引用和敏感键都拒绝。
func ParseAISpec(data []byte) (AISpec, error) {
	if envReference.Match(data) {
		return AISpec{}, &Refusal{Issues: []Issue{{Code: "ENV_REFERENCE", Reason: "spec contains an environment variable reference"}}}
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var spec AISpec
	if err := dec.Decode(&spec); err != nil {
		if strings.Contains(err.Error(), "unknown field") {
			return AISpec{}, &Refusal{Issues: []Issue{{Code: "UNKNOWN_FIELD", Reason: err.Error()}}}
		}
		return AISpec{}, fmt.Errorf("ai compile spec: %w", err)
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return AISpec{}, fmt.Errorf("ai compile spec: extra JSON value")
	}
	if issues := secretIssues(data); len(issues) > 0 {
		return AISpec{}, &Refusal{Issues: issues}
	}
	if spec.TrafficClass != ClassAI {
		return AISpec{}, &Refusal{Issues: []Issue{{Code: "TRAFFIC_CLASS", Reason: "traffic_class must be AI"}}}
	}
	return spec, nil
}

// CompileAI 把 AI 规格编成网关 YAML 和一份没有承运商操作的策略 JSON。
// 这一步只编译 LLM。MCP 和 A2A 预检认识，但锁定二进制上的接法还没有量过，这里拒绝。
func CompileAI(spec AISpec) (CompiledArtifacts, error) {
	if issues := aiIssues(spec); len(issues) > 0 {
		return CompiledArtifacts{}, &Refusal{Issues: issues}
	}
	report := Evaluate(nil, spec.intentRaws(), nil, PreflightOptions{})
	if report.IssueCount > 0 {
		return CompiledArtifacts{}, &Refusal{Issues: report.Issues}
	}
	gateway := emitAIGateway(spec)
	policy := emitAIPolicy(spec)
	if envReference.Match(gateway) || envReference.Match(policy) {
		return CompiledArtifacts{}, &Refusal{Issues: []Issue{{Code: "ENV_REFERENCE", Reason: "compiled output contains an environment variable reference"}}}
	}
	if bytes.Contains(gateway, []byte("\nsession:")) || bytes.Contains(gateway, []byte("\nsession :")) {
		return CompiledArtifacts{}, &Refusal{Issues: []Issue{{Code: "SESSION_KEY", Reason: "compiled gateway config contains a session key"}}}
	}
	return CompiledArtifacts{
		GatewayYAML:   gateway,
		PolicyJSON:    policy,
		GatewaySHA256: sha256Hex(gateway),
		PolicySHA256:  sha256Hex(policy),
		RouteCount:    len(spec.Models),
	}, nil
}

func aiIssues(spec AISpec) []Issue {
	var issues []Issue
	add := func(code, reason string) {
		issues = append(issues, Issue{Code: code, Reason: reason})
	}
	raw, err := json.Marshal(spec)
	if err != nil {
		add("SPEC", err.Error())
		return issues
	}
	if envReference.Match(raw) {
		add("ENV_REFERENCE", "spec contains an environment variable reference")
	}
	if spec.TrafficClass != ClassAI {
		add("TRAFFIC_CLASS", "traffic_class must be AI")
	}
	if _, ok := environments[spec.Pool.Environment]; !ok {
		add("ENVIRONMENT", "environment must be DEV, TEST, or PROD")
	}
	if !rePoolName.MatchString(spec.Pool.Name) || !strings.HasPrefix(spec.Pool.Name, "ai-") {
		add("POOL_NAME", "pool name must match ai-(dev|test|prod)")
	}
	if !reHostname.MatchString(spec.Pool.PublicHostname) {
		add("PUBLIC_HOSTNAME", "public_hostname is not a DNS name")
	}
	if !reCanonicalPath.MatchString(spec.Pool.PathPrefix) {
		add("PATH_PREFIX", "path_prefix is not a canonical path")
	}
	if spec.Intent.AIProtocol != "LLM" {
		add("AI_PROTOCOL", "only LLM is compiled; MCP and A2A are not measured on the locked binary")
	}
	if _, ok := aiProviderKinds[spec.Provider.Kind]; !ok {
		add("AI_PROVIDER", "provider kind is not one the locked binary lists")
	}
	if !reProviderID.MatchString(spec.Provider.Name) {
		add("AI_PROVIDER", "provider name must be a lowercase token")
	}
	if !relativePath(spec.Provider.APIKeyFile) {
		add("API_KEY_FILE", "api_key_file must be a relative path and must not contain the key")
	}
	if _, err := canonicalAIBaseURL(spec.Provider.BaseURL, spec.Pool.Environment); err != nil {
		add("BASE_URL", err.Error())
	}
	if len(spec.Models) == 0 {
		add("NO_MODELS", "at least one model is required")
	}
	seen := map[string]struct{}{}
	for _, model := range spec.Models {
		if !aiModelName(model.Name) {
			add("MODEL_NAME", "model name is empty or contains whitespace")
		}
		if _, ok := seen[model.Name]; ok {
			add("DUPLICATE_MODEL", "model name "+model.Name+" is repeated")
		}
		seen[model.Name] = struct{}{}
	}
	if len(spec.Pool.JWTAudiences) == 0 {
		add("JWT_AUDIENCE", "jwt_audiences must not be empty")
	}
	for _, audience := range spec.Pool.JWTAudiences {
		if audience == "" || strings.ContainsAny(audience, " \n\r\t") {
			add("JWT_AUDIENCE", "jwt audience is empty or contains whitespace")
		}
	}
	if spec.Pool.JWTIssuer == "" || strings.ContainsAny(spec.Pool.JWTIssuer, " \n\r\t") {
		add("JWT_ISSUER", "jwt_issuer is empty or contains whitespace")
	}
	if spec.Pool.ListenPort < 1 || spec.Pool.ListenPort > 65535 {
		add("LISTEN_PORT", "listen_port is out of range")
	}
	if spec.Pool.ReadbackPort < 1 || spec.Pool.ReadbackPort > 65535 || spec.Pool.ReadbackPort == spec.Pool.ListenPort {
		add("READBACK_PORT", "readback_port must be a distinct TCP port")
	}
	if spec.Pool.BindAddress == "" || strings.ContainsAny(spec.Pool.BindAddress, " \n\r\t") {
		add("BIND_ADDRESS", "bind_address is empty or contains whitespace")
	}
	admin, stats, ready := spec.Pool.AdminAddr, spec.Pool.StatsAddr, spec.Pool.ReadinessAddr
	if admin == "" || stats == "" || ready == "" ||
		strings.ContainsAny(admin, " \n\r\t") || strings.ContainsAny(stats, " \n\r\t") || strings.ContainsAny(ready, " \n\r\t") ||
		admin == stats || admin == ready || stats == ready {
		add("ADMIN_ADDR", "admin_addr, stats_addr and readiness_addr must be distinct single-line addresses")
	}
	if !strings.HasPrefix(spec.Pool.PublisherIdentity, "spiffe://") || strings.ContainsAny(spec.Pool.PublisherIdentity, " \"\\$'\n\r\t") {
		add("PUBLISHER_IDENTITY", "publisher_identity must be a spiffe id without quotes or references")
	}
	if !relativePath(spec.Pool.TLSDir) || !relativePath(spec.Pool.JWKSFile) {
		add("TLS_PATH", "tls_dir and jwks_file must be relative paths")
	}
	return issues
}

func aiModelName(name string) bool {
	if name == "" || len(name) > 128 || strings.ContainsAny(name, " \t\r\n") {
		return false
	}
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '.' || r == '_' || r == ':' || r == '-':
		default:
			return false
		}
	}
	return true
}

// canonicalAIBaseURL 检查上游地址。密钥不能出现在用户信息、查询或片段里。
// 明文只到 127.0.0.1，并且不能用于 PROD。
func canonicalAIBaseURL(raw, environment string) (string, error) {
	if raw == "" || strings.ContainsAny(raw, " \t\r\n?#") || strings.Contains(raw, "@") {
		return "", fmt.Errorf("base_url must be http or https with an explicit port and no user info, query, or fragment")
	}
	var scheme, rest string
	switch {
	case strings.HasPrefix(raw, "https://"):
		scheme, rest = "https", strings.TrimPrefix(raw, "https://")
	case strings.HasPrefix(raw, "http://"):
		scheme, rest = "http", strings.TrimPrefix(raw, "http://")
	default:
		return "", fmt.Errorf("base_url must start with http:// or https://")
	}
	hostport, path, found := strings.Cut(rest, "/")
	if found {
		path = "/" + path
		if strings.Contains(path, "//") || strings.HasSuffix(path, "/") {
			return "", fmt.Errorf("base_url path must not contain an empty segment or a trailing slash")
		}
	}
	host, port, ok := strings.Cut(hostport, ":")
	if !ok || host == "" || port == "" {
		return "", fmt.Errorf("base_url must include an explicit port")
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 || strconv.Itoa(n) != port {
		return "", fmt.Errorf("base_url port is out of range")
	}
	switch scheme {
	case "http":
		if environment == "PROD" || host != "127.0.0.1" {
			return "", fmt.Errorf("plain HTTP is only allowed to 127.0.0.1 outside PROD")
		}
	default:
		if !reHostname.MatchString(host) {
			return "", fmt.Errorf("https base_url host is not a DNS name")
		}
	}
	return scheme + "://" + host + ":" + port + path, nil
}

func (s AISpec) intentRaws() []map[string]any {
	return []map[string]any{{
		"intent_id":           s.Intent.IntentID,
		"gateway_pool":        s.Pool.Name,
		"traffic_class":       ClassAI,
		"environment":         s.Pool.Environment,
		"logical_path":        s.Pool.PathPrefix,
		"ai_protocol":         s.Intent.AIProtocol,
		"ai_target_ref":       s.Intent.AITargetRef,
		"authz_profile":       s.Intent.AuthzProfile,
		"approval_ref":        s.Intent.ApprovalRef,
		"expected_generation": s.Intent.ExpectedGeneration,
		"policy_bundle_ref":   s.Intent.PolicyBundleRef,
	}}
}

func emitAIGateway(spec AISpec) []byte {
	base, err := canonicalAIBaseURL(spec.Provider.BaseURL, spec.Pool.Environment)
	if err != nil {
		base = spec.Provider.BaseURL
	}
	root := ym(
		yp("config", ym(
			yp("adminAddr", ys(spec.Pool.AdminAddr)),
			yp("statsAddr", ys(spec.Pool.StatsAddr)),
			yp("readinessAddr", ys(spec.Pool.ReadinessAddr)),
			yp("storage", ym(yp("mode", ys("readOnly")))),
		)),
		yp("frontendPolicies", ym(
			yp("networkAuthorization", ym(
				yp("rules", yq(
					ym(yp("allow", ys("destination.port == "+strconv.Itoa(spec.Pool.ListenPort)))),
					ym(yp("allow", ys("destination.port == "+strconv.Itoa(spec.Pool.ReadbackPort)+" && source.spiffeId == "+strconv.Quote(spec.Pool.PublisherIdentity)))),
				)),
			)),
		)),
		yp("gateways", ym(
			yp("read-back", ym(
				yp("port", yi(spec.Pool.ReadbackPort)),
				yp("tls", ym(
					yp("cert", ys(tlsPath(spec.Pool.TLSDir, "gateway-readback.crt"))),
					yp("key", ys(tlsPath(spec.Pool.TLSDir, "gateway-readback.key"))),
					yp("root", ys(tlsPath(spec.Pool.TLSDir, "ca.crt"))),
				)),
			)),
			yp(spec.Pool.Name, ym(
				yp("port", yi(spec.Pool.ListenPort)),
				yp("bindAddress", ys(spec.Pool.BindAddress)),
				yp("protocol", ys("HTTP")),
				yp("jwtAuth", ym(
					yp("mode", ys("strict")),
					yp("issuer", ys(spec.Pool.JWTIssuer)),
					yp("audiences", stringSeq(spec.Pool.JWTAudiences)),
					yp("jwks", ym(yp("file", ys(spec.Pool.JWKSFile)))),
				)),
			)),
		)),
		yp("llm", emitAILLM(spec, base)),
		yp("routes", yq(readBackRoute(spec.Pool.AdminAddr))),
	)
	var buf bytes.Buffer
	root.write(&buf, 0, false)
	return buf.Bytes()
}

func emitAILLM(spec AISpec, base string) *ynode {
	models := make([]*ynode, len(spec.Models))
	for i, model := range spec.Models {
		models[i] = ym(
			yp("name", ys(model.Name)),
			yp("provider", ym(yp("reference", ys(spec.Provider.Name)))),
		)
	}
	return ym(
		yp("gateways", stringSeq([]string{spec.Pool.Name})),
		yp("pathPrefix", ys(spec.Pool.PathPrefix)),
		yp("providers", yq(ym(
			yp("name", ys(spec.Provider.Name)),
			yp("provider", ys(spec.Provider.Kind)),
			yp("params", ym(
				yp("apiKey", ym(yp("file", ys(spec.Provider.APIKeyFile)))),
				yp("baseUrl", ys(base)),
			)),
		))),
		yp("models", yq(models...)),
	)
}

func emitAIPolicy(spec AISpec) []byte {
	doc := ingressPolicyDocument{
		Version:              "ai",
		DefaultDecision:      "DENY",
		RegisteredOperations: []any{},
		Notes:                spec.Pool.Notes,
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(doc); err != nil {
		panic(err)
	}
	return buf.Bytes()
}
