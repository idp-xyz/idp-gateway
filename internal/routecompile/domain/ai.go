package domain

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
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

// MCP 目标名。几个目标时网关用下划线把目标名和工具名接起来，所以这里不许下划线。
// 这一步只编译一个目标，名字规则仍按那个接法收紧。
var reMCPTargetName = regexp.MustCompile(`^[a-z][a-z0-9-]{1,31}$`)

// 转到 MCP 目标的请求头。少了 mcp-session-id 或 mcp-protocol-version，initialize 之后是 400。
// 少了 accept，每个请求都是 406。这五项是 2026-11-23 在锁定的 1.7.0 上量出来的。
const mcpHeaderFilter = `request.headers.filterKeys(k, k in ["accept", "content-type", "mcp-protocol-version", "mcp-session-id", "traceparent"])`

// AISpec 是 AI 池的编译输入。一份文档一个池、一个意图。intent.ai_protocol 选 LLM、MCP 或 A2A。
// 另一支的字段出现就拒绝，不忽略。监听、JWT 和上游地址都在这份文档里。编译器不写死主机名，也不把密钥写进输出。
type AISpec struct {
	TrafficClass string      `json:"traffic_class"`
	Pool         AIPool      `json:"pool"`
	Intent       AIIntent    `json:"intent"`
	Provider     *AIUpstream `json:"provider,omitempty"`
	Models       *[]AIModel  `json:"models,omitempty"`
	MCP          *AIMCP      `json:"mcp,omitempty"`
	A2A          *AIA2A      `json:"a2a,omitempty"`

	// 键在原文里出现过，包括值为 null。指针看不出 null 和缺席，混支不能靠这一点漏掉。
	sawProvider bool `json:"-"`
	sawModels   bool `json:"-"`
	sawMCP      bool `json:"-"`
	sawA2A      bool `json:"-"`
}

// AIPool 是这个 AI 池的监听和调用方 JWT。path_prefix 挂在协议路径前面。
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

// AIIntent 是拼进预检的那一条 AI RouteIntent。ai_protocol 决定编译哪一支。
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

// AIMCP 是 MCP 这一支。这一步只编译一个 target，不收凭证字段。
type AIMCP struct {
	Target AIMCPTarget `json:"target"`
}

// AIMCPTarget 是那一个 MCP 目标。host 的地址规则与 A2A 的 agent 相同。
type AIMCPTarget struct {
	Name        string `json:"name"`
	Host        string `json:"host"`
	Port        int    `json:"port"`
	Path        string `json:"path"`
	TLSHostname string `json:"tls_hostname,omitempty"`
}

// AIA2A 是 A2A 这一支。agent 是普通的 host 后端，路由上带 a2a 策略。
type AIA2A struct {
	Agent AIA2AAgent `json:"agent"`
}

// AIA2AAgent 是 A2A 上游。path_prefix 是改写到上游的路径，`/` 或一条规范路径。
// route_timeout 与入口的 route_timeout 同一个写法。没有凭证字段。
type AIA2AAgent struct {
	Host         string `json:"host"`
	Port         int    `json:"port"`
	TLSHostname  string `json:"tls_hostname,omitempty"`
	PathPrefix   string `json:"path_prefix"`
	RouteTimeout string `json:"route_timeout"`
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
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return AISpec{}, fmt.Errorf("ai compile spec: %w", err)
	}
	_, spec.sawProvider = raw["provider"]
	_, spec.sawModels = raw["models"]
	_, spec.sawMCP = raw["mcp"]
	_, spec.sawA2A = raw["a2a"]
	return spec, nil
}

// CompileAI 把 AI 规格编成网关 YAML 和一份没有承运商操作的策略 JSON。
// LLM、MCP、A2A 三支互斥。公网 CA 签发的上游证书这一步不支持：TLS 只用这个池自己的那套。
func CompileAI(spec AISpec) (CompiledArtifacts, error) {
	if issues := aiIssues(spec); len(issues) > 0 {
		return CompiledArtifacts{}, &Refusal{Issues: issues}
	}
	report := Evaluate(nil, spec.intentRaws(), nil, PreflightOptions{})
	if report.IssueCount > 0 {
		return CompiledArtifacts{}, &Refusal{Issues: report.Issues}
	}
	var gateway []byte
	switch spec.Intent.AIProtocol {
	case "LLM":
		gateway = emitAIGateway(spec)
	case "MCP":
		gateway = emitAIMCPGateway(spec)
	case "A2A":
		gateway = emitAIA2AGateway(spec)
	default:
		return CompiledArtifacts{}, &Refusal{Issues: []Issue{{Code: "AI_PROTOCOL", Reason: "ai_protocol must be LLM, MCP, or A2A"}}}
	}
	policy := emitAIPolicy(spec)
	if envReference.Match(gateway) || envReference.Match(policy) {
		return CompiledArtifacts{}, &Refusal{Issues: []Issue{{Code: "ENV_REFERENCE", Reason: "compiled output contains an environment variable reference"}}}
	}
	if bytes.Contains(gateway, []byte("\nsession:")) || bytes.Contains(gateway, []byte("\nsession :")) {
		return CompiledArtifacts{}, &Refusal{Issues: []Issue{{Code: "SESSION_KEY", Reason: "compiled gateway config contains a session key"}}}
	}
	count := 1
	if spec.Intent.AIProtocol == "LLM" {
		count = len(*spec.Models)
	}
	return CompiledArtifacts{
		GatewayYAML:   gateway,
		PolicyJSON:    policy,
		GatewaySHA256: sha256Hex(gateway),
		PolicySHA256:  sha256Hex(policy),
		RouteCount:    count,
	}, nil
}

func aiIssues(spec AISpec) []Issue {
	issues := aiPoolIssues(spec)
	switch spec.Intent.AIProtocol {
	case "LLM":
		issues = append(issues, aiForeignIssues(spec, "LLM")...)
		issues = append(issues, aiLLMIssues(spec)...)
	case "MCP":
		issues = append(issues, aiForeignIssues(spec, "MCP")...)
		issues = append(issues, aiMCPIssues(spec)...)
	case "A2A":
		issues = append(issues, aiForeignIssues(spec, "A2A")...)
		issues = append(issues, aiA2AIssues(spec)...)
	default:
		issues = append(issues, Issue{Code: "AI_PROTOCOL", Reason: "ai_protocol must be LLM, MCP, or A2A"})
	}
	return issues
}

func aiPoolIssues(spec AISpec) []Issue {
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

// 另一支的块出现了就拒绝。null 也算出现：原文里有这个键。
func aiForeignIssues(spec AISpec, protocol string) []Issue {
	var issues []Issue
	add := func(reason string) {
		issues = append(issues, Issue{Code: "AI_PROTOCOL", Reason: reason})
	}
	if protocol != "LLM" && (spec.sawProvider || spec.Provider != nil || spec.sawModels || spec.Models != nil) {
		add("provider and models belong to the LLM branch")
	}
	if protocol != "MCP" && (spec.sawMCP || spec.MCP != nil) {
		add("mcp belongs to the MCP branch")
	}
	if protocol != "A2A" && (spec.sawA2A || spec.A2A != nil) {
		add("a2a belongs to the A2A branch")
	}
	return issues
}

func aiLLMIssues(spec AISpec) []Issue {
	var issues []Issue
	add := func(code, reason string) {
		issues = append(issues, Issue{Code: code, Reason: reason})
	}
	if spec.Provider == nil {
		add("AI_PROVIDER", "provider is required for LLM")
		return append(issues, aiModelIssues(spec)...)
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
	return append(issues, aiModelIssues(spec)...)
}

func aiModelIssues(spec AISpec) []Issue {
	var issues []Issue
	add := func(code, reason string) {
		issues = append(issues, Issue{Code: code, Reason: reason})
	}
	if spec.Models == nil || len(*spec.Models) == 0 {
		add("NO_MODELS", "at least one model is required")
		return issues
	}
	seen := map[string]struct{}{}
	for _, model := range *spec.Models {
		if !aiModelName(model.Name) {
			add("MODEL_NAME", "model name is empty or contains whitespace")
		}
		if _, ok := seen[model.Name]; ok {
			add("DUPLICATE_MODEL", "model name "+model.Name+" is repeated")
		}
		seen[model.Name] = struct{}{}
	}
	return issues
}

func aiMCPIssues(spec AISpec) []Issue {
	if spec.MCP == nil {
		return []Issue{{Code: "MCP_TARGET", Reason: "mcp.target is required"}}
	}
	target := spec.MCP.Target
	_, _, _, issues := resolveAIEndpoint(aiEndpoint{Host: target.Host, Port: target.Port, TLSHostname: target.TLSHostname}, spec.Pool.Environment)
	if !reMCPTargetName.MatchString(target.Name) {
		issues = append(issues, Issue{Code: "TARGET_NAME", Reason: "mcp target name must match ^[a-z][a-z0-9-]{1,31}$"})
	}
	if !reCanonicalPath.MatchString(target.Path) {
		issues = append(issues, Issue{Code: "TARGET_PATH", Reason: "mcp target path is not a canonical path"})
	}
	return issues
}

func aiA2AIssues(spec AISpec) []Issue {
	if spec.A2A == nil {
		return []Issue{{Code: "A2A_AGENT", Reason: "a2a.agent is required"}}
	}
	agent := spec.A2A.Agent
	_, _, _, issues := resolveAIEndpoint(aiEndpoint{Host: agent.Host, Port: agent.Port, TLSHostname: agent.TLSHostname}, spec.Pool.Environment)
	if agent.PathPrefix != "/" && !reCanonicalPath.MatchString(agent.PathPrefix) {
		issues = append(issues, Issue{Code: "AGENT_PATH", Reason: "a2a agent path_prefix must be / or a canonical path"})
	}
	if !reIngressRouteTimeout.MatchString(agent.RouteTimeout) {
		issues = append(issues, Issue{Code: "ROUTE_TIMEOUT", Reason: "route_timeout must match ^[1-9][0-9]*s$"})
	}
	return issues
}

// aiEndpoint 是 MCP 目标和 A2A agent 共用的地址。
// host 是 DNS 名时必须 TLS，证书名是 tls_hostname，没有就用 host。
// host 是 127.0.0.1 时 PROD 拒绝；DEV 和 TEST 上，没有 tls_hostname 是明文，有就是 TLS。
// 别的 IP 字面量和 localhost 都拒绝。TLS 用这个池自己的证书，不接受公网 CA。
type aiEndpoint struct {
	Host        string
	Port        int
	TLSHostname string
}

func aiEndpointIssues(ep aiEndpoint) []Issue {
	var issues []Issue
	add := func(code, reason string) {
		issues = append(issues, Issue{Code: code, Reason: reason})
	}
	if ep.Port < 1 || ep.Port > 65535 {
		add("UPSTREAM_PORT", "port is out of range")
	}
	switch {
	case ep.Host == "127.0.0.1":
		// PROD 在 resolve 里拒绝。这里只检查 tls_hostname 的形状。
	case reHostname.MatchString(ep.Host):
	default:
		add("UPSTREAM_HOST", "host must be a DNS name or 127.0.0.1; no other IP literal and no localhost")
	}
	if ep.TLSHostname != "" && !reHostname.MatchString(ep.TLSHostname) {
		add("TLS_HOSTNAME", "tls_hostname is not a DNS name")
	}
	return issues
}

// resolveAIEndpoint 在 aiEndpointIssues 和池的环境都通过之后给出 TLS 和 Host 改写。
// 证书名和 urlRewrite 的 authority：tls_hostname 优先，否则 DNS 名的 host，否则 127.0.0.1:端口。
func resolveAIEndpoint(ep aiEndpoint, environment string) (useTLS bool, certName, authority string, issues []Issue) {
	issues = aiEndpointIssues(ep)
	if ep.Host == "127.0.0.1" && environment == "PROD" {
		issues = append(issues, Issue{Code: "UPSTREAM_HOST", Reason: "127.0.0.1 is refused in PROD"})
	}
	if len(issues) > 0 {
		return false, "", "", issues
	}
	if ep.TLSHostname != "" {
		return true, ep.TLSHostname, ep.TLSHostname, nil
	}
	if reHostname.MatchString(ep.Host) {
		return true, ep.Host, ep.Host, nil
	}
	return false, "", "127.0.0.1:" + strconv.Itoa(ep.Port), nil
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
	return emitAIDocument(spec, emitAILLM(spec, base), []*ynode{readBackRoute(spec.Pool.AdminAddr)})
}

func emitAILLM(spec AISpec, base string) *ynode {
	models := make([]*ynode, len(*spec.Models))
	for i, model := range *spec.Models {
		models[i] = ym(
			yp("name", ys(model.Name)),
			yp("provider", ym(yp("reference", ys(spec.Provider.Name)))),
		)
	}
	return ym(
		yp("gateways", stringSeq([]string{spec.Pool.Name})),
		yp("pathPrefix", ys(spec.Pool.PathPrefix)),
		yp("policies", aiLLMPolicies(spec)),
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

// 这一步只放行两个端点。messages、responses、embeddings 故意不在规则里。
// 用 request.host。request.headers["host"] 在锁定的 1.7.0 上会把每个请求都拒掉。
func aiLLMPolicies(spec AISpec) *ynode {
	host := strconv.Quote(spec.Pool.PublicHostname)
	chat := strconv.Quote(spec.Pool.PathPrefix + "/v1/chat/completions")
	models := strconv.Quote(spec.Pool.PathPrefix + "/v1/models")
	rule := "request.host == " + host +
		" && ((request.method == \"POST\" && request.path == " + chat +
		") || (request.method == \"GET\" && request.path == " + models + "))"
	return ym(
		yp("authorization", ym(yp("rules", yq(ym(yp("allow", ys(rule))))))),
		yp("transformations", ym(
			yp("request", ym(yp("replace", ys(ingressHeaderFilter)))),
			yp("response", ym(yp("remove", stringSeq(ingressRemovedResponseHeaders)))),
		)),
	)
}

func emitAIMCPGateway(spec AISpec) []byte {
	target := spec.MCP.Target
	useTLS, certName, authority, errIssues := resolveAIEndpoint(aiEndpoint{Host: target.Host, Port: target.Port, TLSHostname: target.TLSHostname}, spec.Pool.Environment)
	if len(errIssues) > 0 {
		authority = target.Host
	}
	targetPairs := []ypair{
		yp("name", ys(target.Name)),
		yp("mcp", ym(
			yp("host", ys(target.Host)),
			yp("port", yi(target.Port)),
			yp("path", ys(target.Path)),
		)),
	}
	if useTLS {
		targetPairs = append(targetPairs, yp("policies", ym(
			yp("backendTLS", certBundle(spec.Pool.TLSDir, certName)),
		)))
	}
	route := ym(
		yp("name", ys(spec.Pool.Name+"-mcp")),
		yp("gateways", stringSeq([]string{spec.Pool.Name})),
		yp("hostnames", stringSeq([]string{spec.Pool.PublicHostname})),
		yp("matches", yq(
			aiMethodMatch(spec.Pool.PathPrefix, "POST"),
			aiMethodMatch(spec.Pool.PathPrefix, "GET"),
			aiMethodMatch(spec.Pool.PathPrefix, "DELETE"),
		)),
		yp("policies", ym(
			yp("authorization", ym(yp("rules", yq(ym(yp("allow", ys("request.path == "+strconv.Quote(spec.Pool.PathPrefix)))))))),
			yp("transformations", ym(yp("request", ym(yp("replace", ys(mcpHeaderFilter)))))),
			yp("urlRewrite", ym(yp("authority", ym(yp("full", ys(authority)))))),
			yp("responseHeaderModifier", ym(yp("remove", stringSeq(ingressRemovedResponseHeaders)))),
		)),
		yp("backends", yq(ym(
			yp("mcp", ym(yp("targets", yq(ym(targetPairs...))))),
		))),
	)
	return emitAIDocument(spec, nil, []*ynode{route, readBackRoute(spec.Pool.AdminAddr)})
}

func emitAIA2AGateway(spec AISpec) []byte {
	agent := spec.A2A.Agent
	useTLS, certName, authority, errIssues := resolveAIEndpoint(aiEndpoint{Host: agent.Host, Port: agent.Port, TLSHostname: agent.TLSHostname}, spec.Pool.Environment)
	if len(errIssues) > 0 {
		authority = agent.Host
	}
	card := spec.Pool.PathPrefix + "/.well-known/agent-card.json"
	rule := "(request.method == \"POST\" && request.path == " + strconv.Quote(spec.Pool.PathPrefix) +
		") || (request.method == \"GET\" && request.path == " + strconv.Quote(card) + ")"
	var backend []ypair
	if useTLS {
		backend = append(backend, yp("backendTLS", certBundle(spec.Pool.TLSDir, certName)))
	}
	backend = append(backend, yp("transformations", ym(yp("request", ym(yp("replace", ys(ingressHeaderFilter)))))))
	route := ym(
		yp("name", ys(spec.Pool.Name+"-a2a")),
		yp("gateways", stringSeq([]string{spec.Pool.Name})),
		yp("hostnames", stringSeq([]string{spec.Pool.PublicHostname})),
		yp("matches", yq(
			aiMethodMatch(spec.Pool.PathPrefix, "GET"),
			aiMethodMatch(spec.Pool.PathPrefix, "POST"),
		)),
		yp("policies", ym(
			yp("a2a", ym()),
			yp("authorization", ym(yp("rules", yq(ym(yp("allow", ys(rule))))))),
			yp("urlRewrite", ym(
				yp("authority", ym(yp("full", ys(authority)))),
				yp("path", ym(yp("prefix", ys(agent.PathPrefix)))),
			)),
			yp("responseHeaderModifier", ym(yp("remove", stringSeq(ingressRemovedResponseHeaders)))),
			yp("timeout", ym(yp("requestTimeout", ys(agent.RouteTimeout)))),
		)),
		yp("backends", yq(ym(
			yp("host", ys(agent.Host+":"+strconv.Itoa(agent.Port))),
			yp("policies", ym(backend...)),
		))),
	)
	return emitAIDocument(spec, nil, []*ynode{route, readBackRoute(spec.Pool.AdminAddr)})
}

func aiMethodMatch(prefix, method string) *ynode {
	return ym(
		yp("path", ym(yp("pathPrefix", ys(prefix)))),
		yp("method", ys(method)),
	)
}

// emitAIDocument 写出 AI 池的监听。llm 为 nil 时不写 llm 段，MCP 和 A2A 走这里。
// LLM 的键顺序与原先手写的那一份相同。
func emitAIDocument(spec AISpec, llm *ynode, routes []*ynode) []byte {
	pairs := []ypair{
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
	}
	if llm != nil {
		pairs = append(pairs, yp("llm", llm))
	}
	pairs = append(pairs, yp("routes", yq(routes...)))
	root := ym(pairs...)
	var buf bytes.Buffer
	root.write(&buf, 0, false)
	return buf.Bytes()
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
