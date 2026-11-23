package domain

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strings"
)

// 环境变量引用：${...}，或者 $ 后面紧跟大写字母或下划线。与承运商契约测试用的正则相同。
var envReference = regexp.MustCompile(`\$\{|\$[A-Z_]`)

// 凭证方案必须是一个词加一个结尾空格，和网关里 startsWith 的前缀一致。
var credentialSchemePattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9-]* $`)

// 凭证头是一个小写的 HTTP 头名。空串和 authorization 都表示原来的 Authorization。
var credentialHeaderPattern = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)

// canonicalCredentialHeader 把规格里的凭证头收成编译时用的名字。
// 空串和 authorization 都是 authorization。别的名字必须是小写头名，并且不是会被删掉的、
// 逐跳的、cookie，或 x-idp- 开头的头。凭证只放在这个请求头里，不放进查询参数。
func canonicalCredentialHeader(name string) (string, error) {
	if name == "" || name == "authorization" {
		return "authorization", nil
	}
	if !credentialHeaderPattern.MatchString(name) || strings.HasPrefix(name, "x-idp-") || forbiddenCredentialHeader(name) {
		return "", fmt.Errorf("credential_header %q is not a permitted header name", name)
	}
	return name, nil
}

func forbiddenCredentialHeader(name string) bool {
	switch name {
	case "cookie", "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
		"te", "trailer", "transfer-encoding", "upgrade":
		return true
	}
	for _, removed := range removedRequestHeaders {
		if name == removed {
			return true
		}
	}
	return false
}

// 评审过的请求头删除名单。承运商两份配置用的都是这九个，不是更多。
var removedRequestHeaders = []string{
	"x-provider-account",
	"cookie",
	"x-forwarded-host",
	"x-forwarded-for",
	"x-forwarded-proto",
	"forwarded",
	"x-idp-verified-subject",
	"x-idp-verified-tenant",
	"x-idp-verified-env",
}

// 应答里去掉的头。location 防止把调用方带去上游，set-cookie 不透传，判定编号不留给上游伪造。
var removedResponseHeaders = []string{"location", "set-cookie", "x-idp-decision-id"}

const reviewedHeaderFilter = `request.headers.filterKeys(k, k in ["accept", "authorization", "content-type", "idempotency-key", "traceparent", "x-client-trace"])`

const (
	fixedAuthzDecision = `has(extauthz.decision_id) ? extauthz.decision_id : response.headers["x-idp-decision-id"]`
	fixedTenantRef     = `jwt.tenant_id`
)

// CompileSpec 是编译器的输入：一个池、一家承运商、谁可以调用、要暴露的路由。
// 里面没有密钥，也不允许环境变量引用。
type CompileSpec struct {
	Pool     PoolSpec     `json:"pool"`
	Provider ProviderSpec `json:"provider"`
	Access   AccessSpec   `json:"access"`
	Routes   []RouteSpec  `json:"routes"`
}

// PoolSpec 是这份配置所在的那个出站池。
type PoolSpec struct {
	Name              string         `json:"name"`
	Environment       string         `json:"environment"`
	CallerHostname    string         `json:"caller_hostname"`
	ListenPort        int            `json:"listen_port"`
	BindAddress       string         `json:"bind_address"`
	ReadbackPort      int            `json:"readback_port"`
	AdminAddr         string         `json:"admin_addr"`
	StatsAddr         string         `json:"stats_addr"`
	ReadinessAddr     string         `json:"readiness_addr"`
	PublisherIdentity string         `json:"publisher_identity"`
	TLSDir            string         `json:"tls_dir"`
	JWTIssuer         string         `json:"jwt_issuer"`
	JWTAudiences      []string       `json:"jwt_audiences"`
	JWKSFile          string         `json:"jwks_file"`
	ExtAuthz          ExtAuthzSpec   `json:"ext_authz"`
	AccessLog         AccessLogSpec  `json:"access_log"`
	FrontendLimits    *FrontendLimit `json:"frontend_limits,omitempty"`
}

// FrontendLimit 是池入口的并发上限，给后续的流量治理用。不写就不出现在配置里。
type FrontendLimit struct {
	MaxConcurrentRequests *int `json:"max_concurrent_requests,omitempty"`
	MaxConnections        *int `json:"max_connections,omitempty"`
}

// ExtAuthzSpec 是到 gateway-authz 的那一跳。
type ExtAuthzSpec struct {
	Host     string `json:"host"`
	Hostname string `json:"hostname"`
	Timeout  string `json:"timeout"`
}

// AccessLogSpec 的两个表达式原样写进访问日志，用来对上客单号和承运商单号。
type AccessLogSpec struct {
	ProviderReferenceExpr string `json:"provider_reference_expr"`
	ProviderRequestExpr   string `json:"provider_request_expr"`
}

// ProviderSpec 是这一家承运商在这个池上的上游和凭证方案。
type ProviderSpec struct {
	ProviderID           string `json:"provider_id"`
	PolicyVersion        string `json:"policy_version"`
	EnforceTLSUpstream   bool   `json:"enforce_tls_upstream"`
	CredentialScheme     string `json:"credential_scheme"`
	CredentialBindingRef string `json:"credential_binding_ref"`
	// CredentialHeader 是上游要的凭证头。不写、空串、authorization 都表示 Authorization。
	// 凭证只放在这个请求头里，不放进查询参数。
	CredentialHeader     string            `json:"credential_header,omitempty"`
	UpstreamHost         string            `json:"upstream_host"`
	UpstreamPort         int               `json:"upstream_port"`
	RewriteAuthority     string            `json:"rewrite_authority"`
	BackendTLS           *BackendTLSSpec   `json:"backend_tls,omitempty"`
	SetRequestHeaders    map[string]string `json:"set_request_headers,omitempty"`
	RouteTimeout         string            `json:"route_timeout"`
	PlainHTTPSandboxHost string            `json:"plain_http_sandbox_host,omitempty"`
	InternalBackendHost  string            `json:"internal_backend_host,omitempty"`
	LocalRateLimit       []RateLimitSpec   `json:"local_rate_limit,omitempty"`
}

// BackendTLSSpec 表示到上游要做双向 TLS。证书文件名由池的 tls_dir 决定，这里只写校验用的主机名。
type BackendTLSSpec struct {
	Hostname string `json:"hostname"`
}

// RateLimitSpec 是一条本地限流。填了就写到每条业务路由上。
type RateLimitSpec struct {
	MaxTokens     int    `json:"max_tokens"`
	TokensPerFill int    `json:"tokens_per_fill"`
	FillInterval  string `json:"fill_interval"`
	Key           string `json:"key,omitempty"`
}

// AccessSpec 是登记表里每一行相同的调用方范围。
type AccessSpec struct {
	AllowedTenants    []string            `json:"allowed_tenants"`
	AccountsByTenant  map[string][]string `json:"accounts_by_tenant"`
	AllowedServiceIDs []string            `json:"allowed_service_ids"`
	BlockedIPRanges   []string            `json:"blocked_ip_ranges,omitempty"`
	PolicyNotes       string              `json:"policy_notes,omitempty"`
}

// RouteSpec 是一条要编译的出站路由，带上 RouteIntent 里属于这一条的字段。
type RouteSpec struct {
	IntentID                string `json:"intent_id"`
	RouteID                 string `json:"route_id"`
	OperationID             string `json:"operation_id"`
	Method                  string `json:"method"`
	LogicalPath             string `json:"logical_path"`
	PathMatchMode           string `json:"path_match_mode"`
	RewritePathPrefix       string `json:"rewrite_path_prefix"`
	ExpectedGeneration      int    `json:"expected_generation"`
	ApprovalRef             string `json:"approval_ref"`
	AuthzProfile            string `json:"authz_profile"`
	RedirectPolicy          string `json:"redirect_policy"`
	UpstreamTLS             string `json:"upstream_tls"`
	ProviderAccountStrategy string `json:"provider_account_strategy"`
	Transport               string `json:"transport"`
	PolicyBundleRef         string `json:"policy_bundle_ref"`
}

// ParseSpec 解码编译规格。未知字段、环境变量引用都拒绝。语法错误不是 Refusal。
func ParseSpec(data []byte) (CompileSpec, error) {
	if envReference.Match(data) {
		return CompileSpec{}, &Refusal{Issues: []Issue{{Code: "ENV_REFERENCE", Reason: "spec contains an environment variable reference"}}}
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var spec CompileSpec
	if err := dec.Decode(&spec); err != nil {
		if strings.Contains(err.Error(), "unknown field") {
			return CompileSpec{}, &Refusal{Issues: []Issue{{Code: "UNKNOWN_FIELD", Reason: err.Error()}}}
		}
		return CompileSpec{}, fmt.Errorf("compile spec: %w", err)
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return CompileSpec{}, fmt.Errorf("compile spec: extra JSON value")
	}
	if issues := secretIssues(data); len(issues) > 0 {
		return CompileSpec{}, &Refusal{Issues: issues}
	}
	return spec, nil
}

// Compile 把规格编成网关 YAML 和登记表 JSON。任何一条不满足就整份拒绝，不返回半份配置。
func Compile(spec CompileSpec) (CompiledArtifacts, error) {
	issues := specIssues(spec)
	if len(issues) > 0 {
		return CompiledArtifacts{}, &Refusal{Issues: issues}
	}
	raws := spec.intentRaws()
	report := Evaluate(nil, raws, spec.syntheticRegistry(), spec.preflightOptions())
	if report.IssueCount > 0 {
		return CompiledArtifacts{}, &Refusal{Issues: report.Issues}
	}
	if more := shapeIssues(spec); len(more) > 0 {
		return CompiledArtifacts{}, &Refusal{Issues: more}
	}
	gateway := emitGateway(spec)
	policy := emitPolicy(spec)
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
		RouteCount:    len(spec.Routes),
	}, nil
}
