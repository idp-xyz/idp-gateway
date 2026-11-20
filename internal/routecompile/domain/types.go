package domain

import "fmt"

// 流量类别和上游 TLS 的取值。明文沙箱不是 schema 里的合法值，只在编译选项打开时放行。
const (
	ClassIngress = "INGRESS"
	ClassEgress  = "EGRESS"
	ClassAI      = "AI"

	TLSVerifyRequired         = "VERIFY_REQUIRED"
	PlainHTTPSandboxException = "PLAIN_HTTP_SANDBOX_EXCEPTION"
	AccountStrategyGatekeeper = "GATEKEEPER_DECISION_BINDING"
	RedirectDeny              = "DENY"
	StatusPreflightOK         = "STATIC_PREFLIGHT_OK_NOT_DEPLOYABLE"
	StatusReject              = "REJECT"
)

// Issue 是预检或编译拒绝的一条。字段与 scripts/preflight_intents.py 写出的对象对齐：
// 模式和安全问题用 intent_id + reason，路由冲突用 code、first、second。
type Issue struct {
	IntentID string   `json:"intent_id,omitempty"`
	Reason   string   `json:"reason,omitempty"`
	Code     string   `json:"code,omitempty"`
	First    string   `json:"first,omitempty"`
	Second   string   `json:"second,omitempty"`
	Paths    []string `json:"paths,omitempty"`
	RouteKey []any    `json:"route_key,omitempty"`
}

// Report 是一次预检的报告。三个 native/network 标志在预检里永远是 false：
// 这里不生成、也不校验 agentgateway 的原生配置。
type Report struct {
	Status                            string  `json:"status"`
	NativeAgentgatewayConfigGenerated bool    `json:"native_agentgateway_config_generated"`
	NativeAgentgatewaySchemaValidated bool    `json:"native_agentgateway_schema_validated"`
	NetworkDNSAllowlistValidated      bool    `json:"network_dns_allowlist_validated"`
	IntentsSHA256                     string  `json:"intents_sha256"`
	ProviderRegistrySHA256            string  `json:"provider_registry_sha256"`
	IssueCount                        int     `json:"issue_count"`
	Issues                            []Issue `json:"issues"`
}

// Refusal 是规格、预检或原生校验拒绝。调用方据此不写输出文件。
type Refusal struct {
	Issues []Issue
}

func (r *Refusal) Error() string {
	if r == nil || len(r.Issues) == 0 {
		return "REFUSED"
	}
	first := r.Issues[0]
	switch {
	case first.Code != "" && first.Reason != "":
		return fmt.Sprintf("REFUSED: %s: %s", first.Code, first.Reason)
	case first.Code != "":
		return "REFUSED: " + first.Code
	case first.Reason != "":
		return "REFUSED: " + first.Reason
	default:
		return fmt.Sprintf("REFUSED: %d issue(s)", len(r.Issues))
	}
}

// PreflightOptions 是预检的窄例外。零值表示与脚本一样严格，
// 不接受明文上游，也不接受没有点号的内部服务名。
type PreflightOptions struct {
	// AllowPlainHTTPUpstreamHost 是唯一允许 PLAIN_HTTP_SANDBOX_EXCEPTION 的主机名。
	// 环境是 PROD，或主机对不上，仍然拒绝。
	AllowPlainHTTPUpstreamHost string
	// AllowInternalBackendHost 是唯一允许的池内服务名（例如 provider-signer）。
	// 仍要求 upstream_tls 为 VERIFY_REQUIRED，并且规格里写了 backend_tls。
	AllowInternalBackendHost string
	// BackendTLSConfigured 表示编译规格给这个上游配了后端双向 TLS。
	BackendTLSConfigured bool
}

// Intent 是一条 RouteIntent 的类型化视图。未知字段和敏感键靠原始对象检查，不靠这个结构。
type Intent struct {
	IntentID                string   `json:"intent_id"`
	GatewayPool             string   `json:"gateway_pool"`
	TrafficClass            string   `json:"traffic_class"`
	Environment             string   `json:"environment"`
	ProviderID              string   `json:"provider_id,omitempty"`
	OperationID             string   `json:"operation_id,omitempty"`
	LogicalPath             string   `json:"logical_path"`
	AllowedMethods          []string `json:"allowed_methods,omitempty"`
	UpstreamHostname        string   `json:"upstream_hostname,omitempty"`
	UpstreamPort            int      `json:"upstream_port,omitempty"`
	AuthzProfile            string   `json:"authz_profile"`
	ApprovalRef             string   `json:"approval_ref"`
	ExpectedGeneration      int      `json:"expected_generation"`
	ContractRef             string   `json:"contract_ref,omitempty"`
	CredentialBindingRef    string   `json:"credential_binding_ref,omitempty"`
	RedirectPolicy          string   `json:"redirect_policy,omitempty"`
	PublicHostname          string   `json:"public_hostname,omitempty"`
	BackendServiceRef       string   `json:"backend_service_ref,omitempty"`
	AIProtocol              string   `json:"ai_protocol,omitempty"`
	AITargetRef             string   `json:"ai_target_ref,omitempty"`
	Transport               string   `json:"transport,omitempty"`
	PolicyBundleRef         string   `json:"policy_bundle_ref,omitempty"`
	UpstreamTLS             string   `json:"upstream_tls,omitempty"`
	UpstreamSNI             string   `json:"upstream_sni,omitempty"`
	ProviderAccountStrategy string   `json:"provider_account_strategy,omitempty"`
	APIAssetRef             string   `json:"api_asset_ref,omitempty"`
	RoutePriority           int      `json:"route_priority,omitempty"`
	HasRoutePriority        bool     `json:"-"`
}

// RegistryRow 是登记表里预检要看的那一行。其余字段只参与摘要，不参与判定。
type RegistryRow struct {
	ProviderID           string
	Environment          string
	UpstreamHostname     string
	Port                 int
	OperationID          string
	PathPrefix           string
	Method               string
	CredentialBindingRef string
}

// Registry 是批准过的 Provider 登记表。Document 是解码后的整份 JSON，用来算摘要。
type Registry struct {
	Version              string
	DefaultDecision      string
	RegisteredOperations []RegistryRow
	Document             any
}

// CompiledArtifacts 是一次编译的确定字节和摘要。
type CompiledArtifacts struct {
	GatewayYAML   []byte
	PolicyJSON    []byte
	GatewaySHA256 string
	PolicySHA256  string
	RouteCount    int
}
