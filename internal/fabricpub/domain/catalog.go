package domain

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"sort"
)

// PoolBase 是只读的出站 CompileSpec。形状与编译器的输入一致，本包不导入编译器。
type PoolBase struct {
	Pool     PoolSpec     `json:"pool"`
	Provider ProviderSpec `json:"provider"`
	Access   AccessSpec   `json:"access"`
	Routes   []RouteSpec  `json:"routes"`
}

// PoolSpec 是这份目录所在的出站池。
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
	Tracing           *TracingSpec   `json:"tracing,omitempty"`
}

// FrontendLimit 是池入口的并发上限。
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

// AccessLogSpec 的表达式原样留在规格里。
type AccessLogSpec struct {
	ProviderReferenceExpr string `json:"provider_reference_expr"`
	ProviderRequestExpr   string `json:"provider_request_expr"`
}

// ProviderSpec 是这一家承运商的上游和凭证方案。
type ProviderSpec struct {
	ProviderID               string            `json:"provider_id"`
	PolicyVersion            string            `json:"policy_version"`
	EnforceTLSUpstream       bool              `json:"enforce_tls_upstream"`
	CredentialScheme         string            `json:"credential_scheme"`
	CredentialBindingRef     string            `json:"credential_binding_ref"`
	CredentialHeader         string            `json:"credential_header,omitempty"`
	CredentialQueryParameter string            `json:"credential_query_parameter,omitempty"`
	UpstreamHost             string            `json:"upstream_host"`
	UpstreamPort             int               `json:"upstream_port"`
	RewriteAuthority         string            `json:"rewrite_authority"`
	BackendTLS               *BackendTLSSpec   `json:"backend_tls,omitempty"`
	SetRequestHeaders        map[string]string `json:"set_request_headers,omitempty"`
	RouteTimeout             string            `json:"route_timeout"`
	PlainHTTPSandboxHost     string            `json:"plain_http_sandbox_host,omitempty"`
	InternalBackendHost      string            `json:"internal_backend_host,omitempty"`
	LocalRateLimit           []RateLimitSpec   `json:"local_rate_limit,omitempty"`
}

// BackendTLSSpec 只写校验用的主机名。
type BackendTLSSpec struct {
	Hostname string `json:"hostname"`
}

// RateLimitSpec 是一条本地限流。
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

// RouteSpec 是目录里的一条路由，带上编译器要、而 RouteIntent 没有的字段。
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

// TracingSpec 是可选的追踪端点。原样保留，好让合并后的规格仍能通过编译器。
type TracingSpec struct {
	Host           string   `json:"host"`
	Protocol       string   `json:"protocol,omitempty"`
	Path           string   `json:"path,omitempty"`
	ServiceName    string   `json:"service_name"`
	RandomSampling *float64 `json:"random_sampling,omitempty"`
	ClientSampling *float64 `json:"client_sampling,omitempty"`
}

// AcceptedIntent 是已经并进有效集的一条意图，带上目录里才能编译的字段。
type AcceptedIntent struct {
	IntentID                string `json:"intent_id"`
	OperationID             string `json:"operation_id"`
	Method                  string `json:"method"`
	LogicalPath             string `json:"logical_path"`
	CredentialBindingRef    string `json:"credential_binding_ref"`
	UpstreamHostname        string `json:"upstream_hostname"`
	UpstreamPort            int    `json:"upstream_port"`
	UpstreamTLS             string `json:"upstream_tls"`
	AuthzProfile            string `json:"authz_profile"`
	ApprovalRef             string `json:"approval_ref"`
	ExpectedGeneration      int    `json:"expected_generation"`
	RedirectPolicy          string `json:"redirect_policy"`
	ProviderAccountStrategy string `json:"provider_account_strategy"`
	Transport               string `json:"transport"`
	PolicyBundleRef         string `json:"policy_bundle_ref"`
	UpstreamSNI             string `json:"upstream_sni,omitempty"`
	ContractRef             string `json:"contract_ref"`
	RouteID                 string `json:"route_id"`
	PathMatchMode           string `json:"path_match_mode"`
	RewritePathPrefix       string `json:"rewrite_path_prefix"`
}

// ParsePoolBase 读取 --pool-base。入口和 AI 规格拒绝；未知字段、敏感键、环境变量引用拒绝。
func ParsePoolBase(data []byte) (PoolBase, error) {
	doc, err := parseDocument(data)
	if err != nil {
		return PoolBase{}, err
	}
	if _, ok := asObject(doc.Value); !ok {
		return PoolBase{}, invalid("catalog")
	}
	if err := rejectTrafficClass(doc.Value); err != nil {
		return PoolBase{}, err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var base PoolBase
	if err := dec.Decode(&base); err != nil {
		return PoolBase{}, invalid("catalog")
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return PoolBase{}, invalid("catalog")
	}
	if err := validateCatalog(base); err != nil {
		return PoolBase{}, err
	}
	return base, nil
}

func rejectTrafficClass(v any) error {
	switch t := v.(type) {
	case map[string]any:
		if class, ok := t["traffic_class"].(string); ok && (class == "INGRESS" || class == "AI") {
			return invalid("catalog")
		}
		for _, child := range t {
			if err := rejectTrafficClass(child); err != nil {
				return err
			}
		}
	case []any:
		for _, child := range t {
			if err := rejectTrafficClass(child); err != nil {
				return err
			}
		}
	}
	return nil
}

func validateCatalog(base PoolBase) error {
	if base.Pool.Name == "" || base.Pool.Environment == "" || base.Provider.ProviderID == "" {
		return invalid("catalog")
	}
	if len(base.Routes) == 0 {
		return invalid("catalog")
	}
	seenRoute := map[string]struct{}{}
	seenOp := map[string]struct{}{}
	for _, route := range base.Routes {
		if !routeID(route.RouteID) || !reOperationID.MatchString(route.OperationID) {
			return invalid("catalog")
		}
		if _, ok := allowedMethods[route.Method]; !ok {
			return invalid("catalog")
		}
		if !reCanonical.MatchString(route.LogicalPath) || !reCanonical.MatchString(route.RewritePathPrefix) {
			return invalid("catalog")
		}
		if route.PathMatchMode != "exact" && route.PathMatchMode != "one_segment" {
			return invalid("catalog")
		}
		if _, dup := seenRoute[route.RouteID]; dup {
			return invalid("catalog")
		}
		seenRoute[route.RouteID] = struct{}{}
		key := route.OperationID + "\x00" + route.Method
		if _, dup := seenOp[key]; dup {
			return invalid("catalog")
		}
		seenOp[key] = struct{}{}
	}
	return nil
}

func routeID(id string) bool {
	if id == "" || id[0] < 'a' || id[0] > 'z' || len(id) > 64 {
		return false
	}
	for _, c := range id[1:] {
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-':
		default:
			return false
		}
	}
	return true
}

// Merge 把 incoming 并进该池当前有效意图，产出整份出站 CompileSpec JSON。
// nextPolicyVersion 写进 provider.policy_version，每次发布都要换一个新值。
func Merge(base PoolBase, active []AcceptedIntent, incoming Envelope, targetID, nextPolicyVersion string) ([]byte, []AcceptedIntent, error) {
	if nextPolicyVersion == "" || incoming.TargetID != targetID {
		return nil, nil, invalid("catalog")
	}
	if incoming.Intent.GatewayPool != base.Pool.Name || incoming.Intent.Environment != base.Pool.Environment ||
		incoming.Intent.ProviderID != base.Provider.ProviderID {
		return nil, nil, invalid("catalog")
	}
	fresh, err := accept(base, incoming.Intent)
	if err != nil {
		return nil, nil, err
	}
	next := make([]AcceptedIntent, 0, len(active)+1)
	replaced := false
	for _, item := range active {
		if item.IntentID == fresh.IntentID {
			next = append(next, fresh)
			replaced = true
			continue
		}
		checked, err := recheck(base, item)
		if err != nil {
			return nil, nil, err
		}
		next = append(next, checked)
	}
	if !replaced {
		next = append(next, fresh)
	}
	type placed struct {
		index  int
		intent AcceptedIntent
	}
	placedItems := make([]placed, 0, len(next))
	used := map[int]string{}
	for _, item := range next {
		index, route, ok := findCatalog(base.Routes, item.OperationID, item.Method)
		if !ok {
			return nil, nil, invalid("catalog")
		}
		if other, taken := used[index]; taken && other != item.IntentID {
			return nil, nil, invalid("catalog")
		}
		used[index] = item.IntentID
		if route.LogicalPath != item.LogicalPath || route.RouteID != item.RouteID ||
			route.PathMatchMode != item.PathMatchMode || route.RewritePathPrefix != item.RewritePathPrefix ||
			route.UpstreamTLS != item.UpstreamTLS {
			return nil, nil, invalid("catalog")
		}
		placedItems = append(placedItems, placed{index: index, intent: item})
	}
	sort.Slice(placedItems, func(i, j int) bool {
		if placedItems[i].index != placedItems[j].index {
			return placedItems[i].index < placedItems[j].index
		}
		return placedItems[i].intent.IntentID < placedItems[j].intent.IntentID
	})
	spec := base
	spec.Provider.PolicyVersion = nextPolicyVersion
	spec.Routes = make([]RouteSpec, 0, len(placedItems))
	ordered := make([]AcceptedIntent, 0, len(placedItems))
	for _, item := range placedItems {
		spec.Routes = append(spec.Routes, routeFrom(item.intent))
		ordered = append(ordered, item.intent)
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(spec); err != nil {
		return nil, nil, invalid("catalog")
	}
	return buf.Bytes(), ordered, nil
}

func accept(base PoolBase, in Intent) (AcceptedIntent, error) {
	if in.CredentialBindingRef != base.Provider.CredentialBindingRef {
		return AcceptedIntent{}, invalid("catalog")
	}
	if in.UpstreamPort != base.Provider.UpstreamPort || !upstreamHost(base.Provider, in.UpstreamHostname) {
		return AcceptedIntent{}, invalid("catalog")
	}
	_, route, ok := findCatalog(base.Routes, in.OperationID, in.AllowedMethods[0])
	if !ok {
		return AcceptedIntent{}, invalid("catalog")
	}
	if route.LogicalPath != in.LogicalPath || route.UpstreamTLS != in.UpstreamTLS {
		return AcceptedIntent{}, invalid("catalog")
	}
	return AcceptedIntent{
		IntentID: in.IntentID, OperationID: in.OperationID, Method: in.AllowedMethods[0],
		LogicalPath: in.LogicalPath, CredentialBindingRef: in.CredentialBindingRef,
		UpstreamHostname: in.UpstreamHostname, UpstreamPort: in.UpstreamPort, UpstreamTLS: in.UpstreamTLS,
		AuthzProfile: in.AuthzProfile, ApprovalRef: in.ApprovalRef, ExpectedGeneration: in.ExpectedGeneration,
		RedirectPolicy: in.RedirectPolicy, ProviderAccountStrategy: in.ProviderAccountStrategy,
		Transport: in.Transport, PolicyBundleRef: in.PolicyBundleRef, UpstreamSNI: in.UpstreamSNI,
		ContractRef: in.ContractRef, RouteID: route.RouteID, PathMatchMode: route.PathMatchMode,
		RewritePathPrefix: route.RewritePathPrefix,
	}, nil
}

func recheck(base PoolBase, item AcceptedIntent) (AcceptedIntent, error) {
	if item.CredentialBindingRef != base.Provider.CredentialBindingRef || item.UpstreamPort != base.Provider.UpstreamPort {
		return AcceptedIntent{}, invalid("catalog")
	}
	if !upstreamHost(base.Provider, item.UpstreamHostname) {
		return AcceptedIntent{}, invalid("catalog")
	}
	_, route, ok := findCatalog(base.Routes, item.OperationID, item.Method)
	if !ok || route.LogicalPath != item.LogicalPath || route.RouteID != item.RouteID ||
		route.PathMatchMode != item.PathMatchMode || route.RewritePathPrefix != item.RewritePathPrefix ||
		route.UpstreamTLS != item.UpstreamTLS {
		return AcceptedIntent{}, invalid("catalog")
	}
	return item, nil
}

func findCatalog(routes []RouteSpec, operation, method string) (int, RouteSpec, bool) {
	for i, route := range routes {
		if route.OperationID == operation && route.Method == method {
			return i, route, true
		}
	}
	return 0, RouteSpec{}, false
}

// upstreamHost 核对意图里的上游主机。直连承运商必须等于 upstream_host。
// 顺丰这种内部签名器同时接受 upstream_host（provider-signer）和 rewrite_authority（对外的 DNS 名）。
func upstreamHost(provider ProviderSpec, host string) bool {
	if provider.InternalBackendHost != "" {
		return host == provider.UpstreamHost || host == provider.RewriteAuthority
	}
	return host == provider.UpstreamHost
}

func routeFrom(item AcceptedIntent) RouteSpec {
	return RouteSpec{
		IntentID: item.IntentID, RouteID: item.RouteID, OperationID: item.OperationID, Method: item.Method,
		LogicalPath: item.LogicalPath, PathMatchMode: item.PathMatchMode, RewritePathPrefix: item.RewritePathPrefix,
		ExpectedGeneration: item.ExpectedGeneration, ApprovalRef: item.ApprovalRef, AuthzProfile: item.AuthzProfile,
		RedirectPolicy: item.RedirectPolicy, UpstreamTLS: item.UpstreamTLS,
		ProviderAccountStrategy: item.ProviderAccountStrategy, Transport: item.Transport,
		PolicyBundleRef: item.PolicyBundleRef,
	}
}
