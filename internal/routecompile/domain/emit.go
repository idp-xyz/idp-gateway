package domain

import (
	"bytes"
	"encoding/json"
	"sort"
	"strconv"
	"strings"
)

// 配置文本用单引号包住每一个字符串。解析之后与手写的那份相同，字节本身则每次都一样。
type ykind int

const (
	yMap ykind = iota
	ySeq
	yStr
	yInt
)

type ynode struct {
	kind  ykind
	str   string
	n     int
	pairs []ypair
	items []*ynode
}

type ypair struct {
	key string
	val *ynode
}

func ys(s string) *ynode { return &ynode{kind: yStr, str: s} }
func yi(n int) *ynode    { return &ynode{kind: yInt, n: n} }
func ym(pairs ...ypair) *ynode {
	return &ynode{kind: yMap, pairs: pairs}
}
func yq(items ...*ynode) *ynode       { return &ynode{kind: ySeq, items: items} }
func yp(key string, val *ynode) ypair { return ypair{key: key, val: val} }

func emitGateway(spec CompileSpec) []byte {
	routes := make([]*ynode, 0, len(spec.Routes)+1)
	for _, route := range spec.Routes {
		routes = append(routes, businessRoute(spec, route))
	}
	routes = append(routes, readBackRoute(spec.Pool.AdminAddr))
	root := ym(
		yp("config", ym(
			yp("adminAddr", ys(spec.Pool.AdminAddr)),
			yp("statsAddr", ys(spec.Pool.StatsAddr)),
			yp("readinessAddr", ys(spec.Pool.ReadinessAddr)),
			yp("storage", ym(yp("mode", ys("readOnly")))),
		)),
		yp("frontendPolicies", frontend(spec)),
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
		yp("routes", yq(routes...)),
	)
	var buf bytes.Buffer
	root.write(&buf, 0, false)
	return buf.Bytes()
}

func frontend(spec CompileSpec) *ynode {
	pairs := []ypair{
		yp("networkAuthorization", ym(
			yp("rules", yq(
				ym(yp("allow", ys("destination.port == "+strconv.Itoa(spec.Pool.ListenPort)))),
				ym(yp("allow", ys("destination.port == "+strconv.Itoa(spec.Pool.ReadbackPort)+" && source.spiffeId == "+strconv.Quote(spec.Pool.PublisherIdentity)))),
			)),
		)),
		yp("accessLog", ym(
			yp("add", ym(
				yp("authz_decision_id", ys(fixedAuthzDecision)),
				yp("tenant_ref", ys(fixedTenantRef)),
				yp("provider_reference_id", ys(spec.Pool.AccessLog.ProviderReferenceExpr)),
				yp("provider_request_id", ys(spec.Pool.AccessLog.ProviderRequestExpr)),
			)),
		)),
	}
	if lim := spec.Pool.FrontendLimits; lim != nil {
		if lim.MaxConcurrentRequests != nil {
			pairs = append(pairs, yp("http", ym(yp("maxConcurrentRequests", yi(*lim.MaxConcurrentRequests)))))
		}
		if lim.MaxConnections != nil {
			pairs = append(pairs, yp("tcp", ym(yp("maxConnections", yi(*lim.MaxConnections)))))
		}
	}
	return ym(pairs...)
}

func businessRoute(spec CompileSpec, route RouteSpec) *ynode {
	policies := []ypair{
		yp("authorization", ym(yp("rules", yq(ym(yp("allow", ys(pathRule(route)))))))),
		yp("extAuthz", extAuthz(spec, route)),
		yp("urlRewrite", ym(
			yp("authority", ym(yp("full", ys(spec.Provider.RewriteAuthority)))),
			yp("path", ym(yp("prefix", ys(route.RewritePathPrefix)))),
		)),
		yp("responseHeaderModifier", ym(yp("remove", stringSeq(removedResponseHeaders)))),
		yp("timeout", ym(yp("requestTimeout", ys(spec.Provider.RouteTimeout)))),
	}
	if len(spec.Provider.LocalRateLimit) > 0 {
		policies = append(policies, yp("localRateLimit", rateLimits(spec.Provider.LocalRateLimit)))
	}
	return ym(
		yp("name", ys(route.RouteID)),
		yp("gateways", stringSeq([]string{spec.Pool.Name})),
		yp("hostnames", stringSeq([]string{spec.Pool.CallerHostname})),
		yp("matches", yq(ym(
			yp("path", ym(yp("pathPrefix", ys(route.LogicalPath)))),
			yp("method", ys(route.Method)),
		))),
		yp("policies", ym(policies...)),
		yp("backends", yq(ym(
			yp("host", ys(spec.Provider.UpstreamHost+":"+strconv.Itoa(spec.Provider.UpstreamPort))),
			yp("policies", backendPolicies(spec)),
		))),
	)
}

func extAuthz(spec CompileSpec, route RouteSpec) *ynode {
	env := strconv.Quote(spec.Pool.Environment)
	// PDP 那一跳只有一种写法：凭证在 Authorization 应答头里（contracts/gatekeeper/openapi.yaml）。
	// 默认把这个头复制到上游请求上。凭证要放在别处时不复制，只把它读进 extauthz.credential。
	metadata := []ypair{yp("decision_id", ys(`response.headers["x-idp-decision-id"]`))}
	var copyHeaders []ypair
	if spec.Provider.placement().copied() {
		copyHeaders = []ypair{yp("includeResponseHeaders", stringSeq([]string{"authorization"}))}
	} else {
		metadata = append(metadata, yp("credential", ys(`response.headers["authorization"]`)))
	}
	exchange := append([]ypair{
		yp("path", ys(strconv.Quote("/v1/extauthz/check"))),
		yp("addRequestHeaders", ym(
			yp("x-idp-verified-subject", ys("jwt.sub")),
			yp("x-idp-verified-tenant", ys("jwt.tenant_id")),
			yp("x-idp-verified-env", ys(env)),
			yp("x-idp-route-id", ys(strconv.Quote(route.RouteID))),
			yp("x-idp-provider-id", ys(strconv.Quote(spec.Provider.ProviderID))),
			yp("x-idp-operation-id", ys(strconv.Quote(route.OperationID))),
			yp("x-idp-environment", ys(env)),
			yp("x-idp-method", ys("request.method")),
			yp("x-idp-path", ys("request.path")),
			yp("traceparent", ys(`request.headers["traceparent"]`)),
		)),
		yp("metadata", ym(metadata...)),
	}, copyHeaders...)
	return ym(
		yp("host", ys(spec.Pool.ExtAuthz.Host)),
		yp("failureMode", ym(yp("denyWithStatus", yi(503)))),
		yp("includeRequestHeaders", stringSeq([]string{"x-provider-account"})),
		yp("policies", ym(
			yp("backendTLS", certBundle(spec.Pool.TLSDir, spec.Pool.ExtAuthz.Hostname)),
			yp("http", ym(yp("requestTimeout", ys(spec.Pool.ExtAuthz.Timeout)))),
		)),
		yp("protocol", ym(yp("http", ym(exchange...)))),
	)
}

func backendPolicies(spec CompileSpec) *ynode {
	var pairs []ypair
	if spec.Provider.BackendTLS != nil {
		pairs = append(pairs, yp("backendTLS", certBundle(spec.Pool.TLSDir, spec.Provider.BackendTLS.Hostname)))
	}
	placement := spec.Provider.placement()
	scheme := spec.Provider.CredentialScheme
	if placement.copied() {
		pairs = append(pairs,
			yp("authorization", ym(yp("rules", yq(ym(yp("allow", ys(backendAuthRule(scheme)))))))),
			yp("transformations", ym(yp("request", ym(yp("replace", ys(reviewedHeaderFilter)))))),
		)
	} else {
		// 这条规则在 backendAuth 之前求值：那时凭证还不在请求上，所以看的是 extauthz.credential。
		// backendAuth 把去掉方案前缀的值放到指定位置，调用方自带的同名头或参数被换掉。
		// 转发名单在 backendAuth 之后求值，所以凭证头要列在里面；Authorization 不在里面。
		pairs = append(pairs,
			yp("authorization", ym(yp("rules", yq(ym(yp("allow", ys(placedCredentialRule(scheme)))))))),
			yp("backendAuth", ym(yp("key", ym(
				yp("expression", ys("extauthz.credential.stripPrefix("+strconv.Quote(scheme)+")")),
				yp("location", placement.location()),
			)))),
			yp("transformations", ym(yp("request", ym(yp("replace", ys(placedHeaderFilter(placement))))))),
		)
	}
	header := []ypair{yp("remove", stringSeq(removedRequestHeaders))}
	if len(spec.Provider.SetRequestHeaders) > 0 {
		header = append([]ypair{yp("set", stringMap(spec.Provider.SetRequestHeaders))}, header...)
	}
	pairs = append(pairs, yp("requestHeaderModifier", ym(header...)))
	return ym(pairs...)
}

// readBackRoute 是回读口上的那一条。出站、入口和 AI 用同一条：发布器靠它读
// GET /config_dump 和 GET /api/runtime，转到 adminAddr。它不是业务路由。
func readBackRoute(adminAddr string) *ynode {
	return ym(
		yp("name", ys("read-back")),
		yp("gateways", stringSeq([]string{"read-back"})),
		yp("matches", yq(
			ym(yp("path", ym(yp("exact", ys("/config_dump")))), yp("method", ys("GET"))),
			ym(yp("path", ym(yp("exact", ys("/api/runtime")))), yp("method", ys("GET"))),
		)),
		yp("policies", ym(yp("timeout", ym(yp("requestTimeout", ys("2s")))))),
		yp("backends", yq(ym(yp("host", ys(adminAddr))))),
	)
}

func rateLimits(limits []RateLimitSpec) *ynode {
	items := make([]*ynode, len(limits))
	for i, limit := range limits {
		pairs := []ypair{
			yp("maxTokens", yi(limit.MaxTokens)),
			yp("tokensPerFill", yi(limit.TokensPerFill)),
			yp("fillInterval", ys(limit.FillInterval)),
		}
		if limit.Key != "" {
			pairs = append(pairs, yp("key", ys(limit.Key)))
		}
		items[i] = ym(pairs...)
	}
	return yq(items...)
}

func certBundle(dir, hostname string) *ynode {
	return ym(
		yp("cert", ys(tlsPath(dir, "gateway.crt"))),
		yp("key", ys(tlsPath(dir, "gateway.key"))),
		yp("root", ys(tlsPath(dir, "ca.crt"))),
		yp("hostname", ys(hostname)),
	)
}

func stringSeq(values []string) *ynode {
	items := make([]*ynode, len(values))
	for i, value := range values {
		items[i] = ys(value)
	}
	return yq(items...)
}

func stringMap(values map[string]string) *ynode {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	pairs := make([]ypair, len(keys))
	for i, key := range keys {
		pairs[i] = yp(key, ys(values[key]))
	}
	return ym(pairs...)
}

func tlsPath(dir, name string) string {
	return strings.TrimRight(dir, "/") + "/" + name
}

func pathRule(route RouteSpec) string {
	if route.PathMatchMode == "one_segment" {
		pattern := "^" + regexEscape(route.LogicalPath) + "/[A-Za-z0-9][A-Za-z0-9._-]*$"
		return "request.path.matches(" + strconv.Quote(pattern) + ")"
	}
	return "request.path == " + strconv.Quote(route.LogicalPath)
}

// placement 是通过了 specIssues 的规格里凭证的位置。规格没有通过检查时回到默认的 Authorization。
func (p ProviderSpec) placement() credentialPlacement {
	placement, err := placementOf(p)
	if err != nil {
		return credentialPlacement{header: "authorization"}
	}
	return placement
}

// location 是 backendAuth 放凭证的地方。只用在不复制响应头的两种位置上。
func (p credentialPlacement) location() *ynode {
	if p.query != "" {
		return ym(yp("queryParameter", ym(yp("name", ys(p.query)))))
	}
	return ym(yp("header", ym(yp("name", ys(p.header)))))
}

// placedHeaderFilter 是凭证不在 Authorization 里时转发给上游的请求头名单。
// 里面没有 authorization：这种路由上，上游不该收到这个头。
func placedHeaderFilter(p credentialPlacement) string {
	names := []string{"accept", "content-type", "idempotency-key", "traceparent", "x-client-trace"}
	if p.query == "" {
		names = append(names, p.header)
	}
	sort.Strings(names)
	return `request.headers.filterKeys(k, k in ["` + strings.Join(names, `", "`) + `"])`
}

func backendAuthRule(scheme string) string {
	return "request.headers[" + strconv.Quote("authorization") + "].startsWith(" + strconv.Quote(scheme) + ")"
}

// placedCredentialRule 要求 PDP 交出了凭证、方案前缀对得上、前缀后面还有内容。
// 没有交出凭证时 extauthz.credential 不存在，这条规则不放行，调用方自带的值到不了上游。
func placedCredentialRule(scheme string) string {
	return "has(extauthz.credential) && extauthz.credential.startsWith(" + strconv.Quote(scheme) +
		") && size(extauthz.credential) > " + strconv.Itoa(len(scheme))
}

func regexEscape(path string) string {
	var b strings.Builder
	for _, r := range path {
		if strings.ContainsRune(`.+*?()[]{}^$|\`, r) {
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	return b.String()
}

func (n *ynode) write(b *bytes.Buffer, indent int, inline bool) {
	switch n.kind {
	case yMap:
		for i, pair := range n.pairs {
			if !(inline && i == 0) {
				b.WriteString(strings.Repeat(" ", indent))
			}
			b.WriteString(pair.key)
			b.WriteByte(':')
			switch pair.val.kind {
			case ySeq:
				b.WriteByte('\n')
				pair.val.write(b, indent, false)
			case yMap:
				b.WriteByte('\n')
				pair.val.write(b, indent+2, false)
			default:
				b.WriteByte(' ')
				pair.val.writeScalar(b)
				b.WriteByte('\n')
			}
		}
	case ySeq:
		for _, item := range n.items {
			b.WriteString(strings.Repeat(" ", indent))
			b.WriteString("- ")
			switch item.kind {
			case yMap:
				item.write(b, indent+2, true)
			case ySeq:
				b.WriteByte('\n')
				item.write(b, indent+2, false)
			default:
				item.writeScalar(b)
				b.WriteByte('\n')
			}
		}
	default:
		n.writeScalar(b)
	}
}

func (n *ynode) writeScalar(b *bytes.Buffer) {
	switch n.kind {
	case yInt:
		b.WriteString(strconv.Itoa(n.n))
	default:
		b.WriteByte('\'')
		b.WriteString(strings.ReplaceAll(n.str, "'", "''"))
		b.WriteByte('\'')
	}
}

func emitPolicy(spec CompileSpec) []byte {
	doc := policyDocument{
		Version:                      spec.Provider.PolicyVersion,
		DefaultDecision:              "DENY",
		AllowRequestRedirects:        false,
		EnforceTLSUpstream:           spec.Provider.EnforceTLSUpstream,
		GatewayMayRetryNonIdempotent: false,
		Notes:                        spec.Access.PolicyNotes,
		BlockedIPRanges:              append([]string(nil), spec.Access.BlockedIPRanges...),
	}
	for _, route := range spec.Routes {
		doc.RegisteredOperations = append(doc.RegisteredOperations, policyRow{
			RouteID:              route.RouteID,
			ProviderID:           spec.Provider.ProviderID,
			OperationID:          route.OperationID,
			Environment:          spec.Pool.Environment,
			Method:               route.Method,
			PathPrefix:           route.LogicalPath,
			UpstreamHostname:     spec.Provider.UpstreamHost,
			Port:                 spec.Provider.UpstreamPort,
			CredentialBindingRef: spec.Provider.CredentialBindingRef,
			AllowedTenants:       append([]string(nil), spec.Access.AllowedTenants...),
			AccountsByTenant:     copyAccounts(spec.Access.AccountsByTenant),
			AllowedServiceIDs:    append([]string(nil), spec.Access.AllowedServiceIDs...),
		})
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(doc); err != nil {
		// 这个结构体没有循环，编码失败是程序错误，不能当成一份空策略交出去。
		panic(err)
	}
	return buf.Bytes()
}

type policyDocument struct {
	Version                      string      `json:"version"`
	DefaultDecision              string      `json:"default_decision"`
	RegisteredOperations         []policyRow `json:"registered_operations"`
	BlockedIPRanges              []string    `json:"blocked_ip_ranges,omitempty"`
	AllowRequestRedirects        bool        `json:"allow_request_redirects"`
	EnforceTLSUpstream           bool        `json:"enforce_tls_upstream"`
	GatewayMayRetryNonIdempotent bool        `json:"gateway_may_retry_non_idempotent"`
	Notes                        string      `json:"notes,omitempty"`
}

type policyRow struct {
	RouteID              string              `json:"route_id"`
	ProviderID           string              `json:"provider_id"`
	OperationID          string              `json:"operation_id"`
	Environment          string              `json:"environment"`
	Method               string              `json:"method"`
	PathPrefix           string              `json:"path_prefix"`
	UpstreamHostname     string              `json:"upstream_hostname"`
	Port                 int                 `json:"port"`
	CredentialBindingRef string              `json:"credential_binding_ref"`
	AllowedTenants       []string            `json:"allowed_tenants"`
	AccountsByTenant     map[string][]string `json:"accounts_by_tenant"`
	AllowedServiceIDs    []string            `json:"allowed_service_ids"`
}

func copyAccounts(in map[string][]string) map[string][]string {
	out := make(map[string][]string, len(in))
	for key, values := range in {
		out[key] = append([]string(nil), values...)
	}
	return out
}
