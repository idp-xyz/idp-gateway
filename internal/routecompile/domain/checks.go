package domain

import (
	"bytes"
	"encoding/json"
	"strconv"
	"strings"
	"time"
)

func specIssues(spec CompileSpec) []Issue {
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
	issues = append(issues, poolIssues(spec.Pool)...)
	issues = append(issues, providerIssues(spec.Provider)...)
	issues = append(issues, accessIssues(spec.Access)...)
	if len(spec.Routes) == 0 {
		add("NO_ROUTES", "at least one route is required")
	}
	seenID := map[string]struct{}{}
	for i, route := range spec.Routes {
		issues = append(issues, routeIssues(spec, i, route)...)
		if route.RouteID != "" {
			if _, ok := seenID[route.RouteID]; ok {
				add("DUPLICATE_ROUTE", "route id "+route.RouteID+" is repeated")
			}
			seenID[route.RouteID] = struct{}{}
		}
	}
	return issues
}

func poolIssues(pool PoolSpec) []Issue {
	var issues []Issue
	add := func(code, reason string) { issues = append(issues, Issue{Code: code, Reason: reason}) }
	match := rePoolName.FindStringSubmatch(pool.Name)
	if match == nil || match[1] != "egress" || strings.ToUpper(match[2]) != pool.Environment {
		add("POOL_CLASS_ENVIRONMENT_MISMATCH", "pool name must be egress-<environment>")
	}
	if _, ok := environments[pool.Environment]; !ok {
		add("ENVIRONMENT", "environment must be DEV, TEST, or PROD")
	}
	if !reHostname.MatchString(pool.CallerHostname) {
		add("CALLER_HOSTNAME", "caller_hostname is not a DNS name")
	}
	if pool.ListenPort < 1 || pool.ListenPort > 65535 {
		add("LISTEN_PORT", "listen_port is out of range")
	}
	if pool.BindAddress != "127.0.0.1" {
		add("BIND_ADDRESS", "bind_address must be 127.0.0.1")
	}
	if pool.ReadbackPort < 1 || pool.ReadbackPort > 65535 || pool.ReadbackPort == pool.ListenPort {
		add("READBACK_PORT", "readback_port must be a distinct TCP port")
	}
	admin, stats, ready := loopbackPort(pool.AdminAddr), loopbackPort(pool.StatsAddr), loopbackPort(pool.ReadinessAddr)
	if admin == 0 || stats == 0 || ready == 0 || admin == stats || admin == ready || stats == ready {
		add("ADMIN_ADDR", "admin_addr, stats_addr and readiness_addr must be distinct 127.0.0.1:port values")
	}
	if !strings.HasPrefix(pool.PublisherIdentity, "spiffe://") || strings.ContainsAny(pool.PublisherIdentity, " \"\\$'\n\r\t") {
		add("PUBLISHER_IDENTITY", "publisher_identity must be a spiffe id without quotes or references")
	}
	if !relativePath(pool.TLSDir) || !relativePath(pool.JWKSFile) {
		add("TLS_PATH", "tls_dir and jwks_file must be relative paths")
	}
	if pool.JWTIssuer == "" || strings.ContainsAny(pool.JWTIssuer, " \n\r\t") {
		add("JWT_ISSUER", "jwt_issuer is empty or contains whitespace")
	}
	if len(pool.JWTAudiences) == 0 {
		add("JWT_AUDIENCE", "jwt_audiences must not be empty")
	}
	for _, audience := range pool.JWTAudiences {
		if audience == "" || strings.ContainsAny(audience, " \n\r\t") {
			add("JWT_AUDIENCE", "jwt audience is empty or contains whitespace")
		}
	}
	if pool.ExtAuthz.Host == "" || strings.ContainsAny(pool.ExtAuthz.Host, " \n\r\t") || !reHostname.MatchString(pool.ExtAuthz.Hostname) {
		add("EXT_AUTHZ", "ext_authz host and hostname are not acceptable")
	}
	if !durationUnder(pool.ExtAuthz.Timeout, 10*time.Second) {
		add("EXT_AUTHZ_TIMEOUT", "ext_authz timeout must be greater than 0 and less than 10s")
	}
	if pool.AccessLog.ProviderReferenceExpr == "" || pool.AccessLog.ProviderRequestExpr == "" ||
		strings.ContainsAny(pool.AccessLog.ProviderReferenceExpr, "\n\r") || strings.ContainsAny(pool.AccessLog.ProviderRequestExpr, "\n\r") {
		add("ACCESS_LOG", "access log expressions must be single-line and non-empty")
	}
	if pool.FrontendLimits != nil {
		lim := pool.FrontendLimits
		if lim.MaxConcurrentRequests == nil && lim.MaxConnections == nil {
			add("FRONTEND_LIMITS", "frontend_limits is empty")
		}
		if lim.MaxConcurrentRequests != nil && (*lim.MaxConcurrentRequests < 1 || *lim.MaxConcurrentRequests > 1_000_000) {
			add("FRONTEND_LIMITS", "max_concurrent_requests must be from 1 to 1000000")
		}
		if lim.MaxConnections != nil && (*lim.MaxConnections < 1 || *lim.MaxConnections > 1_000_000) {
			add("FRONTEND_LIMITS", "max_connections must be from 1 to 1000000")
		}
	}
	return issues
}

func providerIssues(p ProviderSpec) []Issue {
	var issues []Issue
	add := func(code, reason string) { issues = append(issues, Issue{Code: code, Reason: reason}) }
	if !reProviderID.MatchString(p.ProviderID) {
		add("PROVIDER_ID", "provider_id does not match the provider id pattern")
	}
	if p.PolicyVersion == "" || strings.ContainsAny(p.PolicyVersion, "\n\r") {
		add("POLICY_VERSION", "policy_version is empty")
	}
	if !credentialSchemePattern.MatchString(p.CredentialScheme) {
		add("CREDENTIAL_SCHEME", "credential_scheme must be a token followed by a single space")
	}
	if !strings.HasPrefix(p.CredentialBindingRef, "gatekeeper:") {
		add("CREDENTIAL_BINDING", "credential_binding_ref must start with gatekeeper:")
	}
	if p.UpstreamPort < 1 || p.UpstreamPort > 65535 {
		add("UPSTREAM_PORT", "upstream_port is out of range")
	}
	if !reHostname.MatchString(p.RewriteAuthority) {
		add("REWRITE_AUTHORITY", "rewrite_authority is not a DNS name")
	}
	if !durationUnder(p.RouteTimeout, 10*time.Second) {
		add("ROUTE_TIMEOUT", "route timeout must be greater than 0 and less than 10s")
	}
	if p.PlainHTTPSandboxHost != "" && p.InternalBackendHost != "" {
		add("UPSTREAM_EXCEPTION", "plain_http_sandbox_host and internal_backend_host cannot both be set")
	}
	switch {
	case p.PlainHTTPSandboxHost != "":
		if p.PlainHTTPSandboxHost != p.UpstreamHost || !reHostname.MatchString(p.PlainHTTPSandboxHost) {
			add("PLAIN_HTTP_HOST_MISMATCH", "plain_http_sandbox_host must be the upstream host")
		}
	case p.InternalBackendHost != "":
		if p.InternalBackendHost != p.UpstreamHost {
			add("INTERNAL_BACKEND_HOST_MISMATCH", "internal_backend_host must be the upstream host")
		}
		if p.BackendTLS == nil || !reHostname.MatchString(p.BackendTLS.Hostname) {
			add("INTERNAL_BACKEND_TLS_REQUIRED", "an internal backend requires backend_tls with a DNS hostname")
		}
	default:
		if !reHostname.MatchString(p.UpstreamHost) {
			add("UPSTREAM_HOST", "upstream_host is not a public DNS name")
		}
		if p.BackendTLS != nil && !reHostname.MatchString(p.BackendTLS.Hostname) {
			add("BACKEND_TLS", "backend_tls hostname is not a DNS name")
		}
	}
	for key, value := range p.SetRequestHeaders {
		if !headerName(key) || value == "" || strings.ContainsAny(value, "\n\r") {
			add("REQUEST_HEADER", "set_request_headers has an unacceptable name or value")
		}
	}
	for _, limit := range p.LocalRateLimit {
		if limit.MaxTokens < 0 || limit.TokensPerFill < 0 || !durationUnder(limit.FillInterval, time.Hour) {
			add("LOCAL_RATE_LIMIT", "local_rate_limit needs a non-negative bucket and a fill interval under 1h")
		}
		if strings.ContainsAny(limit.Key, "\n\r") {
			add("LOCAL_RATE_LIMIT", "local_rate_limit key must be a single line")
		}
	}
	return issues
}

func headerName(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-':
		default:
			return false
		}
	}
	return true
}

func accessIssues(access AccessSpec) []Issue {
	var issues []Issue
	add := func(code, reason string) { issues = append(issues, Issue{Code: code, Reason: reason}) }
	if len(access.AllowedTenants) == 0 || len(access.AllowedServiceIDs) == 0 {
		add("ACCESS", "allowed_tenants and allowed_service_ids must not be empty")
	}
	seen := map[string]struct{}{}
	for _, tenant := range access.AllowedTenants {
		if tenant == "" {
			add("ACCESS", "allowed tenant is empty")
		}
		if _, ok := seen[tenant]; ok {
			add("ACCESS", "allowed tenant is repeated")
		}
		seen[tenant] = struct{}{}
		accounts := access.AccountsByTenant[tenant]
		if len(accounts) == 0 {
			add("ACCESS", "tenant "+tenant+" has no accounts")
		}
	}
	if len(access.AccountsByTenant) != len(seen) {
		add("ACCESS", "accounts_by_tenant must list exactly the allowed tenants")
	}
	for _, id := range access.AllowedServiceIDs {
		if id == "" {
			add("ACCESS", "allowed service id is empty")
		}
	}
	for _, cidr := range access.BlockedIPRanges {
		if !cidrShape(cidr) {
			add("BLOCKED_IP", "blocked_ip_ranges entry is not a CIDR")
		}
	}
	if strings.ContainsAny(access.PolicyNotes, "\n\r") {
		// 承运商样例的备注是一行。多行不是密钥，但会让登记表的形状偏离样例，这里拒绝。
		add("POLICY_NOTES", "policy_notes must be a single line")
	}
	return issues
}

func routeIssues(spec CompileSpec, index int, route RouteSpec) []Issue {
	var issues []Issue
	where := route.RouteID
	if where == "" {
		where = strconv.Itoa(index)
	}
	add := func(code, reason string) {
		issues = append(issues, Issue{Code: code, Reason: where + ": " + reason})
	}
	if !reIntentID.MatchString(route.IntentID) {
		add("INTENT_ID", "intent_id does not match gwi-...")
	}
	if !routeIDPattern(route.RouteID) {
		add("ROUTE_ID", "route_id must be a lowercase token")
	}
	if !reOperationID.MatchString(route.OperationID) {
		add("OPERATION_ID", "operation_id does not match the operation id pattern")
	}
	if _, ok := allowedMethods[route.Method]; !ok {
		add("METHOD", "method is not allowed")
	}
	if !IsCanonicalPath(route.LogicalPath) || !IsCanonicalPath(route.RewritePathPrefix) {
		add("PATH", "logical_path and rewrite_path_prefix must be canonical")
	}
	if route.PathMatchMode != "exact" && route.PathMatchMode != "one_segment" {
		add("PATH_MATCH", "path_match_mode must be exact or one_segment")
	}
	if route.ExpectedGeneration < 0 {
		add("GENERATION", "expected_generation must be >= 0")
	}
	if len(route.ApprovalRef) < 4 || len(route.ApprovalRef) > 128 || len(route.AuthzProfile) < 3 || len(route.AuthzProfile) > 100 {
		add("APPROVAL", "approval_ref or authz_profile has the wrong length")
	}
	if route.RedirectPolicy != RedirectDeny || route.ProviderAccountStrategy != AccountStrategyGatekeeper {
		add("ROUTE_POLICY", "redirect_policy must be DENY and the account strategy must be the gatekeeper binding")
	}
	if route.Transport != "HTTP" && route.Transport != "GRPC" {
		add("TRANSPORT", "transport must be HTTP or GRPC")
	}
	if !rePolicyBundle.MatchString(route.PolicyBundleRef) {
		add("POLICY_BUNDLE", "policy_bundle_ref does not match the policy reference pattern")
	}
	switch {
	case spec.Provider.PlainHTTPSandboxHost != "":
		if route.UpstreamTLS != PlainHTTPSandboxException {
			add("UPSTREAM_TLS", "this sandbox route must use PLAIN_HTTP_SANDBOX_EXCEPTION")
		}
	default:
		if route.UpstreamTLS != TLSVerifyRequired {
			add("UPSTREAM_TLS", "upstream_tls must be VERIFY_REQUIRED")
		}
	}
	return issues
}

func shapeIssues(spec CompileSpec) []Issue {
	var issues []Issue
	for i := 0; i < len(spec.Routes); i++ {
		for j := i + 1; j < len(spec.Routes); j++ {
			a, b := spec.Routes[i], spec.Routes[j]
			if a.Method != b.Method || a.LogicalPath == b.LogicalPath {
				continue
			}
			if strings.HasPrefix(a.LogicalPath, b.LogicalPath) || strings.HasPrefix(b.LogicalPath, a.LogicalPath) {
				issues = append(issues, Issue{
					Code:   "STRING_PREFIX_OVERLAP",
					First:  a.RouteID,
					Second: b.RouteID,
					Paths:  []string{a.LogicalPath, b.LogicalPath},
					Reason: "same method and one path prefix contains the other",
				})
			}
		}
	}
	return issues
}

func (s CompileSpec) preflightOptions() PreflightOptions {
	return PreflightOptions{
		AllowPlainHTTPUpstreamHost: s.Provider.PlainHTTPSandboxHost,
		AllowInternalBackendHost:   s.Provider.InternalBackendHost,
		BackendTLSConfigured:       s.Provider.BackendTLS != nil && s.Provider.BackendTLS.Hostname != "",
	}
}

func (s CompileSpec) intentRaws() []map[string]any {
	out := make([]map[string]any, len(s.Routes))
	for i, route := range s.Routes {
		out[i] = map[string]any{
			"intent_id":                 route.IntentID,
			"gateway_pool":              s.Pool.Name,
			"traffic_class":             ClassEgress,
			"environment":               s.Pool.Environment,
			"provider_id":               s.Provider.ProviderID,
			"operation_id":              route.OperationID,
			"logical_path":              route.LogicalPath,
			"allowed_methods":           []any{route.Method},
			"upstream_hostname":         s.Provider.UpstreamHost,
			"upstream_port":             s.Provider.UpstreamPort,
			"authz_profile":             route.AuthzProfile,
			"approval_ref":              route.ApprovalRef,
			"expected_generation":       route.ExpectedGeneration,
			"credential_binding_ref":    s.Provider.CredentialBindingRef,
			"redirect_policy":           route.RedirectPolicy,
			"upstream_tls":              route.UpstreamTLS,
			"provider_account_strategy": route.ProviderAccountStrategy,
			"transport":                 route.Transport,
			"policy_bundle_ref":         route.PolicyBundleRef,
		}
	}
	return out
}

func (s CompileSpec) syntheticRegistry() *Registry {
	reg := &Registry{Version: s.Provider.PolicyVersion, DefaultDecision: "DENY"}
	rows := make([]any, len(s.Routes))
	for i, route := range s.Routes {
		row := RegistryRow{
			ProviderID: s.Provider.ProviderID, Environment: s.Pool.Environment,
			UpstreamHostname: s.Provider.UpstreamHost, Port: s.Provider.UpstreamPort,
			OperationID: route.OperationID, PathPrefix: route.LogicalPath, Method: route.Method,
			CredentialBindingRef: s.Provider.CredentialBindingRef,
		}
		reg.RegisteredOperations = append(reg.RegisteredOperations, row)
		rows[i] = map[string]any{
			"provider_id": row.ProviderID, "environment": row.Environment,
			"upstream_hostname": row.UpstreamHostname, "port": row.Port,
			"operation_id": row.OperationID, "path_prefix": row.PathPrefix,
			"method": row.Method, "credential_binding_ref": row.CredentialBindingRef,
		}
	}
	reg.Document = map[string]any{
		"version": s.Provider.PolicyVersion, "default_decision": "DENY", "registered_operations": rows,
	}
	return reg
}

func secretIssues(data []byte) []Issue {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var doc any
	if err := dec.Decode(&doc); err != nil {
		return nil
	}
	var issues []Issue
	var walk func(any)
	walk = func(v any) {
		switch t := v.(type) {
		case map[string]any:
			for key, child := range t {
				if _, ok := sensitiveKeys[strings.ToLower(key)]; ok && truthy(child) {
					issues = append(issues, Issue{Code: "CREDENTIAL_VALUE_IN_INTENT", Reason: "sensitive key " + key})
				}
				walk(child)
			}
		case []any:
			for _, child := range t {
				walk(child)
			}
		}
	}
	walk(doc)
	return issues
}

func durationUnder(raw string, limit time.Duration) bool {
	d, err := time.ParseDuration(raw)
	return err == nil && d > 0 && d < limit
}

func loopbackPort(addr string) int {
	host, port, ok := strings.Cut(addr, ":")
	if !ok || host != "127.0.0.1" {
		return 0
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 || strconv.Itoa(n) != port {
		return 0
	}
	return n
}

func relativePath(path string) bool {
	if path == "" || strings.HasPrefix(path, "/") || strings.Contains(path, "..") || strings.Contains(path, `\`) {
		return false
	}
	if strings.ContainsAny(path, " \t\n\r") {
		return false
	}
	return true
}

func routeIDPattern(id string) bool {
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

func cidrShape(cidr string) bool {
	addr, bits, ok := strings.Cut(cidr, "/")
	if !ok || addr == "" || bits == "" {
		return false
	}
	n, err := strconv.Atoi(bits)
	if err != nil || n < 0 || n > 128 {
		return false
	}
	if strings.Contains(addr, ":") {
		return parseIPv6(addr)
	}
	return parseIPv4(addr)
}
