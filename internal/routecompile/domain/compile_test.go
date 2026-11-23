package domain

import (
	"errors"
	"strings"
	"testing"
)

func TestCompileOneRoute(t *testing.T) {
	spec := wanbSpec()
	spec.Routes = spec.Routes[:1]
	art, err := Compile(spec)
	if err != nil {
		t.Fatal(err)
	}
	if art.RouteCount != 1 || art.GatewaySHA256 == "" || art.PolicySHA256 == "" {
		t.Fatalf("artifacts %+v", art.RouteCount)
	}
	text := string(art.GatewayYAML)
	if !strings.Contains(text, "mode: 'readOnly'") {
		t.Fatal("storage mode readOnly missing")
	}
	if !strings.Contains(text, `request.headers["authorization"].startsWith("Hc-OweDeveloper ")`) {
		t.Fatal("backend authorization prefix missing")
	}
	if strings.Contains(text, "\nretry:") || strings.Contains(text, "session:") {
		t.Fatal("retry or session leaked into the gateway config")
	}
	if !strings.Contains(text, "denyWithStatus: 503") || !strings.Contains(text, "bindAddress: '127.0.0.1'") {
		t.Fatal("fail-closed gateway settings missing")
	}
}

func TestCompileRefusals(t *testing.T) {
	t.Run("prod plain http", func(t *testing.T) {
		spec := wanbSpec()
		spec.Pool.Name = "egress-prod"
		spec.Pool.Environment = "PROD"
		if err := mustRefuse(t, spec); !refusalHas(err, "TLS_VERIFICATION_MISSING") && !refusalHas(err, "upstream_tls") {
			t.Fatalf("PROD plain HTTP was not refused: %v", err)
		}
	})
	t.Run("internal backend without tls", func(t *testing.T) {
		spec := sfSpec()
		spec.Provider.BackendTLS = nil
		if err := mustRefuse(t, spec); err == nil {
			t.Fatal("missing backend_tls was accepted")
		}
	})
	t.Run("env reference", func(t *testing.T) {
		spec := wanbSpec()
		spec.Access.PolicyNotes = "see ${HOME}"
		if err := mustRefuse(t, spec); !refusalHas(err, "ENV_REFERENCE") {
			t.Fatalf("env reference: %v", err)
		}
	})
	t.Run("duplicate method and prefix", func(t *testing.T) {
		spec := wanbSpec()
		spec.Routes = append(spec.Routes, spec.Routes[0])
		last := len(spec.Routes) - 1
		spec.Routes[last].IntentID = "gwi-wanbexpress-whoami-dup"
		spec.Routes[last].RouteID = "wanbexpress-whoami-dup"
		if err := mustRefuse(t, spec); !refusalHas(err, "EXACT_ROUTE_CONFLICT") {
			t.Fatalf("duplicate: %v", err)
		}
	})
	t.Run("string prefix", func(t *testing.T) {
		spec := sfSpec()
		extra := spec.Routes[0]
		extra.IntentID = "gwi-sfintl-orders-extra"
		extra.RouteID = "sfintl-orders-extra"
		extra.OperationID = "orders.extra"
		extra.LogicalPath = "/providers/sfintl/v1/orders-extra"
		extra.RewritePathPrefix = "/sfintl/v1/orders-extra"
		spec.Routes = append(spec.Routes, extra)
		if err := mustRefuse(t, spec); !refusalHas(err, "STRING_PREFIX_OVERLAP") {
			t.Fatalf("string prefix: %v", err)
		}
	})
	t.Run("timeout", func(t *testing.T) {
		spec := wanbSpec()
		spec.Provider.RouteTimeout = "10s"
		if err := mustRefuse(t, spec); !refusalHas(err, "ROUTE_TIMEOUT") {
			t.Fatalf("timeout: %v", err)
		}
	})
	t.Run("empty scheme", func(t *testing.T) {
		spec := wanbSpec()
		spec.Provider.CredentialScheme = ""
		if err := mustRefuse(t, spec); !refusalHas(err, "CREDENTIAL_SCHEME") {
			t.Fatalf("scheme: %v", err)
		}
	})
	t.Run("different methods share a prefix", func(t *testing.T) {
		spec := wanbSpec()
		if _, err := Compile(spec); err != nil {
			t.Fatal(err)
		}
	})
}

func TestOptionalLimitsAreEmitted(t *testing.T) {
	spec := wanbSpec()
	concurrent, connections := 32, 64
	spec.Pool.FrontendLimits = &FrontendLimit{MaxConcurrentRequests: &concurrent, MaxConnections: &connections}
	spec.Provider.LocalRateLimit = []RateLimitSpec{{MaxTokens: 20, TokensPerFill: 5, FillInterval: "1s", Key: "jwt.tenant_id"}}
	art, err := Compile(spec)
	if err != nil {
		t.Fatal(err)
	}
	text := string(art.GatewayYAML)
	for _, needle := range []string{"maxConcurrentRequests: 32", "maxConnections: 64", "maxTokens: 20", "tokensPerFill: 5", "fillInterval: '1s'", "key: 'jwt.tenant_id'"} {
		if !strings.Contains(text, needle) {
			t.Fatalf("missing %s", needle)
		}
	}
}

func TestSecurityReadOnlyAndAuthorization(t *testing.T) {
	art, err := Compile(wanbSpec())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(art.GatewayYAML), "mode: 'readOnly'") {
		t.Fatal("readOnly storage mode was not emitted")
	}
	if !strings.Contains(string(art.GatewayYAML), `startsWith("Hc-OweDeveloper ")`) {
		t.Fatal("backend authorization prefix was not emitted")
	}
}

func TestSecurityDeniesIPLiteral(t *testing.T) {
	root := repoRoot(t)
	registry := loadRegistry(t, root+"/contracts/gateway/policies/egress-policy.example.json")
	obj := loadObject(t, root+"/contracts/gateway/route-intent.example.json")
	obj["upstream_hostname"] = "127.0.0.1"
	if !hasReason(Evaluate(nil, []map[string]any{obj}, registry, PreflightOptions{}), "IP_LITERAL_UPSTREAM_DENIED") {
		t.Fatal("preflight allowed an IP literal upstream")
	}
}

func TestSecurityPlainHTTPRefusedInProduction(t *testing.T) {
	spec := wanbSpec()
	spec.Pool.Name = "egress-prod"
	spec.Pool.Environment = "PROD"
	if _, err := Compile(spec); err == nil {
		t.Fatal("PROD with PLAIN_HTTP_SANDBOX_EXCEPTION was compiled")
	}
}

func mustRefuse(t *testing.T, spec CompileSpec) error {
	t.Helper()
	_, err := Compile(spec)
	if err == nil {
		t.Fatal("expected refusal")
	}
	return err
}

func refusalHas(err error, text string) bool {
	var refused *Refusal
	if !errors.As(err, &refused) {
		return strings.Contains(err.Error(), text)
	}
	for _, issue := range refused.Issues {
		if issue.Code == text || issue.Reason == text || strings.Contains(issue.Reason, text) || strings.Contains(issue.Code, text) {
			return true
		}
	}
	return false
}

func wanbSpec() CompileSpec {
	return CompileSpec{
		Pool:     commonPool(),
		Provider: wanbProvider(),
		Access:   commonAccess("Example notes for the test."),
		Routes:   wanbRoutes(),
	}
}

func sfSpec() CompileSpec {
	provider := wanbProvider()
	provider.ProviderID = "sfintl"
	provider.PolicyVersion = "sfintl-example"
	provider.EnforceTLSUpstream = true
	provider.CredentialScheme = "Sf-OpenApi "
	provider.CredentialBindingRef = "gatekeeper:sfintl-test"
	provider.UpstreamHost = "provider-signer"
	provider.UpstreamPort = 9444
	provider.RewriteAuthority = "provider-signer.idp.test"
	provider.BackendTLS = &BackendTLSSpec{Hostname: "provider-signer.idp.test"}
	provider.SetRequestHeaders = nil
	provider.PlainHTTPSandboxHost = ""
	provider.InternalBackendHost = "provider-signer"
	return CompileSpec{
		Pool: commonPool(), Provider: provider, Access: commonAccess("Example notes for the test."),
		Routes: sfRoutes(),
	}
}

func commonPool() PoolSpec {
	return PoolSpec{
		Name: "egress-test", Environment: "TEST", CallerHostname: "egress-api.idp.test",
		ListenPort: 8081, BindAddress: "127.0.0.1", ReadbackPort: 8443,
		AdminAddr: "127.0.0.1:15000", StatsAddr: "127.0.0.1:15020", ReadinessAddr: "127.0.0.1:15021",
		PublisherIdentity: "spiffe://idp.test/gateway-control/publisher", TLSDir: "tls",
		JWTIssuer: "http://127.0.0.1:27621", JWTAudiences: []string{"idp-egress-gateway"}, JWKSFile: "tls/jwks.json",
		ExtAuthz:  ExtAuthzSpec{Host: "gateway-authz:9443", Hostname: "gatekeeper.idp.test", Timeout: "1s"},
		AccessLog: AccessLogSpec{ProviderReferenceExpr: "json(request.body).ReferenceId", ProviderRequestExpr: "json(response.body).Data.ProcessCode"},
	}
}

func wanbProvider() ProviderSpec {
	return ProviderSpec{
		ProviderID: "wanbexpress", PolicyVersion: "wanbexpress-example", EnforceTLSUpstream: false,
		CredentialScheme: "Hc-OweDeveloper ", CredentialBindingRef: "gatekeeper:wanbexpress-test",
		UpstreamHost: "api-sbx.wanbexpress.com", UpstreamPort: 80, RewriteAuthority: "api-sbx.wanbexpress.com",
		SetRequestHeaders: map[string]string{"accept": "application/json"}, RouteTimeout: "9s",
		PlainHTTPSandboxHost: "api-sbx.wanbexpress.com",
	}
}

func commonAccess(notes string) AccessSpec {
	return AccessSpec{
		AllowedTenants:    []string{"TENANT-ID-BLUE", "TENANT-ID-GREEN"},
		AllowedServiceIDs: []string{"CLIENT-ID-BLUE", "CLIENT-ID-GREEN"},
		AccountsByTenant: map[string][]string{
			"TENANT-ID-BLUE":  {"account-blue"},
			"TENANT-ID-GREEN": {"account-green"},
		},
		PolicyNotes: notes,
	}
}

func routeBase(id, op, method, path, mode, rewrite, tls string) RouteSpec {
	return RouteSpec{
		IntentID: "gwi-" + id, RouteID: id, OperationID: op, Method: method, LogicalPath: path,
		PathMatchMode: mode, RewritePathPrefix: rewrite, ExpectedGeneration: 0,
		ApprovalRef: "APPROVAL-SANDBOX-001", AuthzProfile: "provider-account-allowlist-v1",
		RedirectPolicy: RedirectDeny, UpstreamTLS: tls, ProviderAccountStrategy: AccountStrategyGatekeeper,
		Transport: "HTTP", PolicyBundleRef: "policy:egress-sandbox-v1",
	}
}

func wanbRoutes() []RouteSpec {
	plain := PlainHTTPSandboxException
	return []RouteSpec{
		routeBase("wanbexpress-whoami-get", "whoami.get", "GET", "/providers/wanbexpress/v1/whoami", "exact", "/api/whoami", plain),
		routeBase("wanbexpress-parcels-create", "parcels.create", "POST", "/providers/wanbexpress/v1/parcels", "exact", "/api/parcels", plain),
		routeBase("wanbexpress-parcels-get", "parcels.get", "GET", "/providers/wanbexpress/v1/parcels", "one_segment", "/api/parcels", plain),
		routeBase("wanbexpress-parcels-delete", "parcels.delete", "DELETE", "/providers/wanbexpress/v1/parcels", "one_segment", "/api/parcels", plain),
	}
}

func sfRoutes() []RouteSpec {
	return []RouteSpec{
		routeBase("sfintl-orders-create", "orders.create", "POST", "/providers/sfintl/v1/orders", "exact", "/sfintl/v1/orders", TLSVerifyRequired),
		routeBase("sfintl-orders-cancel", "orders.cancel", "POST", "/providers/sfintl/v1/order-cancellations", "exact", "/sfintl/v1/order-cancellations", TLSVerifyRequired),
		routeBase("sfintl-agent-numbers-query", "agent-numbers.query", "POST", "/providers/sfintl/v1/agent-number-queries", "exact", "/sfintl/v1/agent-number-queries", TLSVerifyRequired),
		routeBase("sfintl-labels-print", "labels.print", "POST", "/providers/sfintl/v1/label-prints", "exact", "/sfintl/v1/label-prints", TLSVerifyRequired),
	}
}

func TestCredentialHeaderDefaultsToAuthorization(t *testing.T) {
	baseline, err := Compile(wanbSpec())
	if err != nil {
		t.Fatal(err)
	}
	same := wanbSpec()
	same.Provider.CredentialHeader = "authorization"
	again, err := Compile(same)
	if err != nil {
		t.Fatal(err)
	}
	if string(again.GatewayYAML) != string(baseline.GatewayYAML) || string(again.PolicyJSON) != string(baseline.PolicyJSON) {
		t.Fatal("写明 authorization 改变了编译结果")
	}
	if strings.Contains(string(baseline.PolicyJSON), "credential_header") {
		t.Fatal("默认登记表写出了 credential_header")
	}

	spec := wanbSpec()
	spec.Provider.CredentialHeader = "x-api-key"
	art, err := Compile(spec)
	if err != nil {
		t.Fatal(err)
	}
	text := string(art.GatewayYAML)
	for _, needle := range []string{
		`request.headers["x-api-key"].startsWith("Hc-OweDeveloper ")`,
		"'x-api-key'",
		`"x-api-key"`,
	} {
		if !strings.Contains(text, needle) {
			t.Fatalf("缺少 %s\n%s", needle, text)
		}
	}
	if !strings.Contains(string(art.PolicyJSON), `"credential_header": "x-api-key"`) {
		t.Fatalf("登记表没有凭证头：%s", art.PolicyJSON)
	}
	if strings.Contains(text, `request.headers["authorization"].startsWith`) {
		t.Fatal("自定义头仍然检查 authorization")
	}
}

func TestCredentialHeaderIsRejected(t *testing.T) {
	for _, name := range []string{"X-Api-Key", "cookie", "x-idp-token", "x-forwarded-for", "not a header", ""} {
		if name == "" {
			continue
		}
		spec := wanbSpec()
		spec.Provider.CredentialHeader = name
		if err := mustRefuse(t, spec); !refusalHas(err, "CREDENTIAL_HEADER") {
			t.Fatalf("%q: %v", name, err)
		}
	}
}
