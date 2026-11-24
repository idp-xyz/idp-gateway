package domain

import "testing"

func testBase() PoolBase {
	return PoolBase{
		Pool:     PoolSpec{Name: "egress-test", Environment: "TEST"},
		Provider: ProviderSpec{ProviderID: "mockcarrier", CredentialBindingRef: "gatekeeper:mockcarrier-test", CredentialScheme: "Bearer ", UpstreamHost: "mockcarrier.example", UpstreamPort: 443, RewriteAuthority: "mockcarrier.example"},
	}
}

func testBinding(scheme string) Binding {
	return Binding{
		BindingID: "bind-mockcarrier", ProviderID: "mockcarrier", Environment: "TEST", AuthScheme: scheme,
		AccountResolution: "GATEKEEPER_AUTHORIZED_ACCOUNT", GatewayWorkloadID: "spiffe://idp.test/egress/gateway",
		AuthorizedCredentialRef: "gatekeeper:mockcarrier-test", ApprovalRef: "APPROVAL-PENDING-001",
	}
}

func testIntent() Intent {
	return Intent{
		ProviderID: "mockcarrier", Environment: "TEST", CredentialBindingRef: "gatekeeper:mockcarrier-test",
		UpstreamTLS: "VERIFY_REQUIRED", ProviderAccountStrategy: "GATEKEEPER_DECISION_BINDING",
	}
}

func TestParseBindingsRejectsSecretsAndUnknown(t *testing.T) {
	_, err := ParseBindings([]byte(`[{"binding_id":"bind-1","provider_id":"mockcarrier","environment":"TEST","auth_scheme":"API_KEY","account_resolution":"GATEKEEPER_AUTHORIZED_ACCOUNT","gateway_workload_id":"gw-1","authorized_credential_ref":"gatekeeper:mockcarrier-test","approval_ref":"APPROVAL-1","api_key":"secret"}]`))
	if codeOf(err) != "sensitive_key" {
		t.Fatal(err)
	}
	_, err = ParseBindings([]byte(`[{"binding_id":"bind-1","provider_id":"mockcarrier","environment":"TEST","auth_scheme":"API_KEY","account_resolution":"GATEKEEPER_AUTHORIZED_ACCOUNT","gateway_workload_id":"gw-1","authorized_credential_ref":"gatekeeper:mockcarrier-test","approval_ref":"APPROVAL-1","extra":1}]`))
	if codeOf(err) != "unknown_field" {
		t.Fatal(err)
	}
	_, err = ParseBindings([]byte(`{"binding_id":"bind-1","provider_id":"mockcarrier","environment":"TEST","auth_scheme":"API_KEY","account_resolution":"GATEKEEPER_AUTHORIZED_ACCOUNT","gateway_workload_id":"gw-1","authorized_credential_ref":"gatekeeper:mockcarrier-test","approval_ref":"APPROVAL-1"}`))
	if err != nil {
		t.Fatal(err)
	}
}

func TestBindingMatchesSchemes(t *testing.T) {
	base := testBase()
	in := testIntent()
	if err := testBinding("API_KEY").Matches(in, base); err != nil {
		t.Fatal(err)
	}
	oauth := testBinding("OAUTH2_CLIENT_CREDENTIALS")
	oauth.Audience = "api"
	oauth.ScopeSet = []string{"read"}
	oauth.TokenTTLMaxSeconds = 60
	oauth.HasTokenTTL = true
	if err := oauth.Matches(in, base); err != nil {
		t.Fatal(err)
	}
	both := base
	both.Provider.CredentialHeader = "x-api-key"
	both.Provider.CredentialQueryParameter = "key"
	if err := testBinding("API_KEY").Matches(in, both); err == nil {
		t.Fatal("头和查询参数同时设置时应拒绝")
	}
	if err := testBinding("OAUTH2_AUTHORIZATION_CODE").Matches(in, base); err == nil {
		t.Fatal("授权码模式应拒绝")
	}
	hmac := testBinding("HMAC_REQUEST_SIGNING")
	if err := hmac.Matches(in, base); err == nil {
		t.Fatal("没有签名器引用的 HMAC 应拒绝")
	}
	hmac.RequestSignerRef = "signer:sf/one"
	if err := hmac.Matches(in, base); err != nil {
		t.Fatal(err)
	}
	mtls := testBinding("MTLS_CLIENT_CERT")
	if err := mtls.Matches(in, base); err == nil {
		t.Fatal("没有 backend_tls 的 mTLS 应拒绝")
	}
	withTLS := base
	withTLS.Provider.BackendTLS = &BackendTLSSpec{Hostname: "mockcarrier.example"}
	if err := mtls.Matches(in, withTLS); err != nil {
		t.Fatal(err)
	}
}

func TestNamedAdapters(t *testing.T) {
	wanb := testBase()
	wanb.Provider.ProviderID = providerWanb
	wanb.Provider.CredentialScheme = schemeWanb
	wanb.Provider.CredentialBindingRef = "gatekeeper:wanbexpress-test"
	in := testIntent()
	in.ProviderID = providerWanb
	in.CredentialBindingRef = wanb.Provider.CredentialBindingRef
	b := testBinding("API_KEY")
	b.ProviderID = providerWanb
	b.AuthorizedCredentialRef = wanb.Provider.CredentialBindingRef
	if err := b.Matches(in, wanb); err != nil {
		t.Fatal(err)
	}
	wanb.Provider.CredentialScheme = "Bearer "
	if err := b.Matches(in, wanb); err == nil {
		t.Fatal("万邦的方案词必须是 Hc-OweDeveloper")
	}

	sf := testBase()
	sf.Provider.ProviderID = providerSF
	sf.Provider.CredentialScheme = schemeSF
	sf.Provider.CredentialBindingRef = "gatekeeper:sfintl-test"
	sf.Provider.InternalBackendHost = "provider-signer"
	sf.Provider.BackendTLS = &BackendTLSSpec{Hostname: "provider-signer.idp.test"}
	sf.Provider.UpstreamHost = "provider-signer"
	sf.Provider.RewriteAuthority = "provider-signer.idp.test"
	in = testIntent()
	in.ProviderID = providerSF
	in.CredentialBindingRef = sf.Provider.CredentialBindingRef
	b = testBinding("HMAC_REQUEST_SIGNING")
	b.ProviderID = providerSF
	b.AuthorizedCredentialRef = sf.Provider.CredentialBindingRef
	if err := b.Matches(in, sf); err == nil {
		t.Fatal("顺丰没有签名器引用时应拒绝")
	}
	b.RequestSignerRef = "signer:sfintl/sandbox"
	if err := b.Matches(in, sf); err != nil {
		t.Fatal(err)
	}
	plain := in
	plain.UpstreamTLS = "PLAIN_HTTP_SANDBOX_EXCEPTION"
	if err := b.Matches(plain, sf); err == nil {
		t.Fatal("顺丰明文应拒绝")
	}
}
