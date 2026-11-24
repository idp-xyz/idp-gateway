package domain

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

const catalogJSON = `{
  "pool": {
    "name": "egress-test", "environment": "TEST", "caller_hostname": "egress-api.idp.test",
    "listen_port": 8081, "bind_address": "127.0.0.1", "readback_port": 8443,
    "admin_addr": "127.0.0.1:15000", "stats_addr": "127.0.0.1:15020", "readiness_addr": "127.0.0.1:15021",
    "publisher_identity": "spiffe://idp.test/gateway-control/publisher", "tls_dir": "tls",
    "jwt_issuer": "http://127.0.0.1:27621", "jwt_audiences": ["idp-egress-gateway"], "jwks_file": "tls/jwks.json",
    "ext_authz": {"host": "gateway-authz:9443", "hostname": "gatekeeper.idp.test", "timeout": "1s"},
    "access_log": {"provider_reference_expr": "request.id", "provider_request_expr": "response.id"}
  },
  "provider": {
    "provider_id": "mockcarrier", "policy_version": "mock-1", "enforce_tls_upstream": true,
    "credential_scheme": "Bearer ", "credential_binding_ref": "gatekeeper:mockcarrier-test",
    "upstream_host": "mockcarrier.example", "upstream_port": 443, "rewrite_authority": "mockcarrier.example",
    "route_timeout": "9s"
  },
  "access": {
    "allowed_tenants": ["TENANT-ID-BLUE"],
    "accounts_by_tenant": {"TENANT-ID-BLUE": ["account-blue"]},
    "allowed_service_ids": ["CLIENT-ID-BLUE"]
  },
  "routes": [
    {
      "intent_id": "gwi-catalog-tracking", "route_id": "mock-tracking", "operation_id": "tracking.get",
      "method": "GET", "logical_path": "/providers/mockcarrier/v1/tracking", "path_match_mode": "exact",
      "rewrite_path_prefix": "/v1/tracking", "expected_generation": 0, "approval_ref": "APPROVAL-PENDING-001",
      "authz_profile": "provider-account-allowlist-v1", "redirect_policy": "DENY", "upstream_tls": "VERIFY_REQUIRED",
      "provider_account_strategy": "GATEKEEPER_DECISION_BINDING", "transport": "HTTP",
      "policy_bundle_ref": "policy:egress-standard-v1"
    },
    {
      "intent_id": "gwi-catalog-quotes", "route_id": "mock-quotes", "operation_id": "quotes.create",
      "method": "POST", "logical_path": "/providers/mockcarrier/v1/quotes", "path_match_mode": "exact",
      "rewrite_path_prefix": "/v1/quotes", "expected_generation": 0, "approval_ref": "APPROVAL-PENDING-001",
      "authz_profile": "provider-account-allowlist-v1", "redirect_policy": "DENY", "upstream_tls": "VERIFY_REQUIRED",
      "provider_account_strategy": "GATEKEEPER_DECISION_BINDING", "transport": "HTTP",
      "policy_bundle_ref": "policy:egress-standard-v1"
    }
  ]
}`

func TestParsePoolBaseRejectsIngressAndSecrets(t *testing.T) {
	base, err := ParsePoolBase([]byte(catalogJSON))
	if err != nil {
		t.Fatal(err)
	}
	if len(base.Routes) != 2 || base.Provider.CredentialScheme != "Bearer " {
		t.Fatalf("目录 %+v", base.Provider)
	}
	if _, err := ParsePoolBase([]byte(strings.Replace(catalogJSON, `"pool"`, `"traffic_class":"INGRESS","pool"`, 1))); err == nil {
		t.Fatal("INGRESS 目录应拒绝")
	}
	if _, err := ParsePoolBase([]byte(strings.Replace(catalogJSON, `"pool"`, `"traffic_class":"AI","pool"`, 1))); err == nil {
		t.Fatal("AI 目录应拒绝")
	}
	secret := strings.Replace(catalogJSON, `"provider_id"`, `"api_key":"secret","provider_id"`, 1)
	if codeOf(mustErr(ParsePoolBase([]byte(secret)))) != "sensitive_key" {
		t.Fatal("敏感键应拒绝")
	}
}

func mustErr(base PoolBase, err error) error { return err }

func TestMergeOrdersAndReplaces(t *testing.T) {
	base, err := ParsePoolBase([]byte(catalogJSON))
	if err != nil {
		t.Fatal(err)
	}
	env, err := ParseEnvelope(exampleEnvelope(t))
	if err != nil {
		t.Fatal(err)
	}
	merged, active, err := Merge(base, nil, env, env.TargetID, "mock-1-g0-abcdef12")
	if err != nil {
		t.Fatal(err)
	}
	if len(active) != 1 || active[0].RouteID != "mock-tracking" {
		t.Fatalf("有效集 %+v", active)
	}
	if !strings.Contains(string(merged), `"policy_version":"mock-1-g0-abcdef12"`) {
		t.Fatalf("版本没有写进规格：%s", merged)
	}
	second := mutateEnvelope(t, exampleEnvelope(t), func(doc map[string]any) {
		doc["idempotency_key"] = "pub-mockcarrier-quotes-00002"
		in := intentOf(t, doc)
		in["intent_id"] = "gwi-example-quotes"
		in["operation_id"] = "quotes.create"
		in["logical_path"] = "/providers/mockcarrier/v1/quotes"
		in["allowed_methods"] = []any{"POST"}
	})
	env2, err := ParseEnvelope(second)
	if err != nil {
		t.Fatal(err)
	}
	_, active, err = Merge(base, active, env2, env2.TargetID, "mock-1-g1-abcdef12")
	if err != nil {
		t.Fatal(err)
	}
	if len(active) != 2 || active[0].OperationID != "tracking.get" || active[1].OperationID != "quotes.create" {
		t.Fatalf("顺序 %+v", active)
	}
	replaced := mutateEnvelope(t, exampleEnvelope(t), func(doc map[string]any) {
		doc["idempotency_key"] = "pub-mockcarrier-tracking-0002"
		intentOf(t, doc)["approval_ref"] = "APPROVAL-PENDING-002"
	})
	env3, err := ParseEnvelope(replaced)
	if err != nil {
		t.Fatal(err)
	}
	_, active, err = Merge(base, active, env3, env3.TargetID, "mock-1-g2-abcdef12")
	if err != nil {
		t.Fatal(err)
	}
	if len(active) != 2 || active[0].IntentID != "gwi-example-001" || active[0].ApprovalRef != "APPROVAL-PENDING-002" {
		t.Fatalf("替换后 %+v", active)
	}
	wrongHost := mutateEnvelope(t, exampleEnvelope(t), func(doc map[string]any) {
		intentOf(t, doc)["upstream_hostname"] = "other.example"
		intentOf(t, doc)["upstream_sni"] = "other.example"
	})
	env4, err := ParseEnvelope(wrongHost)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := Merge(base, nil, env4, env4.TargetID, "mock-1-g3-abcdef12"); err == nil {
		t.Fatal("目录里没有的上游应拒绝")
	}
}

func TestMergeSFInternalHost(t *testing.T) {
	raw, err := os.ReadFile("../../../deploy/providers/sfintl/compile-spec.json")
	if err != nil {
		t.Fatal(err)
	}
	base, err := ParsePoolBase(raw)
	if err != nil {
		t.Fatal(err)
	}
	wanb, err := os.ReadFile("../../../deploy/providers/wanbexpress/compile-spec.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParsePoolBase(wanb); err != nil {
		t.Fatal(err)
	}
	for _, host := range []string{base.Provider.UpstreamHost, base.Provider.RewriteAuthority} {
		body := sfIntent(t, base, host)
		env, err := ParseEnvelope(body)
		if err != nil {
			t.Fatal(host, err)
		}
		merged, active, err := Merge(base, nil, env, "fabric-target:egress-test", "sfintl-example-g0-abcdef12")
		if err != nil {
			t.Fatalf("host %s: %v", host, err)
		}
		if len(active) != 1 || !strings.Contains(string(merged), base.Provider.UpstreamHost) {
			t.Fatalf("host %s 没有并进去", host)
		}
		var spec PoolBase
		if err := json.Unmarshal(merged, &spec); err != nil {
			t.Fatal(err)
		}
		if spec.Provider.PolicyVersion != "sfintl-example-g0-abcdef12" || spec.Routes[0].RouteID == "" {
			t.Fatalf("合并规格 %+v", spec.Provider.PolicyVersion)
		}
	}
}

func sfIntent(t *testing.T, base PoolBase, host string) []byte {
	t.Helper()
	route := base.Routes[0]
	doc := map[string]any{
		"idempotency_key": "pub-sfintl-orders-create01",
		"release_ref":     "fabric-release:sfintl/0001",
		"target_id":       "fabric-target:egress-test",
		"intent": map[string]any{
			"intent_id": "gwi-sfintl-orders-create", "gateway_pool": base.Pool.Name, "traffic_class": "EGRESS",
			"environment": base.Pool.Environment, "provider_id": base.Provider.ProviderID,
			"operation_id": route.OperationID, "logical_path": route.LogicalPath, "allowed_methods": []any{route.Method},
			"upstream_hostname": host, "upstream_port": base.Provider.UpstreamPort,
			"authz_profile": route.AuthzProfile, "approval_ref": route.ApprovalRef, "expected_generation": 0,
			"contract_ref": "consumer-api-sfintl-v1", "credential_binding_ref": base.Provider.CredentialBindingRef,
			"redirect_policy": "DENY", "upstream_tls": route.UpstreamTLS,
			"provider_account_strategy": "GATEKEEPER_DECISION_BINDING", "transport": "HTTP",
			"policy_bundle_ref": route.PolicyBundleRef,
		},
	}
	if host == base.Provider.RewriteAuthority {
		doc["intent"].(map[string]any)["upstream_sni"] = host
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
