package application

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"go.idp.xyz/idp-gateway/internal/routecompile/domain"
	"go.idp.xyz/idp-gateway/internal/routecompile/ports"
)

type refuseValidator struct{}

func (refuseValidator) Validate(context.Context, []byte, string, string) error {
	return fmt.Errorf("%w: boom", ports.ErrRefused)
}

func TestValidatorRefusalWritesNothing(t *testing.T) {
	dir := t.TempDir()
	gateway := filepath.Join(dir, "agentgateway.yaml")
	policy := filepath.Join(dir, "policy.json")
	_, err := (Compiler{Validator: refuseValidator{}}).Compile(context.Background(), sampleSpec(), gateway, policy, "", "")
	if err == nil {
		t.Fatal("expected refusal")
	}
	var refused *domain.Refusal
	if !errors.As(err, &refused) || refused.Issues[0].Code != "NATIVE_VALIDATION_FAILED" {
		t.Fatal(err)
	}
	if _, statErr := os.Stat(gateway); !os.IsNotExist(statErr) {
		t.Fatal("gateway file exists")
	}
	if _, statErr := os.Stat(policy); !os.IsNotExist(statErr) {
		t.Fatal("policy file exists")
	}
}

func TestCompileWritesBothFiles(t *testing.T) {
	dir := t.TempDir()
	gateway := filepath.Join(dir, "agentgateway.yaml")
	policy := filepath.Join(dir, "policy.json")
	result, err := (Compiler{}).Compile(context.Background(), sampleSpec(), gateway, policy, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if result.NativeValidated {
		t.Fatal("validated without a validator")
	}
	gotGW, err := os.ReadFile(gateway)
	if err != nil {
		t.Fatal(err)
	}
	gotPol, err := os.ReadFile(policy)
	if err != nil {
		t.Fatal(err)
	}
	if string(gotGW) != string(result.Artifacts.GatewayYAML) || string(gotPol) != string(result.Artifacts.PolicyJSON) {
		t.Fatal("written bytes differ from the compiled artifacts")
	}
}

func sampleSpec() domain.CompileSpec {
	return domain.CompileSpec{
		Pool: domain.PoolSpec{
			Name: "egress-test", Environment: "TEST", CallerHostname: "egress-api.idp.test",
			ListenPort: 8081, BindAddress: "127.0.0.1", ReadbackPort: 8443,
			AdminAddr: "127.0.0.1:15000", StatsAddr: "127.0.0.1:15020", ReadinessAddr: "127.0.0.1:15021",
			PublisherIdentity: "spiffe://idp.test/gateway-control/publisher", TLSDir: "tls",
			JWTIssuer: "http://127.0.0.1:27621", JWTAudiences: []string{"idp-egress-gateway"}, JWKSFile: "tls/jwks.json",
			ExtAuthz:  domain.ExtAuthzSpec{Host: "gateway-authz:9443", Hostname: "gatekeeper.idp.test", Timeout: "1s"},
			AccessLog: domain.AccessLogSpec{ProviderReferenceExpr: "ref", ProviderRequestExpr: "req"},
		},
		Provider: domain.ProviderSpec{
			ProviderID: "wanbexpress", PolicyVersion: "wanbexpress-example",
			CredentialScheme: "Hc-OweDeveloper ", CredentialBindingRef: "gatekeeper:wanbexpress-test",
			UpstreamHost: "api-sbx.wanbexpress.com", UpstreamPort: 80, RewriteAuthority: "api-sbx.wanbexpress.com",
			SetRequestHeaders: map[string]string{"accept": "application/json"}, RouteTimeout: "9s",
			PlainHTTPSandboxHost: "api-sbx.wanbexpress.com",
		},
		Access: domain.AccessSpec{
			AllowedTenants: []string{"TENANT-ID-BLUE"}, AllowedServiceIDs: []string{"CLIENT-ID-BLUE"},
			AccountsByTenant: map[string][]string{"TENANT-ID-BLUE": {"account-blue"}},
			PolicyNotes:      "notes",
		},
		Routes: []domain.RouteSpec{{
			IntentID: "gwi-wanbexpress-whoami-get", RouteID: "wanbexpress-whoami-get", OperationID: "whoami.get",
			Method: "GET", LogicalPath: "/providers/wanbexpress/v1/whoami", PathMatchMode: "exact",
			RewritePathPrefix: "/api/whoami", ApprovalRef: "APPROVAL-SANDBOX-001", AuthzProfile: "provider-account-allowlist-v1",
			RedirectPolicy: "DENY", UpstreamTLS: domain.PlainHTTPSandboxException, ProviderAccountStrategy: domain.AccountStrategyGatekeeper,
			Transport: "HTTP", PolicyBundleRef: "policy:egress-sandbox-v1",
		}},
	}
}
