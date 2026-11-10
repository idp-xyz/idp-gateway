package application

import (
	"context"
	"errors"
	"strings"
	"testing"

	"go.idp.xyz/idp-gateway/internal/egressauthz/domain"
	"go.idp.xyz/idp-gateway/internal/egressauthz/ports"
)

type fakeCredentials struct {
	held  map[string]string
	err   error
	asked []string
}

func (f *fakeCredentials) AuthorizationHeader(_ context.Context, bindingRef, accountID string) (ports.Secret, error) {
	handle := ports.Handle(bindingRef, accountID)
	f.asked = append(f.asked, handle)
	if f.err != nil {
		return ports.Secret{}, f.err
	}
	value, ok := f.held[handle]
	if !ok {
		return ports.Secret{}, ports.ErrCredentialNotHeld
	}
	return ports.NewSecret(value), nil
}

type fakeRevocations struct {
	revoked map[string]bool
	epoch   uint64
	err     error
}

func (f *fakeRevocations) State(_ context.Context, accountID string) (bool, uint64, error) {
	return f.revoked[accountID], f.epoch, f.err
}

func (f *fakeRevocations) Epoch(context.Context) (uint64, error) { return f.epoch, f.err }

const binding = "gatekeeper:mockcarrier-test"

func twoTenantPolicy() domain.Policy {
	return domain.Policy{Version: "policy-7", Operations: []domain.Operation{{
		ProviderID: "mockcarrier", OperationID: "tracking.get", Environment: "TEST", Method: "GET",
		PathPrefix: "/providers/mockcarrier/v1/tracking", CredentialBindingRef: binding,
		AllowedTenants: []string{"tenant-blue", "tenant-green"}, AllowedServiceIDs: []string{"parcel-service"},
		AccountsByTenant: map[string][]string{"tenant-blue": {"account-blue"}, "tenant-green": {"account-green"}},
	}}}
}

func blueInput() Input {
	return Input{Subject: "parcel-service", Tenant: "tenant-blue", TokenEnvironment: "TEST", RouteID: "r1",
		ProviderID: "mockcarrier", OperationID: "tracking.get", Environment: "TEST", Method: "GET",
		Path: "/providers/mockcarrier/v1/tracking/TRK-1"}
}

func newService() (*Service, *fakeCredentials, *fakeRevocations) {
	credentials := &fakeCredentials{held: map[string]string{
		ports.Handle(binding, "account-blue"):  "Bearer blue-token",
		ports.Handle(binding, "account-green"): "Bearer green-token",
	}}
	revocations := &fakeRevocations{revoked: map[string]bool{}, epoch: 3}
	return New(twoTenantPolicy(), credentials, revocations), credentials, revocations
}

func TestAuthorizeReleasesTheTenantsOwnCredential(t *testing.T) {
	service, credentials, _ := newService()
	for tenant, want := range map[string]string{"tenant-blue": "Bearer blue-token", "tenant-green": "Bearer green-token"} {
		in := blueInput()
		in.Tenant = tenant
		out, credential, err := service.Authorize(context.Background(), in)
		if err != nil || !out.Allowed {
			t.Fatalf("%s: %+v, %v", tenant, out, err)
		}
		if credential.Reveal() != want {
			t.Fatalf("%s 拿到了别的凭证", tenant)
		}
		if out.Reason != string(domain.ReasonActiveAccountGrant) || out.PolicyVersion != "policy-7" || out.RevocationEpoch != 3 {
			t.Fatalf("%s: %+v", tenant, out)
		}
		if !strings.HasPrefix(out.DecisionID, "dec-") || len(out.DecisionID) != 16 {
			t.Fatalf("判定标识 %q", out.DecisionID)
		}
	}
	if len(credentials.asked) != 2 {
		t.Fatalf("凭证来源被问了 %d 次", len(credentials.asked))
	}
}

func TestDecisionIDsDiffer(t *testing.T) {
	service, _, _ := newService()
	a, _ := service.Decide(context.Background(), blueInput())
	b, _ := service.Decide(context.Background(), blueInput())
	if a.DecisionID == b.DecisionID {
		t.Fatal("两次判定用了同一个标识")
	}
}

// 拒绝的请求不得去碰凭证来源，也不得带出凭证绑定。
func TestDenialsNeverTouchTheCredentialSource(t *testing.T) {
	cases := map[string]struct {
		mutate func(*Input)
		reason string
	}{
		"蓝租户申请绿账户":               {func(in *Input) { in.RequestedAccount = "account-green" }, string(domain.ReasonAccountNotGranted)},
		"没有租户":                   {func(in *Input) { in.Tenant = "" }, string(domain.ReasonUnauthenticated)},
		"没有服务身份":                 {func(in *Input) { in.Subject = "" }, string(domain.ReasonUnauthenticated)},
		"没有 Token 环境":            {func(in *Input) { in.TokenEnvironment = "" }, string(domain.ReasonUnauthenticated)},
		"PROD 的 Token 用在 TEST 池": {func(in *Input) { in.TokenEnvironment = "PROD" }, string(domain.ReasonEnvironmentMismatch)},
		"未获授的服务":                 {func(in *Input) { in.Subject = "cargo-service" }, string(domain.ReasonServiceNotGranted)},
		"未获授的租户":                 {func(in *Input) { in.Tenant = "tenant-red" }, string(domain.ReasonTenantNotGranted)},
		"不规范的路径":                 {func(in *Input) { in.Path += "/%252e%252e/admin" }, string(domain.ReasonPathNotCanonical)},
		"未登记的操作":                 {func(in *Input) { in.OperationID = "labels.create" }, string(domain.ReasonNoMatchingOperation)},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			service, credentials, _ := newService()
			in := blueInput()
			tc.mutate(&in)
			out, credential, err := service.Authorize(context.Background(), in)
			if err != nil {
				t.Fatal(err)
			}
			if out.Allowed || out.Reason != tc.reason || out.BindingRef != "" || out.CredentialHandle() != "" || !credential.IsZero() {
				t.Fatalf("%+v", out)
			}
			if len(credentials.asked) != 0 {
				t.Fatalf("拒绝的请求问了凭证来源：%v", credentials.asked)
			}
		})
	}
}

func TestRevocationAppliesToTheNextDecisionOnly(t *testing.T) {
	service, credentials, revocations := newService()
	revocations.revoked["account-blue"] = true
	revocations.epoch = 4

	out, credential, err := service.Authorize(context.Background(), blueInput())
	if err != nil || out.Allowed || out.Reason != ReasonAccountRevoked || out.RevocationEpoch != 4 || !credential.IsZero() {
		t.Fatalf("%+v, %v", out, err)
	}
	if len(credentials.asked) != 0 {
		t.Fatal("已撤销的账户仍去取了凭证")
	}
	green := blueInput()
	green.Tenant = "tenant-green"
	if out, _, err := service.Authorize(context.Background(), green); err != nil || !out.Allowed {
		t.Fatalf("绿租户受了蓝账户撤销的影响：%+v, %v", out, err)
	}
	revocations.revoked["account-blue"] = false
	revocations.epoch = 5
	if out, _, err := service.Authorize(context.Background(), blueInput()); err != nil || !out.Allowed || out.RevocationEpoch != 5 {
		t.Fatalf("恢复后仍被拒：%+v, %v", out, err)
	}
}

// 撤销只在策略本来会放行时才成为原因：对别人账户的申请不能借此探出该账户是否被撤销。
func TestRevocationIsNotDisclosedToOtherTenants(t *testing.T) {
	service, _, revocations := newService()
	revocations.revoked["account-green"] = true
	in := blueInput()
	in.RequestedAccount = "account-green"
	out, _ := service.Decide(context.Background(), in)
	if out.Reason != string(domain.ReasonAccountNotGranted) {
		t.Fatalf("原因码 %s", out.Reason)
	}
}

func TestUnreadableRevocationStateIsIndeterminate(t *testing.T) {
	service, credentials, revocations := newService()
	revocations.err = errors.New("store down")
	out, credential, err := service.Authorize(context.Background(), blueInput())
	if !errors.Is(err, ErrIndeterminate) || out.Allowed || out.Reason != ReasonRevocationStateUnavailable || !credential.IsZero() {
		t.Fatalf("%+v, %v", out, err)
	}
	if len(credentials.asked) != 0 {
		t.Fatal("撤销状态读不到时仍去取了凭证")
	}
	if service.RevocationEpoch(context.Background()) != 0 {
		t.Fatal("读不到代次时应为 0")
	}
}

func TestMissingCredentialIsIndeterminateNotAllowed(t *testing.T) {
	for name, prepare := range map[string]func(*fakeCredentials){
		"来源里没有":  func(c *fakeCredentials) { delete(c.held, ports.Handle(binding, "account-blue")) },
		"来源报错":   func(c *fakeCredentials) { c.err = errors.New("secret manager timeout") },
		"来源给了空值": func(c *fakeCredentials) { c.held[ports.Handle(binding, "account-blue")] = "" },
	} {
		t.Run(name, func(t *testing.T) {
			service, credentials, _ := newService()
			prepare(credentials)
			out, credential, err := service.Authorize(context.Background(), blueInput())
			if !errors.Is(err, ErrIndeterminate) {
				t.Fatalf("err = %v", err)
			}
			if out.Allowed || out.BindingRef != "" || out.CredentialHandle() != "" || out.Reason != ReasonCredentialUnavailable || !credential.IsZero() {
				t.Fatalf("%+v", out)
			}
		})
	}
}

func TestDecideDoesNotFetchCredentials(t *testing.T) {
	service, credentials, _ := newService()
	out, err := service.Decide(context.Background(), blueInput())
	if err != nil || !out.Allowed || out.CredentialHandle() != ports.Handle(binding, "account-blue") || out.Account != "account-blue" {
		t.Fatalf("%+v, %v", out, err)
	}
	if len(credentials.asked) != 0 {
		t.Fatal("只做判定时去取了凭证")
	}
}

func TestAccountDefaulting(t *testing.T) {
	service, _, _ := newService()
	explicit := blueInput()
	explicit.RequestedAccount = "account-blue"
	if out, _ := service.Decide(context.Background(), explicit); !out.Allowed || out.Account != "account-blue" {
		t.Fatalf("%+v", out)
	}

	policy := twoTenantPolicy()
	policy.Operations[0].AccountsByTenant["tenant-blue"] = []string{"account-blue", "account-blue-2"}
	service = New(policy, &fakeCredentials{}, &fakeRevocations{})
	out, _ := service.Decide(context.Background(), blueInput())
	if out.Allowed || out.Reason != string(domain.ReasonAccountNotGranted) || out.Account != "" {
		t.Fatalf("两个获授账户、没有指明时应拒绝：%+v", out)
	}
}
