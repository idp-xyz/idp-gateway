package application

import (
	"context"
	"errors"
	"fmt"
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
	banned  map[string]bool
	epoch   uint64
	err     error
}

func (f *fakeRevocations) State(_ context.Context, accountID string) (bool, uint64, error) {
	return f.revoked[accountID], f.epoch, f.err
}

func (f *fakeRevocations) View(_ context.Context, accountID, operationID string) (bool, bool, uint64, error) {
	return f.revoked[accountID], f.banned[operationID], f.epoch, f.err
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

type fakeGrants struct {
	granted bool
	err     error
	asked   [][3]string
}

func (f *fakeGrants) MayUse(_ context.Context, subject, tenantID, accountID string) (bool, error) {
	f.asked = append(f.asked, [3]string{subject, tenantID, accountID})
	return f.granted, f.err
}

func newServiceWithGrants(grants *fakeGrants) (*Service, *fakeCredentials, *fakeRevocations) {
	_, credentials, revocations := newService()
	return New(twoTenantPolicy(), credentials, revocations, WithGrants(grants)), credentials, revocations
}

func TestGrantsAreAskedAboutTheVerifiedCallerAndTheChosenAccount(t *testing.T) {
	grants := &fakeGrants{granted: true}
	service, _, _ := newServiceWithGrants(grants)
	out, credential, err := service.Authorize(context.Background(), blueInput())
	if err != nil || !out.Allowed || credential.Reveal() != "Bearer blue-token" || out.Reason != string(domain.ReasonActiveAccountGrant) {
		t.Fatalf("%+v, %v", out, err)
	}
	if len(grants.asked) != 1 || grants.asked[0] != [3]string{"parcel-service", "tenant-blue", "account-blue"} {
		t.Fatalf("问的是 %v", grants.asked)
	}
}

func TestGrantsCanOnlyNarrowThePolicy(t *testing.T) {
	// 登记表拒绝的请求不去问，哪怕授权来源会说可以。
	grants := &fakeGrants{granted: true}
	service, credentials, _ := newServiceWithGrants(grants)
	in := blueInput()
	in.RequestedAccount = "account-green"
	out, _, err := service.Authorize(context.Background(), in)
	if err != nil || out.Allowed || out.Reason != string(domain.ReasonAccountNotGranted) {
		t.Fatalf("%+v, %v", out, err)
	}
	if len(grants.asked) != 0 || len(credentials.asked) != 0 {
		t.Fatalf("登记表已拒绝，仍问了授权来源 %v 或凭证来源 %v", grants.asked, credentials.asked)
	}

	// 登记表放行、授权来源说没有：拒绝，不取凭证。
	grants = &fakeGrants{granted: false}
	service, credentials, _ = newServiceWithGrants(grants)
	out, credential, err := service.Authorize(context.Background(), blueInput())
	if err != nil || out.Allowed || out.Reason != string(domain.ReasonAccountNotGranted) || out.BindingRef != "" || !credential.IsZero() {
		t.Fatalf("%+v, %v", out, err)
	}
	if len(grants.asked) != 1 || len(credentials.asked) != 0 {
		t.Fatalf("授权来源 %v，凭证来源 %v", grants.asked, credentials.asked)
	}
}

func TestUnansweredGrantIsIndeterminate(t *testing.T) {
	grants := &fakeGrants{granted: true, err: errors.New("pdp unreachable")}
	service, credentials, _ := newServiceWithGrants(grants)
	for name, decide := range map[string]func() (Outcome, error){
		"取凭证的判定": func() (Outcome, error) {
			out, _, err := service.Authorize(context.Background(), blueInput())
			return out, err
		},
		"只要判定": func() (Outcome, error) { return service.Decide(context.Background(), blueInput()) },
	} {
		out, err := decide()
		if !errors.Is(err, ErrIndeterminate) || out.Allowed || out.Reason != ReasonGrantStateUnavailable || out.CredentialHandle() != "" {
			t.Fatalf("%s: %+v, %v", name, out, err)
		}
	}
	if len(credentials.asked) != 0 {
		t.Fatal("授权问不出结果时仍去取了凭证")
	}
}

func TestRevokedAccountIsNotAskedAbout(t *testing.T) {
	grants := &fakeGrants{granted: true}
	service, _, revocations := newServiceWithGrants(grants)
	revocations.revoked["account-blue"] = true
	out, _ := service.Decide(context.Background(), blueInput())
	if out.Allowed || out.Reason != ReasonAccountRevoked || len(grants.asked) != 0 {
		t.Fatalf("%+v，问了 %v", out, grants.asked)
	}
}

// fakeLedger 是可以改的撤销表。fail 不为 nil 时改动"没有写下去"：撤销照样生效，恢复不生效。
type fakeLedger struct {
	fakeRevocations
	fail  error
	calls []string
}

func (f *fakeLedger) Revoke(_ context.Context, accountID, by, reason string) (ports.RevocationChange, error) {
	f.calls = append(f.calls, "revoke "+accountID+" by "+by+" because "+reason)
	changed := !f.revoked[accountID]
	if changed {
		f.revoked[accountID] = true
		f.epoch++
	}
	return ports.RevocationChange{Changed: changed, Revoked: true, Epoch: f.epoch}, f.fail
}

func (f *fakeLedger) Restore(_ context.Context, accountID string) (ports.RevocationChange, error) {
	f.calls = append(f.calls, "restore "+accountID)
	if !f.revoked[accountID] {
		return ports.RevocationChange{Epoch: f.epoch}, nil
	}
	if f.fail != nil {
		return ports.RevocationChange{Revoked: true, Epoch: f.epoch}, f.fail
	}
	delete(f.revoked, accountID)
	f.epoch++
	return ports.RevocationChange{Changed: true, Epoch: f.epoch}, nil
}

func (f *fakeLedger) Revoked(context.Context) ([]ports.RevokedAccount, uint64, error) {
	var accounts []ports.RevokedAccount
	for account := range f.revoked {
		accounts = append(accounts, ports.RevokedAccount{AccountID: account})
	}
	return accounts, f.epoch, f.err
}

func (f *fakeLedger) Ban(_ context.Context, operationID, by, reason string) (ports.BanChange, error) {
	f.calls = append(f.calls, "ban "+operationID+" by "+by+" because "+reason)
	changed := !f.banned[operationID]
	if changed {
		if f.banned == nil {
			f.banned = map[string]bool{}
		}
		f.banned[operationID] = true
		f.epoch++
	}
	return ports.BanChange{Changed: changed, Banned: true, Epoch: f.epoch}, f.fail
}

func (f *fakeLedger) Lift(_ context.Context, operationID string) (ports.BanChange, error) {
	f.calls = append(f.calls, "lift "+operationID)
	if !f.banned[operationID] {
		return ports.BanChange{Epoch: f.epoch}, nil
	}
	if f.fail != nil {
		return ports.BanChange{Banned: true, Epoch: f.epoch}, f.fail
	}
	delete(f.banned, operationID)
	f.epoch++
	return ports.BanChange{Changed: true, Epoch: f.epoch}, nil
}

func (f *fakeLedger) Banned(context.Context) ([]ports.BannedOperation, uint64, error) {
	var operations []ports.BannedOperation
	for operation, banned := range f.banned {
		if banned {
			operations = append(operations, ports.BannedOperation{OperationID: operation})
		}
	}
	return operations, f.epoch, f.err
}

func newServiceWithLedger() (*Service, *fakeCredentials, *fakeLedger) {
	_, credentials, _ := newService()
	// account-gone 是登记表换过之后留在撤销表里的账户：登记表里已经没有它了。
	ledger := &fakeLedger{fakeRevocations: fakeRevocations{revoked: map[string]bool{"account-gone": true}, epoch: 3}}
	return New(twoTenantPolicy(), credentials, ledger, WithRevocationLedger(ledger)), credentials, ledger
}

func TestRevokingAnAccountStopsItFromTheNextDecision(t *testing.T) {
	ctx := context.Background()
	service, credentials, ledger := newServiceWithLedger()
	if out, _, err := service.Authorize(ctx, blueInput()); err != nil || !out.Allowed {
		t.Fatalf("撤销之前：%+v %v", out, err)
	}
	credentials.asked = nil

	change, err := service.RevokeAccount(ctx, "account-blue", "spiffe://idp.test/revoker", "key leaked")
	if err != nil || change != (ports.RevocationChange{Changed: true, Revoked: true, Epoch: 4}) {
		t.Fatalf("撤销：%+v %v", change, err)
	}
	if len(ledger.calls) != 1 || ledger.calls[0] != "revoke account-blue by spiffe://idp.test/revoker because key leaked" {
		t.Fatalf("交给撤销表的是 %v", ledger.calls)
	}
	out, credential, err := service.Authorize(ctx, blueInput())
	if err != nil || out.Allowed || out.Reason != ReasonAccountRevoked || out.RevocationEpoch != 4 || !credential.IsZero() || len(credentials.asked) != 0 {
		t.Fatalf("撤销之后：%+v %v，问过凭证来源 %v", out, err, credentials.asked)
	}
	green := blueInput()
	green.Tenant = "tenant-green"
	if out, _, err := service.Authorize(ctx, green); err != nil || !out.Allowed {
		t.Fatalf("撤销蓝账户影响了绿租户：%+v %v", out, err)
	}

	change, err = service.RestoreAccount(ctx, "account-blue")
	if err != nil || change != (ports.RevocationChange{Changed: true, Epoch: 5}) {
		t.Fatalf("恢复：%+v %v", change, err)
	}
	if out, _, err := service.Authorize(ctx, blueInput()); err != nil || !out.Allowed || out.RevocationEpoch != 5 {
		t.Fatalf("恢复之后：%+v %v", out, err)
	}
	// 恢复一个登记表里有、但没有被撤销的账户：不算错，什么都不改。
	if change, err := service.RestoreAccount(ctx, "account-green"); err != nil || change != (ports.RevocationChange{Epoch: 5}) {
		t.Fatalf("恢复没撤销过的账户：%+v %v", change, err)
	}
	if accounts, epoch, err := service.RevokedAccounts(ctx); err != nil || epoch != 5 || len(accounts) != 1 || accounts[0].AccountID != "account-gone" {
		t.Fatalf("读表：%+v %d %v", accounts, epoch, err)
	}
}

// 名字打错了要得到一个错误，不是一次什么都没拦住的成功。
func TestRevocationsAreOnlyChangedForAccountsTheServiceKnows(t *testing.T) {
	ctx := context.Background()
	service, _, ledger := newServiceWithLedger()
	for _, account := range []string{"account-bleu", "Account-Blue", "tenant-blue", ""} {
		if change, err := service.RevokeAccount(ctx, account, "spiffe://idp.test/revoker", "typo"); !errors.Is(err, ErrUnknownAccount) || change != (ports.RevocationChange{Epoch: 3}) {
			t.Errorf("撤销 %q：%+v %v", account, change, err)
		}
		if change, err := service.RestoreAccount(ctx, account); !errors.Is(err, ErrUnknownAccount) || change != (ports.RevocationChange{Epoch: 3}) {
			t.Errorf("恢复 %q：%+v %v", account, change, err)
		}
	}
	if len(ledger.calls) != 0 {
		t.Fatalf("不认识的账户仍交给了撤销表：%v", ledger.calls)
	}

	// 登记表里已经没有、撤销表里还留着的账户：重复撤销不算错，也恢复得了；恢复之后它就是不认识的了。
	if change, err := service.RevokeAccount(ctx, "account-gone", "spiffe://idp.test/revoker", "again"); err != nil || change != (ports.RevocationChange{Revoked: true, Epoch: 3}) {
		t.Fatalf("重复撤销留在表里的账户：%+v %v", change, err)
	}
	if change, err := service.RestoreAccount(ctx, "account-gone"); err != nil || change != (ports.RevocationChange{Changed: true, Epoch: 4}) {
		t.Fatalf("恢复留在表里的账户：%+v %v", change, err)
	}
	if _, err := service.RestoreAccount(ctx, "account-gone"); !errors.Is(err, ErrUnknownAccount) {
		t.Fatalf("再恢复一次：%v", err)
	}
}

func TestRevocationThatWasNotWrittenIsReportedAndStillInEffect(t *testing.T) {
	ctx := context.Background()
	service, _, ledger := newServiceWithLedger()
	ledger.fail = fmt.Errorf("%w: disk full", ports.ErrRevocationNotWritten)
	change, err := service.RevokeAccount(ctx, "account-blue", "spiffe://idp.test/revoker", "key leaked")
	if !errors.Is(err, ports.ErrRevocationNotWritten) || change != (ports.RevocationChange{Changed: true, Revoked: true, Epoch: 4}) {
		t.Fatalf("没写下去的撤销：%+v %v", change, err)
	}
	if out, _, _ := service.Authorize(ctx, blueInput()); out.Allowed || out.Reason != ReasonAccountRevoked {
		t.Fatalf("没写下去的撤销没有生效：%+v", out)
	}
	// 恢复没写下去：不生效，错误原样传出来。
	ledger.fail = errors.New("restore not applied: disk full")
	if change, err := service.RestoreAccount(ctx, "account-blue"); err == nil || change != (ports.RevocationChange{Revoked: true, Epoch: 4}) {
		t.Fatalf("没写下去的恢复：%+v %v", change, err)
	}
	if out, _, _ := service.Authorize(ctx, blueInput()); out.Allowed {
		t.Fatal("没写下去的恢复却生效了")
	}
}

func TestRevocationStateThatCannotBeReadIsNotMistakenForAnUnknownAccount(t *testing.T) {
	ctx := context.Background()
	service, _, ledger := newServiceWithLedger()
	ledger.err = errors.New("revocation store down")
	for name, change := range map[string]func() error{
		"撤销": func() error {
			_, err := service.RevokeAccount(ctx, "account-bleu", "spiffe://idp.test/revoker", "typo")
			return err
		},
		"恢复": func() error { _, err := service.RestoreAccount(ctx, "account-blue"); return err },
		"读表": func() error { _, _, err := service.RevokedAccounts(ctx); return err },
	} {
		if err := change(); err == nil || errors.Is(err, ErrUnknownAccount) || !strings.Contains(err.Error(), "revocation store down") {
			t.Errorf("%s: %v", name, err)
		}
	}
	if len(ledger.calls) != 0 {
		t.Fatalf("状态读不出来时仍去改了撤销表：%v", ledger.calls)
	}
}

func policyWithLabels() domain.Policy {
	policy := twoTenantPolicy()
	labels := policy.Operations[0]
	labels.OperationID = "labels.print"
	labels.Method = "POST"
	labels.PathPrefix = "/providers/mockcarrier/v1/labels"
	policy.Operations = append(policy.Operations, labels)
	return policy
}

func labelsInput() Input {
	in := blueInput()
	in.OperationID = "labels.print"
	in.Method = "POST"
	in.Path = "/providers/mockcarrier/v1/labels/1"
	return in
}

// 封禁只挡住点名的那一个操作。账户撤销先检查。不认识的操作不改表。
func TestBanningAnOperationDeniesOnlyThatOperation(t *testing.T) {
	ctx := context.Background()
	credentials := &fakeCredentials{held: map[string]string{
		ports.Handle(binding, "account-blue"):  "Bearer blue-token",
		ports.Handle(binding, "account-green"): "Bearer green-token",
	}}
	ledger := &fakeLedger{fakeRevocations: fakeRevocations{revoked: map[string]bool{}, banned: map[string]bool{}, epoch: 3}}
	service := New(policyWithLabels(), credentials, ledger, WithRevocationLedger(ledger))

	if out, _, err := service.Authorize(ctx, blueInput()); err != nil || !out.Allowed {
		t.Fatalf("封禁之前：%+v %v", out, err)
	}
	credentials.asked = nil

	change, err := service.BanOperation(ctx, "tracking.get", "spiffe://idp.test/revoker", "abuse")
	if err != nil || change != (ports.BanChange{Changed: true, Banned: true, Epoch: 4}) {
		t.Fatalf("封禁：%+v %v", change, err)
	}
	out, credential, err := service.Authorize(ctx, blueInput())
	if err != nil || out.Allowed || out.Reason != ReasonOperationBanned || !credential.IsZero() || len(credentials.asked) != 0 {
		t.Fatalf("封禁之后：%+v %v，问过凭证来源 %v", out, err, credentials.asked)
	}
	if out, _, err := service.Authorize(ctx, labelsInput()); err != nil || !out.Allowed || len(credentials.asked) != 1 {
		t.Fatalf("另一个操作：%+v %v，问过 %v", out, err, credentials.asked)
	}
	green := blueInput()
	green.Tenant = "tenant-green"
	if out, _, err := service.Authorize(ctx, green); err != nil || out.Allowed || out.Reason != ReasonOperationBanned {
		t.Fatalf("绿账户做被封的操作：%+v %v", out, err)
	}

	// 两样都碰上时，账户撤销先说。
	if _, err := service.RevokeAccount(ctx, "account-blue", "spiffe://idp.test/revoker", "key leaked"); err != nil {
		t.Fatal(err)
	}
	credentials.asked = nil
	out, _, err = service.Authorize(ctx, blueInput())
	if err != nil || out.Allowed || out.Reason != ReasonAccountRevoked || len(credentials.asked) != 0 {
		t.Fatalf("账户撤销应当先于封禁：%+v %v，问过 %v", out, err, credentials.asked)
	}

	before := len(ledger.calls)
	epoch := ledger.epoch
	for _, operation := range []string{"tracking.put", "Tracking.Get", ""} {
		if change, err := service.BanOperation(ctx, operation, "spiffe://idp.test/revoker", "typo"); !errors.Is(err, ErrUnknownOperation) || change.Epoch != epoch || change.Changed || change.Banned {
			t.Errorf("封禁 %q：%+v %v", operation, change, err)
		}
	}
	if len(ledger.calls) != before {
		t.Fatalf("不认识的操作仍交给了表：%v", ledger.calls)
	}
	if change, err := service.BanOperation(ctx, "tracking.get", "spiffe://idp.test/revoker", "again"); err != nil || change.Changed || change.Epoch != epoch || !change.Banned {
		t.Fatalf("重复封禁：%+v %v", change, err)
	}

	ledger.fail = errors.New("lift not applied: disk full")
	if change, err := service.LiftOperationBan(ctx, "tracking.get"); err == nil || change.Banned != true || change.Epoch != epoch {
		t.Fatalf("没写下去的解除：%+v %v", change, err)
	}
	if out, _, _ := service.Authorize(ctx, green); out.Allowed || out.Reason != ReasonOperationBanned {
		t.Fatalf("没写下去的解除却生效了：%+v", out)
	}
}

func TestWithoutALedgerRevocationsCannotBeChanged(t *testing.T) {
	ctx := context.Background()
	service, _, _ := newService()
	if _, err := service.RevokeAccount(ctx, "account-blue", "spiffe://idp.test/revoker", "key leaked"); !errors.Is(err, ErrNoRevocationLedger) {
		t.Errorf("撤销：%v", err)
	}
	if _, err := service.RestoreAccount(ctx, "account-blue"); !errors.Is(err, ErrNoRevocationLedger) {
		t.Errorf("恢复：%v", err)
	}
	if _, _, err := service.RevokedAccounts(ctx); !errors.Is(err, ErrNoRevocationLedger) {
		t.Errorf("读表：%v", err)
	}
	if _, err := service.BanOperation(ctx, "tracking.get", "spiffe://idp.test/revoker", "abuse"); !errors.Is(err, ErrNoRevocationLedger) {
		t.Errorf("封禁：%v", err)
	}
	if _, err := service.LiftOperationBan(ctx, "tracking.get"); !errors.Is(err, ErrNoRevocationLedger) {
		t.Errorf("解除：%v", err)
	}
	if out, _, err := service.Authorize(ctx, blueInput()); err != nil || !out.Allowed {
		t.Fatalf("被拒绝的改动影响了判定：%+v %v", out, err)
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

// countingPolicy 每被读一次就记一笔，返回的始终是同一份。
type countingPolicy struct {
	policy domain.Policy
	calls  int
}

func (c *countingPolicy) Current() domain.Policy {
	c.calls++
	return c.policy
}

// 热重载：来源换掉之后，判定、版本、撤销和封禁都立刻用新的那一份，而且一次调用只读一次。
func TestPolicySourceHotReload(t *testing.T) {
	ctx := context.Background()
	source := &countingPolicy{policy: twoTenantPolicy()}
	credentials := &fakeCredentials{held: map[string]string{
		ports.Handle(binding, "account-blue"): "Bearer blue-token",
		ports.Handle(binding, "account-red"):  "Bearer red-token",
	}}
	ledger := &fakeLedger{fakeRevocations: fakeRevocations{revoked: map[string]bool{}, banned: map[string]bool{}, epoch: 3}}
	// 构造时塞一份过期登记表。配置了来源之后不该再读它。
	stale := domain.Policy{Version: "stale", Operations: []domain.Operation{{
		ProviderID: "mockcarrier", OperationID: "stale.op", Environment: "TEST", Method: "GET",
		PathPrefix: "/stale", CredentialBindingRef: binding,
		AllowedTenants:    []string{"tenant-blue"},
		AllowedServiceIDs: []string{"parcel-service"},
		AccountsByTenant:  map[string][]string{"tenant-blue": {"account-stale"}},
	}}}
	service := New(stale, credentials, ledger, WithPolicySource(source), WithRevocationLedger(ledger))

	if service.PolicyVersion() != "policy-7" || source.calls != 1 {
		t.Fatalf("版本 %s，读了 %d 次", service.PolicyVersion(), source.calls)
	}
	out, err := service.Decide(ctx, blueInput())
	if err != nil || !out.Allowed || out.PolicyVersion != "policy-7" || out.Account != "account-blue" || source.calls != 2 {
		t.Fatalf("重载前：%+v %v，读了 %d 次", out, err, source.calls)
	}

	source.policy = domain.Policy{Version: "policy-8", Operations: []domain.Operation{{
		ProviderID: "mockcarrier", OperationID: "labels.print", Environment: "TEST", Method: "POST",
		PathPrefix: "/providers/mockcarrier/v1/labels", CredentialBindingRef: binding,
		AllowedTenants:    []string{"tenant-blue"},
		AllowedServiceIDs: []string{"parcel-service"},
		AccountsByTenant:  map[string][]string{"tenant-blue": {"account-red"}},
	}}}

	if service.PolicyVersion() != "policy-8" {
		t.Fatalf("版本没有跟上：%s", service.PolicyVersion())
	}
	removed, err := service.Decide(ctx, blueInput())
	if err != nil || removed.Allowed || removed.Reason != string(domain.ReasonNoMatchingOperation) || removed.PolicyVersion != "policy-8" {
		t.Fatalf("被拿掉的路由：%+v %v", removed, err)
	}
	added, err := service.Decide(ctx, labelsInput())
	if err != nil || !added.Allowed || added.Account != "account-red" || added.PolicyVersion != "policy-8" || added.BindingRef != binding {
		t.Fatalf("新路由：%+v %v", added, err)
	}

	before := source.calls
	if change, err := service.RevokeAccount(ctx, "account-red", "spiffe://idp.test/revoker", "rotated"); err != nil || !change.Revoked || source.calls != before+1 {
		t.Fatalf("新账户：%+v %v，读了 %d 次", change, err, source.calls-before)
	}
	before = source.calls
	if _, err := service.RevokeAccount(ctx, "account-blue", "spiffe://idp.test/revoker", "old"); !errors.Is(err, ErrUnknownAccount) || source.calls != before+1 {
		t.Fatalf("旧账户仍被当成在登记表里：%v，读了 %d 次", err, source.calls-before)
	}
	before = source.calls
	if _, err := service.RevokeAccount(ctx, "account-stale", "spiffe://idp.test/revoker", "stale"); !errors.Is(err, ErrUnknownAccount) || source.calls != before+1 {
		t.Fatalf("构造时的账户仍被当成在登记表里：%v", err)
	}
	before = source.calls
	if change, err := service.RestoreAccount(ctx, "account-red"); err != nil || change.Revoked || source.calls != before+1 {
		t.Fatalf("恢复新账户：%+v %v", change, err)
	}
	before = source.calls
	if change, err := service.BanOperation(ctx, "labels.print", "spiffe://idp.test/revoker", "abuse"); err != nil || !change.Banned || source.calls != before+1 {
		t.Fatalf("新操作：%+v %v", change, err)
	}
	before = source.calls
	if _, err := service.BanOperation(ctx, "tracking.get", "spiffe://idp.test/revoker", "old"); !errors.Is(err, ErrUnknownOperation) || source.calls != before+1 {
		t.Fatalf("旧操作仍被当成在登记表里：%v", err)
	}
	before = source.calls
	if change, err := service.LiftOperationBan(ctx, "labels.print"); err != nil || change.Banned || source.calls != before+1 {
		t.Fatalf("解除新操作：%+v %v", change, err)
	}
	before = source.calls
	if _, err := service.LiftOperationBan(ctx, "tracking.get"); !errors.Is(err, ErrUnknownOperation) || source.calls != before+1 {
		t.Fatalf("解除旧操作：%v", err)
	}
}
