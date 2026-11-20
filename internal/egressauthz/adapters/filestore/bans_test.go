package filestore

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"go.idp.xyz/idp-gateway/internal/egressauthz/application"
	"go.idp.xyz/idp-gateway/internal/egressauthz/domain"
	"go.idp.xyz/idp-gateway/internal/egressauthz/ports"
)

const bindingRef = "gatekeeper:mockcarrier-test"

type countingCredentials struct{ calls int }

func (c *countingCredentials) AuthorizationHeader(context.Context, string, string) (ports.Secret, error) {
	c.calls++
	return ports.NewSecret("Bearer token"), nil
}

func twoOperations() domain.Policy {
	return domain.Policy{Version: "policy-7", Operations: []domain.Operation{
		{
			ProviderID: "mockcarrier", OperationID: "tracking.get", Environment: "TEST", Method: "GET",
			PathPrefix: "/providers/mockcarrier/v1/tracking", CredentialBindingRef: bindingRef,
			AllowedTenants: []string{"tenant-blue"}, AllowedServiceIDs: []string{"parcel-service"},
			AccountsByTenant: map[string][]string{"tenant-blue": {"account-blue"}},
		},
		{
			ProviderID: "mockcarrier", OperationID: "labels.print", Environment: "TEST", Method: "POST",
			PathPrefix: "/providers/mockcarrier/v1/labels", CredentialBindingRef: bindingRef,
			AllowedTenants: []string{"tenant-blue"}, AllowedServiceIDs: []string{"parcel-service"},
			AccountsByTenant: map[string][]string{"tenant-blue": {"account-blue"}},
		},
	}}
}

func trackingInput() application.Input {
	return application.Input{Subject: "parcel-service", Tenant: "tenant-blue", TokenEnvironment: "TEST",
		ProviderID: "mockcarrier", OperationID: "tracking.get", Environment: "TEST", Method: "GET",
		Path: "/providers/mockcarrier/v1/tracking/TRK-1"}
}

func labelsInput() application.Input {
	in := trackingInput()
	in.OperationID = "labels.print"
	in.Method = "POST"
	in.Path = "/providers/mockcarrier/v1/labels/1"
	return in
}

func TestARevocationFileWithoutBannedOperationsLoads(t *testing.T) {
	ledger := loadRevocations(t, writeFile(t, nothingRevoked, 0o600))
	_, banned, epoch, err := ledger.View(context.Background(), "account-blue", "tracking.get")
	if err != nil || banned || epoch != 0 {
		t.Fatalf("旧文件：banned=%v epoch=%d err=%v", banned, epoch, err)
	}
	if operations, epoch, err := ledger.Banned(context.Background()); err != nil || len(operations) != 0 || epoch != 0 {
		t.Fatalf("封禁表：%+v %d %v", operations, epoch, err)
	}
}

func TestBanningAnOperationIsDeniedOnTheNextDecisionAndSurvivesReload(t *testing.T) {
	ctx := context.Background()
	path := writeFile(t, nothingRevoked, 0o600)
	ledger := loadRevocations(t, path)
	ledger.now = func() time.Time { return time.Date(2026, 11, 21, 1, 2, 3, 0, time.UTC) }
	credentials := &countingCredentials{}
	service := application.New(twoOperations(), credentials, ledger, application.WithRevocationLedger(ledger))

	if out, _, err := service.Authorize(ctx, trackingInput()); err != nil || !out.Allowed {
		t.Fatalf("封禁之前：%+v %v", out, err)
	}
	credentials.calls = 0

	change, err := service.BanOperation(ctx, "tracking.get", "spiffe://idp.test/revoker", "abuse")
	if err != nil || change != (ports.BanChange{Changed: true, Banned: true, Epoch: 1}) {
		t.Fatalf("封禁：%+v %v", change, err)
	}
	raw, err := os.ReadFile(path)
	if err != nil || !strings.Contains(string(raw), `"banned_operations"`) || !strings.Contains(string(raw), `"revoked_accounts"`) || !strings.Contains(string(raw), "tracking.get") {
		t.Fatalf("写出来的文件应当两张表都有：%s %v", raw, err)
	}
	out, _, err := service.Authorize(ctx, trackingInput())
	if err != nil || out.Allowed || out.Reason != application.ReasonOperationBanned || credentials.calls != 0 {
		t.Fatalf("下一次判定：%+v %v，凭证来源被叫了 %d 次", out, err, credentials.calls)
	}
	if out, _, err := service.Authorize(ctx, labelsInput()); err != nil || !out.Allowed || credentials.calls != 1 {
		t.Fatalf("另一个操作：%+v %v，凭证来源 %d 次", out, err, credentials.calls)
	}

	reloaded := loadRevocations(t, path)
	if _, banned, epoch, err := reloaded.View(ctx, "account-blue", "tracking.get"); err != nil || !banned || epoch != 1 {
		t.Fatalf("重新读入：banned=%v epoch=%d err=%v", banned, epoch, err)
	}
	if _, banned, _, _ := reloaded.View(ctx, "account-blue", "labels.print"); banned {
		t.Fatal("重新读入之后另一个操作也被封了")
	}

	before := fileInfo(t, path)
	change, err = service.BanOperation(ctx, "tracking.get", "spiffe://idp.test/revoker", "again")
	if err != nil || change != (ports.BanChange{Banned: true, Epoch: 1}) {
		t.Fatalf("重复封禁：%+v %v", change, err)
	}
	if !os.SameFile(before, fileInfo(t, path)) {
		t.Fatal("重复封禁重写了文件")
	}

	snapshot, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if change, err := service.BanOperation(ctx, "no.such", "spiffe://idp.test/revoker", "typo"); !errors.Is(err, application.ErrUnknownOperation) || change != (ports.BanChange{Epoch: 1}) {
		t.Fatalf("不认识的操作：%+v %v", change, err)
	}
	if again, err := os.ReadFile(path); err != nil || string(again) != string(snapshot) {
		t.Fatalf("不认识的操作改了文件：%s", again)
	}
	if operations, epoch, _ := ledger.Banned(ctx); len(operations) != 1 || operations[0].OperationID != "tracking.get" || epoch != 1 {
		t.Fatalf("表：%+v %d", operations, epoch)
	}

	credentials.calls = 0
	if _, err := service.RevokeAccount(ctx, "account-blue", "spiffe://idp.test/revoker", "key leaked"); err != nil {
		t.Fatal(err)
	}
	out, _, err = service.Authorize(ctx, trackingInput())
	if err != nil || out.Allowed || out.Reason != application.ReasonAccountRevoked || credentials.calls != 0 {
		t.Fatalf("账户撤销应当先于封禁：%+v %v，凭证来源 %d 次", out, err, credentials.calls)
	}
}

func TestLiftingABanDoesNotTakeEffectWhenTheWriteFails(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root 写得进只读的目录，这条测试在它手里看不出什么")
	}
	ctx := context.Background()
	path := writeFile(t, nothingRevoked, 0o600)
	directory := filepath.Dir(path)
	ledger := loadRevocations(t, path)
	if _, err := ledger.Ban(ctx, "tracking.get", "spiffe://idp.test/revoker", "abuse"); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(directory, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(directory, 0o700) })

	change, err := ledger.Lift(ctx, "tracking.get")
	if err == nil || errors.Is(err, ports.ErrRevocationNotWritten) || change != (ports.BanChange{Banned: true, Epoch: 1}) {
		t.Fatalf("写不成的解除：%+v %v", change, err)
	}
	if _, banned, epoch, _ := ledger.View(ctx, "account-blue", "tracking.get"); !banned || epoch != 1 {
		t.Fatalf("解除却生效了：banned=%v epoch=%d", banned, epoch)
	}
	reloaded := loadRevocations(t, path)
	if _, banned, epoch, err := reloaded.View(ctx, "", "tracking.get"); err != nil || !banned || epoch != 1 {
		t.Fatalf("文件里的封禁：banned=%v epoch=%d err=%v", banned, epoch, err)
	}
}
