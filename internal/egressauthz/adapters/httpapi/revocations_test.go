package httpapi

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"testing"
	"time"

	"go.idp.xyz/idp-gateway/internal/egressauthz/adapters/memory"
	"go.idp.xyz/idp-gateway/internal/egressauthz/application"
	"go.idp.xyz/idp-gateway/internal/egressauthz/domain"
	"go.idp.xyz/idp-gateway/internal/egressauthz/ports"
	"go.idp.xyz/idp-gateway/internal/platform/workloadtls/tlstest"
)

const revokerID = "spiffe://idp.test/egress/revoker"

// testLedger 是一张可以改的撤销表。broken 为 true 时改动"写不下去"：撤销照样生效，恢复不生效。
type testLedger struct {
	table   memory.Revocations
	entries map[string]ports.RevokedAccount
	broken  bool
}

func (l *testLedger) State(ctx context.Context, accountID string) (bool, uint64, error) {
	return l.table.State(ctx, accountID)
}

func (l *testLedger) Epoch(ctx context.Context) (uint64, error) { return l.table.Epoch(ctx) }

func (l *testLedger) Revoke(ctx context.Context, accountID, by, reason string) (ports.RevocationChange, error) {
	already, _, _ := l.table.State(ctx, accountID)
	if !already {
		l.table.Revoke(accountID)
		l.entries[accountID] = ports.RevokedAccount{AccountID: accountID, At: time.Date(2026, 11, 18, 5, 0, 0, 0, time.UTC), By: by, Reason: reason}
	}
	epoch, _ := l.table.Epoch(ctx)
	change := ports.RevocationChange{Changed: !already, Revoked: true, Epoch: epoch}
	if l.broken {
		return change, fmt.Errorf("%w: disk full", ports.ErrRevocationNotWritten)
	}
	return change, nil
}

func (l *testLedger) Restore(ctx context.Context, accountID string) (ports.RevocationChange, error) {
	revoked, epoch, _ := l.table.State(ctx, accountID)
	if !revoked {
		return ports.RevocationChange{Epoch: epoch}, nil
	}
	if l.broken {
		return ports.RevocationChange{Revoked: true, Epoch: epoch}, errors.New("restore not applied: disk full")
	}
	l.table.Restore(accountID)
	delete(l.entries, accountID)
	epoch, _ = l.table.Epoch(ctx)
	return ports.RevocationChange{Changed: true, Epoch: epoch}, nil
}

func (l *testLedger) Revoked(ctx context.Context) ([]ports.RevokedAccount, uint64, error) {
	accounts := make([]ports.RevokedAccount, 0, len(l.entries))
	for _, entry := range l.entries {
		accounts = append(accounts, entry)
	}
	sort.Slice(accounts, func(i, j int) bool { return accounts[i].AccountID < accounts[j].AccountID })
	epoch, _ := l.table.Epoch(ctx)
	return accounts, epoch, nil
}

// newRevokerFixture 与 newFixture 是同一张登记表、同样的凭证，多了一张可以改的撤销表和撤销者的身份。
func newRevokerFixture(t *testing.T) (*fixture, *testLedger) {
	t.Helper()
	ca := tlstest.NewCA(t, "workload CA")
	ledger := &testLedger{entries: map[string]ports.RevokedAccount{}}
	f := &fixture{
		credentials: staticCredentials{
			ports.Handle(binding, "account-blue"):  blueToken,
			ports.Handle(binding, "account-green"): greenToken,
		},
		logs: &bytes.Buffer{},
		peers: map[string]tlstest.Leaf{
			"gateway":   ca.Issue("gateway", []string{gatewayID}),
			"broker":    ca.Issue("broker", []string{brokerID}),
			"business":  ca.Issue("business", []string{businessID}),
			"revoker":   ca.Issue("revoker", []string{revokerID}),
			"anonymous": ca.Issue("anonymous", nil),
			"two-names": ca.Issue("two-names", []string{revokerID, businessID}),
		},
	}
	policy := domain.Policy{Version: "policy-7", Operations: []domain.Operation{{
		ProviderID: "mockcarrier", OperationID: "tracking.get", Environment: "TEST", Method: "GET",
		PathPrefix: tracking, CredentialBindingRef: binding,
		AllowedTenants: []string{"tenant-blue", "tenant-green"}, AllowedServiceIDs: []string{"parcel-service"},
		AccountsByTenant: map[string][]string{"tenant-blue": {"account-blue"}, "tenant-green": {"account-green"}},
	}}}
	service := application.New(policy, f.credentials, ledger, application.WithRevocationLedger(ledger))
	f.handler = New(service, Callers{Gateway: gatewayID, Broker: brokerID, Revoker: revokerID}, slog.New(slog.NewJSONHandler(f.logs, nil)))
	return f, ledger
}

const (
	revokeBlue  = `{"account_id":"account-blue","revoked":true,"reason":"key leaked"}`
	restoreBlue = `{"account_id":"account-blue","revoked":false}`
)

func (f *fixture) blueIsAllowed() bool {
	return f.call("gateway", "GET", PathExtAuthz, trusted("tenant-blue"), "").Code == http.StatusOK
}

func TestRevocationsThroughTheInterface(t *testing.T) {
	f, _ := newRevokerFixture(t)
	exactly := func(what string, peer, method, body string, status int, want string) {
		t.Helper()
		recorder := f.call(peer, method, PathRevocations, nil, body)
		if recorder.Code != status || recorder.Body.String() != want {
			t.Fatalf("%s：%d %s", what, recorder.Code, recorder.Body)
		}
		if carriesCredential(recorder) || recorder.Header().Get("Cache-Control") != "no-store" || recorder.Header().Get("Authorization") != "" {
			t.Fatalf("%s：应答里有凭证，或者可以被缓存", what)
		}
	}
	exactly("一开始的表", "revoker", "GET", "", http.StatusOK, `{"revocation_epoch":0,"revoked_accounts":[]}`)

	exactly("撤销", "revoker", "POST", revokeBlue, http.StatusOK,
		`{"account_id":"account-blue","revoked":true,"changed":true,"revocation_epoch":1}`)
	// 下一次判定就拒绝，取不到凭证；另一个账户不受影响。
	denied := f.call("gateway", "GET", PathExtAuthz, trusted("tenant-blue"), "")
	if body := decode(t, denied); denied.Code != http.StatusForbidden || body["reason_code"] != "ACCOUNT_REVOKED" ||
		body["revocation_epoch"] != float64(1) || carriesCredential(denied) {
		t.Fatalf("撤销之后的蓝租户：%d %s", denied.Code, denied.Body)
	}
	if green := f.call("gateway", "GET", PathExtAuthz, trusted("tenant-green"), ""); green.Code != http.StatusOK || green.Header().Get("Authorization") != greenToken {
		t.Fatalf("撤销蓝账户影响了绿租户：%d", green.Code)
	}
	exactly("重复撤销", "revoker", "POST", `{"account_id":"account-blue","revoked":true,"reason":"again"}`, http.StatusOK,
		`{"account_id":"account-blue","revoked":true,"changed":false,"revocation_epoch":1}`)
	exactly("撤销之后的表", "revoker", "GET", "", http.StatusOK, `{"revocation_epoch":1,"revoked_accounts":[`+
		`{"account_id":"account-blue","revoked_at":"2026-11-18T05:00:00Z","revoked_by":"`+revokerID+`","reason":"key leaked"}]}`)

	// 名字打错了：是一个错误，什么都没有变。
	exactly("撤销一个不认识的账户", "revoker", "POST", `{"account_id":"account-bleu","revoked":true,"reason":"typo"}`, http.StatusUnprocessableEntity,
		`{"account_id":"account-bleu","revoked":false,"changed":false,"revocation_epoch":1,"error":"unknown_account"}`)
	exactly("恢复一个不认识的账户", "revoker", "POST", `{"account_id":"account-bleu","revoked":false}`, http.StatusUnprocessableEntity,
		`{"account_id":"account-bleu","revoked":false,"changed":false,"revocation_epoch":1,"error":"unknown_account"}`)

	exactly("恢复", "revoker", "POST", restoreBlue, http.StatusOK,
		`{"account_id":"account-blue","revoked":false,"changed":true,"revocation_epoch":2}`)
	if !f.blueIsAllowed() {
		t.Fatal("恢复之后蓝租户仍被拒绝")
	}
	exactly("重复恢复", "revoker", "POST", restoreBlue, http.StatusOK,
		`{"account_id":"account-blue","revoked":false,"changed":false,"revocation_epoch":2}`)
	exactly("恢复之后的表", "revoker", "GET", "", http.StatusOK, `{"revocation_epoch":2,"revoked_accounts":[]}`)

	// 每次改动一行日志：谁、哪个账户、撤销还是恢复、为什么、之后的代次。读表不记。
	var changes []string
	for _, line := range strings.Split(strings.TrimSpace(f.logs.String()), "\n") {
		if strings.Contains(line, `"msg":"egress revocation"`) {
			changes = append(changes, line)
		}
	}
	if len(changes) != 6 {
		t.Fatalf("改动的日志 %d 行：%s", len(changes), f.logs)
	}
	for _, expected := range []string{`"level":"INFO"`, `"caller":"` + revokerID + `"`, `"action":"revoke"`, `"account":"account-blue"`,
		`"reason":"key leaked"`, `"changed":true`, `"revoked":true`, `"revocation_epoch":1`, `"status":200`} {
		if !strings.Contains(changes[0], expected) {
			t.Errorf("撤销的那一行里没有 %s：%s", expected, changes[0])
		}
	}
	if !strings.Contains(changes[2], `"level":"ERROR"`) || !strings.Contains(changes[2], `"status":422`) || !strings.Contains(changes[2], `"account":"account-bleu"`) {
		t.Errorf("不认识的账户那一行：%s", changes[2])
	}
	if !strings.Contains(changes[4], `"action":"restore"`) || !strings.Contains(changes[4], `"revocation_epoch":2`) {
		t.Errorf("恢复的那一行：%s", changes[4])
	}
	if strings.Contains(f.logs.String(), "provider-token") {
		t.Error("凭证出现在日志里")
	}
}

// 只有撤销者能读、能改。别的身份，包括能拿到凭证的网关，得到 401，状态不变。
func TestRevocationsOnlyTheRevokerMayReadOrChange(t *testing.T) {
	f, ledger := newRevokerFixture(t)
	if recorder := f.call("revoker", "POST", PathRevocations, nil, revokeBlue); recorder.Code != http.StatusOK {
		t.Fatalf("撤销者自己：%d %s", recorder.Code, recorder.Body)
	}
	for _, peer := range []string{"gateway", "broker", "business", "anonymous", "two-names", ""} {
		for name, request := range map[string][2]string{"读表": {"GET", ""}, "恢复": {"POST", restoreBlue},
			"撤销": {"POST", `{"account_id":"account-green","revoked":true,"reason":"not mine to revoke"}`}, "别的方法": {"DELETE", ""}} {
			recorder := f.call(peer, request[0], PathRevocations, nil, request[1])
			if recorder.Code != http.StatusUnauthorized || decode(t, recorder)["reason_code"] != reasonRevokerUnauthenticated {
				t.Errorf("%q %s：%d %s", peer, name, recorder.Code, recorder.Body)
			}
			if strings.Contains(recorder.Body.String(), "account-blue") || carriesCredential(recorder) {
				t.Errorf("%q %s：应答里带出了撤销表或凭证：%s", peer, name, recorder.Body)
			}
		}
	}
	if accounts, epoch, _ := ledger.Revoked(context.Background()); epoch != 1 || len(accounts) != 1 || accounts[0].AccountID != "account-blue" {
		t.Fatalf("被拒绝的调用改了撤销表：%+v，代次 %d", accounts, epoch)
	}
	if f.blueIsAllowed() {
		t.Fatal("被拒绝的恢复却生效了")
	}
	// 撤销者只能做这一件事：它要不到判定，也要不到凭证。
	for _, path := range []string{PathExtAuthz, PathDecision} {
		if recorder := f.call("revoker", "GET", path, trusted("tenant-green"), ""); recorder.Code != http.StatusUnauthorized || carriesCredential(recorder) {
			t.Errorf("撤销者调 %s：%d", path, recorder.Code)
		}
	}
}

func TestRevocationRequestsThatAreNotAccepted(t *testing.T) {
	f, ledger := newRevokerFixture(t)
	long := strings.Repeat("r", maxReasonBytes+1)
	for name, body := range map[string]string{
		"空的":           ``,
		"不是 JSON":      `revoke account-blue`,
		"数组":           `[]`,
		"空对象":          `{}`,
		"没有说撤销还是恢复":    `{"account_id":"account-blue","reason":"x"}`,
		"没有账户":         `{"revoked":true,"reason":"x"}`,
		"账户是 null":     `{"account_id":null,"revoked":true,"reason":"x"}`,
		"空账户":          `{"account_id":"","revoked":true,"reason":"x"}`,
		"撤销没有原因":       `{"account_id":"account-blue","revoked":true}`,
		"原因只有空白":       `{"account_id":"account-blue","revoked":true,"reason":"   "}`,
		"revoked 是字符串": `{"account_id":"account-blue","revoked":"true","reason":"x"}`,
		"有不认识的字段":      `{"account_id":"account-blue","revoked":true,"reason":"x","restore_all":true}`,
		"后面还有内容":       revokeBlue + ` ` + restoreBlue,
		"原因里有换行":       `{"account_id":"account-blue","revoked":true,"reason":"line one\nlevel=ERROR forged"}`,
		"原因太长":         `{"account_id":"account-blue","revoked":true,"reason":"` + long + `"}`,
		"账户太长":         `{"account_id":"` + strings.Repeat("a", maxAccountIDBytes+1) + `","revoked":true,"reason":"x"}`,
		"账户里有控制字符":     `{"account_id":"account-blue\u0000","revoked":true,"reason":"x"}`,
		"请求太大":         `{"account_id":"account-blue","revoked":true,"reason":"x","padding":"` + strings.Repeat("p", maxRevocationRequestBytes) + `"}`,
	} {
		recorder := f.call("revoker", "POST", PathRevocations, nil, body)
		if recorder.Code != http.StatusBadRequest || decode(t, recorder)["error"] != "invalid_revocation_request" {
			t.Errorf("%s：%d %s", name, recorder.Code, recorder.Body)
		}
	}
	for _, method := range []string{"PUT", "PATCH", "DELETE", "HEAD"} {
		recorder := f.call("revoker", method, PathRevocations, nil, revokeBlue)
		if recorder.Code != http.StatusMethodNotAllowed || recorder.Header().Get("Allow") != "GET, POST" {
			t.Errorf("%s：%d，Allow 是 %q", method, recorder.Code, recorder.Header().Get("Allow"))
		}
	}
	if accounts, epoch, _ := ledger.Revoked(context.Background()); epoch != 0 || len(accounts) != 0 || !f.blueIsAllowed() {
		t.Fatalf("没有被接受的请求改了撤销表：%+v，代次 %d", accounts, epoch)
	}
	// 长度正好在上限上的原因是可以的；恢复不用写原因。
	atLimit := `{"account_id":"account-blue","revoked":true,"reason":"` + long[1:] + `"}`
	if recorder := f.call("revoker", "POST", PathRevocations, nil, atLimit); recorder.Code != http.StatusOK {
		t.Errorf("原因正好 %d 字节：%d %s", maxReasonBytes, recorder.Code, recorder.Body)
	}
	if recorder := f.call("revoker", "POST", PathRevocations, nil, restoreBlue); recorder.Code != http.StatusOK {
		t.Errorf("不写原因的恢复：%d %s", recorder.Code, recorder.Body)
	}
}

// 撤销没写下去：照样生效，接口说出来。恢复没写下去：不恢复。
func TestRevocationThatCouldNotBeWrittenIsStillInEffect(t *testing.T) {
	f, ledger := newRevokerFixture(t)
	ledger.broken = true
	recorder := f.call("revoker", "POST", PathRevocations, nil, revokeBlue)
	if recorder.Code != http.StatusInternalServerError || recorder.Body.String() !=
		`{"account_id":"account-blue","revoked":true,"changed":true,"revocation_epoch":1,"error":"revocation_in_effect_but_not_written"}` {
		t.Fatalf("没写下去的撤销：%d %s", recorder.Code, recorder.Body)
	}
	if f.blueIsAllowed() {
		t.Fatal("没写下去的撤销没有生效")
	}
	recorder = f.call("revoker", "POST", PathRevocations, nil, restoreBlue)
	if recorder.Code != http.StatusInternalServerError || recorder.Body.String() !=
		`{"account_id":"account-blue","revoked":true,"changed":false,"revocation_epoch":1,"error":"revocations_not_changed"}` {
		t.Fatalf("没写下去的恢复：%d %s", recorder.Code, recorder.Body)
	}
	if f.blueIsAllowed() {
		t.Fatal("没写下去的恢复却生效了")
	}
	if logs := f.logs.String(); strings.Count(logs, `"level":"ERROR"`) != 2 || !strings.Contains(logs, "revocation in effect but not written") {
		t.Errorf("两次没写下去应当各记一行错误：%s", logs)
	}
}

// 没有配置撤销者时，这个接口不存在：对谁都是 404。
func TestWithoutARevokerThereIsNoRevocationInterface(t *testing.T) {
	f := newFixture(t)
	for _, peer := range []string{"gateway", "broker", "business", "anonymous", ""} {
		for _, method := range []string{"GET", "POST", "DELETE"} {
			recorder := f.call(peer, method, PathRevocations, nil, revokeBlue)
			if recorder.Code != http.StatusNotFound || decode(t, recorder)["error"] != "not_found" {
				t.Errorf("%q %s：%d %s", peer, method, recorder.Code, recorder.Body)
			}
		}
	}
	if !f.blueIsAllowed() {
		t.Fatal("对一个不存在的接口的调用改变了判定")
	}
}
