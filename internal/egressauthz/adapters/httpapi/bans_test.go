package httpapi

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"strings"
	"testing"

	"go.idp.xyz/idp-gateway/internal/egressauthz/application"
	"go.idp.xyz/idp-gateway/internal/egressauthz/domain"
	"go.idp.xyz/idp-gateway/internal/egressauthz/ports"
	"go.idp.xyz/idp-gateway/internal/platform/workloadtls/tlstest"
)

func newBanFixture(t *testing.T) (*fixture, *testLedger) {
	t.Helper()
	ca := tlstest.NewCA(t, "workload CA")
	ledger := &testLedger{entries: map[string]ports.RevokedAccount{}, bans: map[string]ports.BannedOperation{}}
	f := &fixture{
		credentials: staticCredentials{
			ports.Handle(binding, "account-blue"):  blueToken,
			ports.Handle(binding, "account-green"): greenToken,
		},
		logs: &bytes.Buffer{},
		peers: map[string]tlstest.Leaf{
			"gateway":  ca.Issue("gateway", []string{gatewayID}),
			"broker":   ca.Issue("broker", []string{brokerID}),
			"business": ca.Issue("business", []string{businessID}),
			"revoker":  ca.Issue("revoker", []string{revokerID}),
		},
	}
	policy := domain.Policy{Version: "policy-7", Operations: []domain.Operation{
		{
			ProviderID: "mockcarrier", OperationID: "tracking.get", Environment: "TEST", Method: "GET",
			PathPrefix: tracking, CredentialBindingRef: binding,
			AllowedTenants: []string{"tenant-blue", "tenant-green"}, AllowedServiceIDs: []string{"parcel-service"},
			AccountsByTenant: map[string][]string{"tenant-blue": {"account-blue"}, "tenant-green": {"account-green"}},
		},
		{
			ProviderID: "mockcarrier", OperationID: "labels.print", Environment: "TEST", Method: "POST",
			PathPrefix: "/providers/mockcarrier/v1/labels", CredentialBindingRef: binding,
			AllowedTenants: []string{"tenant-blue"}, AllowedServiceIDs: []string{"parcel-service"},
			AccountsByTenant: map[string][]string{"tenant-blue": {"account-blue"}},
		},
	}}
	service := application.New(policy, f.credentials, ledger, application.WithRevocationLedger(ledger))
	f.handler = New(service, Callers{Gateway: gatewayID, Broker: brokerID, Revoker: revokerID}, slog.New(slog.NewJSONHandler(f.logs, nil)))
	return f, ledger
}

func labelsHeaders() [][2]string {
	headers := trusted("tenant-blue")
	for i, header := range headers {
		switch strings.ToLower(header[0]) {
		case "x-idp-operation-id":
			headers[i][1] = "labels.print"
		case "x-idp-method":
			headers[i][1] = "POST"
		case "x-idp-path":
			headers[i][1] = "/providers/mockcarrier/v1/labels/1"
		}
	}
	return headers
}

func TestOperationBansThroughTheInterface(t *testing.T) {
	f, ledger := newBanFixture(t)
	ban := `{"operation_id":"tracking.get","banned":true,"reason":"abuse"}`
	lift := `{"operation_id":"tracking.get","banned":false}`

	recorder := f.call("revoker", "POST", PathOperationBans, nil, ban)
	if recorder.Code != http.StatusOK || recorder.Body.String() !=
		`{"operation_id":"tracking.get","banned":true,"changed":true,"revocation_epoch":1}` {
		t.Fatalf("封禁：%d %s", recorder.Code, recorder.Body)
	}
	denied := f.call("gateway", "GET", PathExtAuthz, trusted("tenant-blue"), "")
	body := decode(t, denied)
	if denied.Code != http.StatusForbidden || body["reason_code"] != "OPERATION_BANNED" || carriesCredential(denied) {
		t.Fatalf("封禁之后：%d %s", denied.Code, denied.Body)
	}
	allowed := f.call("gateway", "POST", PathExtAuthz, labelsHeaders(), "")
	if allowed.Code != http.StatusOK || allowed.Header().Get("Authorization") != blueToken {
		t.Fatalf("另一个操作：%d %s", allowed.Code, allowed.Body)
	}
	green := f.call("gateway", "GET", PathExtAuthz, trusted("tenant-green"), "")
	if green.Code != http.StatusForbidden || decode(t, green)["reason_code"] != "OPERATION_BANNED" || carriesCredential(green) {
		t.Fatalf("绿账户：%d %s", green.Code, green.Body)
	}

	again := f.call("revoker", "POST", PathOperationBans, nil, `{"operation_id":"tracking.get","banned":true,"reason":"again"}`)
	if again.Code != http.StatusOK || again.Body.String() !=
		`{"operation_id":"tracking.get","banned":true,"changed":false,"revocation_epoch":1}` {
		t.Fatalf("重复封禁：%d %s", again.Code, again.Body)
	}
	unknown := f.call("revoker", "POST", PathOperationBans, nil, `{"operation_id":"no.such","banned":true,"reason":"typo"}`)
	if unknown.Code != http.StatusUnprocessableEntity || unknown.Body.String() !=
		`{"operation_id":"no.such","banned":false,"changed":false,"revocation_epoch":1,"error":"unknown_operation"}` {
		t.Fatalf("不认识的操作：%d %s", unknown.Code, unknown.Body)
	}
	if operations, epoch, _ := ledger.Banned(context.Background()); len(operations) != 1 || operations[0].OperationID != "tracking.get" || epoch != 1 {
		t.Fatalf("表被不认识的操作改了：%+v %d", operations, epoch)
	}

	if recorder := f.call("gateway", "POST", PathOperationBans, nil, ban); recorder.Code != http.StatusUnauthorized {
		t.Fatalf("网关去封禁：%d", recorder.Code)
	}
	listed := f.call("revoker", "GET", PathOperationBans, nil, "")
	if listed.Code != http.StatusOK || !strings.Contains(listed.Body.String(), `"operation_id":"tracking.get"`) || carriesCredential(listed) {
		t.Fatalf("读表：%d %s", listed.Code, listed.Body)
	}

	lifted := f.call("revoker", "POST", PathOperationBans, nil, lift)
	if lifted.Code != http.StatusOK || lifted.Body.String() !=
		`{"operation_id":"tracking.get","banned":false,"changed":true,"revocation_epoch":2}` {
		t.Fatalf("解除：%d %s", lifted.Code, lifted.Body)
	}
	if restored := f.call("gateway", "GET", PathExtAuthz, trusted("tenant-blue"), ""); restored.Code != http.StatusOK || restored.Header().Get("Authorization") != blueToken {
		t.Fatalf("解除之后：%d", restored.Code)
	}
}

func TestWithoutARevokerThereIsNoOperationBanInterface(t *testing.T) {
	f := newFixture(t)
	recorder := f.call("gateway", "POST", PathOperationBans, nil, `{"operation_id":"tracking.get","banned":true,"reason":"abuse"}`)
	if recorder.Code != http.StatusNotFound || decode(t, recorder)["error"] != "not_found" {
		t.Fatalf("%d %s", recorder.Code, recorder.Body)
	}
	if !f.blueIsAllowed() {
		t.Fatal("对一个不存在的接口的调用改变了判定")
	}
}
