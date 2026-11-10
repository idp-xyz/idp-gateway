package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"go.idp.xyz/idp-gateway/internal/egressauthz/adapters/memory"
	"go.idp.xyz/idp-gateway/internal/egressauthz/application"
	"go.idp.xyz/idp-gateway/internal/egressauthz/domain"
	"go.idp.xyz/idp-gateway/internal/egressauthz/ports"
	"go.idp.xyz/idp-gateway/internal/platform/workloadtls/tlstest"
)

const (
	gatewayID  = "spiffe://idp.test/egress/agentgateway"
	brokerID   = "spiffe://idp.test/egress/credential-broker"
	businessID = "spiffe://idp.test/apps/parcel-service"
	binding    = "gatekeeper:mockcarrier-test"
	blueToken  = "Bearer provider-token-blue"
	greenToken = "Bearer provider-token-green"
	tracking   = "/providers/mockcarrier/v1/tracking"
)

type staticCredentials map[string]string

func (s staticCredentials) AuthorizationHeader(_ context.Context, bindingRef, accountID string) (ports.Secret, error) {
	value, ok := s[ports.Handle(bindingRef, accountID)]
	if !ok {
		return ports.Secret{}, ports.ErrCredentialNotHeld
	}
	return ports.NewSecret(value), nil
}

type brokenRevocations struct{}

func (brokenRevocations) State(context.Context, string) (bool, uint64, error) {
	return false, 0, errors.New("revocation store down")
}
func (brokenRevocations) Epoch(context.Context) (uint64, error) {
	return 0, errors.New("revocation store down")
}

type fixture struct {
	handler     *Handler
	revocations *memory.Revocations
	credentials staticCredentials
	logs        *bytes.Buffer
	peers       map[string]tlstest.Leaf
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	ca := tlstest.NewCA(t, "workload CA")
	f := &fixture{
		revocations: &memory.Revocations{},
		credentials: staticCredentials{
			ports.Handle(binding, "account-blue"):  blueToken,
			ports.Handle(binding, "account-green"): greenToken,
		},
		logs: &bytes.Buffer{},
		peers: map[string]tlstest.Leaf{
			"gateway":   ca.Issue("gateway", []string{gatewayID}),
			"broker":    ca.Issue("broker", []string{brokerID}),
			"business":  ca.Issue("business", []string{businessID}),
			"anonymous": ca.Issue("anonymous", nil),
			"two-names": ca.Issue("two-names", []string{gatewayID, businessID}),
		},
	}
	policy := domain.Policy{Version: "policy-7", Operations: []domain.Operation{{
		ProviderID: "mockcarrier", OperationID: "tracking.get", Environment: "TEST", Method: "GET",
		PathPrefix: tracking, CredentialBindingRef: binding,
		AllowedTenants: []string{"tenant-blue", "tenant-green"}, AllowedServiceIDs: []string{"parcel-service"},
		AccountsByTenant: map[string][]string{"tenant-blue": {"account-blue"}, "tenant-green": {"account-green"}},
	}}}
	service := application.New(policy, f.credentials, f.revocations)
	f.handler = New(service, Callers{Gateway: gatewayID, Broker: brokerID}, slog.New(slog.NewJSONHandler(f.logs, nil)))
	f.handler.now = func() time.Time { return time.Date(2026, 11, 10, 8, 0, 0, 0, time.UTC) }
	return f
}

// trusted 是网关会写入的可信上下文。
func trusted(tenant string) [][2]string {
	return [][2]string{
		{"x-idp-verified-subject", "parcel-service"}, {"x-idp-verified-tenant", tenant}, {"x-idp-verified-env", "TEST"},
		{"x-idp-route-id", "mockcarrier-tracking-get"}, {"x-idp-provider-id", "mockcarrier"},
		{"x-idp-operation-id", "tracking.get"}, {"x-idp-environment", "TEST"}, {"x-idp-method", "GET"},
		{"x-idp-path", tracking + "/TRK-1"},
	}
}

// call 以 peer 的证书调用处理器；peer 为空表示连接上没有已验证的客户端证书。
func (f *fixture) call(peer, method, path string, headers [][2]string, body string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	for _, h := range headers {
		request.Header.Add(h[0], h[1])
	}
	if peer != "" {
		request.TLS = tlstest.PeerState(f.peers[peer])
	}
	recorder := httptest.NewRecorder()
	f.handler.ServeHTTP(recorder, request)
	return recorder
}

func decode(t *testing.T, recorder *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var body map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("响应不是 JSON：%q", recorder.Body.String())
	}
	return body
}

// carriesCredential 报告响应的任何位置是否出现了 Provider 凭证。
func carriesCredential(recorder *httptest.ResponseRecorder) bool {
	var all strings.Builder
	all.Write(recorder.Body.Bytes())
	for name, values := range recorder.Header() {
		all.WriteString(name + strings.Join(values, ","))
	}
	return strings.Contains(all.String(), "provider-token")
}

func TestExtAuthzReleasesEachTenantsOwnCredentialInAHeaderOnly(t *testing.T) {
	f := newFixture(t)
	for tenant, token := range map[string]string{"tenant-blue": blueToken, "tenant-green": greenToken} {
		recorder := f.call("gateway", "GET", PathExtAuthz, trusted(tenant), "")
		if recorder.Code != http.StatusOK {
			t.Fatalf("%s: %d %s", tenant, recorder.Code, recorder.Body)
		}
		if got := recorder.Header().Values("Authorization"); len(got) != 1 || got[0] != token {
			t.Fatalf("%s: Authorization 头不是它自己账户的凭证", tenant)
		}
		body := decode(t, recorder)
		if body["result"] != "ALLOW" || body["reason_code"] != "ACTIVE_ACCOUNT_GRANT" || body["policy_version"] != "policy-7" {
			t.Fatalf("%s: %v", tenant, body)
		}
		if recorder.Header().Get("X-Idp-Decision-Id") != body["decision_id"] || body["decision_id"] == "" {
			t.Fatalf("%s: 判定标识不一致", tenant)
		}
		if strings.Contains(recorder.Body.String(), "provider-token") {
			t.Fatalf("%s: 凭证出现在响应正文里", tenant)
		}
		if recorder.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("%s: 响应可被缓存", tenant)
		}
	}
	if strings.Contains(f.logs.String(), "provider-token") {
		t.Fatalf("凭证出现在日志里：%s", f.logs)
	}
}

// 契约规定网关转发原方法；每种方法的交换都相同。
func TestExtAuthzAnswersEveryMethod(t *testing.T) {
	f := newFixture(t)
	for _, method := range []string{"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"} {
		if recorder := f.call("gateway", method, PathExtAuthz, trusted("tenant-blue"), ""); recorder.Code != http.StatusOK ||
			recorder.Header().Get("Authorization") != blueToken {
			t.Errorf("%s: %d", method, recorder.Code)
		}
	}
}

func TestExtAuthzOnlyTheGatewayMayAsk(t *testing.T) {
	f := newFixture(t)
	// 请求本身挑不出毛病，还带着一个调用方 JWT 模样的 Authorization 头：拒绝只能是因为身份。
	headers := append(trusted("tenant-blue"), [2]string{"Authorization", "Bearer eyJhbGciOiJSUzI1NiJ9.e30.c2ln"})
	for _, peer := range []string{"", "business", "broker", "anonymous", "two-names"} {
		recorder := f.call(peer, "GET", PathExtAuthz, headers, "")
		if recorder.Code != http.StatusUnauthorized {
			t.Errorf("身份 %q: %d", peer, recorder.Code)
		}
		if body := decode(t, recorder); body["result"] != "DENY" || body["reason_code"] != reasonCallerUnauthenticated {
			t.Errorf("身份 %q: %v", peer, body)
		}
		if carriesCredential(recorder) {
			t.Errorf("身份 %q 拿到了凭证", peer)
		}
	}
	if recorder := f.call("gateway", "GET", PathExtAuthz, headers, ""); recorder.Code != http.StatusOK || !carriesCredential(recorder) {
		t.Fatalf("对照：同一个请求换成网关的证书应当放行，得到 %d", recorder.Code)
	}
}

// 没有配置网关身份时，任何身份都不等于它，包括空身份。
func TestNoCallerMatchesAnUnsetIdentity(t *testing.T) {
	var none Callers
	for _, path := range []string{PathExtAuthz, PathDecision, PathHealth} {
		for _, identity := range []string{"", gatewayID} {
			if none.MayCall(path, identity) {
				t.Errorf("%s 对身份 %q 放行", path, identity)
			}
		}
	}
	if (Callers{Gateway: gatewayID}).MayCall(PathDecision, "") {
		t.Error("空身份匹配上了未配置的 Broker")
	}
}

func TestExtAuthzDenials(t *testing.T) {
	replace := func(name, value string) func([][2]string) [][2]string {
		return func(headers [][2]string) [][2]string {
			for i := range headers {
				if headers[i][0] == name {
					headers[i][1] = value
				}
			}
			return headers
		}
	}
	add := func(name, value string) func([][2]string) [][2]string {
		return func(headers [][2]string) [][2]string { return append(headers, [2]string{name, value}) }
	}
	drop := func(name string) func([][2]string) [][2]string {
		return func(headers [][2]string) [][2]string {
			var kept [][2]string
			for _, h := range headers {
				if h[0] != name {
					kept = append(kept, h)
				}
			}
			return kept
		}
	}
	cases := map[string]struct {
		mutate func([][2]string) [][2]string
		reason string
	}{
		"蓝租户申请绿账户":     {add("X-Provider-Account", "account-green"), "ACCOUNT_NOT_GRANTED"},
		"申请不存在的账户":     {add("X-Provider-Account", "account-nobody"), "ACCOUNT_NOT_GRANTED"},
		"没有租户":         {drop("x-idp-verified-tenant"), "UNAUTHENTICATED"},
		"没有服务身份":       {drop("x-idp-verified-subject"), "UNAUTHENTICATED"},
		"没有 Token 环境":  {drop("x-idp-verified-env"), "UNAUTHENTICATED"},
		"PROD 的 Token": {replace("x-idp-verified-env", "PROD"), "ENVIRONMENT_MISMATCH"},
		"未获授的服务":       {replace("x-idp-verified-subject", "cargo-service"), "SERVICE_NOT_GRANTED"},
		"未获授的租户":       {replace("x-idp-verified-tenant", "tenant-red"), "TENANT_NOT_GRANTED"},
		"二次编码的点段":      {replace("x-idp-path", tracking+"/%252e%252e/admin"), "PATH_NOT_CANONICAL"},
		"没有路径":         {drop("x-idp-path"), "PATH_NOT_CANONICAL"},
		"未登记的操作":       {replace("x-idp-operation-id", "labels.create"), "NO_MATCHING_ALLOWLIST_OPERATION"},
		"未登记的方法":       {replace("x-idp-method", "POST"), "NO_MATCHING_ALLOWLIST_OPERATION"},
		"第二份租户头":       {add("X-Idp-Verified-Tenant", "tenant-green"), reasonAmbiguousContext},
		"第二份相同的租户头":    {add("x-idp-verified-tenant", "tenant-blue"), reasonAmbiguousContext},
		"第二份路径头":       {add("X-IDP-PATH", tracking+"/TRK-2"), reasonAmbiguousContext},
		"第二份操作头":       {add("x-idp-operation-id", "tracking.get"), reasonAmbiguousContext},
		"两个账户申请": {func(h [][2]string) [][2]string {
			return append(h, [2]string{"X-Provider-Account", "account-blue"}, [2]string{"x-provider-account", "account-blue"})
		}, reasonAmbiguousAccount},
		"什么上下文都没有": {func([][2]string) [][2]string { return nil }, "UNAUTHENTICATED"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			recorder := f.call("gateway", "GET", PathExtAuthz, tc.mutate(trusted("tenant-blue")), "")
			if recorder.Code != http.StatusForbidden {
				t.Fatalf("状态 %d：%s", recorder.Code, recorder.Body)
			}
			body := decode(t, recorder)
			if body["result"] != "DENY" || body["reason_code"] != tc.reason {
				t.Fatalf("%v，期望 %s", body, tc.reason)
			}
			// 契约 ExtAuthzDenial 的必填项。
			for _, field := range []string{"result", "reason_code", "policy_version", "revocation_epoch"} {
				if _, ok := body[field]; !ok {
					t.Errorf("拒绝正文缺 %s", field)
				}
			}
			if carriesCredential(recorder) || recorder.Header().Get("Authorization") != "" {
				t.Fatal("拒绝响应里有凭证")
			}
		})
	}
}

func TestExtAuthzRevocation(t *testing.T) {
	f := newFixture(t)
	f.revocations.Revoke("account-blue")
	recorder := f.call("gateway", "GET", PathExtAuthz, trusted("tenant-blue"), "")
	if body := decode(t, recorder); recorder.Code != http.StatusForbidden || body["reason_code"] != "ACCOUNT_REVOKED" || body["revocation_epoch"] != float64(1) {
		t.Fatalf("%d %v", recorder.Code, body)
	}
	if carriesCredential(recorder) {
		t.Fatal("已撤销的账户拿到了凭证")
	}
	if recorder := f.call("gateway", "GET", PathExtAuthz, trusted("tenant-green"), ""); recorder.Code != http.StatusOK {
		t.Fatalf("绿租户受影响：%d", recorder.Code)
	}
	f.revocations.Restore("account-blue")
	if recorder := f.call("gateway", "GET", PathExtAuthz, trusted("tenant-blue"), ""); recorder.Code != http.StatusOK {
		t.Fatalf("恢复后：%d", recorder.Code)
	}
}

// 判定做不出来时回答 503 而不是 403，也绝不是 200。
func TestExtAuthzIndeterminate(t *testing.T) {
	f := newFixture(t)
	delete(f.credentials, ports.Handle(binding, "account-blue"))
	recorder := f.call("gateway", "GET", PathExtAuthz, trusted("tenant-blue"), "")
	if body := decode(t, recorder); recorder.Code != http.StatusServiceUnavailable || body["result"] != "INDETERMINATE" ||
		body["reason_code"] != application.ReasonCredentialUnavailable {
		t.Fatalf("取不到凭证：%d %v", recorder.Code, body)
	}
	if recorder.Header().Get("Authorization") != "" {
		t.Fatal("取不到凭证时仍写了 Authorization 头")
	}

	service := application.New(domain.Policy{Version: "policy-7"}, f.credentials, brokenRevocations{})
	handler := New(service, Callers{Gateway: gatewayID}, slog.New(slog.NewJSONHandler(f.logs, nil)))
	request := httptest.NewRequest("GET", PathExtAuthz, nil)
	request.TLS = tlstest.PeerState(f.peers["gateway"])
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if body := decode(t, response); response.Code != http.StatusServiceUnavailable || body["reason_code"] != application.ReasonRevocationStateUnavailable {
		t.Fatalf("读不到撤销状态：%d %v", response.Code, body)
	}
}

func decisionJSON(overrides map[string]any) string {
	request := map[string]any{
		"request_id": "req-0001", "route_id": "mockcarrier-tracking-get", "operation_id": "tracking.get",
		"provider_id": "mockcarrier", "requested_account_id": "", "environment": "TEST", "method": "GET",
		"path": tracking + "/TRK-1", "config_digest": "sha256:abc", "service_id": "parcel-service",
		"tenant_id": "tenant-blue", "token_environment": "TEST",
	}
	for key, value := range overrides {
		if value == nil {
			delete(request, key)
		} else {
			request[key] = value
		}
	}
	encoded, _ := json.Marshal(request)
	return string(encoded)
}

func TestDecisionReturnsAHandleAndNeverACredential(t *testing.T) {
	f := newFixture(t)
	for _, peer := range []string{"gateway", "broker"} {
		recorder := f.call(peer, "POST", PathDecision, nil, decisionJSON(nil))
		if recorder.Code != http.StatusOK {
			t.Fatalf("%s: %d %s", peer, recorder.Code, recorder.Body)
		}
		body := decode(t, recorder)
		want := map[string]any{
			"result": "ALLOW", "reason_code": "ACTIVE_ACCOUNT_GRANT", "policy_version": "policy-7",
			"revocation_epoch": float64(0), "request_id": "req-0001", "expires_at": "2026-11-10T08:00:30Z",
			"credential_handle": binding + "/account-blue",
		}
		for key, value := range want {
			if body[key] != value {
				t.Errorf("%s: %s = %v，期望 %v", peer, key, body[key], value)
			}
		}
		// authz-decision.schema.json 不允许多余的字段。
		if len(body) != len(want)+1 || body["decision_id"] == "" {
			t.Errorf("%s: 字段集合 %v", peer, body)
		}
		if carriesCredential(recorder) || recorder.Header().Get("Authorization") != "" {
			t.Fatalf("%s: 只返回判定的接口带出了凭证", peer)
		}
	}
}

func TestDecisionDenials(t *testing.T) {
	f := newFixture(t)
	for name, tc := range map[string]struct {
		overrides map[string]any
		reason    string
	}{
		"蓝租户申请绿账户":      {map[string]any{"requested_account_id": "account-green"}, "ACCOUNT_NOT_GRANTED"},
		"PROD 的 Token":  {map[string]any{"token_environment": "PROD"}, "ENVIRONMENT_MISMATCH"},
		"没有转述 Token 环境": {map[string]any{"token_environment": nil}, "UNAUTHENTICATED"},
		"没有转述租户":        {map[string]any{"tenant_id": nil}, "UNAUTHENTICATED"},
		"不规范的路径":        {map[string]any{"path": tracking + "/..%2fadmin"}, "PATH_NOT_CANONICAL"},
	} {
		recorder := f.call("broker", "POST", PathDecision, nil, decisionJSON(tc.overrides))
		body := decode(t, recorder)
		if recorder.Code != http.StatusOK || body["result"] != "DENY" || body["reason_code"] != tc.reason {
			t.Errorf("%s: %d %v", name, recorder.Code, body)
		}
		if _, has := body["credential_handle"]; has {
			t.Errorf("%s: 拒绝的判定带了凭证句柄", name)
		}
	}

	f.revocations.Revoke("account-blue")
	body := decode(t, f.call("broker", "POST", PathDecision, nil, decisionJSON(nil)))
	if body["result"] != "DENY" || body["reason_code"] != "ACCOUNT_REVOKED" || body["revocation_epoch"] != float64(1) {
		t.Fatalf("撤销后：%v", body)
	}
}

func TestDecisionRejectsMalformedRequests(t *testing.T) {
	f := newFixture(t)
	bad := map[string]string{
		"空正文":       ``,
		"不是 JSON":   `not json`,
		"null":      `null`,
		"数组":        `[]`,
		"缺必填项":      decisionJSON(map[string]any{"config_digest": nil}),
		"缺申请的账户":    decisionJSON(map[string]any{"requested_account_id": nil}),
		"必填项不是字符串":  decisionJSON(map[string]any{"path": 7}),
		"必填项为 null": strings.Replace(decisionJSON(nil), `"req-0001"`, `null`, 1),
		"可选项不是字符串":  decisionJSON(map[string]any{"tenant_id": []string{"tenant-blue"}}),
		"契约之外的字段":   decisionJSON(map[string]any{"target_override": "http://127.0.0.1/"}),
		"文档后面还有内容":  decisionJSON(nil) + `{"tenant_id":"tenant-green"}`,
		"超过大小上限":    decisionJSON(map[string]any{"delegated_subject": strings.Repeat("x", maxDecisionRequestBytes)}),
	}
	for name, body := range bad {
		recorder := f.call("broker", "POST", PathDecision, nil, body)
		if recorder.Code != http.StatusBadRequest || decode(t, recorder)["error"] != "invalid_decision_request" {
			t.Errorf("%s: %d %s", name, recorder.Code, recorder.Body)
		}
	}
	if recorder := f.call("broker", "POST", PathDecision, nil, decisionJSON(map[string]any{"delegated_subject": "user-1"})); recorder.Code != http.StatusOK {
		t.Errorf("契约里的可选字段被拒绝：%d", recorder.Code)
	}
}

func TestDecisionCallersAndMethod(t *testing.T) {
	f := newFixture(t)
	for _, peer := range []string{"", "business", "anonymous", "two-names"} {
		recorder := f.call(peer, "POST", PathDecision, nil, decisionJSON(nil))
		if recorder.Code != http.StatusUnauthorized || decode(t, recorder)["reason_code"] != reasonCallerUnauthenticated {
			t.Errorf("身份 %q: %d", peer, recorder.Code)
		}
	}
	for _, method := range []string{"GET", "PUT", "DELETE"} {
		recorder := f.call("broker", method, PathDecision, nil, decisionJSON(nil))
		if recorder.Code != http.StatusMethodNotAllowed || recorder.Header().Get("Allow") != "POST" {
			t.Errorf("%s: %d", method, recorder.Code)
		}
	}
}

func TestOtherPaths(t *testing.T) {
	f := newFixture(t)
	if recorder := f.call("gateway", "GET", PathHealth, nil, ""); recorder.Code != http.StatusOK {
		t.Fatalf("healthz: %d", recorder.Code)
	}
	for _, path := range []string{"/", "/admin/log", "/admin/mode?value=error500", "/v1/extauthz/check/", "/v1/egress/credentials/materialize",
		"/v1/extauthz", "/V1/EXTAUTHZ/CHECK"} {
		recorder := f.call("gateway", "GET", path, trusted("tenant-blue"), "")
		if recorder.Code != http.StatusNotFound || carriesCredential(recorder) {
			t.Errorf("%s: %d", path, recorder.Code)
		}
	}
}

// 每次判定留一行日志，里面有判定的事实，没有凭证，也没有请求头的原值。
func TestDecisionsAreLoggedWithoutSecrets(t *testing.T) {
	f := newFixture(t)
	headers := append(trusted("tenant-blue"), [2]string{"Authorization", "Bearer caller-jwt-should-not-be-logged"},
		[2]string{"Cookie", "session=should-not-be-logged"})
	f.call("gateway", "GET", PathExtAuthz, headers, "")
	f.call("gateway", "GET", PathExtAuthz, append(trusted("tenant-blue"), [2]string{"X-Provider-Account", "account-green"}), "")
	f.call("business", "GET", PathExtAuthz, headers, "")

	lines := strings.Split(strings.TrimSpace(f.logs.String()), "\n")
	if len(lines) != 3 {
		t.Fatalf("日志 %d 行：%s", len(lines), f.logs)
	}
	var allow, denial, refused map[string]any
	for i, target := range []*map[string]any{&allow, &denial, &refused} {
		if err := json.Unmarshal([]byte(lines[i]), target); err != nil {
			t.Fatal(err)
		}
	}
	if allow["result"] != "ALLOW" || allow["caller"] != gatewayID || allow["tenant"] != "tenant-blue" || allow["account"] != "account-blue" ||
		allow["route_id"] != "mockcarrier-tracking-get" || allow["decision_id"] == "" {
		t.Errorf("放行的日志：%v", allow)
	}
	if denial["result"] != "DENY" || denial["reason"] != "ACCOUNT_NOT_GRANTED" || denial["account"] != "account-green" {
		t.Errorf("拒绝的日志：%v", denial)
	}
	if refused["caller"] != businessID || refused["reason"] != reasonCallerUnauthenticated {
		t.Errorf("身份不对的日志：%v", refused)
	}
	for _, forbidden := range []string{"provider-token", "should-not-be-logged"} {
		if strings.Contains(f.logs.String(), forbidden) {
			t.Errorf("日志里出现了 %q", forbidden)
		}
	}
}
