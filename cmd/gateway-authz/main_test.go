package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"go.idp.xyz/idp-gateway/internal/egressauthz/ports"
	"go.idp.xyz/idp-gateway/internal/platform/workloadtls/tlstest"
)

const (
	serverName  = "authz.idp.test"
	gatewayID   = "spiffe://idp.test/egress/agentgateway"
	brokerID    = "spiffe://idp.test/egress/credential-broker"
	operatorID  = "spiffe://idp.test/poc/operator"
	businessID  = "spiffe://idp.test/apps/parcel-service"
	revokerID   = "spiffe://idp.test/egress/revoker"
	publisherID = "spiffe://idp.test/egress/publisher"
	tracking    = "/providers/mockcarrier/v1/tracking"
	blueToken   = "provider-token-blue"
	greenToken  = "provider-token-green"

	extAuthzPath    = "/v1/extauthz/check"
	decisionPath    = "/v1/egress/authorizations/decision"
	revocationsPath = "/v1/egress/revocations"
)

const policyJSON = `{
  "version": "policy-e2e",
  "default_decision": "DENY",
  "registered_operations": [{
    "route_id": "mockcarrier-tracking-get", "provider_id": "mockcarrier", "operation_id": "tracking.get",
    "environment": "TEST", "method": "GET", "path_prefix": "/providers/mockcarrier/v1/tracking",
    "credential_binding_ref": "gatekeeper:mockcarrier-test",
    "allowed_tenants": ["tenant-blue", "tenant-green"],
    "accounts_by_tenant": {"tenant-blue": ["account-blue"], "tenant-green": ["account-green"]},
    "allowed_service_ids": ["parcel-service"]
  }]
}`

const credentialsJSON = `{"gatekeeper:mockcarrier-test/account-blue": "` + blueToken + `",
 "gatekeeper:mockcarrier-test/account-green": "` + greenToken + `"}`

// lockedBuffer 收服务的日志：服务在自己的 goroutine 里写，测试在另一个里读。
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

type harness struct {
	t           *testing.T
	ca          *tlstest.CA
	server      tlstest.Leaf
	peers       map[string]tlstest.Leaf
	policy      string
	credentials string
	logs        *lockedBuffer
	extra       []string // 追加在必需参数之后
	url         string
	stop        func() error
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	flavorEnv(t)
	ca := tlstest.NewCA(t, "workload CA")
	rogue := tlstest.NewCA(t, "a CA outside the trust domain")
	dir := t.TempDir()
	h := &harness{
		t: t, ca: ca, logs: &lockedBuffer{},
		server: ca.Issue("server", []string{"spiffe://idp.test/egress/authz"}, serverName),
		peers: map[string]tlstest.Leaf{
			"gateway":       ca.Issue("gateway", []string{gatewayID}),
			"broker":        ca.Issue("broker", []string{brokerID}),
			"operator":      ca.Issue("operator", []string{operatorID}),
			"business":      ca.Issue("business", []string{businessID}),
			"revoker":       ca.Issue("revoker", []string{revokerID}),
			"publisher":     ca.Issue("publisher", []string{publisherID}),
			"rogue-gateway": rogue.Issue("gateway", []string{gatewayID}),
			"rogue-revoker": rogue.Issue("revoker", []string{revokerID}),
		},
		policy:      filepath.Join(dir, "policy.json"),
		credentials: filepath.Join(dir, "credentials.json"),
	}
	for path, content := range map[string]string{h.policy: policyJSON, h.credentials: credentialsJSON} {
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return h
}

// args 是启动参数。h.credentials 被清空时不带 --credentials。
func (h *harness) args(listen string) []string {
	args := []string{"--listen", listen, "--tls-cert", h.server.CertFile, "--tls-key", h.server.KeyFile,
		"--client-ca", h.ca.File(), "--policy", h.policy}
	if h.credentials != "" {
		args = append(args, "--credentials", h.credentials)
	}
	return append(args, "--gateway-identity", gatewayID, "--broker-identity", brokerID)
}

// start 在本进程里把服务跑起来，监听一个空闲的回环端口。
func (h *harness) start() *harness {
	h.t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	addr, done := make(chan net.Addr, 1), make(chan error, 1)
	go func() {
		done <- run(ctx, append(h.args("127.0.0.1:0"), h.extra...), h.logs, func(a net.Addr) { addr <- a })
	}()
	select {
	case a := <-addr:
		h.url = "https://" + a.String()
	case err := <-done:
		cancel()
		h.t.Fatalf("服务没有启动：%v", err)
	case <-time.After(10 * time.Second):
		cancel()
		h.t.Fatal("服务没有在 10 秒内启动")
	}
	h.stop = sync.OnceValue(func() error { cancel(); return <-done })
	h.t.Cleanup(func() { _ = h.stop() })
	return h
}

type answer struct {
	status int
	header http.Header
	body   string
	proto  string
}

func (a answer) json(t *testing.T) map[string]any {
	t.Helper()
	var decoded map[string]any
	if err := json.Unmarshal([]byte(a.body), &decoded); err != nil {
		t.Fatalf("响应不是 JSON：%q", a.body)
	}
	return decoded
}

func (a answer) carriesCredential() bool {
	all := a.body
	for name, values := range a.header {
		all += name + strings.Join(values, ",")
	}
	return strings.Contains(all, "provider-token")
}

type call struct {
	peer    string // 出示谁的证书；空串表示不出示
	method  string
	path    string
	headers [][2]string
	body    string
	http2   bool
}

func (h *harness) do(c call) (answer, error) {
	h.t.Helper()
	var leaf *tlstest.Leaf
	if c.peer != "" {
		l, ok := h.peers[c.peer]
		if !ok {
			h.t.Fatalf("没有名为 %q 的证书", c.peer)
		}
		leaf = &l
	}
	transport := &http.Transport{TLSClientConfig: tlstest.ClientConfig(h.ca, serverName, leaf), ForceAttemptHTTP2: c.http2}
	defer transport.CloseIdleConnections()
	if c.method == "" {
		c.method = http.MethodGet
	}
	request, err := http.NewRequest(c.method, h.url+c.path, strings.NewReader(c.body))
	if err != nil {
		h.t.Fatal(err)
	}
	for _, header := range c.headers {
		request.Header.Add(header[0], header[1])
	}
	response, err := (&http.Client{Transport: transport, Timeout: 10 * time.Second}).Do(request)
	if err != nil {
		return answer{}, err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	return answer{status: response.StatusCode, header: response.Header, body: string(body), proto: response.Proto}, err
}

func (h *harness) must(c call) answer {
	h.t.Helper()
	a, err := h.do(c)
	if err != nil {
		h.t.Fatalf("%s %s 以 %q 的身份：%v", c.method, c.path, c.peer, err)
	}
	return a
}

func trusted(tenant string) [][2]string {
	return [][2]string{
		{"x-idp-verified-subject", "parcel-service"}, {"x-idp-verified-tenant", tenant}, {"x-idp-verified-env", "TEST"},
		{"x-idp-route-id", "mockcarrier-tracking-get"}, {"x-idp-provider-id", "mockcarrier"},
		{"x-idp-operation-id", "tracking.get"}, {"x-idp-environment", "TEST"}, {"x-idp-method", "GET"},
		{"x-idp-path", tracking + "/TRK-1"},
	}
}

const decisionBody = `{"request_id":"req-1","route_id":"mockcarrier-tracking-get","operation_id":"tracking.get",
 "provider_id":"mockcarrier","requested_account_id":"","environment":"TEST","method":"GET",
 "path":"/providers/mockcarrier/v1/tracking/TRK-1","config_digest":"sha256:abc","service_id":"parcel-service",
 "tenant_id":"tenant-blue","token_environment":"TEST"}`

func TestServesOverMutualTLS(t *testing.T) {
	h := newHarness(t).start()

	for _, http2 := range []bool{false, true} {
		wantProto := map[bool]string{false: "HTTP/1.1", true: "HTTP/2.0"}[http2]
		for tenant, token := range map[string]string{"tenant-blue": blueToken, "tenant-green": greenToken} {
			a := h.must(call{peer: "gateway", path: extAuthzPath, headers: trusted(tenant), http2: http2})
			if a.status != http.StatusOK || a.header.Get("Authorization") != "Bearer "+token || a.proto != wantProto {
				t.Fatalf("%s 经 %s：%d %s %s", tenant, wantProto, a.status, a.proto, a.body)
			}
			if body := a.json(t); body["result"] != "ALLOW" || body["policy_version"] != "policy-e2e" ||
				body["decision_id"] != a.header.Get("X-Idp-Decision-Id") {
				t.Fatalf("%s: %v", tenant, body)
			}
		}
		denied := h.must(call{peer: "gateway", path: extAuthzPath, http2: http2,
			headers: append(trusted("tenant-blue"), [2]string{"X-Provider-Account", "account-green"})})
		if denied.status != http.StatusForbidden || denied.json(t)["reason_code"] != "ACCOUNT_NOT_GRANTED" || denied.carriesCredential() {
			t.Fatalf("蓝租户申请绿账户，经 %s：%d %s", wantProto, denied.status, denied.body)
		}
		// 一份可信上下文出现两次。HTTP/2 下重复的头同样是分开到达的。
		ambiguous := h.must(call{peer: "gateway", path: extAuthzPath, http2: http2,
			headers: append(trusted("tenant-blue"), [2]string{"X-Idp-Verified-Tenant", "tenant-green"})})
		if ambiguous.status != http.StatusForbidden || ambiguous.json(t)["reason_code"] != "AMBIGUOUS_TRUSTED_CONTEXT" {
			t.Fatalf("两份租户头，经 %s：%d %s", wantProto, ambiguous.status, ambiguous.body)
		}
	}

	// 同一信任域里不是网关的工作负载：握手能过，要不到凭证。
	for _, peer := range []string{"business", "broker", "operator"} {
		a := h.must(call{peer: peer, path: extAuthzPath, headers: trusted("tenant-blue")})
		if a.status != http.StatusUnauthorized || a.carriesCredential() {
			t.Errorf("%s: %d %s", peer, a.status, a.body)
		}
	}
	// 没有证书，或证书来自别的 CA：没有 HTTP 交换。
	for _, peer := range []string{"", "rogue-gateway"} {
		if a, err := h.do(call{peer: peer, path: extAuthzPath, headers: trusted("tenant-blue")}); err == nil {
			t.Errorf("证书 %q 得到了 HTTP 响应：%d", peer, a.status)
		}
	}

	// 只返回判定的接口：Broker 和网关都能问，答案里没有凭证。
	for _, peer := range []string{"broker", "gateway"} {
		a := h.must(call{peer: peer, method: http.MethodPost, path: decisionPath, body: decisionBody})
		body := a.json(t)
		if a.status != http.StatusOK || body["result"] != "ALLOW" || body["credential_handle"] != "gatekeeper:mockcarrier-test/account-blue" ||
			body["request_id"] != "req-1" {
			t.Errorf("%s: %d %s", peer, a.status, a.body)
		}
		if a.carriesCredential() {
			t.Errorf("%s: 只返回判定的接口带出了凭证", peer)
		}
	}
	if a := h.must(call{peer: "business", method: http.MethodPost, path: decisionPath, body: decisionBody}); a.status != http.StatusUnauthorized {
		t.Errorf("业务应用问判定：%d", a.status)
	}
	// 没有 --publisher-identity 时，版本接口不存在。
	if a := h.must(call{peer: "publisher", path: "/v1/egress/policy-version"}); a.status != http.StatusNotFound || a.header.Get("Authorization") != "" {
		t.Errorf("未配置发布者时的版本接口：%d %s", a.status, a.body)
	}

	logs := h.logs.String()
	if strings.Contains(logs, "provider-token") {
		t.Errorf("凭证出现在服务日志里：%s", logs)
	}
	for _, expected := range []string{`"msg":"gateway-authz listening"`, `"build":"` + buildFlavor + `"`, `"policy_version":"policy-e2e"`,
		`"credentials":2`, "TLS handshake error"} {
		if !strings.Contains(logs, expected) {
			t.Errorf("服务日志里没有 %s", expected)
		}
	}
}

// 配置了 Gatekeeper 时，登记表放行的请求还要它点头；它说没有就是拒绝，它答不出来就是没有结论。
func TestAsksGatekeeperWhenConfigured(t *testing.T) {
	const pdpToken = "pdp-token-e2e"
	var mu sync.Mutex
	answer, asked := `{"decision":true,"reason":"rebac:use"}`, 0
	pdp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		asked++
		if r.URL.Path != "/authz/check" || r.Header.Get("Authorization") != "Bearer "+pdpToken {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = io.WriteString(w, answer)
	}))
	defer pdp.Close()
	set := func(body string) {
		mu.Lock()
		defer mu.Unlock()
		answer = body
	}

	h := newHarness(t)
	tokenFile := filepath.Join(t.TempDir(), "pdp-token")
	if err := os.WriteFile(tokenFile, []byte(pdpToken+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	h.extra = []string{"--gatekeeper-url", pdp.URL, "--gatekeeper-token-file", tokenFile}
	h.start()

	allowed := h.must(call{peer: "gateway", path: extAuthzPath, headers: trusted("tenant-blue")})
	if allowed.status != http.StatusOK || allowed.header.Get("Authorization") != "Bearer "+blueToken {
		t.Fatalf("Gatekeeper 放行：%d %s", allowed.status, allowed.body)
	}

	set(`{"decision":false,"reason":"rebac denied"}`)
	denied := h.must(call{peer: "gateway", path: extAuthzPath, headers: trusted("tenant-blue")})
	if denied.status != http.StatusForbidden || denied.json(t)["reason_code"] != "ACCOUNT_NOT_GRANTED" || denied.carriesCredential() {
		t.Fatalf("Gatekeeper 说没有授权：%d %s", denied.status, denied.body)
	}

	set(`{"decision":false,"indeterminate":true,"reason":"rebac lookup failed"}`)
	// 给网关的接口用状态码说话；只返回判定的接口把结果写在响应体里。
	for _, c := range []struct {
		call
		status int
	}{
		{call{peer: "gateway", path: extAuthzPath, headers: trusted("tenant-blue")}, http.StatusServiceUnavailable},
		{call{peer: "broker", method: http.MethodPost, path: decisionPath, body: decisionBody}, http.StatusOK},
	} {
		unknown := h.must(c.call)
		body := unknown.json(t)
		if unknown.status != c.status || body["result"] != "INDETERMINATE" || body["reason_code"] != "GRANT_STATE_UNAVAILABLE" ||
			body["credential_handle"] != nil || unknown.carriesCredential() {
			t.Fatalf("Gatekeeper 答不出来，%s：%d %s", c.path, unknown.status, unknown.body)
		}
	}

	// 登记表自己就拒绝的请求不去问 Gatekeeper。
	mu.Lock()
	before := asked
	mu.Unlock()
	h.must(call{peer: "gateway", path: extAuthzPath, headers: append(trusted("tenant-blue"), [2]string{"X-Provider-Account", "account-green"})})
	mu.Lock()
	after := asked
	mu.Unlock()
	if after != before {
		t.Fatal("登记表已拒绝的请求仍问了 Gatekeeper")
	}

	logs := h.logs.String()
	if strings.Contains(logs, pdpToken) {
		t.Error("PDP 令牌出现在服务日志里")
	}
	if !strings.Contains(logs, `"grants":"policy+gatekeeper"`) {
		t.Error("启动日志没有说明授权来源")
	}
}

// 开发者令牌文件（docs/adr/ADR-0011.md 第 3 条）。账号和令牌里都带着 provider-token，
// 好让 carriesCredential 和各处"日志里、错误里没有凭证"的检查一并管到它们。
const (
	greenHandle         = "gatekeeper:mockcarrier-test/account-green"
	greenAccountNo      = "ACCT-provider-token-green"
	greenDeveloperToken = "provider-token-green-developer"
)

var developerHeader = regexp.MustCompile(`^Hc-OweDeveloper ([^; ]+);([^; ]+);([0-9a-f]{32})$`)

func developerTokensJSON(handle, account, token string) string {
	return `{"` + handle + `": {"account": "` + account + `", "token": "` + token + `"}}`
}

// writePrivate 写一个只有属主能读写的文件。path 已经有文件时用改名盖上去，不就地改写。
func writePrivate(t *testing.T, path, content string) string {
	t.Helper()
	next := path + ".next"
	if err := os.WriteFile(next, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(next, path); err != nil {
		t.Fatal(err)
	}
	return path
}

// 绿租户的认证头：账号、令牌是文件里的那一对，返回随机数。
func developerNonce(t *testing.T, a answer, token string) string {
	t.Helper()
	match := developerHeader.FindStringSubmatch(a.header.Get("Authorization"))
	if a.status != http.StatusOK || match == nil || match[1] != greenAccountNo || match[2] != token {
		t.Fatalf("绿租户：%d %s，认证头的样子或内容不对", a.status, a.body)
	}
	return match[3]
}

// 两种凭证文件一起给：蓝账户的凭证在 Bearer 文件里，绿账户的在开发者令牌文件里，各走各的。
func TestDeveloperTokensNextToBearerCredentials(t *testing.T) {
	h := newHarness(t)
	writePrivate(t, h.credentials, `{"gatekeeper:mockcarrier-test/account-blue": "`+blueToken+`"}`)
	tokens := writePrivate(t, filepath.Join(t.TempDir(), "developer-tokens.json"),
		developerTokensJSON(greenHandle, greenAccountNo, greenDeveloperToken))
	h.extra = []string{"--developer-tokens", tokens}
	h.start()

	nonces := map[string]bool{}
	for _, http2 := range []bool{false, true} {
		blue := h.must(call{peer: "gateway", path: extAuthzPath, headers: trusted("tenant-blue"), http2: http2})
		if blue.status != http.StatusOK || blue.header.Get("Authorization") != "Bearer "+blueToken {
			t.Fatalf("蓝租户：%d %s", blue.status, blue.body)
		}
		// 每个请求的随机数都不同。
		for range 20 {
			nonce := developerNonce(t, h.must(call{peer: "gateway", path: extAuthzPath, headers: trusted("tenant-green"), http2: http2}), greenDeveloperToken)
			if nonces[nonce] {
				t.Fatalf("随机数 %s 出现了两次", nonce)
			}
			nonces[nonce] = true
		}
	}

	// 拿不到凭证的那些路，对这一种凭证也一样：别的租户申请这个账户，不是网关的调用方，只返回判定的接口。
	denied := h.must(call{peer: "gateway", path: extAuthzPath,
		headers: append(trusted("tenant-blue"), [2]string{"X-Provider-Account", "account-green"})})
	if denied.status != http.StatusForbidden || denied.json(t)["reason_code"] != "ACCOUNT_NOT_GRANTED" || denied.carriesCredential() {
		t.Fatalf("蓝租户申请绿账户：%d %s", denied.status, denied.body)
	}
	for _, peer := range []string{"business", "broker", "operator"} {
		if a := h.must(call{peer: peer, path: extAuthzPath, headers: trusted("tenant-green")}); a.status != http.StatusUnauthorized || a.carriesCredential() {
			t.Errorf("%s: %d %s", peer, a.status, a.body)
		}
	}
	greenDecision := strings.Replace(decisionBody, `"tenant_id":"tenant-blue"`, `"tenant_id":"tenant-green"`, 1)
	decided := h.must(call{peer: "broker", method: http.MethodPost, path: decisionPath, body: greenDecision})
	if body := decided.json(t); decided.status != http.StatusOK || body["result"] != "ALLOW" || body["credential_handle"] != greenHandle ||
		decided.carriesCredential() || decided.header.Get("Authorization") != "" {
		t.Fatalf("只返回判定的接口：%d %s", decided.status, decided.body)
	}

	// 换令牌：把文件换掉，不重启；下一个请求用的就是新令牌。
	const rotated = "provider-token-green-rotated"
	writePrivate(t, tokens, developerTokensJSON(greenHandle, greenAccountNo, rotated))
	developerNonce(t, h.must(call{peer: "gateway", path: extAuthzPath, headers: trusted("tenant-green")}), rotated)
	// 换上一份读不成的：继续用上一份，判定不中断。
	writePrivate(t, tokens, developerTokensJSON(greenHandle, greenAccountNo, "provider-token with a space"))
	developerNonce(t, h.must(call{peer: "gateway", path: extAuthzPath, headers: trusted("tenant-green")}), rotated)
	// 换上一份把蓝账户也写进去的：这个句柄已经在 Bearer 文件里，整份不要。
	writePrivate(t, tokens, `{"gatekeeper:mockcarrier-test/account-blue": {"account": "x", "token": "provider-token-blue-twice"},
 "`+greenHandle+`": {"account": "`+greenAccountNo+`", "token": "provider-token-green-third"}}`)
	developerNonce(t, h.must(call{peer: "gateway", path: extAuthzPath, headers: trusted("tenant-green")}), rotated)
	if blue := h.must(call{peer: "gateway", path: extAuthzPath, headers: trusted("tenant-blue")}); blue.header.Get("Authorization") != "Bearer "+blueToken {
		t.Fatalf("蓝租户的凭证被开发者令牌文件改掉了：%d %s", blue.status, blue.body)
	}

	logs := h.logs.String()
	if strings.Contains(logs, "provider-token") {
		t.Errorf("账号或令牌出现在服务日志里：%s", logs)
	}
	for _, expected := range []string{`"credentials":1`, `"developer_tokens":1`, `"msg":"developer tokens file loaded again"`,
		`"msg":"developer tokens file did not load; still using the last one that loaded"`, "cannot go into a header", "one source only"} {
		if !strings.Contains(logs, expected) {
			t.Errorf("服务日志里没有 %s", expected)
		}
	}
}

// 只给开发者令牌文件也能启动。文件里没有的账户，登记表放行了也拿不到凭证：不是放行。
func TestDeveloperTokensAlone(t *testing.T) {
	h := newHarness(t)
	h.credentials = ""
	h.extra = []string{"--developer-tokens", writePrivate(t, filepath.Join(t.TempDir(), "developer-tokens.json"),
		developerTokensJSON(greenHandle, greenAccountNo, greenDeveloperToken))}
	h.start()

	developerNonce(t, h.must(call{peer: "gateway", path: extAuthzPath, headers: trusted("tenant-green")}), greenDeveloperToken)
	blue := h.must(call{peer: "gateway", path: extAuthzPath, headers: trusted("tenant-blue")})
	if body := blue.json(t); blue.status != http.StatusServiceUnavailable || body["result"] != "INDETERMINATE" ||
		body["reason_code"] != "CREDENTIAL_UNAVAILABLE" || blue.header.Get("Authorization") != "" || blue.carriesCredential() {
		t.Fatalf("蓝账户没有凭证：%d %s", blue.status, blue.body)
	}
	if logs := h.logs.String(); !strings.Contains(logs, `"credentials":0`) || !strings.Contains(logs, `"developer_tokens":1`) ||
		strings.Contains(logs, "provider-token") {
		t.Errorf("启动日志：%s", logs)
	}
}

type fixedSource struct {
	held  map[string]string
	fails error
	asked *[]string
	name  string
}

func (f fixedSource) AuthorizationHeader(_ context.Context, bindingRef, accountID string) (ports.Secret, error) {
	*f.asked = append(*f.asked, f.name)
	if f.fails != nil {
		return ports.Secret{}, f.fails
	}
	value, ok := f.held[ports.Handle(bindingRef, accountID)]
	if !ok {
		return ports.Secret{}, fmt.Errorf("%w: from %s", ports.ErrCredentialNotHeld, f.name)
	}
	return ports.NewSecret(value), nil
}

// 几个凭证来源排在一起：前一个没有才问后一个；前一个出了别的错，不拿后一个顶上。
func TestCredentialSourcesAreAskedInOrder(t *testing.T) {
	var asked []string
	first := fixedSource{held: map[string]string{"b/one": "from-first"}, asked: &asked, name: "first"}
	second := fixedSource{held: map[string]string{"b/two": "from-second"}, asked: &asked, name: "second"}
	broken := fixedSource{fails: errors.New("source is down"), asked: &asked, name: "broken"}

	for _, tc := range []struct {
		sources credentialSources
		account string
		want    string
		notHeld bool
		fails   bool
		asks    string
	}{
		{credentialSources{first, second}, "one", "from-first", false, false, "first"},
		{credentialSources{first, second}, "two", "from-second", false, false, "first,second"},
		{credentialSources{first, second}, "three", "", true, false, "first,second"},
		{credentialSources{broken, second}, "two", "", false, true, "broken"},
		{credentialSources{first, broken}, "two", "", false, true, "first,broken"},
		{credentialSources{}, "one", "", true, false, ""},
	} {
		asked = nil
		credential, err := tc.sources.AuthorizationHeader(context.Background(), "b", tc.account)
		if credential.Reveal() != tc.want || errors.Is(err, ports.ErrCredentialNotHeld) != tc.notHeld ||
			(err != nil && !tc.notHeld) != tc.fails || strings.Join(asked, ",") != tc.asks {
			t.Errorf("%v 问 %s：凭证 %q，错误 %v，问过 %v", len(tc.sources), tc.account, credential.Reveal(), err, asked)
		}
	}
}

// 撤销（docs/adr/ADR-0012.md）。
const (
	nothingRevoked = `{"epoch": 0, "revoked_accounts": {}}`
	revokeBlue     = `{"account_id":"account-blue","revoked":true,"reason":"key leaked"}`
	restoreBlue    = `{"account_id":"account-blue","revoked":false}`
)

// withRevocations 让服务带着一份撤销文件和撤销者的身份启动，返回文件的路径。
func (h *harness) withRevocations(content string) string {
	h.t.Helper()
	file := writePrivate(h.t, filepath.Join(h.t.TempDir(), "revocations.json"), content)
	h.extra = append(h.extra, "--revocations", file, "--revoker-identity", revokerID)
	return file
}

func (h *harness) revocations(peer, method, body string) answer {
	h.t.Helper()
	return h.must(call{peer: peer, method: method, path: revocationsPath, body: body})
}

func (h *harness) blue() answer {
	h.t.Helper()
	return h.must(call{peer: "gateway", path: extAuthzPath, headers: trusted("tenant-blue")})
}

// 撤销经产品的接口做，由撤销者的证书证明身份；重启之后它还在，代次接着数。
func TestRevocationsAreChangedByTheRevokerAndSurviveARestart(t *testing.T) {
	h := newHarness(t)
	file := h.withRevocations(nothingRevoked)
	h.start()

	if a := h.blue(); a.status != http.StatusOK {
		t.Fatalf("撤销之前：%d %s", a.status, a.body)
	}
	revoked := h.revocations("revoker", http.MethodPost, revokeBlue)
	if body := revoked.json(t); revoked.status != http.StatusOK || body["revoked"] != true || body["changed"] != true ||
		body["revocation_epoch"] != float64(1) || revoked.carriesCredential() {
		t.Fatalf("撤销：%d %s", revoked.status, revoked.body)
	}
	denied := h.blue()
	if denied.status != http.StatusForbidden || denied.json(t)["reason_code"] != "ACCOUNT_REVOKED" || denied.carriesCredential() {
		t.Fatalf("撤销之后的蓝租户：%d %s", denied.status, denied.body)
	}
	if a := h.must(call{peer: "gateway", path: extAuthzPath, headers: trusted("tenant-green")}); a.status != http.StatusOK {
		t.Fatalf("撤销蓝账户影响了绿租户：%d", a.status)
	}

	// 别的身份改不了，也读不到：同一个信任域里的每一个，包括拿得到凭证的网关。
	for _, peer := range []string{"gateway", "broker", "business", "operator"} {
		for _, request := range [][2]string{{http.MethodPost, restoreBlue}, {http.MethodGet, ""}} {
			if a := h.revocations(peer, request[0], request[1]); a.status != http.StatusUnauthorized || strings.Contains(a.body, "account-blue") {
				t.Errorf("%s %s：%d %s", peer, request[0], a.status, a.body)
			}
		}
	}
	// 没有证书，或者撤销者的名字、别的 CA 签的：没有 HTTP 交换。
	for _, peer := range []string{"", "rogue-revoker"} {
		if a, err := h.do(call{peer: peer, method: http.MethodPost, path: revocationsPath, body: restoreBlue}); err == nil {
			t.Errorf("证书 %q 得到了 HTTP 响应：%d", peer, a.status)
		}
	}
	if a := h.blue(); a.status != http.StatusForbidden {
		t.Fatalf("被拒绝的恢复却生效了：%d", a.status)
	}

	// 重启：还是撤销着的，代次不回到 0，表里记着是谁、为什么。
	if err := h.stop(); err != nil {
		t.Fatal(err)
	}
	h.start()
	denied = h.blue()
	if body := denied.json(t); denied.status != http.StatusForbidden || body["reason_code"] != "ACCOUNT_REVOKED" || body["revocation_epoch"] != float64(1) {
		t.Fatalf("重启之后的蓝租户：%d %s", denied.status, denied.body)
	}
	table := h.revocations("revoker", http.MethodGet, "")
	accounts, _ := table.json(t)["revoked_accounts"].([]any)
	if table.status != http.StatusOK || len(accounts) != 1 {
		t.Fatalf("重启之后的表：%d %s", table.status, table.body)
	}
	if entry := accounts[0].(map[string]any); entry["account_id"] != "account-blue" || entry["revoked_by"] != revokerID || entry["reason"] != "key leaked" {
		t.Fatalf("重启之后的那一行：%v", entry)
	}

	restored := h.revocations("revoker", http.MethodPost, restoreBlue)
	if body := restored.json(t); restored.status != http.StatusOK || body["revoked"] != false || body["revocation_epoch"] != float64(2) {
		t.Fatalf("恢复：%d %s", restored.status, restored.body)
	}
	if a := h.blue(); a.status != http.StatusOK || a.header.Get("Authorization") != "Bearer "+blueToken {
		t.Fatalf("恢复之后：%d %s", a.status, a.body)
	}
	if written, err := os.ReadFile(file); err != nil || !strings.Contains(string(written), `"epoch": 2`) || strings.Contains(string(written), "account-blue") {
		t.Fatalf("恢复之后的文件：%s %v", written, err)
	}

	logs := h.logs.String()
	for _, expected := range []string{`"revocations":"file"`, `"revoked_accounts":0`, `"revoked_accounts":1`, `"revocation_epoch":1`,
		`"revoker_identity":"` + revokerID + `"`, `"msg":"egress revocation"`, `"action":"revoke"`, `"reason":"key leaked"`,
		`"reason":"REVOKER_WORKLOAD_UNAUTHENTICATED"`} {
		if !strings.Contains(logs, expected) {
			t.Errorf("服务日志里没有 %s", expected)
		}
	}
	if strings.Contains(logs, "provider-token") {
		t.Error("凭证出现在服务日志里")
	}
}

// 不给撤销文件和撤销者时，与以前相同：没有改撤销表的接口，拿着撤销者证书的也一样。
func TestWithoutRevocationFlagsThereIsNoRevocationInterface(t *testing.T) {
	h := newHarness(t).start()
	for _, peer := range []string{"revoker", "gateway", "operator"} {
		for _, request := range [][2]string{{http.MethodPost, revokeBlue}, {http.MethodGet, ""}} {
			if a := h.revocations(peer, request[0], request[1]); a.status != http.StatusNotFound {
				t.Errorf("%s %s：%d %s", peer, request[0], a.status, a.body)
			}
		}
	}
	if a := h.blue(); a.status != http.StatusOK {
		t.Fatalf("对不存在的接口的调用改变了判定：%d", a.status)
	}
	if logs := h.logs.String(); !strings.Contains(logs, `"revocations":"memory"`) || !strings.Contains(logs, `"revoker_identity":""`) {
		t.Errorf("启动日志没有说明撤销表在内存里：%s", logs)
	}
}

func TestStopsWhenAskedTo(t *testing.T) {
	h := newHarness(t).start()
	if a := h.must(call{peer: "gateway", path: "/healthz"}); a.status != http.StatusOK {
		t.Fatalf("healthz: %d", a.status)
	}
	if err := h.stop(); err != nil {
		t.Fatalf("停止时返回了错误：%v", err)
	}
	if _, err := h.do(call{peer: "gateway", path: "/healthz"}); err == nil {
		t.Fatal("停止之后还在应答")
	}
	if !strings.Contains(h.logs.String(), "gateway-authz stopped") {
		t.Error("没有记录停止")
	}
}

func TestRefusesToStart(t *testing.T) {
	h := newHarness(t)
	replace := func(flag, value string) []string {
		args := h.args("127.0.0.1:0")
		for i := range args {
			if args[i] == flag {
				args[i+1] = value
			}
		}
		return args
	}
	without := func(flag string) []string {
		var args []string
		all := h.args("127.0.0.1:0")
		for i := 0; i < len(all); i += 2 {
			if all[i] != flag {
				args = append(args, all[i], all[i+1])
			}
		}
		return args
	}
	dir := t.TempDir()
	write := func(name, content string, mode os.FileMode) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(content), mode); err != nil {
			t.Fatal(err)
		}
		return path
	}
	cases := map[string]struct {
		args []string
		says string
	}{
		"没有参数":            {nil, "missing required flags"},
		"没有网关身份":          {without("--gateway-identity"), "--gateway-identity"},
		"没有客户端 CA":        {without("--client-ca"), "--client-ca"},
		"多余的参数":           {append(h.args("127.0.0.1:0"), "serve"), "unexpected argument"},
		"Broker 与网关同一个身份": {replace("--broker-identity", gatewayID), "must differ"},
		"登记表不存在":          {replace("--policy", filepath.Join(dir, "missing.json")), "policy"},
		"登记表默认放行":         {replace("--policy", write("allow.json", `{"version":"v","default_decision":"ALLOW"}`, 0o600)), "only DENY"},
		"凭证文件别人可读":        {replace("--credentials", write("open.json", credentialsJSON, 0o644)), "readable by others"},
		"两种凭证文件都没有给":      {without("--credentials"), "--credentials or --developer-tokens"},
		"开发者令牌文件不存在":      {append(h.args("127.0.0.1:0"), "--developer-tokens", filepath.Join(dir, "missing-tokens.json")), "developer tokens"},
		"开发者令牌文件别人可读": {append(h.args("127.0.0.1:0"), "--developer-tokens",
			write("open-tokens.json", developerTokensJSON("other-binding/account", greenAccountNo, greenDeveloperToken), 0o644)), "readable by others"},
		"开发者令牌里有分号": {append(h.args("127.0.0.1:0"), "--developer-tokens",
			write("semicolon.json", developerTokensJSON("other-binding/account", greenAccountNo, greenDeveloperToken+";x"), 0o600)), "semicolon"},
		"开发者令牌文件是 Bearer 文件的写法": {append(h.args("127.0.0.1:0"), "--developer-tokens", write("bearer-shape.json", credentialsJSON, 0o600)), "not a JSON object"},
		"同一个句柄在两个凭证文件里": {append(h.args("127.0.0.1:0"), "--developer-tokens",
			write("twice.json", developerTokensJSON(greenHandle, greenAccountNo, greenDeveloperToken), 0o600)), "one source only"},
		"有撤销文件没有撤销者": {append(h.args("127.0.0.1:0"), "--revocations", write("r1.json", nothingRevoked, 0o600)), "go together"},
		"有撤销者没有撤销文件": {append(h.args("127.0.0.1:0"), "--revoker-identity", revokerID), "go together"},
		"撤销者就是网关": {append(h.args("127.0.0.1:0"), "--revocations", write("r2.json", nothingRevoked, 0o600),
			"--revoker-identity", gatewayID), "must differ"},
		"撤销者就是 Broker": {append(h.args("127.0.0.1:0"), "--revocations", write("r3.json", nothingRevoked, 0o600),
			"--revoker-identity", brokerID), "must differ"},
		// 没有文件不是"没有撤销"：文件丢了，服务不启动。
		"撤销文件不存在": {append(h.args("127.0.0.1:0"), "--revocations", filepath.Join(dir, "missing-revocations.json"),
			"--revoker-identity", revokerID), "revocations"},
		"撤销文件别人可读": {append(h.args("127.0.0.1:0"), "--revocations", write("r4.json", nothingRevoked, 0o644),
			"--revoker-identity", revokerID), "readable by others"},
		"撤销文件读不懂": {append(h.args("127.0.0.1:0"), "--revocations", write("r5.json", `{"epoch": 0, "revoked_accounts": {`, 0o600),
			"--revoker-identity", revokerID), "not a JSON object"},
		"撤销文件里没有写表": {append(h.args("127.0.0.1:0"), "--revocations", write("r6.json", `{"epoch": 0}`, 0o600),
			"--revoker-identity", revokerID), "both required"},
		"证书与私钥不配对":            {replace("--tls-key", h.peers["gateway"].KeyFile), "server certificate"},
		"监听地址不可用":             {replace("--listen", "256.0.0.1:1"), ""},
		"有 Gatekeeper 地址没有令牌": {append(h.args("127.0.0.1:0"), "--gatekeeper-url", "https://gk.idp.test"), "go together"},
		"有令牌没有 Gatekeeper 地址": {append(h.args("127.0.0.1:0"), "--gatekeeper-token-file", write("t1", "pdp-token", 0o600)), "go together"},
		// 非回环的地址要带客户端证书才过得了参数检查，这一条要走到读令牌文件那一步，所以带上。
		"Gatekeeper 令牌别人可读": {append(h.args("127.0.0.1:0"), "--gatekeeper-url", "https://gk.idp.test",
			"--gatekeeper-token-file", write("t2", "pdp-token", 0o644),
			"--gatekeeper-tls-cert", h.peers["gateway"].CertFile, "--gatekeeper-tls-key", h.peers["gateway"].KeyFile,
			"--gatekeeper-tls-ca", h.ca.File(), "--gatekeeper-name", "gk.idp.test"), "readable by others"},
		"明文连接非回环的 Gatekeeper": {append(h.args("127.0.0.1:0"), "--gatekeeper-url", "http://gk.idp.test",
			"--gatekeeper-token-file", write("t3", "pdp-token", 0o600)), "must be https"},
	}
	for name, tc := range cases {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		err := run(ctx, tc.args, io.Discard, nil)
		cancel()
		if err == nil {
			t.Errorf("%s: 启动了", name)
		} else if !strings.Contains(err.Error(), tc.says) {
			t.Errorf("%s: 错误是 %q，期望提到 %q", name, err, tc.says)
		} else if strings.Contains(err.Error(), "provider-token") {
			t.Errorf("%s: 错误信息里有凭证", name)
		}
	}
	// 没有 Broker 身份是允许的：那就没有只要判定的调用方。
	if _, err := parse(without("--broker-identity"), io.Discard); err != nil {
		t.Errorf("不设 --broker-identity 被拒绝：%v", err)
	}
}

func TestPublisherIdentityMustDifferFromGatewayBrokerAndRevoker(t *testing.T) {
	h := newHarness(t)
	revocations := writePrivate(t, filepath.Join(t.TempDir(), "revocations.json"), nothingRevoked)
	cases := map[string][]string{
		"发布者就是网关":      append(h.args("127.0.0.1:0"), "--publisher-identity", gatewayID),
		"发布者就是 Broker": append(h.args("127.0.0.1:0"), "--publisher-identity", brokerID),
		"发布者就是撤销者": append(h.args("127.0.0.1:0"), "--revocations", revocations,
			"--revoker-identity", revokerID, "--publisher-identity", revokerID),
	}
	for name, args := range cases {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		err := run(ctx, args, io.Discard, nil)
		cancel()
		if err == nil || !strings.Contains(err.Error(), "must differ") || strings.Contains(err.Error(), "provider-token") {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := parse(append(h.args("127.0.0.1:0"), "--publisher-identity", publisherID), io.Discard); err != nil {
		t.Fatalf("与网关、Broker、撤销者都不同的发布者被拒绝：%v", err)
	}
}

func policyRevision(version string, labels bool) string {
	operations := `{"route_id":"mockcarrier-tracking-get","provider_id":"mockcarrier","operation_id":"tracking.get",
		"environment":"TEST","method":"GET","path_prefix":"/providers/mockcarrier/v1/tracking",
		"credential_binding_ref":"gatekeeper:mockcarrier-test",
		"allowed_tenants":["tenant-blue","tenant-green"],
		"accounts_by_tenant":{"tenant-blue":["account-blue"],"tenant-green":["account-green"]},
		"allowed_service_ids":["parcel-service"]}`
	if labels {
		operations += `,{"route_id":"mockcarrier-labels-post","provider_id":"mockcarrier","operation_id":"labels.print",
		"environment":"TEST","method":"POST","path_prefix":"/providers/mockcarrier/v1/labels",
		"credential_binding_ref":"gatekeeper:mockcarrier-test",
		"allowed_tenants":["tenant-blue"],
		"accounts_by_tenant":{"tenant-blue":["account-blue"]},
		"allowed_service_ids":["parcel-service"]}`
	}
	return `{"version":"` + version + `","default_decision":"DENY","registered_operations":[` + operations + `]}`
}

func labelsHeaders() [][2]string {
	headers := trusted("tenant-blue")
	for i := range headers {
		switch strings.ToLower(headers[i][0]) {
		case "x-idp-operation-id":
			headers[i][1] = "labels.print"
		case "x-idp-method":
			headers[i][1] = "POST"
		case "x-idp-path":
			headers[i][1] = "/providers/mockcarrier/v1/labels/1"
		case "x-idp-route-id":
			headers[i][1] = "mockcarrier-labels-post"
		}
	}
	return headers
}

func TestPolicyReloadsAndThePublisherReadsOnlyTheVersion(t *testing.T) {
	h := newHarness(t)
	h.extra = append(h.extra, "--publisher-identity", publisherID)
	h.start()

	version := func() string {
		t.Helper()
		a := h.must(call{peer: "publisher", path: "/v1/egress/policy-version"})
		if a.status != http.StatusOK || a.header.Get("Authorization") != "" || a.carriesCredential() {
			t.Fatalf("版本：%d %s", a.status, a.body)
		}
		got, _ := a.json(t)["policy_version"].(string)
		return got
	}
	if got := version(); got != "policy-e2e" {
		t.Fatalf("启动版本是 %s", got)
	}
	if posted := h.must(call{peer: "publisher", method: http.MethodPost, path: "/v1/egress/policy-version"}); posted.status != http.StatusMethodNotAllowed ||
		posted.header.Get("Allow") != http.MethodGet || posted.header.Get("Authorization") != "" {
		t.Fatalf("发布者 POST：%d Allow=%q %s", posted.status, posted.header.Get("Allow"), posted.body)
	}
	before := h.must(call{peer: "gateway", path: extAuthzPath, headers: labelsHeaders()})
	if before.status != http.StatusForbidden || before.json(t)["reason_code"] != "NO_MATCHING_ALLOWLIST_OPERATION" || before.carriesCredential() {
		t.Fatalf("新操作在换登记表之前：%d %s", before.status, before.body)
	}

	writePrivate(h.t, h.policy, policyRevision("policy-e2e-2", true))
	if got := version(); got != "policy-e2e-2" {
		t.Fatalf("换上新登记表之后版本是 %s", got)
	}
	allowed := h.must(call{peer: "gateway", method: http.MethodPost, path: extAuthzPath, headers: labelsHeaders()})
	if allowed.status != http.StatusOK || allowed.header.Get("Authorization") != "Bearer "+blueToken ||
		allowed.json(t)["policy_version"] != "policy-e2e-2" {
		t.Fatalf("新操作：%d %s %s", allowed.status, allowed.header.Get("Authorization"), allowed.body)
	}

	const marker = "policy-body-must-not-be-logged"
	writePrivate(h.t, h.policy, marker+" { not json")
	if got := version(); got != "policy-e2e-2" {
		t.Fatalf("坏登记表之后版本是 %s", got)
	}
	if got := version(); got != "policy-e2e-2" {
		t.Fatalf("坏登记表再问一次：%s", got)
	}
	still := h.must(call{peer: "gateway", path: extAuthzPath, headers: labelsHeaders()})
	if still.status != http.StatusOK || still.header.Get("Authorization") != "Bearer "+blueToken ||
		still.json(t)["policy_version"] != "policy-e2e-2" {
		t.Fatalf("坏登记表之后新操作：%d %s", still.status, still.body)
	}
	if health := h.must(call{peer: "gateway", path: "/healthz"}); health.status != http.StatusOK {
		t.Fatalf("healthz: %d", health.status)
	}
	if trackingOK := h.blue(); trackingOK.status != http.StatusOK || trackingOK.json(t)["policy_version"] != "policy-e2e-2" {
		t.Fatalf("原来的操作：%d %s", trackingOK.status, trackingOK.body)
	}
	logs := h.logs.String()
	if strings.Contains(logs, marker) || strings.Count(logs, "did not load") != 1 {
		t.Fatalf("坏文件日志：%s", logs)
	}
	if a := h.must(call{peer: "publisher", path: extAuthzPath, headers: trusted("tenant-blue")}); a.status != http.StatusUnauthorized ||
		a.carriesCredential() || a.header.Get("Authorization") != "" {
		t.Fatalf("发布者要凭证：%d %s", a.status, a.body)
	}
	if a := h.must(call{peer: "gateway", path: "/v1/egress/policy-version"}); a.status != http.StatusUnauthorized || a.header.Get("Authorization") != "" {
		t.Fatalf("网关读版本：%d %s", a.status, a.body)
	}
}
