package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"go.idp.xyz/idp-gateway/internal/platform/workloadtls/tlstest"
)

const (
	serverName = "authz.idp.test"
	gatewayID  = "spiffe://idp.test/egress/agentgateway"
	brokerID   = "spiffe://idp.test/egress/credential-broker"
	operatorID = "spiffe://idp.test/poc/operator"
	businessID = "spiffe://idp.test/apps/parcel-service"
	tracking   = "/providers/mockcarrier/v1/tracking"
	blueToken  = "provider-token-blue"
	greenToken = "provider-token-green"

	extAuthzPath = "/v1/extauthz/check"
	decisionPath = "/v1/egress/authorizations/decision"
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
			"rogue-gateway": rogue.Issue("gateway", []string{gatewayID}),
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

func (h *harness) args(listen string) []string {
	return []string{"--listen", listen, "--tls-cert", h.server.CertFile, "--tls-key", h.server.KeyFile,
		"--client-ca", h.ca.File(), "--policy", h.policy, "--credentials", h.credentials,
		"--gateway-identity", gatewayID, "--broker-identity", brokerID}
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
		"没有参数":                {nil, "missing required flags"},
		"没有网关身份":              {without("--gateway-identity"), "--gateway-identity"},
		"没有客户端 CA":            {without("--client-ca"), "--client-ca"},
		"多余的参数":               {append(h.args("127.0.0.1:0"), "serve"), "unexpected argument"},
		"Broker 与网关同一个身份":     {replace("--broker-identity", gatewayID), "must differ"},
		"登记表不存在":              {replace("--policy", filepath.Join(dir, "missing.json")), "policy"},
		"登记表默认放行":             {replace("--policy", write("allow.json", `{"version":"v","default_decision":"ALLOW"}`, 0o600)), "only DENY"},
		"凭证文件别人可读":            {replace("--credentials", write("open.json", credentialsJSON, 0o644)), "readable by others"},
		"证书与私钥不配对":            {replace("--tls-key", h.peers["gateway"].KeyFile), "server certificate"},
		"监听地址不可用":             {replace("--listen", "256.0.0.1:1"), ""},
		"有 Gatekeeper 地址没有令牌": {append(h.args("127.0.0.1:0"), "--gatekeeper-url", "https://gk.idp.test"), "go together"},
		"有令牌没有 Gatekeeper 地址": {append(h.args("127.0.0.1:0"), "--gatekeeper-token-file", write("t1", "pdp-token", 0o600)), "go together"},
		"Gatekeeper 令牌别人可读": {append(h.args("127.0.0.1:0"), "--gatekeeper-url", "https://gk.idp.test",
			"--gatekeeper-token-file", write("t2", "pdp-token", 0o644)), "readable by others"},
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
