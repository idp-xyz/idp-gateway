package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"go.idp.xyz/idp-gateway/internal/platform/workloadtls/tlstest"
	"go.idp.xyz/idp-gateway/internal/providersigner/domain"
)

const (
	serverName = "signer.idp.test"
	gatewayID  = "spiffe://idp.test/egress/agentgateway"
	otherID    = "spiffe://idp.test/apps/other"

	// 下面三个值是编造的，与 internal/providersigner/domain/testdata/vectors.json 里的相同。
	appKey = "idpgw-test-app-key-0001"
	token  = "auth_idpgw-test-token-0001"
	aesKey = "MDEyMzQ1Njc4OTo7PD0+P0BBQkNERUZHSElKS0xNTk8"

	authorization = "Sf-OpenApi " + appKey + ";" + token + ";" + aesKey

	// 三个标记：请求正文里的、承运商业务 JSON 里的、承运商 apiErrorMsg 里的。任何日志里都不许有它们。
	bodyMarker     = "BODY-MARKER-7f3a"
	businessMarker = "BUSINESS-MARKER-2d9c"
	errorMarker    = "ERRMSG-MARKER-Access denied, token invalid"

	dispatchPath = "/openapi/api/dispatch"
)

type operation struct {
	path    string
	msgType string
}

var operations = []operation{
	{"/sfintl/v1/orders", "IECS_CREATE_ORDER"},
	{"/sfintl/v1/order-cancellations", "IECS_CANCEL_ORDER"},
	{"/sfintl/v1/agent-number-queries", "IECS_QUERY_AGENTNO"},
	{"/sfintl/v1/label-prints", "IECS_PRINT_ORDER"},
}

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

// ---- 承运商的替身 ----

// seenRequest 是替身收到的一个请求，和它对这个请求的核对结果。
type seenRequest struct {
	method           string
	uri              string
	host             string
	header           http.Header
	ciphertext       string
	contentLength    int64
	transferEncoding []string
	signatureOK      bool
	plain            []byte
	decryptErr       error
}

// fakeCarrier 实现承运商的一侧：核对请求头，重算签名，用已知的测试密钥解密正文，
// 默认答一个加密的信封。respond 非 nil 时由它决定怎么答。
type fakeCarrier struct {
	t       *testing.T
	key     domain.Key
	server  *httptest.Server
	mu      sync.Mutex
	seen    []seenRequest
	respond func(w http.ResponseWriter, r *http.Request, seen seenRequest)
}

func newFakeCarrier(t *testing.T, respond func(http.ResponseWriter, *http.Request, seenRequest)) *fakeCarrier {
	t.Helper()
	key, err := domain.ParseKey(aesKey)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeCarrier{t: t, key: key, respond: respond}
	f.server = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.server.Close)
	return f
}

func (f *fakeCarrier) url() string { return f.server.URL + dispatchPath }

func (f *fakeCarrier) serve(w http.ResponseWriter, r *http.Request) {
	raw, _ := io.ReadAll(r.Body)
	seen := seenRequest{method: r.Method, uri: r.RequestURI, host: r.Host, header: r.Header.Clone(), ciphertext: string(raw),
		contentLength: r.ContentLength, transferEncoding: r.TransferEncoding}
	seen.signatureOK = domain.Sign(r.Header.Get("token"), r.Header.Get("timestamp"), r.Header.Get("nonce"), seen.ciphertext) == r.Header.Get("signature")
	seen.plain, seen.decryptErr = domain.Decrypt(f.key, r.Header.Get("appKey"), seen.ciphertext)
	f.mu.Lock()
	f.seen = append(f.seen, seen)
	respond := f.respond
	f.mu.Unlock()
	if respond != nil {
		respond(w, r, seen)
		return
	}
	business := businessFor(r.Header.Get("msgType"))
	ciphertext, err := domain.Encrypt(f.key, r.Header.Get("appKey"), []byte(business), rand.Reader)
	if err != nil {
		f.t.Errorf("替身加密失败：%v", err)
		return
	}
	_, _ = io.WriteString(w, `{"apiResultCode": 0, "apiErrorMsg": null, "apiResultData": "`+ciphertext+`", "apiTimestamp": 1763611200000}`)
}

// businessFor 是替身为某个 msgType 答的业务 JSON：间距不寻常，带 <、>、& 和非 ASCII 文字。
func businessFor(msgType string) string {
	return "{\"success\": true,\n \"msgType\": \"" + msgType + "\", \"text\": \"<ok> & 顺丰 " + businessMarker + "\", \"n\": 1}"
}

// wrapped 是 businessFor 放进信封之后应当得到的样子：成员按名字的字节序，业务 JSON 逐字节原样。
func wrapped(msgType string) string {
	return `{"apiErrorMsg":null,"apiResultCode":0,"apiResultData":` + businessFor(msgType) + `,"apiTimestamp":1763611200000}`
}

func (f *fakeCarrier) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.seen)
}

func (f *fakeCarrier) requests() []seenRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]seenRequest(nil), f.seen...)
}

// ---- 被测的命令 ----

type harness struct {
	t        *testing.T
	ca       *tlstest.CA
	server   tlstest.Leaf
	peers    map[string]tlstest.Leaf
	carrier  *fakeCarrier
	logs     *lockedBuffer
	extra    []string // 追加在必需参数之后，同名参数以后面的为准
	url      string
	stop     func() error
	answered int // 得到了 HTTP 答复的请求数
	mu       sync.Mutex
}

func newHarness(t *testing.T, carrier *fakeCarrier) *harness {
	t.Helper()
	ca := tlstest.NewCA(t, "workload CA")
	rogue := tlstest.NewCA(t, "a CA outside the trust domain")
	h := &harness{
		t: t, ca: ca, carrier: carrier, logs: &lockedBuffer{},
		server: ca.Issue("server", []string{"spiffe://idp.test/egress/provider-signer"}, serverName),
		peers: map[string]tlstest.Leaf{
			"gateway": ca.Issue("gateway", []string{gatewayID}),
			"other":   ca.Issue("other", []string{otherID}),
			// 一张证书里有两个 URI，其中一个是网关：身份有歧义，不算网关。
			"multi": ca.Issue("multi", []string{gatewayID, otherID}),
			// 没有 URI 的证书。
			"nameless": ca.Issue("nameless", nil),
			"rogue":    rogue.Issue("gateway", []string{gatewayID}),
		},
	}
	// 在 start 注册的"停止"之后执行：每个测试结束时，对服务写的全部日志做一次泄露检查。
	t.Cleanup(h.auditLogs)
	return h
}

func (h *harness) args(listen string) []string {
	return []string{"--listen", listen, "--tls-cert", h.server.CertFile, "--tls-key", h.server.KeyFile,
		"--client-ca", h.ca.File(), "--gateway-identity", gatewayID, "--carrier-url", h.carrier.url()}
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

func (a answer) fields(t *testing.T) map[string]any {
	t.Helper()
	var decoded map[string]any
	if err := json.Unmarshal([]byte(a.body), &decoded); err != nil {
		t.Fatalf("答复不是 JSON：%q", a.body)
	}
	return decoded
}

type call struct {
	peer    string // 出示谁的证书，默认 gateway；none 表示不出示
	method  string // 默认 POST
	path    string
	headers [][2]string
	body    string
	http2   bool
	host    string // 非空时改写 Host 头
}

// good 是一个合规矩的请求的头，extra 追加其后。
func good(extra ...[2]string) [][2]string {
	return append([][2]string{{"Content-Type", "application/json"}, {"Authorization", authorization}}, extra...)
}

func (h *harness) do(c call) (answer, error) {
	h.t.Helper()
	if c.peer == "" {
		c.peer = "gateway"
	}
	var leaf *tlstest.Leaf
	if c.peer != "none" {
		l, ok := h.peers[c.peer]
		if !ok {
			h.t.Fatalf("没有名为 %q 的证书", c.peer)
		}
		leaf = &l
	}
	if c.method == "" {
		c.method = http.MethodPost
	}
	transport := &http.Transport{TLSClientConfig: tlstest.ClientConfig(h.ca, serverName, leaf), ForceAttemptHTTP2: c.http2}
	defer transport.CloseIdleConnections()
	request, err := http.NewRequest(c.method, h.url+c.path, strings.NewReader(c.body))
	if err != nil {
		h.t.Fatal(err)
	}
	for _, header := range c.headers {
		request.Header.Add(header[0], header[1])
	}
	if c.host != "" {
		request.Host = c.host
	}
	response, err := (&http.Client{Transport: transport, Timeout: 15 * time.Second}).Do(request)
	if err != nil {
		return answer{}, err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	h.mu.Lock()
	h.answered++
	h.mu.Unlock()
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

// post 以网关的身份发一个合规矩的 POST。
func (h *harness) post(path, body string, http2 bool, extra ...[2]string) answer {
	h.t.Helper()
	return h.must(call{path: path, body: body, headers: good(extra...), http2: http2})
}

// expectRefusal 核对答复是签名适配器自己的错误，并且承运商一个请求也没有收到。
func (h *harness) expectRefusal(a answer, status int, code string) {
	h.t.Helper()
	fields := a.fields(h.t)
	if a.status != status || fields["error"] != code {
		h.t.Fatalf("得到 %d %s，期望 %d %s", a.status, a.body, status, code)
	}
	if detail, _ := fields["detail"].(string); detail == "" || len(fields) != 2 {
		h.t.Errorf("答复的成员不对：%s", a.body)
	}
	if a.header.Get("Content-Type") != "application/json" {
		h.t.Errorf("Content-Type %q", a.header.Get("Content-Type"))
	}
	if n := h.carrier.count(); n != 0 {
		h.t.Fatalf("承运商收到了 %d 个请求", n)
	}
}

// logLines 是服务写的日志里，每一行 JSON 解出来的样子。
func (h *harness) logLines() []map[string]any {
	h.t.Helper()
	var lines []map[string]any
	for _, raw := range strings.Split(strings.TrimSpace(h.logs.String()), "\n") {
		if raw == "" {
			continue
		}
		var line map[string]any
		if err := json.Unmarshal([]byte(raw), &line); err != nil {
			h.t.Fatalf("日志里有一行不是 JSON：%q", raw)
		}
		lines = append(lines, line)
	}
	return lines
}

func (h *harness) callLines() []map[string]any {
	var calls []map[string]any
	for _, line := range h.logLines() {
		if line["msg"] == "signer call" {
			calls = append(calls, line)
		}
	}
	return calls
}

// auditLogs 在每个测试结束、服务停下之后运行：服务写的全部东西里，没有任何一个秘密或内容。
// 替身收到的随机数、签名、密文也在其中：它们是每个请求现做的，日志里同样不许有。
func (h *harness) auditLogs() {
	if h.stop == nil {
		return
	}
	_ = h.stop()
	logs := h.logs.String()
	forbidden := []string{appKey, token, aesKey, authorization, "Sf-OpenApi", bodyMarker, businessMarker, errorMarker, "Authorization"}
	for _, seen := range h.carrier.requests() {
		forbidden = append(forbidden, seen.header.Get("nonce"), seen.header.Get("signature"), seen.ciphertext)
	}
	for _, secret := range forbidden {
		if secret != "" && strings.Contains(logs, secret) {
			h.t.Errorf("服务日志里有 %q", secret)
		}
	}
	// 每个得到 HTTP 答复的请求，日志里恰好一行。
	h.mu.Lock()
	answered := h.answered
	h.mu.Unlock()
	if lines := len(h.callLines()); lines != answered {
		h.t.Errorf("日志里有 %d 行 signer call，得到答复的请求有 %d 个", lines, answered)
	}
}

// 间距和键序都不寻常的请求正文：它要原样进入明文。
func oddBody(extra string) string {
	return "{ \"zeta\" : 1,\n\t\"alpha\": [ 3,2 , 1 ] ,\"note\":\"" + bodyMarker + " <&> 顺丰 " + extra + "\"  }\n"
}

func milliseconds(t *testing.T, value string) time.Time {
	t.Helper()
	ms, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		t.Fatalf("时间戳 %q 不是十进制整数", value)
	}
	return time.UnixMilli(ms)
}
