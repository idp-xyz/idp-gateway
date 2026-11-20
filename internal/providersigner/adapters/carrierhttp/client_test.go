package carrierhttp

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"go.idp.xyz/idp-gateway/internal/providersigner/ports"
)

func TestParseURL(t *testing.T) {
	const secret = "SECRETPW"
	for _, c := range []struct {
		name   string
		raw    string
		plain  string
		accept bool
	}{
		// 接受的。
		{"production", "https://api-ifsp.sf.global/openapi/api/dispatch", "", true},
		{"https with a port", "https://api-ifsp.sf.global:8443/openapi/api/dispatch", "", true},
		{"https with the scheme in capitals", "HTTPS://API.EXAMPLE.TEST/x", "", true},
		{"https to an address", "https://203.0.113.9/x", "", true},
		{"https to localhost", "https://localhost/x", "", true},
		{"https with the exception set", "https://api.example.test/x", "sandbox.example.test", true},
		{"http to 127.0.0.1", "http://127.0.0.1:8080/openapi/api/dispatch", "", true},
		{"http to another address in 127.0.0.0/8", "http://127.5.6.7/x", "", true},
		{"http to the last address in 127.0.0.0/8", "http://127.255.255.255:1/x", "", true},
		{"http to ::1", "http://[::1]:8080/x", "", true},
		{"http to the excepted host", "http://sandbox.example.test/openapi/api/dispatch", "sandbox.example.test", true},
		{"http to the excepted host with a port", "http://sandbox.example.test:8080/x", "sandbox.example.test", true},
		{"http to the excepted host in other letter case", "http://Sandbox.EXAMPLE.test/x", "sandbox.example.test", true},
		{"the exception in other letter case", "http://sandbox.example.test/x", "SANDBOX.Example.TEST", true},
		{"no path", "https://api.example.test", "", true},

		// 不是绝对地址，或没有主机。
		{"empty", "", "", false},
		{"a path only", "/openapi/api/dispatch", "", false},
		{"no scheme", "api.example.test/x", "", false},
		{"scheme-relative", "//api.example.test/x", "", false},
		{"no host", "https://", "", false},
		{"empty host with a path", "https:///x", "", false},
		{"only a port", "https://:443/x", "", false},
		{"opaque", "https:api.example.test", "", false},
		{"a bad port", "https://api.example.test:abc/x", "", false},
		{"not a URL", "http://[::1", "", false},
		// 协议。
		{"ftp", "ftp://api.example.test/x", "", false},
		{"ws", "ws://127.0.0.1/x", "", false},
		{"file", "file:///etc/passwd", "", false},
		// 明文 http。
		{"http to a name", "http://api.example.test/x", "", false},
		{"http to localhost", "http://localhost:8080/x", "", false},
		{"http to localhost with an exception for another host", "http://localhost:8080/x", "sandbox.example.test", false},
		{"http to an address outside 127.0.0.0/8", "http://128.0.0.1/x", "", false},
		{"http to a private address", "http://10.0.0.1/x", "", false},
		{"http to the unspecified address", "http://0.0.0.0/x", "", false},
		{"http to the unspecified IPv6 address", "http://[::]/x", "", false},
		{"http to a short form of 127.0.0.1", "http://127.1/x", "", false},
		{"http to a hexadecimal form of 127.0.0.1", "http://0x7f.0.0.1/x", "", false},
		{"http to a decimal form of 127.0.0.1", "http://2130706433/x", "", false},
		{"http to an IPv4-mapped loopback address", "http://[::ffff:127.0.0.1]/x", "", false},
		{"http to ::1 with a zone", "http://[::1%25lo]/x", "", false},
		{"http to a name that starts like a loopback address", "http://127.0.0.1.example.test/x", "", false},
		{"the exception for another host", "http://b.example.test/x", "a.example.test", false},
		{"a suffix of the excepted host", "http://evil-sandbox.example.test/x", "sandbox.example.test", false},
		{"a subdomain of the excepted host", "http://x.sandbox.example.test/x", "sandbox.example.test", false},
		{"the excepted host as a prefix of another name", "http://sandbox.example.test.evil.test/x", "sandbox.example.test", false},
		{"a prefix of the excepted host", "http://sandbox.example.tes/x", "sandbox.example.test", false},
		{"the excepted host with a trailing dot", "http://sandbox.example.test./x", "sandbox.example.test", false},
		{"a wildcard exception", "http://a.example.test/x", "*.example.test", false},
		{"the excepted host in the user information", "http://sandbox.example.test@evil.test/x", "sandbox.example.test", false},
		// 用户信息、查询串、片段。
		{"user", "https://user@api.example.test/x", "", false},
		{"user and password", "https://user:" + secret + "@api.example.test/x", "", false},
		{"empty user", "https://@api.example.test/x", "", false},
		{"user on a loopback address", "http://user:" + secret + "@127.0.0.1/x", "", false},
		{"a query", "https://api.example.test/x?a=1", "", false},
		{"an empty query", "https://api.example.test/x?", "", false},
		{"a query without a path", "https://api.example.test?x=1", "", false},
		{"a query on a loopback address", "http://127.0.0.1/x?a=1", "", false},
		{"a fragment", "https://api.example.test/x#f", "", false},
		{"an empty fragment", "https://api.example.test/x#", "", false},
		// 只许可见 ASCII。
		{"a space", "https://api.example.test/x y", "", false},
		{"a leading space", " https://api.example.test/x", "", false},
		{"a trailing newline", "https://api.example.test/x\n", "", false},
		{"a tab", "https://api.example.test/\tx", "", false},
		{"a NUL", "https://api.example.test/\x00", "", false},
		{"a non-ASCII character in the path", "https://api.example.test/é", "", false},
		{"a non-ASCII host", "https://exämple.test/x", "", false},
		// --carrier-plain-http-host 本身必须是裸主机名。
		{"exception with a port", "https://api.example.test/x", "a:80", false},
		{"exception with a slash", "https://api.example.test/x", "a/b", false},
		{"exception with a leading slash", "https://api.example.test/x", "/a", false},
		{"exception with an at sign", "https://api.example.test/x", "a@b", false},
		{"exception with a question mark", "https://api.example.test/x", "a?b", false},
		{"exception with a number sign", "https://api.example.test/x", "a#b", false},
		{"exception with a space", "https://api.example.test/x", "a b", false},
		{"exception with a non-ASCII character", "https://api.example.test/x", "é.example.test", false},
		{"exception with a control character", "https://api.example.test/x", "a\tb", false},
		{"exception as a URL", "https://api.example.test/x", "http://sandbox.example.test", false},
		{"exception as an IPv6 literal", "https://api.example.test/x", "::1", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			target, err := ParseURL(c.raw, c.plain)
			if c.accept {
				if err != nil || target == nil {
					t.Fatalf("被拒绝：%v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("没有被拒绝：%v", target)
			}
			// 错误里没有地址：地址里可能带着用户信息。
			if strings.Contains(err.Error(), secret) || (c.raw != "" && strings.Contains(err.Error(), c.raw)) {
				t.Errorf("错误里有地址：%q", err)
			}
		})
	}
}

func TestNewChecksItsLimits(t *testing.T) {
	good := Config{URL: "https://api.example.test/x", Timeout: time.Second, MaxResponseBytes: 1}
	if _, err := New(good); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*Config){
		"no timeout":       func(c *Config) { c.Timeout = 0 },
		"negative timeout": func(c *Config) { c.Timeout = -time.Second },
		"no limit":         func(c *Config) { c.MaxResponseBytes = 0 },
		"negative limit":   func(c *Config) { c.MaxResponseBytes = -1 },
		"a bad URL":        func(c *Config) { c.URL = "http://api.example.test/x" },
	} {
		config := good
		mutate(&config)
		if _, err := New(config); err == nil {
			t.Errorf("%s: 没有被拒绝", name)
		}
	}
	client, err := New(Config{URL: "http://Sandbox.example.test:8080/openapi/api/dispatch", PlainHTTPHost: "sandbox.example.test", Timeout: time.Second, MaxResponseBytes: 1})
	if err != nil {
		t.Fatal(err)
	}
	if client.Scheme() != "http" || client.Host() != "Sandbox.example.test:8080" {
		t.Errorf("%s %s", client.Scheme(), client.Host())
	}
}

// 到承运商的那一跳的传输设置：不用环境变量里的代理，TLS 1.2 起，验证服务端证书，不跟随重定向，
// 整次交换有时限。
func TestTransportSettings(t *testing.T) {
	client, err := New(Config{URL: "https://api.example.test/x", Timeout: 3 * time.Second, MaxResponseBytes: 10})
	if err != nil {
		t.Fatal(err)
	}
	transport, ok := client.http.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("传输层是 %T", client.http.Transport)
	}
	if transport.Proxy != nil {
		t.Error("Proxy 不是 nil：HTTP_PROXY 等环境变量会生效")
	}
	if transport.TLSClientConfig == nil || transport.TLSClientConfig.MinVersion != tls.VersionTLS12 {
		t.Errorf("TLS 配置 %+v", transport.TLSClientConfig)
	}
	if transport.TLSClientConfig.InsecureSkipVerify || transport.TLSClientConfig.RootCAs != nil {
		t.Error("证书验证被改动了")
	}
	if client.http.Timeout != 3*time.Second {
		t.Errorf("时限 %v", client.http.Timeout)
	}
	if client.http.CheckRedirect == nil || !errors.Is(client.http.CheckRedirect(&http.Request{}, nil), http.ErrUseLastResponse) {
		t.Error("重定向会被跟随")
	}
	if client.http.Jar != nil {
		t.Error("不该有 cookie 罐")
	}
}

type seenRequest struct {
	method           string
	uri              string
	header           http.Header
	body             string
	contentLength    int64
	transferEncoding []string
	host             string
}

// recorder 是一个承运商的替身：记下收到的每个请求，用 answer 答。
type recorder struct {
	mu     sync.Mutex
	seen   []seenRequest
	server *httptest.Server
}

func newRecorder(t *testing.T, answer http.HandlerFunc) *recorder {
	t.Helper()
	r := &recorder{}
	r.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		body, _ := io.ReadAll(req.Body)
		r.mu.Lock()
		r.seen = append(r.seen, seenRequest{method: req.Method, uri: req.RequestURI, header: req.Header.Clone(), body: string(body),
			contentLength: req.ContentLength, transferEncoding: req.TransferEncoding, host: req.Host})
		r.mu.Unlock()
		answer(w, req)
	}))
	t.Cleanup(r.server.Close)
	return r
}

func (r *recorder) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.seen)
}

func newClient(t *testing.T, url string, timeout time.Duration, limit int64) *Client {
	t.Helper()
	client, err := New(Config{URL: url, Timeout: timeout, MaxResponseBytes: limit})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func sample() ports.CarrierRequest {
	return ports.CarrierRequest{MsgType: "IECS_CREATE_ORDER", Lang: "zh-CN",
		AppKey: ports.NewSecret("app-key-1"), Token: ports.NewSecret("token-1"),
		Timestamp: "1763611200000", Nonce: "00112233445566778899aabbccddeeff", Signature: "abcdef0123456789",
		Ciphertext: "Y2lwaGVydGV4dA=="}
}

func ok(body string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, body) }
}

func TestSendWritesExactlyTheCarrierRequest(t *testing.T) {
	carrier := newRecorder(t, ok(`{"apiResultCode":0}`))
	client := newClient(t, carrier.server.URL+"/openapi/api/dispatch", 5*time.Second, 1<<10)

	response, err := client.Send(context.Background(), sample())
	if err != nil || response.Status != 200 || string(response.Body) != `{"apiResultCode":0}` {
		t.Fatalf("%+v %v", response, err)
	}
	if carrier.count() != 1 {
		t.Fatalf("承运商收到 %d 个请求", carrier.count())
	}
	seen := carrier.seen[0]
	if seen.method != "POST" || seen.uri != "/openapi/api/dispatch" {
		t.Errorf("%s %s", seen.method, seen.uri)
	}
	// 请求体就是密文本身，有长度，不是分块的。
	if seen.body != "Y2lwaGVydGV4dA==" || seen.contentLength != int64(len(seen.body)) || len(seen.transferEncoding) != 0 {
		t.Errorf("正文 %q，长度 %d，传输编码 %v", seen.body, seen.contentLength, seen.transferEncoding)
	}
	want := map[string]string{
		"Appkey": "app-key-1", "Token": "token-1", "Timestamp": "1763611200000", "Nonce": "00112233445566778899aabbccddeeff",
		"Signature": "abcdef0123456789", "Msgtype": "IECS_CREATE_ORDER", "Lang": "zh-CN", "Content-Type": "application/json",
	}
	for name, value := range want {
		if values := seen.header.Values(name); len(values) != 1 || values[0] != value {
			t.Errorf("头 %s：%v", name, values)
		}
	}
	// 八个头之外，只有 Go 的客户端自己总会加的：Content-Length、User-Agent、Accept-Encoding。
	for name := range seen.header {
		if _, listed := want[name]; !listed && name != "Content-Length" && name != "User-Agent" && name != "Accept-Encoding" {
			t.Errorf("多出一个头 %s：%v", name, seen.header[name])
		}
	}
	if !strings.HasPrefix(seen.header.Get("User-Agent"), "Go-http-client/") {
		t.Errorf("User-Agent %q", seen.header.Get("User-Agent"))
	}
}

// 重定向不被跟随：包括保留方法和正文的 307、308。第二台服务一个请求也不应收到。
func TestSendDoesNotFollowRedirects(t *testing.T) {
	second := newRecorder(t, ok(`{"apiResultCode":0}`))
	for _, code := range []int{301, 302, 303, 307, 308} {
		first := newRecorder(t, func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, second.server.URL+"/elsewhere", code)
		})
		response, err := newClient(t, first.server.URL+"/dispatch", 5*time.Second, 1<<10).Send(context.Background(), sample())
		if err != nil || response.Status != code || response.Body != nil {
			t.Errorf("%d: %+v %v", code, response, err)
		}
		if first.count() != 1 || second.count() != 0 {
			t.Errorf("%d: 第一台收到 %d 个，第二台收到 %d 个", code, first.count(), second.count())
		}
	}
}

func TestSendDiscardsTheBodyOfAnyStatusButOK(t *testing.T) {
	for _, status := range []int{201, 204, 400, 500, 502, 503} {
		carrier := newRecorder(t, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(status)
			if status != 204 {
				_, _ = io.WriteString(w, strings.Repeat("x", 4096))
			}
		})
		response, err := newClient(t, carrier.server.URL, 5*time.Second, 16).Send(context.Background(), sample())
		// 正文比上限大也没关系：状态不是 200，正文不读。
		if err != nil || response.Status != status || response.Body != nil {
			t.Errorf("%d: %+v %v", status, response, err)
		}
	}
}

func TestSendLimitsTheAnswer(t *testing.T) {
	for _, c := range []struct {
		name    string
		limit   int64
		size    int
		chunked bool
		tooBig  bool
	}{
		{"exactly the limit", 100, 100, false, false},
		{"one byte over", 100, 101, false, true},
		{"far over", 100, 100000, false, true},
		{"exactly the limit, chunked", 100, 100, true, false},
		{"one byte over, chunked", 100, 101, true, true},
		{"empty", 100, 0, false, false},
		{"a limit of one byte, one byte", 1, 1, false, false},
		{"a limit of one byte, two bytes", 1, 2, false, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			carrier := newRecorder(t, func(w http.ResponseWriter, _ *http.Request) {
				content := strings.Repeat("a", c.size)
				if c.chunked {
					for len(content) > 0 {
						n := min(len(content), 7)
						_, _ = io.WriteString(w, content[:n])
						w.(http.Flusher).Flush()
						content = content[n:]
					}
					return
				}
				w.Header().Set("Content-Length", strconv.Itoa(len(content)))
				_, _ = io.WriteString(w, content)
			})
			response, err := newClient(t, carrier.server.URL, 5*time.Second, c.limit).Send(context.Background(), sample())
			if c.tooBig {
				if err != ports.ErrAnswerTooLarge || response.Body != nil {
					t.Fatalf("%+v %v", response, err)
				}
				return
			}
			if err != nil || response.Status != 200 || len(response.Body) != c.size {
				t.Fatalf("%d 字节：%+v %v", len(response.Body), response.Status, err)
			}
		})
	}
}

func TestSendTimesOut(t *testing.T) {
	wait := func(r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(3 * time.Second):
		}
	}
	for name, handler := range map[string]http.HandlerFunc{
		"no answer at all": func(_ http.ResponseWriter, r *http.Request) { wait(r) },
		"headers, then a stalled body": func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Length", "100")
			w.WriteHeader(200)
			_, _ = io.WriteString(w, "partial")
			w.(http.Flusher).Flush()
			wait(r)
		},
	} {
		carrier := newRecorder(t, handler)
		started := time.Now()
		response, err := newClient(t, carrier.server.URL, 200*time.Millisecond, 1<<10).Send(context.Background(), sample())
		if err != ports.ErrTimeout || response.Body != nil || response.Status != 0 {
			t.Errorf("%s: %+v %v", name, response, err)
		}
		if elapsed := time.Since(started); elapsed > 2*time.Second {
			t.Errorf("%s: 用了 %v", name, elapsed)
		}
		time.Sleep(300 * time.Millisecond)
		if carrier.count() != 1 {
			t.Errorf("%s: 承运商收到 %d 个请求：超时之后重试了", name, carrier.count())
		}
	}
}

// 连不上，握手失败，连接断了：都是 ErrUnreachable，而且错误值就是哨兵本身，不带地址。
func TestSendReportsUnreachable(t *testing.T) {
	closed := httptest.NewServer(http.NotFoundHandler())
	closedURL := closed.URL
	closed.Close()
	if _, err := newClient(t, closedURL, 2*time.Second, 1<<10).Send(context.Background(), sample()); err != ports.ErrUnreachable {
		t.Errorf("连接被拒绝：%v", err)
	}

	// 对端收到请求就断开，不答。
	var mu sync.Mutex
	asked := 0
	hangUp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		asked++
		mu.Unlock()
		conn, _, err := w.(http.Hijacker).Hijack()
		if err == nil {
			_ = conn.Close()
		}
	}))
	defer hangUp.Close()
	if _, err := newClient(t, hangUp.URL, 2*time.Second, 1<<10).Send(context.Background(), sample()); err != ports.ErrUnreachable {
		t.Errorf("连接被断开：%v", err)
	}
	mu.Lock()
	if asked != 1 {
		t.Errorf("对端被问了 %d 次", asked)
	}
	mu.Unlock()

	// 调用方撤销了请求：不是超时。
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := newClient(t, closedURL, 2*time.Second, 1<<10).Send(ctx, sample()); err != ports.ErrUnreachable {
		t.Errorf("上下文已取消：%v", err)
	}
}

// 服务端证书由系统根证书验证：测试服务器的证书不在其中，握手失败，请求到不了处理器。
func TestSendVerifiesTheServerCertificate(t *testing.T) {
	var mu sync.Mutex
	reached := 0
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		reached++
		mu.Unlock()
	}))
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.StartTLS()
	defer server.Close()

	if _, err := newClient(t, server.URL, 2*time.Second, 1<<10).Send(context.Background(), sample()); err != ports.ErrUnreachable {
		t.Errorf("%v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if reached != 0 {
		t.Error("证书没有被验证，请求到了处理器")
	}
}

type spyTransport struct {
	inner http.RoundTripper
	mu    sync.Mutex
	seen  []*http.Request
}

func (s *spyTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	s.mu.Lock()
	s.seen = append(s.seen, r)
	s.mu.Unlock()
	return s.inner.RoundTrip(r)
}

// 请求没有 GetBody：Go 的传输层要靠它才会在复用的空闲连接上重发一个没写出去的请求。
// 这里连那种悄悄的重发也不要，"不重试"是一个字都不重发。
func TestSendRequestCannotBeReplayed(t *testing.T) {
	carrier := newRecorder(t, ok(`{"apiResultCode":0}`))
	client := newClient(t, carrier.server.URL, 5*time.Second, 1<<10)
	spy := &spyTransport{inner: client.http.Transport}
	client.http.Transport = spy

	if _, err := client.Send(context.Background(), sample()); err != nil {
		t.Fatal(err)
	}
	if len(spy.seen) != 1 {
		t.Fatalf("%d 个请求", len(spy.seen))
	}
	r := spy.seen[0]
	if r.GetBody != nil || r.Body == nil || r.Body == http.NoBody || r.ContentLength != int64(len(sample().Ciphertext)) {
		t.Errorf("GetBody=%v ContentLength=%d", r.GetBody != nil, r.ContentLength)
	}
	if r.Method != http.MethodPost || r.URL.String() != carrier.server.URL {
		t.Errorf("%s %s", r.Method, r.URL)
	}
}

// 请求只由 ports.CarrierRequest 决定：同一个 Client 先后发的两个请求互不影响，URL 也始终是配置的那一个。
func TestSendUsesTheConfiguredURLOnly(t *testing.T) {
	carrier := newRecorder(t, ok(`{"apiResultCode":0}`))
	client := newClient(t, carrier.server.URL+"/openapi/api/dispatch", 5*time.Second, 1<<10)
	first, second := sample(), sample()
	second.MsgType, second.Ciphertext = "IECS_CANCEL_ORDER", "c2Vjb25k"
	for _, request := range []ports.CarrierRequest{first, second} {
		if _, err := client.Send(context.Background(), request); err != nil {
			t.Fatal(err)
		}
	}
	if carrier.count() != 2 {
		t.Fatal(carrier.count())
	}
	for i, want := range []ports.CarrierRequest{first, second} {
		seen := carrier.seen[i]
		if seen.uri != "/openapi/api/dispatch" || seen.header.Get("msgType") != want.MsgType || seen.body != want.Ciphertext {
			t.Errorf("第 %d 个：%s %s %q", i+1, seen.uri, seen.header.Get("msgType"), seen.body)
		}
	}
}
