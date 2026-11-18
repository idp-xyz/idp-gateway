package oauthclient

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.idp.xyz/idp-gateway/internal/egressauthz/application"
	"go.idp.xyz/idp-gateway/internal/egressauthz/domain"
	"go.idp.xyz/idp-gateway/internal/egressauthz/ports"
)

const (
	binding      = "gatekeeper:mockcarrier-test"
	blueHandle   = binding + "/account-blue"
	greenHandle  = binding + "/account-green"
	blueSecret   = "client-secret-blue-3f9a"
	greenSecret  = "client-secret-green-77c1"
	blueClient   = "client-blue"
	greenClient  = "client-green"
	bodySecret   = "BODY-SECRET-that-an-endpoint-might-echo"
	tokenPattern = "access-token-"
)

// fakeClock 是可以拨的时钟。
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func newClock() *fakeClock { return &fakeClock{now: time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)} }

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// tokenEndpoint 是替身令牌端点。每个客户端各发各的令牌，记下收到的请求。
type tokenEndpoint struct {
	*httptest.Server

	mu       sync.Mutex
	requests []received
	issued   int
	// handler 不为 nil 时它替默认的应答作答（在记下请求之后）。
	handler   func(w http.ResponseWriter, r *http.Request)
	expiresIn string // 写进应答里的 expires_in（JSON 原文）
}

type received struct {
	method, contentType, authorization, body string
	form                                     url.Values
}

func newEndpoint(t *testing.T) *tokenEndpoint {
	t.Helper()
	e := &tokenEndpoint{expiresIn: "3600"}
	e.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		form, _ := url.ParseQuery(string(raw))
		e.mu.Lock()
		e.requests = append(e.requests, received{r.Method, r.Header.Get("Content-Type"), r.Header.Get("Authorization"), string(raw), form})
		e.issued++
		n, handler, expires := e.issued, e.handler, e.expiresIn
		e.mu.Unlock()
		if handler != nil {
			handler(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"access_token":"%s%d","token_type":"Bearer","expires_in":%s}`, tokenPattern, n, expires)
	}))
	t.Cleanup(e.Close)
	return e
}

func (e *tokenEndpoint) count() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.requests)
}

func (e *tokenEndpoint) set(handler func(w http.ResponseWriter, r *http.Request)) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.handler = handler
}

func (e *tokenEndpoint) setExpiresIn(v string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.expiresIn = v
}

func (e *tokenEndpoint) last() received {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.requests[len(e.requests)-1]
}

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

type fixture struct {
	t     *testing.T
	path  string
	clock *fakeClock
	logs  *lockedBuffer
	c     *Client
}

// entryJSON 写一条记录。fields 是 client_id 之外的可选字段，原样接在后面。
func entryJSON(handle, endpoint, clientID, secret, keyVersion string, more ...string) string {
	extra := ""
	for _, m := range more {
		extra += "," + m
	}
	return fmt.Sprintf(`%q:{"token_endpoint":%q,"client_id":%q,"client_secret":%q,"key_version":%q%s}`,
		handle, endpoint, clientID, secret, keyVersion, extra)
}

func fileOf(entries ...string) string { return "{" + strings.Join(entries, ",") + "}" }

// written 数着写过多少次文件：每次写的修改时间都比上一次晚一秒。重读靠修改时间、大小和是不是同一个文件
// 看文件变没变（见 sameFile）；内核给修改时间的刻度很粗，连着写两份一样长的文件、又碰上 inode 被重用时，
// 不拨修改时间这几项会全部相同，测试就时灵时不灵。
var written atomic.Int64

func write(t *testing.T, path, content string, mode os.FileMode) {
	t.Helper()
	next := path + ".next"
	if err := os.WriteFile(next, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(next, mode); err != nil {
		t.Fatal(err)
	}
	stamp := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC).Add(time.Duration(written.Add(1)) * time.Second)
	if err := os.Chtimes(next, stamp, stamp); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(next, path); err != nil {
		t.Fatal(err)
	}
}

func newFixture(t *testing.T, content string, timeout time.Duration, reserved func(string) bool) *fixture {
	t.Helper()
	f := &fixture{t: t, path: filepath.Join(t.TempDir(), "oauth-clients.json"), clock: newClock(), logs: &lockedBuffer{}}
	write(t, f.path, content, 0o600)
	c, err := Load(Config{Path: f.path, Timeout: timeout, Reserved: reserved, Now: f.clock.Now,
		Logger: slog.New(slog.NewJSONHandler(f.logs, nil))})
	if err != nil {
		t.Fatal(err)
	}
	f.c = c
	return f
}

func (f *fixture) get(handle string) (string, error) {
	f.t.Helper()
	b, a, _ := strings.Cut(handle, "/")
	s, err := f.c.AuthorizationHeader(context.Background(), b, a)
	return s.Reveal(), err
}

// two 是两个账户各一个客户端，都指向 endpoint。
func two(endpoint string) string {
	return fileOf(entryJSON(blueHandle, endpoint, blueClient, blueSecret, "v1"),
		entryJSON(greenHandle, endpoint, greenClient, greenSecret, "v1"))
}

func TestFetchesWithClientCredentialsAndBasic(t *testing.T) {
	ep := newEndpoint(t)
	f := newFixture(t, fileOf(
		entryJSON(blueHandle, ep.URL+"/oauth/token", blueClient, blueSecret, "v1", `"scope":"parcels.read"`, `"audience":"https://api.example"`),
		entryJSON(greenHandle, ep.URL+"/oauth/token", greenClient, greenSecret, "v1")), 0, nil)

	got, err := f.get(blueHandle)
	if err != nil || got != "Bearer "+tokenPattern+"1" {
		t.Fatalf("%q %v", got, err)
	}
	r := ep.last()
	if r.method != http.MethodPost || r.contentType != "application/x-www-form-urlencoded" {
		t.Errorf("%s %s", r.method, r.contentType)
	}
	if want := "Basic " + base64.StdEncoding.EncodeToString([]byte(blueClient+":"+blueSecret)); r.authorization != want {
		t.Errorf("Authorization 不是 client_secret_basic")
	}
	if r.form.Get("grant_type") != "client_credentials" || r.form.Get("scope") != "parcels.read" || r.form.Get("audience") != "https://api.example" ||
		strings.Contains(r.body, blueSecret) || strings.Contains(r.body, "client_secret") {
		t.Errorf("正文 %q", r.body)
	}
	// 没有 scope 和 audience 就不带。
	if _, err := f.get(greenHandle); err != nil {
		t.Fatal(err)
	}
	if r := ep.last(); r.body != "grant_type=client_credentials" {
		t.Errorf("正文 %q", r.body)
	}
}

func TestBasicEncodesTheClientPerRFC6749(t *testing.T) {
	ep := newEndpoint(t)
	f := newFixture(t, fileOf(entryJSON(blueHandle, ep.URL, "id:with/odd", "se+cr:et%", "v1")), 0, nil)
	if _, err := f.get(blueHandle); err != nil {
		t.Fatal(err)
	}
	user, pass, ok := (&http.Request{Header: http.Header{"Authorization": {ep.last().authorization}}}).BasicAuth()
	if !ok || user != url.QueryEscape("id:with/odd") || pass != url.QueryEscape("se+cr:et%") {
		t.Errorf("%q %q", user, pass)
	}
}

func TestTwoAccountsEachGetTheirOwnTokenAndItIsCached(t *testing.T) {
	ep := newEndpoint(t)
	f := newFixture(t, two(ep.URL), 0, nil)
	blue, _ := f.get(blueHandle)
	green, _ := f.get(greenHandle)
	if blue == "" || green == "" || blue == green || ep.count() != 2 {
		t.Fatalf("%q %q %d", blue, green, ep.count())
	}
	for range 5 {
		if again, _ := f.get(blueHandle); again != blue {
			t.Fatal("同一个账户拿到了别的令牌")
		}
		if again, _ := f.get(greenHandle); again != green {
			t.Fatal("同一个账户拿到了别的令牌")
		}
	}
	if ep.count() != 2 {
		t.Errorf("令牌端点被问了 %d 次", ep.count())
	}
	// 各用各的客户端。
	ep.mu.Lock()
	defer ep.mu.Unlock()
	if !strings.HasPrefix(ep.requests[0].authorization, "Basic ") || ep.requests[0].authorization == ep.requests[1].authorization {
		t.Error("两个账户用了同一个客户端凭证")
	}
}

func TestRefreshLead(t *testing.T) {
	for lifetime, want := range map[time.Duration]time.Duration{
		5 * time.Second:    500 * time.Millisecond,
		100 * time.Second:  10 * time.Second,
		300 * time.Second:  30 * time.Second,
		301 * time.Second:  30 * time.Second,
		3600 * time.Second: 30 * time.Second,
		1 * time.Second:    100 * time.Millisecond,
	} {
		if got := RefreshLead(lifetime); got != want {
			t.Errorf("寿命 %v：提前 %v，期望 %v", lifetime, got, want)
		}
	}
}

func TestTokenIsRenewedBeforeItExpires(t *testing.T) {
	ep := newEndpoint(t)
	ep.setExpiresIn("100") // 提前 10 秒
	f := newFixture(t, two(ep.URL), 0, nil)
	first, _ := f.get(blueHandle)

	f.clock.Advance(89*time.Second + 999*time.Millisecond) // 剩 10.001 秒：还多于提前量
	if again, _ := f.get(blueHandle); again != first || ep.count() != 1 {
		t.Fatalf("还没到时候就换了：%d", ep.count())
	}
	f.clock.Advance(time.Millisecond) // 剩下正好 10 秒：不超过提前量，不再交出
	second, err := f.get(blueHandle)
	if err != nil || second == first || ep.count() != 2 {
		t.Fatalf("该换新了：%q %v %d", second, err, ep.count())
	}
	// 长寿命的令牌，提前量是 30 秒。
	ep.setExpiresIn("3600")
	f.clock.Advance(100 * time.Second)
	third, _ := f.get(blueHandle)
	if ep.count() != 3 {
		t.Fatal(ep.count())
	}
	f.clock.Advance(3600*time.Second - 30*time.Second - time.Second)
	if again, _ := f.get(blueHandle); again != third || ep.count() != 3 {
		t.Fatal("剩 31 秒就换了")
	}
	f.clock.Advance(time.Second)
	if again, _ := f.get(blueHandle); again == third || ep.count() != 4 {
		t.Fatal("剩 30 秒不该再交出")
	}
}

func TestConcurrentRequestsAskTheEndpointOnce(t *testing.T) {
	ep := newEndpoint(t)
	release := make(chan struct{})
	ep.set(func(w http.ResponseWriter, r *http.Request) {
		<-release
		fmt.Fprint(w, `{"access_token":"one-token","token_type":"bearer","expires_in":3600}`)
	})
	f := newFixture(t, two(ep.URL), 5*time.Second, nil)

	const n = 24
	results := make(chan string, n)
	var started sync.WaitGroup
	started.Add(n)
	for range n {
		go func() {
			started.Done()
			got, err := f.get(blueHandle)
			if err != nil {
				got = "error: " + err.Error()
			}
			results <- got
		}()
	}
	started.Wait()
	time.Sleep(100 * time.Millisecond) // 让它们都排到队里
	close(release)
	for range n {
		if got := <-results; got != "Bearer one-token" {
			t.Fatal(got)
		}
	}
	if ep.count() != 1 {
		t.Fatalf("令牌端点被问了 %d 次", ep.count())
	}
}

func TestConcurrentRequestsAllRefuseWhenTheOneFetchFails(t *testing.T) {
	ep := newEndpoint(t)
	release := make(chan struct{})
	ep.set(func(w http.ResponseWriter, r *http.Request) {
		<-release
		w.WriteHeader(http.StatusInternalServerError)
	})
	f := newFixture(t, two(ep.URL), 5*time.Second, nil)

	const n = 24
	errs := make(chan error, n)
	for range n {
		go func() { _, err := f.get(blueHandle); errs <- err }()
	}
	time.Sleep(100 * time.Millisecond)
	close(release)
	for range n {
		if err := <-errs; err == nil {
			t.Fatal("等着的请求拿到了凭证")
		}
	}
	if ep.count() != 1 {
		t.Fatalf("令牌端点被问了 %d 次：失败了，等着的不该各自再发", ep.count())
	}
	// 之后的请求再去取，端点恢复就好。
	ep.set(nil)
	if got, err := f.get(blueHandle); err != nil || got == "" {
		t.Fatalf("端点恢复之后：%q %v", got, err)
	}
}

func TestDifferentAccountsAreNotMadeToWaitForEachOther(t *testing.T) {
	ep := newEndpoint(t)
	release := make(chan struct{})
	ep.set(func(w http.ResponseWriter, r *http.Request) {
		if user, _, _ := r.BasicAuth(); user == blueClient {
			<-release
		}
		fmt.Fprint(w, `{"access_token":"t","token_type":"Bearer","expires_in":3600}`)
	})
	f := newFixture(t, two(ep.URL), 5*time.Second, nil)
	blocked := make(chan error, 1)
	go func() { _, err := f.get(blueHandle); blocked <- err }()
	time.Sleep(50 * time.Millisecond)
	if _, err := f.get(greenHandle); err != nil {
		t.Fatal(err)
	}
	close(release)
	if err := <-blocked; err != nil {
		t.Fatal(err)
	}
	if ep.count() != 2 {
		t.Fatal(ep.count())
	}
}

func TestAWaiterThatGivesUpDoesNotFailTheOthers(t *testing.T) {
	ep := newEndpoint(t)
	release := make(chan struct{})
	ep.set(func(w http.ResponseWriter, r *http.Request) {
		<-release
		fmt.Fprint(w, `{"access_token":"slow-token","token_type":"Bearer","expires_in":3600}`)
	})
	f := newFixture(t, two(ep.URL), 5*time.Second, nil)

	// 发起这次获取的请求自己走了。
	ctx, cancel := context.WithCancel(context.Background())
	leader := make(chan error, 1)
	go func() { _, err := f.c.AuthorizationHeader(ctx, binding, "account-blue"); leader <- err }()
	time.Sleep(50 * time.Millisecond)
	waiter := make(chan string, 1)
	go func() { got, _ := f.get(blueHandle); waiter <- got }()
	time.Sleep(50 * time.Millisecond)
	cancel()
	if err := <-leader; !errors.Is(err, context.Canceled) {
		t.Fatalf("取消了的请求：%v", err)
	}
	close(release)
	if got := <-waiter; got != "Bearer slow-token" {
		t.Fatalf("另一个等着的请求：%q", got)
	}
	if ep.count() != 1 {
		t.Fatal(ep.count())
	}
}

// 各种取不到。每一种：这次请求拿不到凭证；错误信息和日志里没有密钥、令牌和应答正文；端点恢复之后下一个请求照常。
func TestWhenTheEndpointCannotBeUsedTheRequestIsRefused(t *testing.T) {
	big := `{"access_token":"x","token_type":"Bearer","expires_in":3600,"pad":"` + strings.Repeat("a", maxBody) + `"}`
	good := `"access_token":"leaked-` + bodySecret + `","token_type":"Bearer","expires_in":3600`
	answers := map[string]struct {
		status int
		body   string
		result string
	}{
		"状态 500":                 {500, `{"error":"` + bodySecret + `"}`, "status 500"},
		"状态 401":                 {401, `{"error":"invalid_client","client_secret":"` + bodySecret + `"}`, "status 401"},
		"状态 201":                 {201, `{` + good + `}`, "status 201"},
		"状态 204":                 {204, ``, "status 204"},
		"不是 JSON":                {200, `<html>` + bodySecret + `</html>`, "bad_answer"},
		"JSON 数组":                {200, `[{` + good + `}]`, "bad_answer"},
		"对象后面还有内容":               {200, `{` + good + `} ` + bodySecret, "bad_answer"},
		"没有 access_token":        {200, `{"token_type":"Bearer","expires_in":3600,"x":"` + bodySecret + `"}`, "bad_answer"},
		"access_token 为空":        {200, `{"access_token":"","token_type":"Bearer","expires_in":3600}`, "bad_answer"},
		"access_token 不是字符串":     {200, `{"access_token":7,"token_type":"Bearer","expires_in":3600}`, "bad_answer"},
		"access_token 里有空格":      {200, `{"access_token":"a b","token_type":"Bearer","expires_in":3600}`, "bad_answer"},
		"access_token 里有换行":      {200, `{"access_token":"a\r\nX: 1","token_type":"Bearer","expires_in":3600}`, "bad_answer"},
		"access_token 里有非 ASCII": {200, `{"access_token":"é","token_type":"Bearer","expires_in":3600}`, "bad_answer"},
		"token_type 不是 Bearer":   {200, `{"access_token":"` + bodySecret + `","token_type":"mac","expires_in":3600}`, "bad_answer"},
		"没有 token_type":          {200, `{"access_token":"` + bodySecret + `","expires_in":3600}`, "bad_answer"},
		"没有 expires_in":          {200, `{"access_token":"` + bodySecret + `","token_type":"Bearer"}`, "bad_answer"},
		"expires_in 为 0":         {200, `{"access_token":"` + bodySecret + `","token_type":"Bearer","expires_in":0}`, "bad_answer"},
		"expires_in 为负":          {200, `{"access_token":"` + bodySecret + `","token_type":"Bearer","expires_in":-5}`, "bad_answer"},
		"expires_in 是字符串":        {200, `{"access_token":"` + bodySecret + `","token_type":"Bearer","expires_in":"3600"}`, "bad_answer"},
		"expires_in 是小数":         {200, `{"access_token":"` + bodySecret + `","token_type":"Bearer","expires_in":3600.5}`, "bad_answer"},
		"expires_in 是 null":      {200, `{"access_token":"` + bodySecret + `","token_type":"Bearer","expires_in":null}`, "bad_answer"},
		"应答超过 64KB":              {200, big, "bad_answer"},
	}
	for name, answer := range answers {
		t.Run(name, func(t *testing.T) {
			ep := newEndpoint(t)
			f := newFixture(t, two(ep.URL), 0, nil)
			ep.set(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(answer.status)
				io.WriteString(w, answer.body)
			})
			got, err := f.get(blueHandle)
			if err == nil || got != "" || errors.Is(err, ports.ErrCredentialNotHeld) {
				t.Fatalf("%q %v", got, err)
			}
			noSecrets(t, err.Error()+f.logs.String(), name)
			if !strings.Contains(f.logs.String(), `"result":"`+answer.result+`"`) {
				t.Errorf("日志里没有类别 %q：%s", answer.result, f.logs.String())
			}
			// 端点恢复，下一个请求照常。
			ep.set(nil)
			if got, err := f.get(blueHandle); err != nil || got == "" {
				t.Fatalf("恢复之后：%q %v", got, err)
			}
		})
	}
}

func noSecrets(t *testing.T, text, what string) {
	t.Helper()
	basic := base64.StdEncoding.EncodeToString([]byte(blueClient + ":" + blueSecret))
	for _, secret := range []string{blueSecret, greenSecret, bodySecret, tokenPattern, "one-token", "slow-token", basic, "Basic ", "Bearer "} {
		if strings.Contains(text, secret) {
			t.Errorf("%s：输出里有 %q：%s", what, secret, text)
		}
	}
}

func TestTimeoutUnreachableAndRedirects(t *testing.T) {
	t.Run("超时", func(t *testing.T) {
		ep := newEndpoint(t)
		release := make(chan struct{})
		t.Cleanup(func() { close(release) })
		ep.set(func(w http.ResponseWriter, r *http.Request) { <-release })
		f := newFixture(t, two(ep.URL), 100*time.Millisecond, nil)
		begun := time.Now()
		_, err := f.get(blueHandle)
		if err == nil || time.Since(begun) > 2*time.Second || !strings.Contains(f.logs.String(), `"result":"timeout"`) {
			t.Fatalf("%v %v %s", err, time.Since(begun), f.logs.String())
		}
		noSecrets(t, err.Error()+f.logs.String(), "超时")
	})
	t.Run("应答头来了正文迟迟不来", func(t *testing.T) {
		ep := newEndpoint(t)
		release := make(chan struct{})
		t.Cleanup(func() { close(release) })
		ep.set(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(200)
			w.(http.Flusher).Flush()
			<-release
		})
		f := newFixture(t, two(ep.URL), 100*time.Millisecond, nil)
		begun := time.Now()
		if _, err := f.get(blueHandle); err == nil || time.Since(begun) > 2*time.Second {
			t.Fatalf("%v %v", err, time.Since(begun))
		}
	})
	t.Run("连不上", func(t *testing.T) {
		closed := httptest.NewServer(http.NotFoundHandler())
		address := closed.URL
		closed.Close()
		f := newFixture(t, two(address), 0, nil)
		_, err := f.get(blueHandle)
		if err == nil || !strings.Contains(f.logs.String(), `"result":"unreachable"`) {
			t.Fatalf("%v %s", err, f.logs.String())
		}
		noSecrets(t, err.Error()+f.logs.String(), "连不上")
	})
	t.Run("不跟随重定向", func(t *testing.T) {
		var elsewhere atomic.Int32
		other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			elsewhere.Add(1)
			fmt.Fprint(w, `{"access_token":"stolen","token_type":"Bearer","expires_in":3600}`)
		}))
		defer other.Close()
		ep := newEndpoint(t)
		ep.set(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, other.URL, http.StatusTemporaryRedirect)
		})
		f := newFixture(t, two(ep.URL), 0, nil)
		if _, err := f.get(blueHandle); err == nil || elsewhere.Load() != 0 || !strings.Contains(f.logs.String(), `"result":"status 307"`) {
			t.Fatalf("%v %d %s", err, elsewhere.Load(), f.logs.String())
		}
	})
	t.Run("不用环境变量里的代理", func(t *testing.T) {
		var proxied atomic.Int32
		proxy := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { proxied.Add(1) }))
		defer proxy.Close()
		t.Setenv("HTTP_PROXY", proxy.URL)
		t.Setenv("http_proxy", proxy.URL)
		t.Setenv("NO_PROXY", "")
		ep := newEndpoint(t)
		f := newFixture(t, two(ep.URL), 0, nil)
		if _, err := f.get(blueHandle); err != nil || proxied.Load() != 0 {
			t.Fatalf("%v %d", err, proxied.Load())
		}
	})
}

func TestHTTPSEndpoint(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"access_token":"tls-token","token_type":"BEARER","expires_in":60}`)
	}))
	defer server.Close()
	f := newFixture(t, two(server.URL), 0, nil)
	f.c.http.Transport = server.Client().Transport // 信任测试服务器的证书
	if got, err := f.get(blueHandle); err != nil || got != "Bearer tls-token" {
		t.Fatalf("%q %v", got, err)
	}
	// 不信任它的证书时取不到，也是取不到，不是别的样子。
	g := newFixture(t, two(server.URL), 0, nil)
	if _, err := g.get(blueHandle); err == nil || errors.Is(err, ports.ErrCredentialNotHeld) {
		t.Fatalf("%v", err)
	}
}

// 取失败时不拿上一枚顶上：上一枚还没到期、但已经进入该换新的时段，端点又坏了，请求拒绝。
func TestNoStandInWhenTheFetchFails(t *testing.T) {
	ep := newEndpoint(t)
	ep.setExpiresIn("100")
	f := newFixture(t, two(ep.URL), 0, nil)
	first, err := f.get(blueHandle)
	if err != nil {
		t.Fatal(err)
	}
	ep.set(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(500) })

	f.clock.Advance(95 * time.Second) // 寿命 100 秒，还剩 5 秒：没过期，但在提前量（10 秒）之内
	for i := range 3 {
		if got, err := f.get(blueHandle); err == nil || got != "" {
			t.Fatalf("第 %d 次：交出了 %q（%v）", i, got, err)
		}
	}
	if ep.count() != 4 {
		t.Errorf("每次拒绝之前都该问一次令牌端点：%d", ep.count())
	}
	// 端点仍然坏着，令牌也已经过期。
	f.clock.Advance(10 * time.Second)
	if got, err := f.get(blueHandle); err == nil || got != "" {
		t.Fatalf("过期之后：%q %v", got, err)
	}
	// 恢复了。
	ep.set(nil)
	second, err := f.get(blueHandle)
	if err != nil || second == first || second == "" {
		t.Fatalf("恢复之后：%q %v", second, err)
	}
	// 另一个账户一直不受影响（它的令牌没到该换的时候）。
	if _, err := f.get(greenHandle); err != nil {
		t.Fatal(err)
	}
}

func TestAnExpiredTokenIsNeverHandedOut(t *testing.T) {
	ep := newEndpoint(t)
	ep.setExpiresIn("10")
	f := newFixture(t, two(ep.URL), 0, nil)
	first, _ := f.get(blueHandle)
	f.clock.Advance(time.Hour)
	second, err := f.get(blueHandle)
	if err != nil || second == first || ep.count() != 2 {
		t.Fatalf("%q %v %d", second, err, ep.count())
	}
}

func TestACachedTokenIsKeyedByEveryPartOfTheKey(t *testing.T) {
	ep := newEndpoint(t)
	other := newEndpoint(t)
	base := func(mut func(map[string]string)) string {
		f := map[string]string{"endpoint": ep.URL, "client": blueClient, "secret": blueSecret, "version": "v1", "scope": "s1", "audience": "a1"}
		if mut != nil {
			mut(f)
		}
		return fileOf(entryJSON(blueHandle, f["endpoint"], f["client"], f["secret"], f["version"],
			fmt.Sprintf(`"scope":%q`, f["scope"]), fmt.Sprintf(`"audience":%q`, f["audience"])),
			entryJSON(greenHandle, ep.URL, greenClient, greenSecret, "v1"))
	}
	changes := map[string]func(map[string]string){
		"令牌端点":        func(f map[string]string) { f["endpoint"] = other.URL },
		"client_id":   func(f map[string]string) { f["client"] = "client-blue-2" },
		"scope":       func(f map[string]string) { f["scope"] = "s2" },
		"audience":    func(f map[string]string) { f["audience"] = "a2" },
		"key_version": func(f map[string]string) { f["version"] = "v2" },
		"客户端密钥（key_version 不变）": func(f map[string]string) { f["secret"] = "another-secret" },
		"scope 去掉了":             func(f map[string]string) { f["scope"] = "" },
		"audience 去掉了":          func(f map[string]string) { f["audience"] = "" },
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			ep.mu.Lock()
			ep.requests = nil
			ep.mu.Unlock()
			other.mu.Lock()
			other.requests = nil
			other.mu.Unlock()
			f := newFixture(t, base(nil), 0, nil)
			first, _ := f.get(blueHandle)
			green, _ := f.get(greenHandle)
			f.get(blueHandle)
			if ep.count() != 2 {
				t.Fatalf("文件没变，令牌端点被问了 %d 次", ep.count())
			}
			write(t, f.path, base(change), 0o600)
			second, err := f.get(blueHandle)
			// 换了端点时，新端点自己数自己的，发出的第一枚令牌和旧端点的第一枚同名：看是不是真的去问了新端点。
			if err != nil || (name != "令牌端点" && second == first) || ep.count()+other.count() != 3 || (name == "令牌端点" && other.count() != 1) {
				t.Fatalf("变了之后没有重新取：%q %v %d", second, err, ep.count()+other.count())
			}
			if again, _ := f.get(greenHandle); again != green {
				t.Error("没变的那个账户的缓存被丢掉了")
			}
			if again, _ := f.get(blueHandle); again != second {
				t.Error("新的那一条没有被缓存")
			}
		})
	}
}

// 文件里不再有的句柄：拿不到凭证，缓存里它的令牌也被丢掉。换回来之后重新取，不会用到旧的。
func TestAHandleThatLeavesTheFileLeavesTheCache(t *testing.T) {
	ep := newEndpoint(t)
	f := newFixture(t, two(ep.URL), 0, nil)
	first, _ := f.get(greenHandle)
	f.get(blueHandle)
	write(t, f.path, fileOf(entryJSON(blueHandle, ep.URL, blueClient, blueSecret, "v1")), 0o600)
	if _, err := f.get(greenHandle); !errors.Is(err, ports.ErrCredentialNotHeld) {
		t.Fatalf("%v", err)
	}
	f.c.cmu.Lock()
	slots := len(f.c.slots)
	f.c.cmu.Unlock()
	if slots != 1 {
		t.Errorf("缓存里还有 %d 条", slots)
	}
	write(t, f.path, two(ep.URL), 0o600)
	again, _ := f.get(greenHandle)
	if again == first || ep.count() != 3 {
		t.Errorf("回来之后用了旧令牌：%q %d", again, ep.count())
	}
}

// 密钥换了而 key_version 没变（运维忘了改）：缓存键里有密钥的摘要，旧密钥取来的令牌不再用，
// 下一个请求用新密钥重新取。
func TestChangingOnlyTheSecretFetchesAgainWithTheNewSecret(t *testing.T) {
	ep := newEndpoint(t)
	f := newFixture(t, two(ep.URL), 0, nil)
	first, _ := f.get(blueHandle)
	write(t, f.path, fileOf(entryJSON(blueHandle, ep.URL, blueClient, "another-secret", "v1"),
		entryJSON(greenHandle, ep.URL, greenClient, greenSecret, "v1")), 0o600)
	second, err := f.get(blueHandle)
	if err != nil || second == first || ep.count() != 2 {
		t.Fatalf("只换密钥、key_version 不变，没有重新取：%q %v %d", second, err, ep.count())
	}
	if want := "Basic " + base64.StdEncoding.EncodeToString([]byte(blueClient+":another-secret")); ep.last().authorization != want {
		t.Error("没有用新密钥取")
	}
	if again, _ := f.get(blueHandle); again != second || ep.count() != 2 {
		t.Error("新的那一条没有被缓存")
	}
	// 密钥没变、只是文件被重写（修改时间变了）：缓存的令牌照用。
	write(t, f.path, fileOf(entryJSON(blueHandle, ep.URL, blueClient, "another-secret", "v1"),
		entryJSON(greenHandle, ep.URL, greenClient, greenSecret, "v1")), 0o600)
	if again, _ := f.get(blueHandle); again != second || ep.count() != 2 {
		t.Error("文件重写但内容没变，缓存被丢了")
	}
	// 摘要不是密钥，但没有理由写出去：日志、错误里没有它的任何常见写法。
	sum := sha256.Sum256([]byte("another-secret"))
	for _, form := range []string{hex.EncodeToString(sum[:]), base64.StdEncoding.EncodeToString(sum[:]), base64.RawURLEncoding.EncodeToString(sum[:]), "another-secret"} {
		if strings.Contains(f.logs.String(), form) {
			t.Errorf("日志里有密钥或它的摘要：%s", form)
		}
	}
	ep.set(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(500) })
	write(t, f.path, fileOf(entryJSON(blueHandle, ep.URL, blueClient, "third-secret", "v1")), 0o600)
	_, err = f.get(blueHandle)
	sum = sha256.Sum256([]byte("third-secret"))
	for _, form := range []string{hex.EncodeToString(sum[:]), base64.StdEncoding.EncodeToString(sum[:]), "third-secret"} {
		if strings.Contains(err.Error()+f.logs.String(), form) {
			t.Errorf("错误或日志里有密钥或它的摘要：%s", form)
		}
	}
}

func TestScopeIsOneOrMoreSpaceSeparatedTokens(t *testing.T) {
	for scope, ok := range map[string]bool{
		"":     true, // 空串等于没给
		"read": true, "parcels.read": true, "read write": true, "a b c": true, "https://x.example/a:b": true, "a,b": true,
		" read": false, "read ": false, "read  write": false, " ": false, "  ": false, "read\twrite": false, "read\nwrite": false,
		"read\x00": false, "read\x7f": false, "re\"ad": false, "re\\ad": false, "\"": false, "read wr\"ite": false, "é": false, "read write": false,
	} {
		if got := scope == "" || validScope(scope); got != ok {
			t.Errorf("scope %q：%v，期望 %v", scope, got, ok)
		}
		content := fileOf(entryJSON("b/a", "https://auth.example/t", "id", "secret", "v1", fmt.Sprintf(`"scope":%q`, scope)))
		path := filepath.Join(t.TempDir(), "c.json")
		write(t, path, content, 0o600)
		_, err := Load(Config{Path: path})
		if (err == nil) != ok {
			t.Errorf("文件里的 scope %q：%v，期望接受=%v", scope, err, ok)
		}
	}
}

// 令牌端点收到的 scope 与文件里写的一致：带空格的整串原样放进表单。
func TestTheEndpointReceivesTheScopeAsWritten(t *testing.T) {
	ep := newEndpoint(t)
	f := newFixture(t, fileOf(entryJSON(blueHandle, ep.URL, blueClient, blueSecret, "v1", `"scope":"parcels.read parcels.write"`),
		entryJSON(greenHandle, ep.URL, greenClient, greenSecret, "v1", `"scope":""`)), 0, nil)
	if _, err := f.get(blueHandle); err != nil {
		t.Fatal(err)
	}
	if got := ep.last().form["scope"]; len(got) != 1 || got[0] != "parcels.read parcels.write" {
		t.Errorf("令牌端点收到的 scope：%q，正文 %q", got, ep.last().body)
	}
	if _, err := f.get(greenHandle); err != nil {
		t.Fatal(err)
	}
	if _, has := ep.last().form["scope"]; has {
		t.Errorf("空 scope 不该发：%q", ep.last().body)
	}
}

func TestFileMustBePrivateAndWellFormed(t *testing.T) {
	ep := newEndpoint(t)
	good := fileOf(entryJSON("b/a", ep.URL, "id", "secret-value", "v1"))
	load := func(content string, mode os.FileMode, reserved func(string) bool) error {
		path := filepath.Join(t.TempDir(), "c.json")
		write(t, path, content, mode)
		_, err := Load(Config{Path: path, Reserved: reserved})
		return err
	}
	for _, mode := range []os.FileMode{0o640, 0o604, 0o644, 0o660, 0o666} {
		if err := load(good, mode, nil); err == nil || !strings.Contains(err.Error(), "readable by others") {
			t.Errorf("权限 %04o：%v", mode, err)
		}
	}
	for _, mode := range []os.FileMode{0o600, 0o400} {
		if err := load(good, mode, nil); err != nil {
			t.Errorf("权限 %04o：%v", mode, err)
		}
	}
	const secret = "never-shown-secret"
	e := func(mutate string) string { // 一条记录，其中一个字段被换掉
		return `{"b/a":{` + mutate + `}}`
	}
	ok := `"token_endpoint":"https://auth.example/token","client_id":"id","client_secret":"` + secret + `","key_version":"v1"`
	for name, content := range map[string]string{
		"不是 JSON":            secret + ` not json`,
		"空文件":                ``,
		"顶层是数组":              `[` + secret + `]`,
		"值是字符串":              `{"b/a":"` + secret + `"}`,
		"值是 null":            `{"b/a":null}`,
		"没有 token_endpoint":  e(`"client_id":"id","client_secret":"` + secret + `","key_version":"v1"`),
		"没有 client_id":       e(`"token_endpoint":"https://a.example/t","client_secret":"` + secret + `","key_version":"v1"`),
		"没有 client_secret":   e(`"token_endpoint":"https://a.example/t","client_id":"id","key_version":"v1"`),
		"没有 key_version":     e(`"token_endpoint":"https://a.example/t","client_id":"id","client_secret":"` + secret + `"`),
		"key_version 为空":     e(`"token_endpoint":"https://a.example/t","client_id":"id","client_secret":"` + secret + `","key_version":""`),
		"client_id 为空":       e(`"token_endpoint":"https://a.example/t","client_id":"","client_secret":"` + secret + `","key_version":"v1"`),
		"client_secret 为空":   e(`"token_endpoint":"https://a.example/t","client_id":"id","client_secret":"","key_version":"v1"`),
		"密钥里有空格":             e(`"token_endpoint":"https://a.example/t","client_id":"id","client_secret":"` + secret + ` x","key_version":"v1"`),
		"密钥里有换行":             e(`"token_endpoint":"https://a.example/t","client_id":"id","client_secret":"` + secret + `\n","key_version":"v1"`),
		"密钥里有非 ASCII":        e(`"token_endpoint":"https://a.example/t","client_id":"id","client_secret":"` + secret + `é","key_version":"v1"`),
		"client_id 里有空格":     e(`"token_endpoint":"https://a.example/t","client_id":"i d","client_secret":"` + secret + `","key_version":"v1"`),
		"key_version 里有空格":   e(`"token_endpoint":"https://a.example/t","client_id":"id","client_secret":"` + secret + `","key_version":"v 1"`),
		"scope 里有控制字符":       e(ok + `,"scope":"a\tb"`),
		"audience 里有非 ASCII": e(ok + `,"audience":"é"`),
		"密钥不是字符串":            e(`"token_endpoint":"https://a.example/t","client_id":"id","client_secret":` + secret[:0] + `7,"key_version":"v1"`),
		"有不认识的字段":            e(ok + `,"client_secret_file":"/x"`),
		"空句柄":                `{"":{` + ok + `}}`,
		"同一个句柄写了两次":          `{"b/a":{` + ok + `},"b/a":{` + ok + `}}`,
		"文件后面还有内容":           `{"b/a":{` + ok + `}} {}`,
		"对象没有写完":             `{"b/a":{` + ok + `}`,
	} {
		err := load(content, 0o600, nil)
		if err == nil {
			t.Errorf("%s：被接受了", name)
			continue
		}
		if strings.Contains(err.Error(), secret) {
			t.Errorf("%s：错误信息带出了文件内容：%v", name, err)
		}
	}
	if _, err := Load(Config{Path: filepath.Join(t.TempDir(), "missing.json")}); err == nil {
		t.Error("不存在的文件被接受了")
	}
	// 一个句柄只能在一个凭证来源里。
	taken := func(handle string) bool { return handle == "b/a" }
	if err := load(good, 0o600, taken); err == nil || !strings.Contains(err.Error(), "one source only") {
		t.Errorf("被别的来源占着的句柄：%v", err)
	}
	// 一份没有条目的文件读得进来，只是谁的凭证都没有。
	if err := load(`{}`, 0o600, nil); err != nil {
		t.Error(err)
	}
}

func TestTokenEndpointMustBeHTTPSOrLoopbackHTTP(t *testing.T) {
	accepted := []string{
		"https://auth.example/oauth/token", "https://auth.example:8443/t", "https://10.0.0.1/t", "https://localhost/t",
		"http://127.0.0.1:9/oauth/token", "http://127.1.2.3/t", "http://[::1]:9/t", "https://[::1]/t",
	}
	rejected := map[string]string{
		"http://auth.example/t":          "https",
		"http://localhost/t":             "https",
		"http://localhost.example/t":     "https",
		"http://10.0.0.1/t":              "https",
		"http://128.0.0.1/t":             "https",
		"http://0.0.0.0/t":               "https",
		"http://[::ffff:127.0.0.1]/t":    "https",
		"http://[::2]/t":                 "https",
		"http://2130706433/t":            "https",
		"ftp://127.0.0.1/t":              "https",
		"https://user@auth.example/t":    "user information",
		"https://user:pw@auth.example/t": "user information",
		"http://user@127.0.0.1/t":        "user information",
		"https://auth.example/t?x=1":     "query",
		"https://auth.example/t?":        "query",
		"https://auth.example/t#frag":    "fragment",
		"https://auth.example/t#":        "fragment",
		"https://":                       "host",
		"/oauth/token":                   "host",
		"auth.example/t":                 "host",
		"":                               "visible",
		"https://auth.example/ t":        "visible",
	}
	for _, endpoint := range accepted {
		if err := checkEndpoint(endpoint); err != nil {
			t.Errorf("%s：%v", endpoint, err)
		}
	}
	for endpoint, says := range rejected {
		err := checkEndpoint(endpoint)
		if err == nil || !strings.Contains(err.Error(), says) {
			t.Errorf("%q：%v，期望提到 %q", endpoint, err, says)
		} else if strings.Contains(err.Error(), "pw@") || strings.Contains(err.Error(), "user") && !strings.Contains(says, "user") {
			t.Errorf("%q：错误信息里有地址的内容：%v", endpoint, err)
		}
	}
	// 同样的规矩在文件里：不合要求，整份不要。
	path := filepath.Join(t.TempDir(), "c.json")
	write(t, path, fileOf(entryJSON("b/a", "http://auth.example/t", "id", "secret", "v1")), 0o600)
	if _, err := Load(Config{Path: path}); err == nil {
		t.Error("非回环的 http 端点被接受了")
	}
}

func TestReplacedFiles(t *testing.T) {
	ep := newEndpoint(t)
	f := newFixture(t, two(ep.URL), 0, nil)
	first, _ := f.get(blueHandle)
	reads := func(msg string) int { return strings.Count(f.logs.String(), `"msg":"`+msg) }

	// 一份写坏的：继续用上一份，记一条不含秘密的错误；它再被换掉之前不再读也不再记。
	write(t, f.path, `{"`+blueHandle+`":{"token_endpoint":"https://a.example/t","client_id":"id","client_secret":"leaky-new-secret","key_version":""}}`, 0o600)
	for range 3 {
		if got, err := f.get(blueHandle); err != nil || got != first {
			t.Fatalf("%q %v", got, err)
		}
	}
	if reads("oauth clients file did not load") != 1 || strings.Contains(f.logs.String(), "leaky-new-secret") {
		t.Errorf("%s", f.logs.String())
	}
	// 权限不对的：同样继续用上一份。
	write(t, f.path, two(ep.URL), 0o644)
	if got, _ := f.get(blueHandle); got != first || reads("oauth clients file did not load") != 2 || !strings.Contains(f.logs.String(), "readable by others") {
		t.Errorf("%q %s", got, f.logs.String())
	}
	// 非回环的 http：继续用上一份。
	write(t, f.path, fileOf(entryJSON(blueHandle, "http://auth.example/t", blueClient, blueSecret, "v2")), 0o600)
	if got, _ := f.get(blueHandle); got != first || reads("oauth clients file did not load") != 3 {
		t.Errorf("%q", got)
	}
	// 文件不见了：继续用上一份，记一次。
	if err := os.Remove(f.path); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if got, _ := f.get(blueHandle); got != first {
			t.Fatalf("%q", got)
		}
	}
	if reads("oauth clients file cannot be seen") != 1 {
		t.Errorf("%s", f.logs.String())
	}
	// 好的换上来：用新的。
	write(t, f.path, fileOf(entryJSON(blueHandle, ep.URL, blueClient, blueSecret, "v2")), 0o600)
	second, err := f.get(blueHandle)
	if err != nil || second == first || reads("oauth clients file loaded again") != 1 {
		t.Fatalf("%q %v", second, err)
	}
	// 新文件把一个句柄写进了别的来源已经占着的名下：整份不要。
	taken := false
	g := newFixture(t, two(ep.URL), 0, func(h string) bool { return taken && h == greenHandle })
	taken = true
	write(t, g.path, fileOf(entryJSON(blueHandle, ep.URL, blueClient, blueSecret, "v9"), entryJSON(greenHandle, ep.URL, greenClient, greenSecret, "v1")), 0o600)
	g.get(blueHandle)
	if ep.count() != 3 || !strings.Contains(g.logs.String(), "one source only") {
		t.Errorf("%d %s", ep.count(), g.logs.String())
	}
	noSecrets(t, f.logs.String()+g.logs.String(), "重读")
}

func TestHolds(t *testing.T) {
	ep := newEndpoint(t)
	f := newFixture(t, two(ep.URL), 0, nil)
	if !f.c.Holds(blueHandle) || f.c.Holds("other/handle") || f.c.Len() != 2 {
		t.Fatal("Holds / Len")
	}
}

func TestNeitherLogsNorErrorsHoldSecrets(t *testing.T) {
	ep := newEndpoint(t)
	f := newFixture(t, two(ep.URL), 0, nil)
	var seen []string
	collect := func(handle string) {
		got, err := f.get(handle)
		if err != nil {
			seen = append(seen, err.Error())
		}
		_ = got
	}
	collect(blueHandle)
	collect("gatekeeper:unknown/account-x")
	ep.set(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(503)
		fmt.Fprint(w, `{"client_secret":"`+blueSecret+`","access_token":"`+bodySecret+`","Authorization":"Basic xyz"}`)
	})
	f.clock.Advance(2 * time.Hour)
	collect(blueHandle)
	got, _ := f.c.AuthorizationHeader(context.Background(), binding, "account-green")
	if fmt.Sprintf("%v %+v %#v %s", got, got, got, got) != strings.Repeat("[REDACTED] ", 3)+"[REDACTED]" {
		t.Errorf("令牌被打印出来了：%v", got)
	}
	text := strings.Join(seen, "\n") + f.logs.String()
	basic := base64.StdEncoding.EncodeToString([]byte(blueClient + ":" + blueSecret))
	for _, secret := range []string{blueSecret, greenSecret, bodySecret, tokenPattern + "1", basic, "Basic xyz"} {
		if strings.Contains(text, secret) {
			t.Errorf("输出里有 %q：%s", secret, text)
		}
	}
	// 每次取令牌记一行：句柄、类别、用时、成功时的 expires_in。
	for _, want := range []string{`"msg":"oauth token fetched"`, `"handle":"` + blueHandle + `"`, `"result":"ok"`, `"elapsed_ms":`, `"expires_in":3600`,
		`"msg":"oauth token not fetched"`, `"result":"status 503"`} {
		if !strings.Contains(f.logs.String(), want) {
			t.Errorf("日志里没有 %s：%s", want, f.logs.String())
		}
	}
	if strings.Count(f.logs.String(), "oauth token") != 3 { // 成功一次、失败一次，另一条是 green 的成功
		t.Errorf("日志行数：%s", f.logs.String())
	}
}

func TestEveryHeaderValueIsBearerAndAnAccountCanBeAskedForUnheld(t *testing.T) {
	ep := newEndpoint(t)
	f := newFixture(t, two(ep.URL), 0, nil)
	if _, err := f.get("gatekeeper:other/account-blue"); !errors.Is(err, ports.ErrCredentialNotHeld) || ep.count() != 0 {
		t.Fatalf("%v %d", err, ep.count())
	}
}

// 撤销：判定先看撤销再取凭证（application.Service），被撤销的账户走不到凭证来源。缓存里有它的
// 令牌也不交出，令牌端点不被问；恢复之后照常。凭证来源和撤销表之间没有耦合。
func TestARevokedAccountGetsNoCachedToken(t *testing.T) {
	ep := newEndpoint(t)
	f := newFixture(t, two(ep.URL), 0, nil)
	revocations := &revocationTable{}
	policy := domain.Policy{Version: "p", Operations: []domain.Operation{{
		ProviderID: "mockcarrier", OperationID: "tracking.get", Environment: "TEST", Method: "GET",
		PathPrefix: "/providers/mockcarrier/v1/tracking", CredentialBindingRef: binding,
		AllowedTenants: []string{"tenant-blue"}, AllowedServiceIDs: []string{"parcel-service"},
		AccountsByTenant: map[string][]string{"tenant-blue": {"account-blue"}},
	}}}
	service := application.New(policy, f.c, revocations)
	in := application.Input{Subject: "parcel-service", Tenant: "tenant-blue", TokenEnvironment: "TEST", RouteID: "r",
		ProviderID: "mockcarrier", OperationID: "tracking.get", Environment: "TEST", Method: "GET", Path: "/providers/mockcarrier/v1/tracking/T-1"}

	out, token, err := service.Authorize(context.Background(), in)
	if err != nil || !out.Allowed || token.Reveal() != "Bearer "+tokenPattern+"1" {
		t.Fatalf("%+v %v", out, err)
	}
	revocations.set(true)
	out, token, err = service.Authorize(context.Background(), in)
	if err != nil || out.Allowed || out.Reason != application.ReasonAccountRevoked || !token.IsZero() {
		t.Fatalf("被撤销的账户：%+v %v", out, err)
	}
	if ep.count() != 1 {
		t.Fatalf("令牌端点被问了 %d 次", ep.count())
	}
	revocations.set(false)
	out, token, err = service.Authorize(context.Background(), in)
	if err != nil || !out.Allowed || token.Reveal() != "Bearer "+tokenPattern+"1" || ep.count() != 1 {
		t.Fatalf("恢复之后：%+v %v %d", out, err, ep.count())
	}
}

type revocationTable struct {
	mu      sync.Mutex
	revoked bool
}

func (r *revocationTable) set(v bool) { r.mu.Lock(); r.revoked = v; r.mu.Unlock() }

func (r *revocationTable) State(context.Context, string) (bool, uint64, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.revoked, 1, nil
}

func (r *revocationTable) Epoch(context.Context) (uint64, error) { return 1, nil }

func TestExpiresInIsClamped(t *testing.T) {
	ep := newEndpoint(t)
	ep.setExpiresIn("9223372036854775807")
	f := newFixture(t, two(ep.URL), 0, nil)
	first, err := f.get(blueHandle)
	if err != nil {
		t.Fatal(err)
	}
	if again, _ := f.get(blueHandle); again != first || ep.count() != 1 {
		t.Fatal("过大的 expires_in 算出了溢出的寿命")
	}
}

// 两个账户填了同一个客户端、同一个端点、同样的 scope、audience 和密钥版本：缓存仍然按账户隔离，
// 键里有句柄。否则一个账户的令牌会被另一个账户拿走。
func TestAccountsThatShareAClientStillGetTokensOfTheirOwn(t *testing.T) {
	ep := newEndpoint(t)
	f := newFixture(t, fileOf(entryJSON(blueHandle, ep.URL, "shared-client", "shared-secret", "v1", `"scope":"s"`),
		entryJSON(greenHandle, ep.URL, "shared-client", "shared-secret", "v1", `"scope":"s"`)), 0, nil)
	blue, _ := f.get(blueHandle)
	green, _ := f.get(greenHandle)
	if blue == "" || green == "" || blue == green || ep.count() != 2 {
		t.Fatalf("%q %q %d", blue, green, ep.count())
	}
	if again, _ := f.get(blueHandle); again != blue {
		t.Fatal("蓝账户拿到了别的令牌")
	}
	if again, _ := f.get(greenHandle); again != green || ep.count() != 2 {
		t.Fatal("绿账户拿到了别的令牌")
	}
}
