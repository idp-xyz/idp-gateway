package sfopenapi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
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
)

// 测试里的值都是编出来的，不是真的凭证。
const (
	binding     = "gatekeeper:sfintl-test"
	blueHandle  = binding + "/account-blue"
	greenHandle = binding + "/account-green"
	blueAppKey  = "appkey-blue-1111"
	greenAppKey = "appkey-green-2222"
	// blueSecret 里有查询串里要转义的字符：+ / = &。
	blueSecret  = "a+b/c=d&e-blue-secret"
	greenSecret = "app-secret-green-77c1"
	// bodyMarker 是一个替身会放进应答正文里的字符串：它出现在错误或日志里，就是应答正文被带了出来。
	bodyMarker  = "BODY-MARKER-that-a-carrier-might-echo"
	tokenPrefix = "sf-access-token-"
	tokenPath   = "/openapi/api/token"
)

var (
	blueAES  = aesKey("blue")
	greenAES = aesKey("green")
)

// aesKey 由一个种子算出一个格式合法的 encoding_aes_key：32 字节做标准 base64，去掉末尾的 "="。
func aesKey(seed string) string {
	sum := sha256.Sum256([]byte("made-up key for tests: " + seed))
	return base64.StdEncoding.EncodeToString(sum[:])[:aesKeyChars]
}

// fakeClock 是可以拨的时钟。
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func newClock() *fakeClock { return &fakeClock{now: time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)} }

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

// app 是文件里一个句柄下的那一条。
type app struct {
	Endpoint, AppKey, AppSecret, AESKey, KeyVersion string
}

func blueApp(endpoint string) app {
	return app{endpoint, blueAppKey, blueSecret, blueAES, "v1"}
}

func greenApp(endpoint string) app {
	return app{endpoint, greenAppKey, greenSecret, greenAES, "v1"}
}

func entryJSON(handle string, a app) string {
	body, err := json.Marshal(map[string]string{"token_endpoint": a.Endpoint, "app_key": a.AppKey, "app_secret": a.AppSecret,
		"encoding_aes_key": a.AESKey, "key_version": a.KeyVersion})
	if err != nil {
		panic(err)
	}
	name, _ := json.Marshal(handle)
	return string(name) + ":" + string(body)
}

func fileOf(entries ...string) string { return "{" + strings.Join(entries, ",") + "}" }

// two 是两个账户各一个应用，令牌端点都是 endpoint。
func two(endpoint string) string {
	return fileOf(entryJSON(blueHandle, blueApp(endpoint)), entryJSON(greenHandle, greenApp(endpoint)))
}

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

// tokenEndpoint 是替身令牌端点。默认的应答是承运商沙箱的样子；每个应用各发各的令牌，记下收到的请求。
type tokenEndpoint struct {
	*httptest.Server

	mu       sync.Mutex
	requests []received
	issued   int
	// handler 不为 nil 时它替默认的应答作答（在记下请求之后）。
	handler  func(w http.ResponseWriter, r *http.Request)
	expireIn string // 写进应答里的 expireIn（JSON 原文）
}

type received struct {
	method, path, rawQuery, accept, body string
	query                                url.Values
	header                               http.Header
}

// answer 是承运商成功时的应答信封。
func answer(expireIn, token string) string {
	return fmt.Sprintf(`{"apiResultCode":0,"apiErrorMsg":null,"apiResultData":{"expireIn":%s,"accessToken":%q},"apiTimestamp":1763611200000}`,
		expireIn, token)
}

func newEndpoint(t *testing.T) *tokenEndpoint {
	t.Helper()
	e := &tokenEndpoint{expireIn: "7200"}
	e.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		e.mu.Lock()
		e.requests = append(e.requests, received{r.Method, r.URL.Path, r.URL.RawQuery, r.Header.Get("Accept"), string(raw), r.URL.Query(), r.Header.Clone()})
		e.issued++
		n, handler, expires := e.issued, e.handler, e.expireIn
		e.mu.Unlock()
		if handler != nil {
			handler(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, answer(expires, fmt.Sprintf("%s%s-%d", tokenPrefix, r.URL.Query().Get("appKey"), n)))
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

func (e *tokenEndpoint) setExpireIn(v string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.expireIn = v
}

func (e *tokenEndpoint) last() received {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.requests[len(e.requests)-1]
}

func (e *tokenEndpoint) forget() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.requests = nil
}

// url 是令牌端点的地址，文件里写的就是它。
func (e *tokenEndpoint) tokenURL() string { return e.URL + tokenPath }

type fixture struct {
	t     *testing.T
	path  string
	clock *fakeClock
	logs  *lockedBuffer
	c     *Client
}

// newFixture 把 content 写成应用文件并 Load。取令牌的超时默认放宽到 5 秒，测超时的用例自己再改小。
func newFixture(t *testing.T, content string, options ...func(*Config)) *fixture {
	t.Helper()
	f := &fixture{t: t, path: filepath.Join(t.TempDir(), "sf-openapi-apps.json"), clock: newClock(), logs: &lockedBuffer{}}
	write(t, f.path, content, 0o600)
	cfg := Config{Path: f.path, Timeout: 5 * time.Second, Now: f.clock.Now, Logger: slog.New(slog.NewJSONHandler(f.logs, nil))}
	for _, option := range options {
		option(&cfg)
	}
	c, err := Load(cfg)
	if err != nil {
		t.Fatal(err)
	}
	f.c = c
	return f
}

func withTimeout(d time.Duration) func(*Config) { return func(c *Config) { c.Timeout = d } }

func withReserved(reserved func(string) bool) func(*Config) {
	return func(c *Config) { c.Reserved = reserved }
}

func (f *fixture) get(handle string) (string, error) {
	f.t.Helper()
	b, a, _ := strings.Cut(handle, "/")
	s, err := f.c.AuthorizationHeader(context.Background(), b, a)
	return s.Reveal(), err
}

// lines 数日志里 msg 以 prefix 开头的行。
func (f *fixture) lines(prefix string) int {
	return strings.Count(f.logs.String(), `"msg":"`+prefix)
}

// noSecrets 查 text（错误信息、日志）里没有：应用密钥、AES 密钥、访问令牌、应答正文里的标记、请求的地址和查询串。
// also 是这一次还要查的别的字符串，例如令牌端点的地址。
func noSecrets(t *testing.T, text, what string, also ...string) {
	t.Helper()
	forbidden := []string{blueSecret, url.QueryEscape(blueSecret), greenSecret, blueAES, greenAES, bodyMarker, tokenPrefix, "leaked-",
		"appSecret", "appKey=", "Sf-OpenApi", tokenPath}
	for _, secret := range append(forbidden, also...) {
		if strings.Contains(text, secret) {
			t.Errorf("%s：输出里有 %q：%s", what, secret, text)
		}
	}
}

// waitFor 等 condition 成立，最多 5 秒。
func waitFor(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatal("等不到")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// failed 是取不到时错误信息的固定样子。
func failed(handle, category string) string {
	return "sf openapi token for " + handle + " not obtained: " + category
}
