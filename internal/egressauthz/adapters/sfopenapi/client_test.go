package sfopenapi

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"go.idp.xyz/idp-gateway/internal/egressauthz/ports"
)

// releasedShape 是交出的认证头的样子：Sf-OpenApi appKey;令牌;AES 密钥，三段里没有分号和空白。
var releasedShape = regexp.MustCompile(`^Sf-OpenApi [!-:<-~]+;[!-:<-~]+;[A-Za-z0-9+/]{43}$`)

func TestFetchesWithAGetAndTheTwoQueryParameters(t *testing.T) {
	ep := newEndpoint(t)
	f := newFixture(t, two(ep.tokenURL()))

	got, err := f.get(blueHandle)
	want := "Sf-OpenApi " + blueAppKey + ";" + tokenPrefix + blueAppKey + "-1;" + blueAES
	if err != nil || got != want {
		t.Fatalf("%q %v", got, err)
	}
	if !releasedShape.MatchString(got) {
		t.Errorf("交出的值不是 Sf-OpenApi appKey;令牌;AES密钥 的样子：%q", got)
	}
	r := ep.last()
	if r.method != http.MethodGet || r.path != tokenPath || r.accept != "application/json" || r.body != "" {
		t.Errorf("%s %s Accept=%q 正文 %q", r.method, r.path, r.accept, r.body)
	}
	// 只有这两个参数，值是文件里写的，转义的字符照原样还原（应用密钥是 a+b/c=d&e-blue-secret）。
	if len(r.query) != 2 || r.query.Get("appKey") != blueAppKey || r.query.Get("appSecret") != blueSecret {
		t.Errorf("查询参数 %q", r.query)
	}
	if r.rawQuery != "appKey=appkey-blue-1111&appSecret=a%2Bb%2Fc%3Dd%26e-blue-secret" {
		t.Errorf("查询串 %q", r.rawQuery)
	}
	for _, name := range []string{"Authorization", "Cookie", "Content-Type"} {
		if r.header.Get(name) != "" {
			t.Errorf("不该带 %s 头", name)
		}
	}

	// 另一个账户：自己的 appKey、自己的密钥，和自己的 AES 密钥。
	green, err := f.get(greenHandle)
	if err != nil || green != "Sf-OpenApi "+greenAppKey+";"+tokenPrefix+greenAppKey+"-2;"+greenAES {
		t.Fatalf("%q %v", green, err)
	}
	if q := ep.last().query; len(q) != 2 || q.Get("appKey") != greenAppKey || q.Get("appSecret") != greenSecret {
		t.Errorf("绿账户的查询参数 %q", q)
	}
}

func TestTheReleasedValueIsRedactedEverywhere(t *testing.T) {
	ep := newEndpoint(t)
	f := newFixture(t, two(ep.tokenURL()))
	got, err := f.c.AuthorizationHeader(context.Background(), binding, "account-blue")
	if err != nil || got.Reveal() != "Sf-OpenApi "+blueAppKey+";"+tokenPrefix+blueAppKey+"-1;"+blueAES {
		t.Fatalf("%v", err)
	}
	for name, text := range map[string]string{
		"Sprint": fmt.Sprint(got), "%v": fmt.Sprintf("%v", got), "%+v": fmt.Sprintf("%+v", got), "%#v": fmt.Sprintf("%#v", got),
		"%s": fmt.Sprintf("%s", got), "Println": strings.TrimSpace(fmt.Sprintln(got)),
	} {
		if text != "[REDACTED]" {
			t.Errorf("%s：%q", name, text)
		}
	}
	encoded, err := json.Marshal(got)
	if err != nil || string(encoded) != `"[REDACTED]"` {
		t.Errorf("JSON：%s %v", encoded, err)
	}
	encoded, err = json.Marshal(map[string]any{"authorization": got, "list": []ports.Secret{got}})
	if err != nil || strings.Contains(string(encoded), blueAES) || strings.Contains(string(encoded), tokenPrefix) || !strings.Contains(string(encoded), "[REDACTED]") {
		t.Errorf("JSON：%s %v", encoded, err)
	}
	var out lockedBuffer
	logger := slog.New(slog.NewJSONHandler(&out, nil))
	logger.Info("released", "authorization", got, slog.Any("again", got), slog.Group("g", "authorization", got))
	text := out.String()
	if strings.Count(text, "[REDACTED]") != 3 {
		t.Errorf("slog：%s", text)
	}
	for _, secret := range []string{blueAES, blueAppKey, tokenPrefix, "Sf-OpenApi"} {
		if strings.Contains(text+fmt.Sprintf("%v%+v%#v", got, got, got), secret) {
			t.Errorf("输出里有 %q", secret)
		}
	}
	// slog 的文本处理器也一样。
	var plain lockedBuffer
	slog.New(slog.NewTextHandler(&plain, nil)).Info("released", "authorization", got)
	if strings.Contains(plain.String(), blueAES) || strings.Contains(plain.String(), tokenPrefix) {
		t.Errorf("slog 文本：%s", plain.String())
	}
}

func TestTheTokenIsCachedAndAccountsAreNotCrossed(t *testing.T) {
	ep := newEndpoint(t)
	f := newFixture(t, two(ep.tokenURL()))
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
	// 各用各的：蓝的认证头里是蓝的 appKey、令牌、AES 密钥，没有绿的任何一样；反过来也一样。
	for _, mixed := range []string{greenAppKey, greenAES, tokenPrefix + greenAppKey} {
		if strings.Contains(blue, mixed) {
			t.Errorf("蓝账户的认证头里有绿账户的 %q", mixed)
		}
	}
	for _, mixed := range []string{blueAppKey, blueAES, tokenPrefix + blueAppKey} {
		if strings.Contains(green, mixed) {
			t.Errorf("绿账户的认证头里有蓝账户的 %q", mixed)
		}
	}
	ep.mu.Lock()
	defer ep.mu.Unlock()
	if ep.requests[0].query.Get("appKey") == ep.requests[1].query.Get("appKey") ||
		ep.requests[0].query.Get("appSecret") == ep.requests[1].query.Get("appSecret") {
		t.Error("两个账户用了同一个 appKey 或应用密钥")
	}
}

func TestConcurrentRequestsAskTheEndpointOnce(t *testing.T) {
	ep := newEndpoint(t)
	release := make(chan struct{})
	ep.set(func(w http.ResponseWriter, r *http.Request) {
		<-release
		fmt.Fprint(w, answer("7200", "one-token"))
	})
	f := newFixture(t, two(ep.tokenURL()))

	const n = 50
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
		if got := <-results; got != "Sf-OpenApi "+blueAppKey+";one-token;"+blueAES {
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
	f := newFixture(t, two(ep.tokenURL()))

	const n = 30
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
		if r.URL.Query().Get("appKey") == blueAppKey {
			<-release
		}
		fmt.Fprint(w, answer("7200", "t-"+r.URL.Query().Get("appKey")))
	})
	f := newFixture(t, two(ep.tokenURL()))
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

func TestRefreshLead(t *testing.T) {
	for lifetime, want := range map[time.Duration]time.Duration{
		7200 * time.Second: 600 * time.Second, // 承运商的令牌寿命 2 小时：提前 10 分钟
		6000 * time.Second: 600 * time.Second,
		5999 * time.Second: 599*time.Second + 900*time.Millisecond,
		3600 * time.Second: 360 * time.Second,
		100 * time.Second:  10 * time.Second,
		5 * time.Second:    500 * time.Millisecond,
		1 * time.Second:    100 * time.Millisecond,
		0:                  0,
	} {
		if got := RefreshLead(lifetime); got != want {
			t.Errorf("寿命 %v：提前 %v，期望 %v", lifetime, got, want)
		}
	}
	if MaxRefreshLead != 10*time.Minute || DefaultTimeout != 800*time.Millisecond || Scheme != "Sf-OpenApi" {
		t.Error("导出的常量不对")
	}
}

func TestTheTokenIsRenewedBeforeItExpires(t *testing.T) {
	ep := newEndpoint(t)
	f := newFixture(t, two(ep.tokenURL()))
	first, _ := f.get(blueHandle)

	// 寿命 7200 秒，提前量 600 秒：剩 601 秒还交出，剩 600 秒（不多于提前量）就换。
	f.clock.Advance(6599 * time.Second)
	if again, _ := f.get(blueHandle); again != first || ep.count() != 1 {
		t.Fatalf("还没到时候就换了：%d", ep.count())
	}
	f.clock.Advance(time.Second) // 6600：剩下正好 600 秒
	second, err := f.get(blueHandle)
	if err != nil || second == first || ep.count() != 2 {
		t.Fatalf("剩下正好是提前量时该换了：%q %v %d", second, err, ep.count())
	}
	// 换了之后寿命从头算：+6601 秒（距上一次换新 1 秒）当然不用再换。
	f.clock.Advance(time.Second)
	if again, _ := f.get(blueHandle); again != second || ep.count() != 2 {
		t.Fatal("刚换的令牌又被换了")
	}

	// 另一个账户：+6601 秒时（寿命 7200，剩 599 秒）取。
	g := newFixture(t, two(ep.tokenURL()))
	before := ep.count()
	one, _ := g.get(greenHandle)
	g.clock.Advance(6601 * time.Second)
	if again, err := g.get(greenHandle); err != nil || again == one || ep.count() != before+2 {
		t.Fatalf("剩 599 秒时该换了：%q %v", again, err)
	}
}

func TestARenewedTokenKeepsTheCurrentAESKey(t *testing.T) {
	ep := newEndpoint(t)
	f := newFixture(t, two(ep.tokenURL()))
	f.get(blueHandle)
	f.clock.Advance(7000 * time.Second)
	got, err := f.get(blueHandle)
	if err != nil || !strings.HasSuffix(got, ";"+blueAES) || !strings.HasPrefix(got, "Sf-OpenApi "+blueAppKey+";"+tokenPrefix+blueAppKey+"-2;") {
		t.Fatalf("%q %v", got, err)
	}
}

func TestShortLivedTokensUseAShortLead(t *testing.T) {
	ep := newEndpoint(t)
	ep.setExpireIn("100") // 提前 10 秒
	f := newFixture(t, two(ep.tokenURL()))
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
	// 寿命长了，提前量也跟着长。
	ep.setExpireIn("7200")
	f.clock.Advance(100 * time.Second)
	third, _ := f.get(blueHandle)
	if ep.count() != 3 {
		t.Fatal(ep.count())
	}
	f.clock.Advance(6000 * time.Second) // 剩 1200 秒
	if again, _ := f.get(blueHandle); again != third {
		t.Fatal("剩 1200 秒就换了")
	}
}

func TestAnExpiredTokenIsNeverHandedOut(t *testing.T) {
	ep := newEndpoint(t)
	ep.setExpireIn("10")
	f := newFixture(t, two(ep.tokenURL()))
	first, _ := f.get(blueHandle)
	f.clock.Advance(time.Hour)
	second, err := f.get(blueHandle)
	if err != nil || second == first || ep.count() != 2 {
		t.Fatalf("%q %v %d", second, err, ep.count())
	}
}

func TestExpireInIsClamped(t *testing.T) {
	ep := newEndpoint(t)
	ep.setExpireIn("9223372036854775807")
	f := newFixture(t, two(ep.tokenURL()))
	first, err := f.get(blueHandle)
	if err != nil {
		t.Fatal(err)
	}
	if again, _ := f.get(blueHandle); again != first || ep.count() != 1 {
		t.Fatal("过大的 expireIn 算出了溢出的寿命")
	}
}

// 取失败时不拿上一枚顶上：上一枚还没到期、但已经进入该换新的时段，端点又坏了，请求拒绝；
// 端点恢复之后下一次就好，并且是一枚新的。
func TestNoStaleTokenWhenARefreshFails(t *testing.T) {
	ep := newEndpoint(t)
	f := newFixture(t, two(ep.tokenURL()))
	first, err := f.get(blueHandle)
	if err != nil {
		t.Fatal(err)
	}
	f.clock.Advance(3000 * time.Second)
	green, err := f.get(greenHandle) // 绿账户的令牌晚 3000 秒取
	if err != nil {
		t.Fatal(err)
	}
	ep.set(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusInternalServerError) })

	f.clock.Advance(3601 * time.Second) // 蓝的寿命 7200 秒，还剩 599 秒：没过期，但在提前量（600 秒）之内
	for i := range 3 {
		got, err := f.get(blueHandle)
		if err == nil || got != "" {
			t.Fatalf("第 %d 次：交出了 %q（%v）", i, got, err)
		}
		if err.Error() != failed(blueHandle, "status 500") {
			t.Errorf("%v", err)
		}
	}
	if ep.count() != 5 {
		t.Errorf("每次拒绝之前都该问一次令牌端点：%d", ep.count())
	}
	// 另一个账户的令牌没到该换的时候：蓝的失败不碍它。
	if got, err := f.get(greenHandle); err != nil || got != green || ep.count() != 5 {
		t.Fatalf("%q %v %d", got, err, ep.count())
	}
	// 端点仍然坏着，令牌也已经过期。
	f.clock.Advance(time.Hour)
	if got, err := f.get(blueHandle); err == nil || got != "" {
		t.Fatalf("过期之后：%q %v", got, err)
	}
	// 端点恢复。
	ep.set(nil)
	second, err := f.get(blueHandle)
	if err != nil || second == first || second == "" || !releasedShape.MatchString(second) {
		t.Fatalf("恢复之后：%q %v", second, err)
	}
	if again, _ := f.get(blueHandle); again != second {
		t.Error("恢复之后取到的令牌没有被缓存")
	}
}

func TestHoldsAndLen(t *testing.T) {
	ep := newEndpoint(t)
	f := newFixture(t, two(ep.tokenURL()))
	if !f.c.Holds(blueHandle) || f.c.Holds("other/handle") || f.c.Holds("") || f.c.Len() != 2 {
		t.Fatal("Holds / Len")
	}
	// Holds 不拿锁：文件重读的锁和缓存的锁都被占着，它照样答得出。别的凭证来源在重读时问它，
	// 各自不能拿着锁去等对方。
	f.c.mu.Lock()
	f.c.cmu.Lock()
	done := make(chan bool, 1)
	go func() { done <- f.c.Holds(greenHandle) }()
	select {
	case held := <-done:
		if !held {
			t.Error("Holds")
		}
	case <-time.After(2 * time.Second):
		t.Error("Holds 在等锁")
	}
	f.c.cmu.Unlock()
	f.c.mu.Unlock()
}

func TestUnknownHandlesAreNotHeld(t *testing.T) {
	ep := newEndpoint(t)
	f := newFixture(t, two(ep.tokenURL()))
	for _, handle := range []string{"gatekeeper:other/account-blue", binding + "/account-red", binding + "/", "/account-blue", ""} {
		got, err := f.get(handle)
		if !errors.Is(err, ports.ErrCredentialNotHeld) || got != "" {
			t.Errorf("%q：%q %v", handle, got, err)
		}
	}
	if ep.count() != 0 {
		t.Errorf("令牌端点被问了 %d 次", ep.count())
	}
}

func TestACallerThatGivesUpDoesNotFailTheOthers(t *testing.T) {
	ep := newEndpoint(t)
	release := make(chan struct{})
	ep.set(func(w http.ResponseWriter, r *http.Request) {
		<-release
		fmt.Fprint(w, answer("7200", "slow-token"))
	})
	f := newFixture(t, two(ep.tokenURL()))

	// 发起这次获取的请求自己走了。
	ctx, cancel := context.WithCancel(context.Background())
	leader := make(chan error, 1)
	go func() { _, err := f.c.AuthorizationHeader(ctx, binding, "account-blue"); leader <- err }()
	waitFor(t, func() bool { return ep.count() == 1 }) // 请求已经到了端点，端点还扣着不答
	waiter := make(chan string, 1)
	go func() { got, _ := f.get(blueHandle); waiter <- got }()
	time.Sleep(50 * time.Millisecond)
	begun := time.Now()
	cancel()
	select {
	case err := <-leader:
		if !errors.Is(err, context.Canceled) || time.Since(begun) > 2*time.Second {
			t.Fatalf("取消了的请求：%v %v", err, time.Since(begun))
		}
		if strings.Contains(err.Error(), blueSecret) || strings.Contains(err.Error(), "slow-token") {
			t.Errorf("%v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("取消了的请求没有及时返回：端点还没答它就该走了")
	}
	if ep.count() != 1 {
		t.Fatal(ep.count())
	}
	close(release)
	if got := <-waiter; got != "Sf-OpenApi "+blueAppKey+";slow-token;"+blueAES {
		t.Fatalf("另一个等着的请求：%q", got)
	}
	if ep.count() != 1 {
		t.Fatal(ep.count())
	}
	// 获取没有被发起者的取消打断：结果进了缓存。
	if again, _ := f.get(blueHandle); !strings.Contains(again, "slow-token") || ep.count() != 1 {
		t.Fatalf("%q %d", again, ep.count())
	}
}

func TestACallerWhoseContextIsAlreadyDoneStillStartsTheFetch(t *testing.T) {
	ep := newEndpoint(t)
	f := newFixture(t, two(ep.tokenURL()))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := f.c.AuthorizationHeader(ctx, binding, "account-blue"); err == nil {
		// 取消和结果同时就绪时选哪个不定：这里只要不 panic、不泄露即可。
		t.Log("答出来了")
	} else if !errors.Is(err, context.Canceled) && !strings.Contains(err.Error(), "not obtained") {
		t.Errorf("%v", err)
	}
	// 无论怎样，那一次获取在后台做完，下一个请求用它的结果。
	deadline := time.Now().Add(3 * time.Second)
	for ep.count() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got, err := f.get(blueHandle); err != nil || got == "" || ep.count() != 1 {
		t.Fatalf("%q %v %d", got, err, ep.count())
	}
}

func TestTheHTTPClientIgnoresTheProxyEnvironmentAndDoesNotFollowRedirects(t *testing.T) {
	// 回环地址本来就不走代理，所以靠环境变量测不出它；直接看传输层：Proxy 是 nil，
	// 不会去读 HTTP_PROXY 等环境变量。
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	t.Setenv("http_proxy", "http://127.0.0.1:1")
	t.Setenv("https_proxy", "http://127.0.0.1:1")
	t.Setenv("NO_PROXY", "")
	f := newFixture(t, two("https://carrier.example.test"+tokenPath))
	transport, ok := f.c.http.Transport.(*http.Transport)
	if !ok || transport.Proxy != nil {
		t.Fatalf("传输层 %#v", f.c.http.Transport)
	}
	if transport.TLSClientConfig == nil || transport.TLSClientConfig.MinVersion < tls.VersionTLS12 {
		t.Error("TLS 最低版本不是 1.2")
	}
	if f.c.http.CheckRedirect == nil {
		t.Error("没有设置不跟随重定向")
	}
	if f.c.http.Timeout != 5*time.Second {
		t.Errorf("超时 %v", f.c.http.Timeout)
	}
	// 零值的超时用默认值。
	path := f.path
	g, err := Load(Config{Path: path})
	if err != nil || g.http.Timeout != DefaultTimeout || g.timeout != DefaultTimeout {
		t.Errorf("%v", err)
	}
}

func TestAnHTTPSEndpoint(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, answer("60", "tls-token"))
	}))
	defer server.Close()
	f := newFixture(t, two(server.URL+tokenPath))
	f.c.http.Transport = server.Client().Transport // 信任测试服务器的证书
	if got, err := f.get(blueHandle); err != nil || got != "Sf-OpenApi "+blueAppKey+";tls-token;"+blueAES {
		t.Fatalf("%q %v", got, err)
	}
	// 不信任它的证书时取不到，也是取不到，不是别的样子；错误里没有 TLS 错误的原文，更没有地址。
	g := newFixture(t, two(server.URL+tokenPath))
	_, err := g.get(blueHandle)
	if err == nil || err.Error() != failed(blueHandle, "unreachable") {
		t.Fatalf("%v", err)
	}
	noSecrets(t, err.Error()+g.logs.String(), "不被信任的证书", server.URL, "x509")
}

// 缓存键里有：句柄、令牌端点、appKey、密钥版本、应用密钥的摘要。每一项变了，旧的令牌就不再用；
// 没变的那个账户的缓存留着。
func TestACachedTokenIsKeyedByEveryPartOfTheKey(t *testing.T) {
	ep := newEndpoint(t)
	other := newEndpoint(t)
	base := func(mutate func(*app)) string {
		blue := blueApp(ep.tokenURL())
		if mutate != nil {
			mutate(&blue)
		}
		return fileOf(entryJSON(blueHandle, blue), entryJSON(greenHandle, greenApp(ep.tokenURL())))
	}
	changes := map[string]func(*app){
		"令牌端点":                 func(a *app) { a.Endpoint = other.tokenURL() },
		"appKey":               func(a *app) { a.AppKey = "appkey-blue-2" },
		"key_version":          func(a *app) { a.KeyVersion = "v2" },
		"应用密钥（key_version 不变）": func(a *app) { a.AppSecret = "another-secret" },
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			ep.forget()
			other.forget()
			f := newFixture(t, base(nil))
			first, _ := f.get(blueHandle)
			green, _ := f.get(greenHandle)
			f.get(blueHandle)
			if ep.count() != 2 {
				t.Fatalf("文件没变，令牌端点被问了 %d 次", ep.count())
			}
			write(t, f.path, base(change), 0o600)
			second, err := f.get(blueHandle)
			// 换了端点时，新端点自己数自己的，发出的第一枚令牌可能和旧端点的某一枚同名：看是不是真的去问了新端点。
			if err != nil || ep.count()+other.count() != 3 || (name != "令牌端点" && second == first) {
				t.Fatalf("变了之后没有重新取：%q %v %d", second, err, ep.count()+other.count())
			}
			if name == "令牌端点" && other.count() != 1 {
				t.Errorf("新端点没有被问：%d", other.count())
			}
			if name == "应用密钥（key_version 不变）" && ep.last().query.Get("appSecret") != "another-secret" {
				t.Error("没有用新密钥取")
			}
			if again, _ := f.get(greenHandle); again != green {
				t.Error("没变的那个账户的缓存被丢掉了")
			}
			if again, _ := f.get(blueHandle); again != second {
				t.Error("新的那一条没有被缓存")
			}
			// 应用密钥的摘要不是密钥，但没有理由写出去。
			noSecrets(t, f.logs.String(), name, "another-secret")
		})
	}
}

// 应用密钥重写了但内容没变（修改时间变了）：缓存的令牌照用。
func TestRewritingTheSameFileKeepsTheCache(t *testing.T) {
	ep := newEndpoint(t)
	f := newFixture(t, two(ep.tokenURL()))
	first, _ := f.get(blueHandle)
	write(t, f.path, two(ep.tokenURL()), 0o600)
	if again, _ := f.get(blueHandle); again != first || ep.count() != 1 || f.lines("sf openapi apps file loaded again") != 1 {
		t.Fatalf("%q %d\n%s", again, ep.count(), f.logs.String())
	}
}

func TestReplacingTheKeyVersionFetchesAgain(t *testing.T) {
	ep := newEndpoint(t)
	f := newFixture(t, two(ep.tokenURL()))
	first, _ := f.get(blueHandle)
	blue := blueApp(ep.tokenURL())
	blue.KeyVersion = "v2"
	write(t, f.path, fileOf(entryJSON(blueHandle, blue), entryJSON(greenHandle, greenApp(ep.tokenURL()))), 0o600)
	second, err := f.get(blueHandle)
	if err != nil || second == first || ep.count() != 2 {
		t.Fatalf("%q %v %d", second, err, ep.count())
	}
	if again, _ := f.get(blueHandle); again != second || ep.count() != 2 {
		t.Error("新的那一条没有被缓存")
	}
}

// 只换 AES 密钥：它不在缓存键里，不需要新令牌，交出的认证头马上带新的密钥。
func TestChangingOnlyTheAESKeyChangesTheHeaderAtOnceWithoutAskingTheEndpoint(t *testing.T) {
	ep := newEndpoint(t)
	f := newFixture(t, two(ep.tokenURL()))
	first, _ := f.get(blueHandle)
	if !strings.HasSuffix(first, ";"+blueAES) {
		t.Fatal(first)
	}
	changed := blueApp(ep.tokenURL())
	changed.AESKey = aesKey("blue, rotated")
	write(t, f.path, fileOf(entryJSON(blueHandle, changed), entryJSON(greenHandle, greenApp(ep.tokenURL()))), 0o600)
	second, err := f.get(blueHandle)
	token := strings.Split(first, ";")[1]
	if err != nil || second != "Sf-OpenApi "+blueAppKey+";"+token+";"+changed.AESKey || ep.count() != 1 {
		t.Fatalf("%q %v %d", second, err, ep.count())
	}
	if strings.Contains(second, blueAES) {
		t.Error("还带着旧的 AES 密钥")
	}
	// 缓存没有被丢：下一次还是同一枚令牌。
	if again, _ := f.get(blueHandle); again != second || ep.count() != 1 {
		t.Fatal("换 AES 密钥之后缓存被丢了")
	}
}

func TestAnEntryRemovedFromTheFileIsNotHeldAndLeavesTheCache(t *testing.T) {
	ep := newEndpoint(t)
	f := newFixture(t, two(ep.tokenURL()))
	first, _ := f.get(greenHandle)
	f.get(blueHandle)
	write(t, f.path, fileOf(entryJSON(blueHandle, blueApp(ep.tokenURL()))), 0o600)
	if got, err := f.get(greenHandle); !errors.Is(err, ports.ErrCredentialNotHeld) || got != "" {
		t.Fatalf("%q %v", got, err)
	}
	if f.c.Holds(greenHandle) || !f.c.Holds(blueHandle) || f.c.Len() != 1 {
		t.Error("Holds / Len 没有跟着文件走")
	}
	f.c.cmu.Lock()
	slots := len(f.c.slots)
	f.c.cmu.Unlock()
	if slots != 1 {
		t.Errorf("缓存里还有 %d 条", slots)
	}
	// 换回来之后重新取，不会用到旧的。
	write(t, f.path, two(ep.tokenURL()), 0o600)
	again, _ := f.get(greenHandle)
	if again == first || ep.count() != 3 {
		t.Errorf("回来之后用了旧令牌：%q %d", again, ep.count())
	}
}

func TestReplacedFiles(t *testing.T) {
	ep := newEndpoint(t)
	f := newFixture(t, two(ep.tokenURL()))
	first, _ := f.get(blueHandle)

	// 一份写坏的：继续用上一份，记一条不含秘密的错误；它再被换掉之前不再读也不再记。
	broken := blueApp(ep.tokenURL())
	broken.AppSecret, broken.KeyVersion = "leaky-new-secret", ""
	write(t, f.path, fileOf(entryJSON(blueHandle, broken)), 0o600)
	for range 3 {
		if got, err := f.get(blueHandle); err != nil || got != first {
			t.Fatalf("%q %v", got, err)
		}
	}
	if f.lines("sf openapi apps file did not load") != 1 || strings.Contains(f.logs.String(), "leaky-new-secret") {
		t.Errorf("%s", f.logs.String())
	}
	if got, err := f.get(greenHandle); err != nil || got == "" {
		t.Fatalf("上一份里的另一个账户也该照常：%q %v", got, err)
	}
	// 权限不对的：同样继续用上一份。
	write(t, f.path, two(ep.tokenURL()), 0o644)
	if got, _ := f.get(blueHandle); got != first || f.lines("sf openapi apps file did not load") != 2 || !strings.Contains(f.logs.String(), "readable by others") {
		t.Errorf("%q %s", got, f.logs.String())
	}
	// 非回环、没有例外的 http：继续用上一份。
	write(t, f.path, fileOf(entryJSON(blueHandle, blueApp("http://carrier.example.test"+tokenPath))), 0o600)
	if got, _ := f.get(blueHandle); got != first || f.lines("sf openapi apps file did not load") != 3 {
		t.Errorf("%q", got)
	}
	// 同一个 appKey 写在两个句柄下：继续用上一份。
	dup := greenApp(ep.tokenURL())
	dup.AppKey = blueAppKey
	write(t, f.path, fileOf(entryJSON(blueHandle, blueApp(ep.tokenURL())), entryJSON(greenHandle, dup)), 0o600)
	if got, _ := f.get(blueHandle); got != first || f.lines("sf openapi apps file did not load") != 4 || !strings.Contains(f.logs.String(), "same app_key") {
		t.Errorf("%q %s", got, f.logs.String())
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
	if f.lines("sf openapi apps file cannot be seen") != 1 {
		t.Errorf("%s", f.logs.String())
	}
	// 好的换上来：用新的。
	second := blueApp(ep.tokenURL())
	second.KeyVersion = "v2"
	write(t, f.path, fileOf(entryJSON(blueHandle, second)), 0o600)
	got, err := f.get(blueHandle)
	if err != nil || got == first || f.lines("sf openapi apps file loaded again") != 1 {
		t.Fatalf("%q %v", got, err)
	}
	noSecrets(t, f.logs.String(), "重读", "leaky-new-secret")
}

func TestReloadRefusesHandlesThatAnotherSourceHoldsNow(t *testing.T) {
	ep := newEndpoint(t)
	taken := false
	f := newFixture(t, two(ep.tokenURL()), withReserved(func(h string) bool { return taken && h == greenHandle }))
	first, _ := f.get(blueHandle)
	taken = true
	changed := blueApp(ep.tokenURL())
	changed.KeyVersion = "v9"
	write(t, f.path, fileOf(entryJSON(blueHandle, changed), entryJSON(greenHandle, greenApp(ep.tokenURL()))), 0o600)
	if got, _ := f.get(blueHandle); got != first || ep.count() != 1 || !strings.Contains(f.logs.String(), "one source only") {
		t.Errorf("%q %d %s", got, ep.count(), f.logs.String())
	}
}

// 日志：每次取令牌一行，句柄、类别、用时、成功时的 expires_in；没有任何秘密。
func TestTheLogLines(t *testing.T) {
	ep := newEndpoint(t)
	f := newFixture(t, two(ep.tokenURL()))
	var seen []string
	collect := func(handle string) {
		if _, err := f.get(handle); err != nil {
			seen = append(seen, err.Error())
		}
	}
	collect(blueHandle)
	collect("gatekeeper:unknown/account-x")
	ep.set(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(503)
		fmt.Fprint(w, `{"appSecret":"`+blueSecret+`","accessToken":"`+bodyMarker+`","Authorization":"Basic xyz"}`)
	})
	f.clock.Advance(2 * time.Hour)
	collect(blueHandle)
	collect(greenHandle)

	text := strings.Join(seen, "\n") + f.logs.String()
	noSecrets(t, text, "日志和错误", "Basic xyz", ep.URL)
	for _, want := range []string{`"msg":"sf openapi token fetched"`, `"handle":"` + blueHandle + `"`, `"result":"ok"`, `"elapsed_ms":`, `"expires_in":7200`,
		`"msg":"sf openapi token not fetched"`, `"result":"status 503"`} {
		if !strings.Contains(f.logs.String(), want) {
			t.Errorf("日志里没有 %s：%s", want, f.logs.String())
		}
	}
	if f.lines("sf openapi token") != 3 { // 蓝成功一次，蓝失败一次，绿失败一次
		t.Errorf("日志行数：%s", f.logs.String())
	}
	if strings.Contains(f.logs.String(), `"level":"WARN","msg":"sf openapi token fetched"`) || !strings.Contains(f.logs.String(), `"level":"WARN","msg":"sf openapi token not fetched"`) ||
		!strings.Contains(f.logs.String(), `"level":"INFO","msg":"sf openapi token fetched"`) {
		t.Errorf("日志级别：%s", f.logs.String())
	}
	for _, line := range strings.Split(strings.TrimSpace(f.logs.String()), "\n") {
		var record map[string]any
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			t.Fatalf("%q", line)
		}
		for name := range record {
			switch name {
			case "time", "level", "msg", "handle", "result", "elapsed_ms", "expires_in":
			default:
				t.Errorf("日志里多了字段 %q：%s", name, line)
			}
		}
	}
}
