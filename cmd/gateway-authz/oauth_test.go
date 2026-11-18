package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const (
	oauthClientID     = "client-green"
	oauthClientSecret = "client-secret-green-d41d8"
	oauthTokenPrefix  = "oauth-access-token-"
)

var replaced atomic.Int64

// replaceLater 换文件（写新文件再改名），并且让它的修改时间每次都比上一次晚一秒。文件变没变靠修改时间、大小
// 和是不是同一个文件来看；连着换两份一样长的文件时，内核给的修改时间刻度太粗，这几项可能全都相同。
func replaceLater(t *testing.T, path, content string) {
	t.Helper()
	writePrivate(t, path, content)
	stamp := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC).Add(time.Duration(replaced.Add(1)) * time.Second)
	if err := os.Chtimes(path, stamp, stamp); err != nil {
		t.Fatal(err)
	}
}

// oauthClientsJSON 是只有绿账户一条的客户端凭证文件。
func oauthClientsJSON(endpoint, keyVersion string) string {
	return fmt.Sprintf(`{%q:{"token_endpoint":%q,"client_id":%q,"client_secret":%q,"key_version":%q}}`,
		greenHandle, endpoint, oauthClientID, oauthClientSecret, keyVersion)
}

// tokenServer 是替身令牌端点：failing 为真时答 500，正文里放着密钥和令牌，看它们会不会被带出去。
func tokenServer(t *testing.T, hits *atomic.Int32, failing *atomic.Bool) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := hits.Add(1)
		user, pass, ok := r.BasicAuth()
		if !ok || user != oauthClientID || pass != oauthClientSecret {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if failing.Load() {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintf(w, `{"client_secret":%q,"access_token":%q}`, oauthClientSecret, oauthTokenPrefix+"leak")
			return
		}
		fmt.Fprintf(w, `{"access_token":"%s%d","token_type":"Bearer","expires_in":3600}`, oauthTokenPrefix, n)
	}))
	t.Cleanup(server.Close)
	return server
}

func TestOAuthClientsNextToTheOtherFiles(t *testing.T) {
	var hits atomic.Int32
	var failing atomic.Bool
	server := tokenServer(t, &hits, &failing)
	h := newHarness(t)
	writePrivate(t, h.credentials, `{"gatekeeper:mockcarrier-test/account-blue": "`+blueToken+`"}`)
	clients := writePrivate(t, filepath.Join(t.TempDir(), "oauth-clients.json"), oauthClientsJSON(server.URL+"/oauth/token", "v1"))
	h.extra = []string{"--oauth-clients", clients}
	h.start()

	green := func() answer {
		return h.must(call{peer: "gateway", path: extAuthzPath, headers: trusted("tenant-green")})
	}
	first := green()
	if first.status != http.StatusOK || first.header.Get("Authorization") != "Bearer "+oauthTokenPrefix+"1" {
		t.Fatalf("绿租户：%d %s", first.status, first.body)
	}
	// 缓存：再来几个，令牌端点不再被问。蓝账户仍走 Bearer 文件。
	for range 3 {
		if again := green(); again.header.Get("Authorization") != first.header.Get("Authorization") {
			t.Fatalf("%d %s", again.status, again.body)
		}
	}
	if blue := h.must(call{peer: "gateway", path: extAuthzPath, headers: trusted("tenant-blue")}); blue.header.Get("Authorization") != "Bearer "+blueToken {
		t.Fatalf("蓝租户：%d %s", blue.status, blue.body)
	}
	if hits.Load() != 1 {
		t.Fatalf("令牌端点被问了 %d 次", hits.Load())
	}

	// 换密钥：key_version 变了，下一个请求重新取，服务不重启。
	replaceLater(t, clients, oauthClientsJSON(server.URL+"/oauth/token", "v2"))
	if second := green(); second.header.Get("Authorization") != "Bearer "+oauthTokenPrefix+"2" || hits.Load() != 2 {
		t.Fatalf("换密钥之后：%d %s %d", second.status, second.body, hits.Load())
	}

	// 取不到：503 INDETERMINATE CREDENTIAL_UNAVAILABLE，没有凭证。上一枚没到期也不拿来顶。
	failing.Store(true)
	replaceLater(t, clients, oauthClientsJSON(server.URL+"/oauth/token", "v3"))
	refused := green()
	if body := refused.json(t); refused.status != http.StatusServiceUnavailable || body["result"] != "INDETERMINATE" ||
		body["reason_code"] != "CREDENTIAL_UNAVAILABLE" || refused.header.Get("Authorization") != "" {
		t.Fatalf("令牌端点答 500：%d %s", refused.status, refused.body)
	}
	failing.Store(false)
	if third := green(); third.status != http.StatusOK || !strings.HasPrefix(third.header.Get("Authorization"), "Bearer "+oauthTokenPrefix) {
		t.Fatalf("端点恢复之后：%d %s", third.status, third.body)
	}

	all := refused.body + fmt.Sprint(refused.header) + h.logs.String()
	basic := base64.StdEncoding.EncodeToString([]byte(oauthClientID + ":" + oauthClientSecret))
	for _, secret := range []string{oauthClientSecret, oauthTokenPrefix, basic, "Basic "} {
		if strings.Contains(all, secret) {
			t.Errorf("应答或日志里有 %q：%s", secret, all)
		}
	}
	for _, expected := range []string{`"oauth_clients":1`, `"msg":"oauth token fetched"`, `"result":"status 500"`, `"msg":"oauth clients file loaded again"`} {
		if !strings.Contains(h.logs.String(), expected) {
			t.Errorf("服务日志里没有 %s", expected)
		}
	}
}

// 只给客户端凭证文件也能启动；文件里没有的账户拿不到凭证。
func TestOAuthClientsAlone(t *testing.T) {
	var hits atomic.Int32
	var failing atomic.Bool
	server := tokenServer(t, &hits, &failing)
	h := newHarness(t)
	h.credentials = ""
	h.extra = []string{"--oauth-clients", writePrivate(t, filepath.Join(t.TempDir(), "oauth-clients.json"), oauthClientsJSON(server.URL, "v1"))}
	h.start()
	if green := h.must(call{peer: "gateway", path: extAuthzPath, headers: trusted("tenant-green")}); green.status != http.StatusOK {
		t.Fatalf("%d %s", green.status, green.body)
	}
	if blue := h.must(call{peer: "gateway", path: extAuthzPath, headers: trusted("tenant-blue")}); blue.status != http.StatusServiceUnavailable {
		t.Fatalf("%d %s", blue.status, blue.body)
	}
	if hits.Load() != 1 {
		t.Fatal(hits.Load())
	}
}

// 取令牌的超时由 --oauth-timeout 定：令牌端点比它慢，这次请求拒绝，而且不比它多等多少。
func TestOAuthTimeoutFlag(t *testing.T) {
	release := make(chan struct{})
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-release }))
	t.Cleanup(func() { close(release); slow.Close() })
	h := newHarness(t)
	h.credentials = ""
	h.extra = []string{"--oauth-clients", writePrivate(t, filepath.Join(t.TempDir(), "oauth-clients.json"), oauthClientsJSON(slow.URL, "v1")),
		"--oauth-timeout", "150ms"}
	h.start()
	begun := time.Now()
	refused := h.must(call{peer: "gateway", path: extAuthzPath, headers: trusted("tenant-green")})
	if refused.status != http.StatusServiceUnavailable || time.Since(begun) > 2*time.Second || !strings.Contains(h.logs.String(), `"result":"timeout"`) {
		t.Fatalf("%d %s %v", refused.status, refused.body, time.Since(begun))
	}
}

// 三个文件里一个句柄只能在一个里，重读时也查。
func TestAHandleIsInOneFileOnlyAcrossAllThree(t *testing.T) {
	var hits atomic.Int32
	var failing atomic.Bool
	server := tokenServer(t, &hits, &failing)
	h := newHarness(t)
	writePrivate(t, h.credentials, `{"gatekeeper:mockcarrier-test/account-blue": "`+blueToken+`"}`)
	tokens := writePrivate(t, filepath.Join(t.TempDir(), "developer-tokens.json"),
		developerTokensJSON("gatekeeper:mockcarrier-test/account-other", greenAccountNo, greenDeveloperToken))
	clients := writePrivate(t, filepath.Join(t.TempDir(), "oauth-clients.json"), oauthClientsJSON(server.URL, "v1"))
	h.extra = []string{"--developer-tokens", tokens, "--oauth-clients", clients}
	h.start()

	green := func() answer {
		return h.must(call{peer: "gateway", path: extAuthzPath, headers: trusted("tenant-green")})
	}
	if a := green(); a.header.Get("Authorization") != "Bearer "+oauthTokenPrefix+"1" {
		t.Fatalf("%d %s", a.status, a.body)
	}
	// 开发者令牌文件换成把绿账户也写进去的：整份不要，绿账户仍走客户端凭证。
	replaceLater(t, tokens, developerTokensJSON(greenHandle, greenAccountNo, greenDeveloperToken))
	if a := green(); a.header.Get("Authorization") != "Bearer "+oauthTokenPrefix+"1" {
		t.Fatalf("开发者令牌文件抢走了绿账户的句柄：%d %s", a.status, a.body)
	}
	// 客户端凭证文件换成把蓝账户也写进去的：蓝账户在 Bearer 文件里，整份不要。
	replaceLater(t, clients, `{"gatekeeper:mockcarrier-test/account-blue":{"token_endpoint":"`+server.URL+`","client_id":"x","client_secret":"y","key_version":"v1"}}`)
	if blue := h.must(call{peer: "gateway", path: extAuthzPath, headers: trusted("tenant-blue")}); blue.header.Get("Authorization") != "Bearer "+blueToken {
		t.Fatalf("%d %s", blue.status, blue.body)
	}
	if a := green(); a.header.Get("Authorization") != "Bearer "+oauthTokenPrefix+"1" || hits.Load() != 1 {
		t.Fatalf("客户端凭证文件被换成了一份不合格的：%d %s %d", a.status, a.body, hits.Load())
	}
	if got := strings.Count(h.logs.String(), "one source only"); got != 2 {
		t.Errorf("两份被拒绝的文件应各记一条：%d\n%s", got, h.logs.String())
	}
}

func TestOAuthFlagsRefuseToStart(t *testing.T) {
	h := newHarness(t)
	dir := t.TempDir()
	write := func(name, content string, mode os.FileMode) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(content), mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		return path
	}
	good := oauthClientsJSON("https://auth.example/oauth/token", "v1")
	with := func(extra ...string) []string { return append(h.args("127.0.0.1:0"), extra...) }
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
	for name, tc := range map[string]struct {
		args []string
		says string
	}{
		"三个文件一个都没有给":             {without("--credentials"), "--oauth-clients"},
		"客户端凭证文件不存在":             {with("--oauth-clients", filepath.Join(dir, "missing.json")), "oauth clients"},
		"客户端凭证文件别人可读":            {with("--oauth-clients", write("open.json", good, 0o644)), "readable by others"},
		"客户端凭证文件写的是别的格式":         {with("--oauth-clients", write("shape.json", credentialsJSON, 0o600)), "not a JSON object"},
		"令牌端点是非回环的 http":         {with("--oauth-clients", write("http.json", oauthClientsJSON("http://auth.example/token", "v1"), 0o600)), "must be https"},
		"令牌端点是 localhost 的 http": {with("--oauth-clients", write("localhost.json", oauthClientsJSON("http://localhost/token", "v1"), 0o600)), "must be https"},
		"令牌端点带用户信息":              {with("--oauth-clients", write("userinfo.json", oauthClientsJSON("https://u:p@auth.example/token", "v1"), 0o600)), "user information"},
		"令牌端点带查询串":               {with("--oauth-clients", write("query.json", oauthClientsJSON("https://auth.example/token?x=1", "v1"), 0o600)), "query"},
		"令牌端点带片段":                {with("--oauth-clients", write("fragment.json", oauthClientsJSON("https://auth.example/token#f", "v1"), 0o600)), "fragment"},
		"key_version 为空":         {with("--oauth-clients", write("version.json", oauthClientsJSON("https://auth.example/token", ""), 0o600)), "key_version"},
		"句柄与 Bearer 文件重复": {with("--oauth-clients", write("dup-bearer.json",
			strings.Replace(good, greenHandle, "gatekeeper:mockcarrier-test/account-blue", 1), 0o600)), "one source only"},
		"句柄与开发者令牌文件重复": {with("--developer-tokens", write("dup-tokens.json", developerTokensJSON(greenHandle, greenAccountNo, greenDeveloperToken), 0o600),
			"--oauth-clients", write("dup-oauth.json", good, 0o600)), "one source only"},
		"--oauth-timeout 为零":   {with("--oauth-clients", write("t0.json", good, 0o600), "--oauth-timeout", "0s"), "--oauth-timeout"},
		"--oauth-timeout 为负":   {with("--oauth-clients", write("t1.json", good, 0o600), "--oauth-timeout", "-1s"), "--oauth-timeout"},
		"--oauth-timeout 不是时长": {with("--oauth-clients", write("t2.json", good, 0o600), "--oauth-timeout", "soon"), "oauth-timeout"},
		"--oauth-timeout 没有单位": {with("--oauth-clients", write("t3.json", good, 0o600), "--oauth-timeout", "5"), "oauth-timeout"},
	} {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		err := run(ctx, tc.args, io.Discard, nil)
		cancel()
		if err == nil {
			t.Errorf("%s：启动了", name)
		} else if !strings.Contains(err.Error(), tc.says) {
			t.Errorf("%s：错误是 %q，期望提到 %q", name, err, tc.says)
		} else if strings.Contains(err.Error(), oauthClientSecret) || strings.Contains(err.Error(), "u:p") {
			t.Errorf("%s：错误信息里有凭证", name)
		}
	}
	// 默认超时在 Gateway 等 PDP 的 1 秒之内。
	o, err := parse(with("--oauth-clients", write("ok.json", good, 0o600)), io.Discard)
	if err != nil || o.oauthTimeout != 800*time.Millisecond {
		t.Errorf("默认超时：%v %v", o.oauthTimeout, err)
	}
}
