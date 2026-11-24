package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// 顺丰国际开放平台应用文件（docs/adr/ADR-0014.md）。值都是编出来的。
const (
	sfAppKey      = "sf-app-key-green"
	sfAppSecret   = "sf-app-secret-green-5e2b"
	sfTokenPrefix = "sf-access-token-"
	sfTokenPath   = "/openapi/api/token"
)

// sfAESKeyOf 由种子算出一个格式合法的 encoding_aes_key：32 字节做标准 base64，去掉末尾的 "="。
func sfAESKeyOf(seed string) string {
	sum := sha256.Sum256([]byte("made-up key for command tests: " + seed))
	return base64.StdEncoding.EncodeToString(sum[:])[:43]
}

var (
	sfAESKey     = sfAESKeyOf("green")
	sfRotatedAES = sfAESKeyOf("green, rotated")
	sfHeader     = regexp.MustCompile(`^Sf-OpenApi ([^; ]+);([^; ]+);([A-Za-z0-9+/]{43})$`)
)

const freshHandle = "gatekeeper:mockcarrier-test/account-fresh"

// sfEntry 是应用文件里一个句柄下的一条记录。
func sfEntry(handle, endpoint, appKey, keyVersion, aesKey string) string {
	return fmt.Sprintf(`%q:{"token_endpoint":%q,"app_key":%q,"app_secret":%q,"encoding_aes_key":%q,"key_version":%q}`,
		handle, endpoint, appKey, sfAppSecret, aesKey, keyVersion)
}

// sfAppsJSON 是只有绿账户一条的应用文件。
func sfAppsJSON(endpoint, keyVersion, aesKey string) string {
	return "{" + sfEntry(greenHandle, endpoint, sfAppKey, keyVersion, aesKey) + "}"
}

// sfFreshJSON 是只有一个新句柄的应用文件：这个句柄不在别的凭证文件里。
func sfFreshJSON(endpoint, keyVersion, aesKey string) string {
	return "{" + sfEntry(freshHandle, endpoint, sfAppKey, keyVersion, aesKey) + "}"
}

// 令牌端点的几种答法。
const (
	sfAnswersFine    = 0
	sfAnswersHTTP500 = 1 // HTTP 500，正文里放着应用密钥和令牌
	sfAnswersRefusal = 2 // HTTP 200，apiResultCode 不是 0，说明里放着应用密钥和令牌
)

// sfTokenServer 是替身令牌端点：只有 appKey 和 appSecret 都对、没有别的查询参数的 GET 才发令牌。
func sfTokenServer(t *testing.T, hits *atomic.Int32, mode *atomic.Int32) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := hits.Add(1)
		query := r.URL.Query()
		if r.Method != http.MethodGet || len(query) != 2 || query.Get("appKey") != sfAppKey || query.Get("appSecret") != sfAppSecret {
			fmt.Fprint(w, `{"apiResultCode":10001,"apiErrorMsg":"wrong key","apiResultData":null}`)
			return
		}
		switch mode.Load() {
		case sfAnswersHTTP500:
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintf(w, `{"appSecret":%q,"accessToken":%q,"encodingAesKey":%q}`, sfAppSecret, sfTokenPrefix+"leak", sfAESKey)
		case sfAnswersRefusal:
			fmt.Fprintf(w, `{"apiResultCode":500,"apiErrorMsg":%q,"apiResultData":null}`, "try again "+sfAppSecret+" "+sfTokenPrefix+"leak "+sfAESKey)
		default:
			fmt.Fprintf(w, `{"apiResultCode":0,"apiErrorMsg":null,"apiResultData":{"expireIn":7200,"accessToken":"%s%d"},"apiTimestamp":1763611200000}`, sfTokenPrefix, n)
		}
	}))
	t.Cleanup(server.Close)
	return server
}

func greenCall(h *harness) answer {
	h.t.Helper()
	return h.must(call{peer: "gateway", path: extAuthzPath, headers: trusted("tenant-green")})
}

func blueCall(h *harness) answer {
	h.t.Helper()
	return h.must(call{peer: "gateway", path: extAuthzPath, headers: trusted("tenant-blue")})
}

// sfSecretsIn 报告 text 里有没有应用密钥、AES 密钥、访问令牌（和令牌端点会放进应答的那几样）。
func sfSecretsIn(t *testing.T, text, what string) {
	t.Helper()
	for _, secret := range []string{sfAppSecret, sfAESKey, sfRotatedAES, sfTokenPrefix, "appSecret", "appKey="} {
		if strings.Contains(text, secret) {
			t.Errorf("%s里有 %q：%s", what, secret, text)
		}
	}
}

func TestSFOpenAPINextToTheOtherFiles(t *testing.T) {
	var hits, mode atomic.Int32
	server := sfTokenServer(t, &hits, &mode)
	h := newHarness(t)
	writePrivate(t, h.credentials, `{"gatekeeper:mockcarrier-test/account-blue": "`+blueToken+`"}`)
	apps := writePrivate(t, filepath.Join(t.TempDir(), "sf-openapi-apps.json"), sfAppsJSON(server.URL+sfTokenPath, "v1", sfAESKey))
	h.extra = []string{"--sf-openapi-apps", apps}
	h.start()

	// 绿租户走顺丰的应用：认证头是 Sf-OpenApi appKey;令牌;AES密钥。
	first := greenCall(h)
	want := "Sf-OpenApi " + sfAppKey + ";" + sfTokenPrefix + "1;" + sfAESKey
	if first.status != http.StatusOK || first.header.Get("Authorization") != want || !sfHeader.MatchString(first.header.Get("Authorization")) {
		t.Fatalf("绿租户：%d %s %q", first.status, first.body, first.header.Get("Authorization"))
	}
	if body := first.json(t); body["result"] != "ALLOW" {
		t.Fatalf("%s", first.body)
	}
	sfSecretsIn(t, first.body, "放行的应答正文")
	// 缓存：再来几个，令牌端点不再被问。蓝账户仍走 Bearer 文件。
	for range 3 {
		if again := greenCall(h); again.header.Get("Authorization") != want {
			t.Fatalf("%d %s", again.status, again.body)
		}
	}
	if blue := blueCall(h); blue.status != http.StatusOK || blue.header.Get("Authorization") != "Bearer "+blueToken {
		t.Fatalf("蓝租户：%d %s", blue.status, blue.body)
	}
	if hits.Load() != 1 {
		t.Fatalf("令牌端点被问了 %d 次", hits.Load())
	}

	// 只换 AES 密钥：不重新取令牌，下一个请求交出的认证头就带新的密钥；服务不重启。
	replaceLater(t, apps, sfAppsJSON(server.URL+sfTokenPath, "v1", sfRotatedAES))
	if rotated := greenCall(h); rotated.header.Get("Authorization") != "Sf-OpenApi "+sfAppKey+";"+sfTokenPrefix+"1;"+sfRotatedAES || hits.Load() != 1 {
		t.Fatalf("换 AES 密钥之后：%d %s %d", rotated.status, rotated.header.Get("Authorization"), hits.Load())
	}
	// 换 key_version：下一个请求重新取。
	replaceLater(t, apps, sfAppsJSON(server.URL+sfTokenPath, "v2", sfRotatedAES))
	if second := greenCall(h); second.header.Get("Authorization") != "Sf-OpenApi "+sfAppKey+";"+sfTokenPrefix+"2;"+sfRotatedAES || hits.Load() != 2 {
		t.Fatalf("换 key_version 之后：%d %s %d", second.status, second.header.Get("Authorization"), hits.Load())
	}

	// 取不到：503 INDETERMINATE CREDENTIAL_UNAVAILABLE，没有凭证。上一枚没到期也不拿来顶。
	refusals := map[string]string{}
	for version, failing := range map[string]int32{"v3": sfAnswersHTTP500, "v4": sfAnswersRefusal} {
		mode.Store(failing)
		replaceLater(t, apps, sfAppsJSON(server.URL+sfTokenPath, version, sfRotatedAES))
		refused := greenCall(h)
		if body := refused.json(t); refused.status != http.StatusServiceUnavailable || body["result"] != "INDETERMINATE" ||
			body["reason_code"] != "CREDENTIAL_UNAVAILABLE" || refused.header.Get("Authorization") != "" {
			t.Fatalf("令牌端点答不好（%s）：%d %s", version, refused.status, refused.body)
		}
		refusals[version] = refused.body + fmt.Sprint(refused.header)
	}
	mode.Store(sfAnswersFine)
	if third := greenCall(h); third.status != http.StatusOK || !strings.HasPrefix(third.header.Get("Authorization"), "Sf-OpenApi "+sfAppKey+";"+sfTokenPrefix) {
		t.Fatalf("端点恢复之后：%d %s", third.status, third.body)
	}

	for version, text := range refusals {
		sfSecretsIn(t, text, "拒绝的应答（"+version+"）")
	}
	sfSecretsIn(t, h.logs.String(), "服务日志")
	for _, expected := range []string{`"sf_openapi_apps":1`, `"sf_openapi_plain_http_host":""`, `"msg":"sf openapi token fetched"`,
		`"result":"status 500"`, `"result":"code 500"`, `"msg":"sf openapi apps file loaded again"`, `"credentials":1`} {
		if !strings.Contains(h.logs.String(), expected) {
			t.Errorf("服务日志里没有 %s", expected)
		}
	}
}

// 只给应用文件也能启动；文件里没有的账户拿不到凭证。
func TestSFOpenAPIAlone(t *testing.T) {
	var hits, mode atomic.Int32
	server := sfTokenServer(t, &hits, &mode)
	h := newHarness(t)
	h.credentials = ""
	h.extra = []string{"--sf-openapi-apps", writePrivate(t, filepath.Join(t.TempDir(), "sf-openapi-apps.json"), sfAppsJSON(server.URL, "v1", sfAESKey))}
	h.start()
	if green := greenCall(h); green.status != http.StatusOK || !sfHeader.MatchString(green.header.Get("Authorization")) {
		t.Fatalf("%d %s", green.status, green.body)
	}
	blue := blueCall(h)
	if body := blue.json(t); blue.status != http.StatusServiceUnavailable || body["reason_code"] != "CREDENTIAL_UNAVAILABLE" || blue.header.Get("Authorization") != "" {
		t.Fatalf("%d %s", blue.status, blue.body)
	}
	if hits.Load() != 1 {
		t.Fatal(hits.Load())
	}
	if logs := h.logs.String(); !strings.Contains(logs, `"credentials":0`) || !strings.Contains(logs, `"sf_openapi_apps":1`) {
		t.Errorf("启动日志：%s", logs)
	}
	sfSecretsIn(t, h.logs.String(), "服务日志")
}

// 取令牌的超时由 --sf-openapi-timeout 定：令牌端点比它慢，这次请求拒绝，而且不比它多等多少。
// 令牌端点 500 毫秒之后才答（答的是好的）：超时设成 150 毫秒就拒绝；没传到的话用的是默认的 800 毫秒，
// 答案会及时到，请求就放行了。
func TestSFOpenAPITimeoutFlag(t *testing.T) {
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(500 * time.Millisecond):
			fmt.Fprintf(w, `{"apiResultCode":0,"apiResultData":{"expireIn":7200,"accessToken":"%sslow"}}`, sfTokenPrefix)
		case <-r.Context().Done():
		}
	}))
	t.Cleanup(slow.Close)
	h := newHarness(t)
	h.credentials = ""
	h.extra = []string{"--sf-openapi-apps", writePrivate(t, filepath.Join(t.TempDir(), "sf-openapi-apps.json"), sfAppsJSON(slow.URL, "v1", sfAESKey)),
		"--sf-openapi-timeout", "150ms"}
	h.start()
	begun := time.Now()
	refused := greenCall(h)
	if refused.status != http.StatusServiceUnavailable || refused.header.Get("Authorization") != "" ||
		time.Since(begun) > 2*time.Second || !strings.Contains(h.logs.String(), `"result":"timeout"`) {
		t.Fatalf("%d %s %v", refused.status, refused.body, time.Since(begun))
	}
	sfSecretsIn(t, h.logs.String()+refused.body, "输出")
}

// 超时放宽之后，同一个慢的令牌端点就够用了：超时是真的从参数传到了取令牌的那一步。
func TestSFOpenAPITimeoutFlagCanAlsoBeLonger(t *testing.T) {
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(1200 * time.Millisecond): // 比默认的 800 毫秒慢
			fmt.Fprintf(w, `{"apiResultCode":0,"apiResultData":{"expireIn":7200,"accessToken":"%sslow"}}`, sfTokenPrefix)
		case <-r.Context().Done():
		}
	}))
	t.Cleanup(slow.Close)
	h := newHarness(t)
	h.credentials = ""
	h.extra = []string{"--sf-openapi-apps", writePrivate(t, filepath.Join(t.TempDir(), "sf-openapi-apps.json"), sfAppsJSON(slow.URL, "v1", sfAESKey)),
		"--sf-openapi-timeout", "5s"}
	h.start()
	if allowed := greenCall(h); allowed.status != http.StatusOK || allowed.header.Get("Authorization") != "Sf-OpenApi "+sfAppKey+";"+sfTokenPrefix+"slow;"+sfAESKey {
		t.Fatalf("%d %s", allowed.status, allowed.body)
	}
}

// 四个文件里一个句柄只能在一个里，重读时也查：新来源拒绝别的三个占着的句柄；两个会重读的老来源
// （开发者令牌、OAuth 客户端）拒绝新来源占着的句柄。每一份被拒绝的文件记一条，原来的那份继续用。
func TestAHandleIsInOneFileOnlyAcrossAllFour(t *testing.T) {
	var hits, mode atomic.Int32
	server := sfTokenServer(t, &hits, &mode)
	const (
		developerHandle = "gatekeeper:mockcarrier-test/account-developer"
		oauthHandle     = "gatekeeper:mockcarrier-test/account-oauth"
	)
	oauthOf := func(handle string) string {
		return `{"` + handle + `":{"token_endpoint":"https://auth.example/oauth/token","client_id":"x","client_secret":"y","key_version":"v1"}}`
	}
	h := newHarness(t)
	writePrivate(t, h.credentials, `{"gatekeeper:mockcarrier-test/account-blue": "`+blueToken+`"}`)
	dir := t.TempDir()
	developer := writePrivate(t, filepath.Join(dir, "developer-tokens.json"), developerTokensJSON(developerHandle, greenAccountNo, greenDeveloperToken))
	oauth := writePrivate(t, filepath.Join(dir, "oauth-clients.json"), oauthOf(oauthHandle))
	apps := writePrivate(t, filepath.Join(dir, "sf-openapi-apps.json"), sfAppsJSON(server.URL, "v1", sfAESKey))
	h.extra = []string{"--developer-tokens", developer, "--oauth-clients", oauth, "--sf-openapi-apps", apps}
	h.start()

	wantGreen := "Sf-OpenApi " + sfAppKey + ";" + sfTokenPrefix + "1;" + sfAESKey
	stillGreen := func(what string) {
		t.Helper()
		if a := greenCall(h); a.header.Get("Authorization") != wantGreen || hits.Load() != 1 {
			t.Fatalf("%s：%d %s %d", what, a.status, a.body, hits.Load())
		}
	}
	stillGreen("起点")
	refusals := func() int { return strings.Count(h.logs.String(), "one source only") }

	// 开发者令牌文件换成把绿账户也写进去的：整份不要，绿账户仍走应用文件。
	replaceLater(t, developer, developerTokensJSON(greenHandle, greenAccountNo, greenDeveloperToken))
	stillGreen("开发者令牌文件抢绿账户的句柄")
	if refusals() != 1 {
		t.Fatalf("应该记了一条：%d\n%s", refusals(), h.logs.String())
	}
	// OAuth 客户端文件同样。
	replaceLater(t, oauth, oauthOf(greenHandle))
	stillGreen("OAuth 客户端文件抢绿账户的句柄")
	if refusals() != 2 {
		t.Fatalf("应该记了两条：%d\n%s", refusals(), h.logs.String())
	}
	// 应用文件换成把别的三个来源占着的句柄写进去的：整份不要，绿账户仍走原来那一份。
	for i, handle := range []string{"gatekeeper:mockcarrier-test/account-blue", developerHandle, oauthHandle} {
		replaceLater(t, apps, "{"+sfEntry(handle, server.URL, sfAppKey, "v9", sfAESKey)+"}")
		stillGreen("应用文件写进了别的来源占着的句柄 " + handle)
		if refusals() != 3+i {
			t.Fatalf("%s：应该记了 %d 条：%d\n%s", handle, 3+i, refusals(), h.logs.String())
		}
	}
	// 蓝账户的 Bearer、开发者令牌文件里的账户，各走各的。
	if blue := blueCall(h); blue.header.Get("Authorization") != "Bearer "+blueToken {
		t.Fatalf("蓝租户：%d %s", blue.status, blue.body)
	}
	sfSecretsIn(t, h.logs.String(), "服务日志")
}

// 启动时同一个句柄在新来源和另一个来源里：不启动。
func TestSFOpenAPIRefusesAHandleHeldByAnotherSourceAtStart(t *testing.T) {
	h := newHarness(t)
	dir := t.TempDir()
	good := sfAppsJSON("https://carrier.example.test"+sfTokenPath, "v1", sfAESKey)
	file := func(name, content string) string {
		return writePrivate(t, filepath.Join(dir, name), content)
	}
	oauthOfGreen := `{"` + greenHandle + `":{"token_endpoint":"https://auth.example/oauth/token","client_id":"x","client_secret":"y","key_version":"v1"}}`
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
	for name, args := range map[string][]string{
		"与 --credentials": append(h.args("127.0.0.1:0"), "--sf-openapi-apps", file("a.json", good)),
		"与 --developer-tokens": append(without("--credentials"), "--developer-tokens",
			file("b.json", developerTokensJSON(greenHandle, greenAccountNo, greenDeveloperToken)), "--sf-openapi-apps", file("c.json", good)),
		"与 --oauth-clients": append(without("--credentials"), "--oauth-clients", file("d.json", oauthOfGreen), "--sf-openapi-apps", file("e.json", good)),
	} {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		err := run(ctx, args, io.Discard, nil)
		cancel()
		if err == nil || !strings.Contains(err.Error(), "one source only") {
			t.Errorf("%s：%v", name, err)
		} else {
			sfSecretsIn(t, err.Error(), name+"的错误")
		}
	}
}

func TestSFOpenAPIFlagsRefuseToStart(t *testing.T) {
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
	const endpoint = "https://carrier.example.test" + sfTokenPath
	// good 的句柄（绿账户）在 --credentials 里也有；其余的文件用一个新句柄，不与 --credentials 里的重复。
	good := write("good.json", sfAppsJSON(endpoint, "v1", sfAESKey), 0o600)
	freshGood := write("fresh.json", sfFreshJSON(endpoint, "v1", sfAESKey), 0o600)
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
	cases := map[string]struct {
		args []string
		says string
	}{
		"四个文件一个都没有给":             {without("--credentials"), "--credentials or --developer-tokens or --oauth-clients or --sf-openapi-apps"},
		"应用文件不存在":                {with("--sf-openapi-apps", filepath.Join(dir, "missing.json")), "sf openapi apps"},
		"应用文件别人可读":               {with("--sf-openapi-apps", write("open.json", sfFreshJSON(endpoint, "v1", sfAESKey), 0o644)), "readable by others"},
		"应用文件写的是别的格式":            {with("--sf-openapi-apps", write("shape.json", credentialsJSON, 0o600)), "not a JSON object"},
		"令牌端点是明文 http":           {with("--sf-openapi-apps", write("http.json", sfFreshJSON("http://sandbox.example.test"+sfTokenPath, "v1", sfAESKey), 0o600)), "must be https"},
		"令牌端点是 localhost 的 http": {with("--sf-openapi-apps", write("localhost.json", sfFreshJSON("http://localhost"+sfTokenPath, "v1", sfAESKey), 0o600)), "must be https"},
		"令牌端点带查询串":               {with("--sf-openapi-apps", write("query.json", sfFreshJSON(endpoint+"?appSecret=x", "v1", sfAESKey), 0o600)), "query"},
		"令牌端点带用户信息":              {with("--sf-openapi-apps", write("userinfo.json", sfFreshJSON("https://u:p@carrier.example.test"+sfTokenPath, "v1", sfAESKey), 0o600)), "user information"},
		"key_version 为空":         {with("--sf-openapi-apps", write("version.json", sfFreshJSON(endpoint, "", sfAESKey), 0o600)), "key_version"},
		"AES 密钥只有 42 个字符":        {with("--sf-openapi-apps", write("aes42.json", sfFreshJSON(endpoint, "v1", sfAESKey[:42]), 0o600)), "encoding_aes_key"},
		"AES 密钥有 44 个字符":         {with("--sf-openapi-apps", write("aes44.json", sfFreshJSON(endpoint, "v1", sfAESKey+"A"), 0o600)), "encoding_aes_key"},
		"app_key 里有分号":           {with("--sf-openapi-apps", write("semicolon.json", "{"+sfEntry(freshHandle, endpoint, "sf;key", "v1", sfAESKey)+"}", 0o600)), "semicolon"},
		"同一个 appKey 在两个句柄下": {with("--sf-openapi-apps", write("twice.json", "{"+sfEntry("gatekeeper:mockcarrier-test/account-one", endpoint, sfAppKey, "v1", sfAESKey)+","+
			sfEntry("gatekeeper:mockcarrier-test/account-two", endpoint, sfAppKey, "v1", sfAESKey)+"}", 0o600)), "same app_key"},
		"句柄与 Bearer 文件重复":           {with("--sf-openapi-apps", good), "one source only"},
		"--sf-openapi-timeout 为零":   {with("--sf-openapi-apps", freshGood, "--sf-openapi-timeout", "0s"), "--sf-openapi-timeout"},
		"--sf-openapi-timeout 为负":   {with("--sf-openapi-apps", freshGood, "--sf-openapi-timeout", "-1s"), "--sf-openapi-timeout"},
		"--sf-openapi-timeout 不是时长": {with("--sf-openapi-apps", freshGood, "--sf-openapi-timeout", "soon"), "sf-openapi-timeout"},
		"--sf-openapi-timeout 没有单位": {with("--sf-openapi-apps", freshGood, "--sf-openapi-timeout", "5"), "sf-openapi-timeout"},
		"没有应用文件却给了明文主机":             {with("--sf-openapi-plain-http-host", "sandbox.example.test"), "needs --sf-openapi-apps"},
		"没有应用文件，主机也不合格":             {with("--sf-openapi-plain-http-host", "a/b"), "--sf-openapi-plain-http-host"},
		"明文主机带路径":                   {with("--sf-openapi-apps", freshGood, "--sf-openapi-plain-http-host", "a/b"), "bare host name"},
		"明文主机带端口":                   {with("--sf-openapi-apps", freshGood, "--sf-openapi-plain-http-host", "a:80"), "bare host name"},
		"明文主机是个地址":                  {with("--sf-openapi-apps", freshGood, "--sf-openapi-plain-http-host", "http://a"), "bare host name"},
		"明文主机带用户信息":                 {with("--sf-openapi-apps", freshGood, "--sf-openapi-plain-http-host", "u@a"), "bare host name"},
		"明文主机带查询串":                  {with("--sf-openapi-apps", freshGood, "--sf-openapi-plain-http-host", "a?b"), "bare host name"},
		"明文主机带片段":                   {with("--sf-openapi-apps", freshGood, "--sf-openapi-plain-http-host", "a#b"), "bare host name"},
		"明文主机带空格":                   {with("--sf-openapi-apps", freshGood, "--sf-openapi-plain-http-host", "a b"), "bare host name"},
		"明文主机带非 ASCII":              {with("--sf-openapi-apps", freshGood, "--sf-openapi-plain-http-host", "é.test"), "bare host name"},
		"明文主机是 IPv6 字面量":            {with("--sf-openapi-apps", freshGood, "--sf-openapi-plain-http-host", "[::1]"), "bare host name"},
		"租约参数只给了地址":                 {with("--sf-openapi-apps", freshGood, "--sf-openapi-lease-url", "https://coord.example.test"), "go together"},
		"租约参数少了名字":                  {with("--sf-openapi-apps", freshGood, "--sf-openapi-lease-url", "https://coord.example.test", "--sf-openapi-lease-cert", "c", "--sf-openapi-lease-key", "k", "--sf-openapi-lease-ca", "ca"), "go together"},
		"租约参数没有应用文件":                {with("--sf-openapi-lease-url", "https://coord.example.test", "--sf-openapi-lease-cert", "c", "--sf-openapi-lease-key", "k", "--sf-openapi-lease-ca", "ca", "--sf-openapi-lease-name", "coord.example.test"), "needs --sf-openapi-apps"},
		"租约地址是 http":                {with("--sf-openapi-apps", freshGood, "--sf-openapi-lease-url", "http://coord.example.test", "--sf-openapi-lease-cert", "c", "--sf-openapi-lease-key", "k", "--sf-openapi-lease-ca", "ca", "--sf-openapi-lease-name", "coord.example.test"), "https URL"},
		"租约地址带用户信息":                 {with("--sf-openapi-apps", freshGood, "--sf-openapi-lease-url", "https://u:p@coord.example.test", "--sf-openapi-lease-cert", "c", "--sf-openapi-lease-key", "k", "--sf-openapi-lease-ca", "ca", "--sf-openapi-lease-name", "coord.example.test"), "https URL"},
	}
	for name, tc := range cases {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		err := run(ctx, tc.args, io.Discard, nil)
		cancel()
		if err == nil {
			t.Errorf("%s：启动了", name)
		} else if !strings.Contains(err.Error(), tc.says) {
			t.Errorf("%s：错误是 %q，期望提到 %q", name, err, tc.says)
		} else {
			sfSecretsIn(t, err.Error(), name+"的错误")
			if strings.Contains(err.Error(), "u:p") {
				t.Errorf("%s：错误信息里有地址的用户信息", name)
			}
		}
	}

	// 参数的默认值和合格的写法。
	o, err := parse(with("--sf-openapi-apps", freshGood), io.Discard)
	if err != nil || o.sfOpenAPITimeout != 800*time.Millisecond || o.sfOpenAPIPlainHTTPHost != "" {
		t.Errorf("默认值：%v %q %v", o.sfOpenAPITimeout, o.sfOpenAPIPlainHTTPHost, err)
	}
	for _, host := range []string{"sandbox.example.test", "Sandbox.Example.TEST", "localhost", "10.1.2.3", "a"} {
		if o, err := parse(with("--sf-openapi-apps", freshGood, "--sf-openapi-plain-http-host", host), io.Discard); err != nil || o.sfOpenAPIPlainHTTPHost != host {
			t.Errorf("明文主机 %q：%v", host, err)
		}
	}
	// 没有别的凭证文件、只有这一个：参数检查过得去。
	if _, err := parse(append(without("--credentials"), "--sf-openapi-apps", freshGood), io.Discard); err != nil {
		t.Errorf("只给 --sf-openapi-apps：%v", err)
	}
	leaseArgs := []string{"--sf-openapi-lease-url", "https://coord.example.test/lease", "--sf-openapi-lease-cert", "c.pem",
		"--sf-openapi-lease-key", "k.pem", "--sf-openapi-lease-ca", "ca.pem", "--sf-openapi-lease-name", "coord.example.test"}
	if o, err := parse(append(with("--sf-openapi-apps", freshGood), leaseArgs...), io.Discard); err != nil ||
		o.sfOpenAPILeaseURL != "https://coord.example.test/lease" || o.sfOpenAPILeaseName != "coord.example.test" {
		t.Errorf("五个租约参数：%v", err)
	}
}

// 令牌端点是承运商沙箱那样的明文 http 地址：给了 --sf-openapi-plain-http-host 才启动，主机名要对上。
// 这里只测启动，不发请求：那个主机名不该被真的联系。
func TestSFOpenAPIPlainHTTPHostOnlyForTheOneNamedHost(t *testing.T) {
	const endpoint = "http://sandbox.example.test:8080" + sfTokenPath
	h := newHarness(t)
	h.credentials = ""
	apps := writePrivate(t, filepath.Join(t.TempDir(), "sf-openapi-apps.json"), sfAppsJSON(endpoint, "v1", sfAESKey))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	err := run(ctx, append(h.args("127.0.0.1:0"), "--sf-openapi-apps", apps), io.Discard, nil)
	cancel()
	if err == nil || !strings.Contains(err.Error(), "must be https") {
		t.Fatalf("没有例外：%v", err)
	}
	for _, other := range []string{"example.test", "other.test", "sandbox.example.test.evil.test"} {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		err := run(ctx, append(h.args("127.0.0.1:0"), "--sf-openapi-apps", apps, "--sf-openapi-plain-http-host", other), io.Discard, nil)
		cancel()
		if err == nil || !strings.Contains(err.Error(), "must be https") {
			t.Errorf("例外是 %q：%v", other, err)
		}
	}

	h.extra = []string{"--sf-openapi-apps", apps, "--sf-openapi-plain-http-host", "SANDBOX.example.test"}
	h.start()
	logs := h.logs.String()
	if !strings.Contains(logs, `"sf_openapi_apps":1`) || !strings.Contains(logs, `"sf_openapi_plain_http_host":"SANDBOX.example.test"`) {
		t.Errorf("启动日志：%s", logs)
	}
	sfSecretsIn(t, logs, "服务日志")
}
