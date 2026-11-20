package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"go.idp.xyz/idp-gateway/internal/providersigner/domain"
)

var nonceShape = regexp.MustCompile(`^[0-9a-f]{32}$`)

// encryptUnder 用指定的密钥和 appKey 尾巴加密 plain，给替身做"解不开的应答"用。
func encryptUnder(t *testing.T, encodedKey, app, plain string) string {
	t.Helper()
	key, err := domain.ParseKey(encodedKey)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := domain.Encrypt(key, app, []byte(plain), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return ciphertext
}

// 四个操作各走一遍，HTTP/1.1 和 HTTP/2 各一次：网关用 h2 连后端，Go 的 ServeTLS 要能应付。
func TestEachOperationReachesTheCarrierSigned(t *testing.T) {
	for _, http2 := range []bool{false, true} {
		wantProto := map[bool]string{false: "HTTP/1.1", true: "HTTP/2.0"}[http2]
		for _, op := range operations {
			t.Run(wantProto+" "+op.msgType, func(t *testing.T) {
				h := newHarness(t, newFakeCarrier(t, nil)).start()
				// Content-Type 带参数也行。
				a := h.must(call{path: op.path, body: oddBody(op.msgType), http2: http2,
					headers: [][2]string{{"Content-Type", "application/json; charset=utf-8"}, {"Authorization", authorization}}})
				if a.status != 200 || a.proto != wantProto {
					t.Fatalf("%d %s %s", a.status, a.proto, a.body)
				}
				if a.body != wrapped(op.msgType) {
					t.Errorf("答复不对：\n%s\n期望\n%s", a.body, wrapped(op.msgType))
				}
				if got := a.header.Get("Content-Type"); got != "application/json" {
					t.Errorf("Content-Type %q", got)
				}
			})
		}
	}
}

// 承运商一侧看到的请求：方法、路径、八个头、密文、签名、解出来的正文。
func TestTheCarrierSeesAWellFormedSignedRequest(t *testing.T) {
	for _, op := range operations {
		carrier := newFakeCarrier(t, nil)
		h := newHarness(t, carrier).start()
		body := oddBody(op.msgType)
		start := time.Now()
		if a := h.post(op.path, body, false); a.status != 200 {
			t.Fatalf("%s: %d %s", op.msgType, a.status, a.body)
		}
		if carrier.count() != 1 {
			t.Fatalf("%s: 承运商收到 %d 个请求", op.msgType, carrier.count())
		}
		seen := carrier.requests()[0]
		if seen.method != "POST" || seen.uri != dispatchPath {
			t.Errorf("%s: %s %s，期望 POST %s", op.msgType, seen.method, seen.uri, dispatchPath)
		}
		for name, want := range map[string]string{"appKey": appKey, "token": token, "msgType": op.msgType, "lang": "en", "Content-Type": "application/json"} {
			if values := seen.header.Values(name); len(values) != 1 || values[0] != want {
				t.Errorf("%s: 头 %s 是 %v，期望 %s", op.msgType, name, values, want)
			}
		}
		if when := milliseconds(t, seen.header.Get("timestamp")); when.Before(start.Add(-5*time.Second)) || when.After(time.Now().Add(5*time.Second)) {
			t.Errorf("%s: 时间戳 %v 离现在太远", op.msgType, when)
		}
		if !nonceShape.MatchString(seen.header.Get("nonce")) {
			t.Errorf("%s: 随机数 %q", op.msgType, seen.header.Get("nonce"))
		}
		if !seen.signatureOK || len(seen.header.Get("signature")) != 64 {
			t.Errorf("%s: 签名不对：%q", op.msgType, seen.header.Get("signature"))
		}
		// 解出来的正文，恰好是调用方发来的那些字节：间距、换行、键序都没动。
		if seen.decryptErr != nil || string(seen.plain) != body {
			t.Errorf("%s: 解密得到 %q，%v；调用方发的是 %q", op.msgType, seen.plain, seen.decryptErr, body)
		}
		// 请求体就是密文本身：base64，没有引号、没有 JSON 包装、没有换行，长度已知。
		if _, err := base64.StdEncoding.DecodeString(seen.ciphertext); err != nil || strings.ContainsAny(seen.ciphertext, "\"{}\n\r ") ||
			seen.contentLength != int64(len(seen.ciphertext)) || len(seen.transferEncoding) != 0 {
			t.Errorf("%s: 请求体 %q，长度 %d，传输编码 %v，%v", op.msgType, seen.ciphertext, seen.contentLength, seen.transferEncoding, err)
		}
	}
}

// 正文逐字节原样加密：开头的空白、结尾没有换行、整个正文只有一个对象。
func TestBodyIsEncryptedAsReceived(t *testing.T) {
	carrier := newFakeCarrier(t, nil)
	h := newHarness(t, carrier).start()
	bodies := []string{"{}", "  {}", "\n\t{}\r\n", `{"a":1}`, "{\"a\" :\t1}", `{"é":"顺丰","b":[1.0,1e2,0.10]}`, `{"b":1,"a":2,"b":3}`}
	for _, body := range bodies {
		if a := h.post("/sfintl/v1/orders", body, false); a.status != 200 {
			t.Fatalf("%q: %d %s", body, a.status, a.body)
		}
	}
	seen := carrier.requests()
	if len(seen) != len(bodies) {
		t.Fatal(len(seen))
	}
	for i, body := range bodies {
		if string(seen[i].plain) != body {
			t.Errorf("%q 被改成了 %q", body, seen[i].plain)
		}
	}
}

func TestLangComesFromTheFlag(t *testing.T) {
	for _, lang := range []string{"en", "zh-CN", "zh-HK"} {
		carrier := newFakeCarrier(t, nil)
		h := newHarness(t, carrier)
		h.extra = []string{"--lang", lang}
		h.start()
		// 调用方给的 lang 头不起作用。
		a := h.must(call{path: "/sfintl/v1/orders", body: "{}", headers: good([2]string{"Lang", "fr"}, [2]string{"Accept-Language", "fr"})})
		if a.status != 200 || carrier.requests()[0].header.Get("lang") != lang {
			t.Errorf("%s: %d，承运商看到 %q", lang, a.status, carrier.requests()[0].header.Get("lang"))
		}
	}
}

// 调用方的东西一样也到不了承运商：头、路径、查询串、方法、Host。
func TestNothingFromTheCallerReachesTheCarrier(t *testing.T) {
	carrier := newFakeCarrier(t, nil)
	h := newHarness(t, carrier).start()
	// 每个值里都有一个标记，好在承运商收到的东西里整个找一遍。
	extras := [][2]string{
		{"X-Extra", "caller-marker-extra"}, {"Cookie", "session=caller-marker-cookie"},
		{"Traceparent", "00-caller0marker0trace-0000000000000001-01"}, {"X-Forwarded-For", "203.0.113.77"},
		{"User-Agent", "caller-marker-agent/1.0"}, {"Referer", "https://caller-marker.example.test/"},
		{"Origin", "https://caller-marker.example.test"}, {"Accept", "text/caller-marker"},
		{"Accept-Encoding", "br"}, {"Accept-Language", "caller-marker"}, {"Proxy-Authorization", "Basic caller-marker"},
		{"X-Request-Id", "caller-marker-request"}, {"Forwarded", "for=caller-marker"}, {"Te", "trailers"},
		{"X-Idp-Verified-Subject", "caller-marker-subject"}, {"Idempotency-Key", "caller-marker-key"},
		// 承运商协议里的头名：调用方给的不起作用。
		{"Appkey", "caller-marker-appkey"}, {"Token", "caller-marker-token"}, {"Timestamp", "1"}, {"Nonce", "caller-marker-nonce"},
		{"Signature", "caller-marker-signature"}, {"Msgtype", "IECS_CANCEL_ORDER"}, {"Lang", "caller-marker-lang"},
	}
	for _, http2 := range []bool{false, true} {
		a := h.must(call{path: "/sfintl/v1/orders", body: oddBody(""), http2: http2, host: "caller-marker.example.test",
			headers: good(extras...)})
		if a.status != 200 {
			t.Fatalf("%d %s", a.status, a.body)
		}
	}
	allowed := map[string]bool{"Appkey": true, "Token": true, "Timestamp": true, "Nonce": true, "Signature": true, "Msgtype": true,
		"Lang": true, "Content-Type": true,
		// Go 的客户端自己总会加的。
		"Content-Length": true, "User-Agent": true, "Accept-Encoding": true}
	seenAll := carrier.requests()
	if len(seenAll) != 2 {
		t.Fatalf("承运商收到 %d 个请求", len(seenAll))
	}
	for _, seen := range seenAll {
		for name, values := range seen.header {
			if !allowed[name] {
				t.Errorf("承运商收到了多余的头 %s：%v", name, values)
			}
		}
		for _, name := range []string{"Appkey", "Token", "Timestamp", "Nonce", "Signature", "Msgtype", "Lang", "Content-Type"} {
			if len(seen.header.Values(name)) != 1 {
				t.Errorf("头 %s 出现了 %d 次", name, len(seen.header.Values(name)))
			}
		}
		// 没有显式去掉 User-Agent：它是 Go 的客户端自己的，不是调用方的。
		if agent := seen.header.Get("User-Agent"); !strings.HasPrefix(agent, "Go-http-client/") {
			t.Errorf("User-Agent %q 不是 Go 客户端自己的", agent)
		}
		if seen.header.Get("Accept-Encoding") != "gzip" {
			t.Errorf("Accept-Encoding %q 不是 Go 客户端自己的", seen.header.Get("Accept-Encoding"))
		}
		everything := seen.method + " " + seen.uri + " " + seen.host + " " + seen.ciphertext
		for name, values := range seen.header {
			everything += " " + name + "=" + strings.Join(values, ",")
		}
		for _, leaked := range []string{"caller-marker", "203.0.113.77", "caller0marker", "/sfintl", "orders", "BODY-MARKER"} {
			if strings.Contains(everything, leaked) {
				t.Errorf("承运商收到的东西里有 %q：%s", leaked, everything)
			}
		}
		if seen.method != "POST" || seen.uri != dispatchPath || seen.host != strings.TrimPrefix(carrier.server.URL, "http://") {
			t.Errorf("%s %s Host=%s", seen.method, seen.uri, seen.host)
		}
		if seen.header.Get("msgType") != "IECS_CREATE_ORDER" || seen.header.Get("appKey") != appKey || seen.header.Get("token") != token ||
			seen.header.Get("lang") != "en" || !seen.signatureOK || seen.decryptErr != nil {
			t.Errorf("调用方给的头起了作用：%v", seen.header)
		}
	}
}

func TestCallerMsgTypeHeaderIsIgnored(t *testing.T) {
	carrier := newFakeCarrier(t, nil)
	h := newHarness(t, carrier).start()
	for _, name := range []string{"msgType", "MsgType", "MSGTYPE", "X-Msg-Type"} {
		h.post("/sfintl/v1/order-cancellations", "{}", false, [2]string{name, "IECS_CREATE_ORDER"})
	}
	for _, seen := range carrier.requests() {
		if got := seen.header.Values("msgType"); len(got) != 1 || got[0] != "IECS_CANCEL_ORDER" {
			t.Errorf("承运商看到 msgType %v", got)
		}
	}
	if carrier.count() != 4 {
		t.Errorf("承运商收到 %d 个请求", carrier.count())
	}
}

func TestEveryCallGetsAFreshNonceAndCiphertext(t *testing.T) {
	carrier := newFakeCarrier(t, nil)
	h := newHarness(t, carrier).start()
	const calls = 25
	for range calls {
		if a := h.post("/sfintl/v1/orders", `{"same":"body"}`, false); a.status != 200 {
			t.Fatal(a.body)
		}
	}
	nonces, ciphertexts, signatures := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, seen := range carrier.requests() {
		nonces[seen.header.Get("nonce")], ciphertexts[seen.ciphertext], signatures[seen.header.Get("signature")] = true, true, true
		if !seen.signatureOK || string(seen.plain) != `{"same":"body"}` {
			t.Error("请求不对")
		}
	}
	if len(nonces) != calls || len(ciphertexts) != calls || len(signatures) != calls {
		t.Errorf("%d 个请求里：%d 个不同的随机数，%d 个不同的密文，%d 个不同的签名", calls, len(nonces), len(ciphertexts), len(signatures))
	}
}

func TestOnlyTheGatewayIsServed(t *testing.T) {
	carrier := newFakeCarrier(t, nil)
	h := newHarness(t, carrier).start()
	for _, peer := range []string{"other", "multi", "nameless"} {
		for _, http2 := range []bool{false, true} {
			a := h.must(call{peer: peer, path: "/sfintl/v1/orders", body: "{}", headers: good(), http2: http2})
			h.expectRefusal(a, 403, "caller_not_allowed")
		}
	}
	// 没有证书，或证书来自信任域之外的 CA：没有 HTTP 交换。
	for _, peer := range []string{"none", "rogue"} {
		if a, err := h.do(call{peer: peer, path: "/sfintl/v1/orders", body: "{}", headers: good()}); err == nil {
			t.Errorf("证书 %q 得到了 HTTP 答复：%d", peer, a.status)
		}
	}
	// 请求头里自称是网关，没有用。
	a := h.must(call{peer: "other", path: "/sfintl/v1/orders", body: "{}",
		headers: good([2]string{"X-Forwarded-Client-Cert", gatewayID}, [2]string{"X-Client-Identity", gatewayID})})
	h.expectRefusal(a, 403, "caller_not_allowed")
	// 对照：网关本身是可以的。
	if ok := h.post("/sfintl/v1/orders", "{}", false); ok.status != 200 || carrier.count() != 1 {
		t.Errorf("网关被拒绝了：%d %s", ok.status, ok.body)
	}
}

func TestRefusesBeforeTheCarrier(t *testing.T) {
	for _, c := range []struct {
		name   string
		call   call
		status int
		code   string
	}{
		{"unknown path", call{path: "/sfintl/v1/nope", body: "{}", headers: good()}, 404, "unknown_operation"},
		{"the root", call{path: "/", body: "{}", headers: good()}, 404, "unknown_operation"},
		{"the dispatch path of the carrier", call{path: dispatchPath, body: "{}", headers: good()}, 404, "unknown_operation"},
		{"a health path", call{method: "GET", path: "/healthz"}, 404, "unknown_operation"},
		{"a metrics path", call{method: "GET", path: "/metrics"}, 404, "unknown_operation"},
		{"an admin path", call{path: "/admin", body: "{}", headers: good()}, 404, "unknown_operation"},
		{"GET on a known path", call{method: "GET", path: "/sfintl/v1/orders", headers: good()}, 404, "unknown_operation"},
		{"PUT on a known path", call{method: "PUT", path: "/sfintl/v1/orders", body: "{}", headers: good()}, 404, "unknown_operation"},
		{"DELETE on a known path", call{method: "DELETE", path: "/sfintl/v1/orders", headers: good()}, 404, "unknown_operation"},
		{"a trailing slash", call{path: "/sfintl/v1/orders/", body: "{}", headers: good()}, 404, "unknown_operation"},
		{"a longer path", call{path: "/sfintl/v1/orders/123", body: "{}", headers: good()}, 404, "unknown_operation"},
		{"another case", call{path: "/sfintl/v1/Orders", body: "{}", headers: good()}, 404, "unknown_operation"},
		{"a doubled slash", call{path: "/sfintl//v1/orders", body: "{}", headers: good()}, 404, "unknown_operation"},
		{"a query", call{path: "/sfintl/v1/orders?x=1", body: "{}", headers: good()}, 400, "query_not_allowed"},
		{"a question mark alone", call{path: "/sfintl/v1/orders?", body: "{}", headers: good()}, 400, "query_not_allowed"},
		{"a query on another operation", call{path: "/sfintl/v1/order-cancellations?a=b", body: "{}", headers: good()}, 400, "query_not_allowed"},
		{"a query on an unknown path", call{path: "/nope?x=1", body: "{}", headers: good()}, 404, "unknown_operation"},
		{"no Content-Type", call{path: "/sfintl/v1/orders", body: "{}", headers: [][2]string{{"Authorization", authorization}}}, 415, "unsupported_media_type"},
		{"text/plain", call{path: "/sfintl/v1/orders", body: "{}", headers: [][2]string{{"Content-Type", "text/plain"}, {"Authorization", authorization}}}, 415, "unsupported_media_type"},
		{"a form", call{path: "/sfintl/v1/orders", body: "a=b", headers: [][2]string{{"Content-Type", "application/x-www-form-urlencoded"}, {"Authorization", authorization}}}, 415, "unsupported_media_type"},
	} {
		for _, http2 := range []bool{false, true} {
			t.Run(c.name, func(t *testing.T) {
				h := newHarness(t, newFakeCarrier(t, nil)).start()
				c.call.http2 = http2
				h.expectRefusal(h.must(c.call), c.status, c.code)
			})
		}
	}
}

func TestCredentialMalformed(t *testing.T) {
	scheme := "Sf-OpenApi "
	cases := map[string][]string{
		"no header":                   nil,
		"an empty header":             {""},
		"scheme only":                 {"Sf-OpenApi"},
		"scheme and a space":          {"Sf-OpenApi "},
		"another scheme":              {"Bearer " + token},
		"lower case scheme":           {"sf-openapi " + appKey + ";" + token + ";" + aesKey},
		"another case":                {"Sf-Openapi " + appKey + ";" + token + ";" + aesKey},
		"two spaces":                  {"Sf-OpenApi  " + appKey + ";" + token + ";" + aesKey},
		"no scheme":                   {appKey + ";" + token + ";" + aesKey},
		"two parts":                   {scheme + appKey + ";" + token},
		"four parts":                  {scheme + appKey + ";" + token + ";" + aesKey + ";x"},
		"an empty appKey":             {scheme + ";" + token + ";" + aesKey},
		"an empty token":              {scheme + appKey + ";;" + aesKey},
		"an empty key":                {scheme + appKey + ";" + token + ";"},
		"a space in a part":           {scheme + appKey + ";to ken;" + aesKey},
		"a non-ASCII character":       {scheme + "appé;" + token + ";" + aesKey},
		"a key of 42 characters":      {scheme + appKey + ";" + token + ";" + aesKey[:42]},
		"a key of 44 characters":      {scheme + appKey + ";" + token + ";" + aesKey + "A"},
		"a key outside the alphabet":  {scheme + appKey + ";" + token + ";" + aesKey[:20] + "!" + aesKey[21:]},
		"two good headers":            {authorization, authorization},
		"a good header and a bad one": {authorization, "Bearer x"},
	}
	for name, values := range cases {
		for _, http2 := range []bool{false, true} {
			t.Run(name, func(t *testing.T) {
				h := newHarness(t, newFakeCarrier(t, nil)).start()
				headers := [][2]string{{"Content-Type", "application/json"}}
				for _, value := range values {
					headers = append(headers, [2]string{"Authorization", value})
				}
				a := h.must(call{path: "/sfintl/v1/orders", body: "{}", headers: headers, http2: http2})
				h.expectRefusal(a, 403, "credential_malformed")
				for _, leaked := range []string{appKey, token, aesKey} {
					if strings.Contains(a.body, leaked) {
						t.Errorf("答复里有 %q", leaked)
					}
				}
			})
		}
	}
}

func TestBodyRefusals(t *testing.T) {
	over := `{"k":"` + strings.Repeat("x", 57) + `"}`    // 65 字节
	exactly := `{"k":"` + strings.Repeat("x", 56) + `"}` // 64 字节
	if len(over) != 65 || len(exactly) != 64 {
		t.Fatal(len(over), len(exactly))
	}
	for _, c := range []struct {
		name   string
		body   string
		status int
		code   string
	}{
		{"one byte over the limit", over, 413, "request_too_large"},
		{"far over the limit", `{"k":"` + strings.Repeat("x", 100000) + `"}`, 413, "request_too_large"},
		{"over the limit and not JSON", strings.Repeat("x", 1000), 413, "request_too_large"},
		{"an array", `[1]`, 400, "body_not_json_object"},
		{"an empty array", `[]`, 400, "body_not_json_object"},
		{"a string", `"x"`, 400, "body_not_json_object"},
		{"a number", `1`, 400, "body_not_json_object"},
		{"null", `null`, 400, "body_not_json_object"},
		{"true", `true`, 400, "body_not_json_object"},
		{"two objects", `{} {}`, 400, "body_not_json_object"},
		{"two objects without a space", `{}{}`, 400, "body_not_json_object"},
		{"an object and trailing text", `{} x`, 400, "body_not_json_object"},
		{"empty", ``, 400, "body_not_json_object"},
		{"white space only", " \n\t ", 400, "body_not_json_object"},
		{"invalid JSON", `{"a":`, 400, "body_not_json_object"},
		{"not JSON", `not json`, 400, "body_not_json_object"},
		{"a byte order mark", "\ufeff{}", 400, "body_not_json_object"},
		{"single quotes", `{'a':1}`, 400, "body_not_json_object"},
	} {
		for _, http2 := range []bool{false, true} {
			t.Run(c.name, func(t *testing.T) {
				h := newHarness(t, newFakeCarrier(t, nil))
				h.extra = []string{"--max-request-bytes", "64"}
				h.start()
				a := h.must(call{path: "/sfintl/v1/orders", body: c.body, headers: good(), http2: http2})
				h.expectRefusal(a, c.status, c.code)
			})
		}
	}

	// 对照：恰好等于上限的正文是可以的。
	carrier := newFakeCarrier(t, nil)
	h := newHarness(t, carrier)
	h.extra = []string{"--max-request-bytes", "64"}
	h.start()
	if a := h.post("/sfintl/v1/orders", exactly, false); a.status != 200 || string(carrier.requests()[0].plain) != exactly {
		t.Errorf("恰好 64 字节的正文：%d %s", a.status, a.body)
	}
}

// 默认的请求上限是 1 MiB：恰好 1 MiB 可以，多一个字节不行。
func TestDefaultRequestLimitIsOneMebibyte(t *testing.T) {
	carrier := newFakeCarrier(t, nil)
	h := newHarness(t, carrier).start()
	fill := func(size int) string { return `{"k":"` + strings.Repeat("x", size-8) + `"}` }
	if a := h.post("/sfintl/v1/orders", fill(1<<20), false); a.status != 200 || len(carrier.requests()[0].plain) != 1<<20 {
		t.Fatalf("1 MiB：%d %.200s", a.status, a.body)
	}
	a := h.post("/sfintl/v1/orders", fill(1<<20+1), false)
	if a.status != 413 || carrier.count() != 1 {
		t.Fatalf("1 MiB 多一个字节：%d %.200s", a.status, a.body)
	}
}

// ---- 承运商那一侧出问题 ----

// whenAsked 是个替身的 respond：不管请求是什么，都这样答。
func whenAsked(status int, body string, headers ...string) func(http.ResponseWriter, *http.Request, seenRequest) {
	return func(w http.ResponseWriter, _ *http.Request, _ seenRequest) {
		for i := 0; i+1 < len(headers); i += 2 {
			w.Header().Set(headers[i], headers[i+1])
		}
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}
}

func TestCarrierTimesOutWithoutARetry(t *testing.T) {
	carrier := newFakeCarrier(t, func(_ http.ResponseWriter, r *http.Request, _ seenRequest) {
		select {
		case <-r.Context().Done():
		case <-time.After(3 * time.Second):
		}
	})
	h := newHarness(t, carrier)
	h.extra = []string{"--carrier-timeout", "300ms"}
	h.start()
	started := time.Now()
	a := h.post("/sfintl/v1/orders", oddBody(""), false)
	if elapsed := time.Since(started); elapsed > 2500*time.Millisecond {
		t.Errorf("用了 %v", elapsed)
	}
	fields := a.fields(t)
	if a.status != 504 || fields["error"] != "carrier_timeout" || len(fields) != 2 {
		t.Fatalf("%d %s", a.status, a.body)
	}
	// 没有重试：等一等，承运商仍然只收到一个请求。
	time.Sleep(700 * time.Millisecond)
	if carrier.count() != 1 {
		t.Fatalf("承运商收到 %d 个请求", carrier.count())
	}
	line := h.callLines()[0]
	if line["outcome"] != "carrier_timeout" || line["status"] != float64(504) || line["carrier_status"] != float64(0) {
		t.Errorf("%v", line)
	}
	if _, present := line["api_result_code"]; present {
		t.Errorf("没有 apiResultCode 却记了：%v", line)
	}
}

func TestCarrierRefusesTheConnection(t *testing.T) {
	// 一个刚关掉的服务：它的端口没人听，连接被拒绝。
	gone := httptest.NewServer(http.NotFoundHandler())
	carrier := &fakeCarrier{t: t, server: gone}
	gone.Close()
	h := newHarness(t, carrier).start()
	a := h.post("/sfintl/v1/orders", oddBody(""), false)
	fields := a.fields(t)
	if a.status != 502 || fields["error"] != "carrier_unreachable" || len(fields) != 2 {
		t.Fatalf("%d %s", a.status, a.body)
	}
	if strings.Contains(a.body, "127.0.0.1") || strings.Contains(a.body, "refused") || strings.Contains(a.body, "dial") {
		t.Errorf("答复里有底层错误的文字：%s", a.body)
	}
	if logs := h.logs.String(); strings.Contains(logs, "connection refused") || strings.Contains(logs, "dial tcp") {
		t.Errorf("日志里有底层错误的文字：%s", logs)
	}
}

func TestCarrierStatusOtherThan200(t *testing.T) {
	for _, status := range []int{500, 502, 503, 404, 401, 201, 204} {
		carrier := newFakeCarrier(t, whenAsked(status, `{"apiResultCode":0,"apiErrorMsg":"`+errorMarker+`"}`))
		h := newHarness(t, carrier).start()
		a := h.post("/sfintl/v1/orders", oddBody(""), false)
		fields := a.fields(t)
		if a.status != 502 || fields["error"] != "carrier_status" || fields["carrier_status"] != float64(status) || len(fields) != 3 {
			t.Errorf("%d: %d %s", status, a.status, a.body)
		}
		if strings.Contains(a.body, "ERRMSG") || carrier.count() != 1 {
			t.Errorf("%d: 承运商的正文被带出来了，或被问了 %d 次：%s", status, carrier.count(), a.body)
		}
		if line := h.callLines()[0]; line["outcome"] != "carrier_status" || line["carrier_status"] != float64(status) || line["status"] != float64(502) {
			t.Errorf("%d: %v", status, line)
		}
	}
}

// 重定向不被跟随：3xx 本身就是答复，第二台服务一个请求也收不到。
func TestCarrierRedirectIsNotFollowed(t *testing.T) {
	var mu sync.Mutex
	second := 0
	elsewhere := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		second++
		mu.Unlock()
		_, _ = io.WriteString(w, `{"apiResultCode":0}`)
	}))
	defer elsewhere.Close()
	for _, status := range []int{301, 302, 303, 307, 308} {
		carrier := newFakeCarrier(t, func(w http.ResponseWriter, r *http.Request, _ seenRequest) {
			http.Redirect(w, r, elsewhere.URL+"/elsewhere", status)
		})
		h := newHarness(t, carrier).start()
		a := h.post("/sfintl/v1/orders", oddBody(""), false)
		fields := a.fields(t)
		if a.status != 502 || fields["error"] != "carrier_status" || fields["carrier_status"] != float64(status) {
			t.Errorf("%d: %d %s", status, a.status, a.body)
		}
		if strings.Contains(a.body, elsewhere.URL) || strings.Contains(a.header.Get("Location"), "elsewhere") {
			t.Errorf("%d: Location 被带出来了", status)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if second != 0 {
		t.Fatalf("第二台服务收到了 %d 个请求：重定向被跟随了", second)
	}
}

func TestCarrierAnswerLimit(t *testing.T) {
	// 一个 apiResultCode 为 500 的信封，补到恰好 size 字节。
	envelopeOf := func(size int) string {
		const head, tail = `{"apiResultCode":500,"apiErrorMsg":"`, `"}`
		return head + strings.Repeat("x", size-len(head)-len(tail)) + tail
	}
	const limit = 300
	for _, c := range []struct {
		name   string
		body   string
		status int
		code   string
	}{
		{"exactly the limit", envelopeOf(limit), 200, ""},
		{"one byte over", envelopeOf(limit + 1), 502, "carrier_answer_unreadable"},
		{"far over", envelopeOf(100000), 502, "carrier_answer_unreadable"},
	} {
		carrier := newFakeCarrier(t, whenAsked(200, c.body))
		h := newHarness(t, carrier)
		h.extra = []string{"--max-response-bytes", "300"}
		h.start()
		a := h.post("/sfintl/v1/orders", oddBody(""), false)
		if a.status != c.status {
			t.Errorf("%s: %d %.200s", c.name, a.status, a.body)
			continue
		}
		if c.code == "" {
			if a.body != c.body {
				t.Errorf("%s: 答复不是承运商的原样", c.name)
			}
			continue
		}
		fields := a.fields(t)
		if fields["error"] != c.code || len(fields) != 2 || strings.Contains(a.body, "xxxx") {
			t.Errorf("%s: %s", c.name, a.body)
		}
	}
}

// 承运商拒绝（apiResultCode 不是 0）：答复就是承运商的字节，一个都不改。
func TestCarrierRefusalPassesThroughUnchanged(t *testing.T) {
	raw := "  {\"apiResultCode\": 500 ,\n \"apiErrorMsg\": \"Access denied, token invalid " + errorMarker + "\", \"apiResultData\": null,\n \"apiTimestamp\": 1763611200000 }\n"
	carrier := newFakeCarrier(t, whenAsked(200, raw,
		"Content-Type", "text/plain", "X-Carrier-Secret", "leak", "Set-Cookie", "carrier=leak", "Server", "kong", "Location", "https://elsewhere.example.test/"))
	h := newHarness(t, carrier).start()
	for _, http2 := range []bool{false, true} {
		a := h.must(call{path: "/sfintl/v1/orders", body: oddBody(""), headers: good(), http2: http2})
		if a.status != 200 || a.body != raw {
			t.Fatalf("%d %q", a.status, a.body)
		}
		if a.header.Get("Content-Type") != "application/json" {
			t.Errorf("Content-Type %q", a.header.Get("Content-Type"))
		}
		for _, name := range []string{"X-Carrier-Secret", "Set-Cookie", "Server", "Location", "Via", "X-Kong-Upstream-Latency"} {
			if value := a.header.Get(name); value != "" {
				t.Errorf("承运商的头 %s 被带出来了：%q", name, value)
			}
		}
	}
	line := h.callLines()[0]
	if line["outcome"] != "carrier_refused" || line["status"] != float64(200) || line["carrier_status"] != float64(200) || line["api_result_code"] != float64(500) {
		t.Errorf("%v", line)
	}
	if line["response_bytes"] != float64(len(raw)) || line["request_bytes"] != float64(len(oddBody(""))) {
		t.Errorf("%v", line)
	}
}

func TestCarrierAnswerWithoutData(t *testing.T) {
	for name, raw := range map[string]string{
		"data absent":  `{"apiResultCode":0,"apiErrorMsg":null,"apiTimestamp":1763611200000}`,
		"data null":    "{ \"apiResultCode\" : 0 ,\n \"apiResultData\" : null }\n",
		"only a code":  `{"apiResultCode":0}`,
		"another code": `{"apiResultCode":1004,"apiResultData":"not decrypted, not even base64"}`,
	} {
		carrier := newFakeCarrier(t, whenAsked(200, raw))
		h := newHarness(t, carrier).start()
		if a := h.post("/sfintl/v1/orders", oddBody(""), false); a.status != 200 || a.body != raw {
			t.Errorf("%s: %d %q", name, a.status, a.body)
		}
	}
}

// 解不开的应答：502，答复里没有密文，也没有解了一半的明文；日志里同样没有。
func TestCarrierAnswerThatDoesNotDecrypt(t *testing.T) {
	const marker = "PLAINTEXT-MARKER-0b6e"
	otherKey := "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVowMTIzNDU"
	for name, forge := range map[string]func() string{
		"another key": func() string {
			return encryptUnder(t, otherKey, appKey, `{"success":true,"m":"`+marker+`"}`)
		},
		"another appKey trailer": func() string {
			return encryptUnder(t, aesKey, "another-app-key", `{"success":true,"m":"`+marker+`"}`)
		},
		"an appKey that extends ours": func() string {
			return encryptUnder(t, aesKey, appKey+"x", `{"success":true,"m":"`+marker+`"}`)
		},
		"an appKey that is a prefix of ours": func() string {
			return encryptUnder(t, aesKey, appKey[:len(appKey)-1], `{"success":true,"m":"`+marker+`"}`)
		},
		"not JSON under the right key": func() string {
			return encryptUnder(t, aesKey, appKey, `this is not JSON `+marker)
		},
		"not base64": func() string { return "not base64 " + marker },
	} {
		ciphertext := forge()
		carrier := newFakeCarrier(t, whenAsked(200, `{"apiResultCode":0,"apiErrorMsg":null,"apiResultData":"`+ciphertext+`","apiTimestamp":1}`))
		h := newHarness(t, carrier).start()
		a := h.post("/sfintl/v1/orders", oddBody(""), false)
		fields := a.fields(t)
		if a.status != 502 || fields["error"] != "carrier_answer_unreadable" || len(fields) != 2 {
			t.Errorf("%s: %d %s", name, a.status, a.body)
		}
		for _, leaked := range []string{ciphertext, marker, "success", "apiResult"} {
			if strings.Contains(a.body, leaked) || strings.Contains(h.logs.String(), leaked) {
				t.Errorf("%s: 答复或日志里有 %q", name, leaked)
			}
		}
		line := h.callLines()[0]
		if line["outcome"] != "carrier_answer_unreadable" || line["status"] != float64(502) || line["api_result_code"] != float64(0) || line["carrier_status"] != float64(200) {
			t.Errorf("%s: %v", name, line)
		}
	}
}

func TestCarrierAnswerThatIsNotAnEnvelope(t *testing.T) {
	for name, raw := range map[string]string{
		"html":                  "<html><body>502 Bad Gateway</body></html>",
		"empty":                 "",
		"an array":              `[{"apiResultCode":0}]`,
		"two objects":           `{"apiResultCode":500} {"apiResultCode":500}`,
		"code as a string":      `{"apiResultCode":"0","apiResultData":null}`,
		"code as 0.0":           `{"apiResultCode":0.0}`,
		"code as 1e0":           `{"apiResultCode":1e0}`,
		"no code":               `{"apiResultData":null}`,
		"code null":             `{"apiResultCode":null}`,
		"data a number":         `{"apiResultCode":0,"apiResultData":5}`,
		"data an object":        `{"apiResultCode":0,"apiResultData":{"success":true}}`,
		"truncated":             `{"apiResultCode":0,"apiResultData":"abc`,
		"a JSON string of JSON": `"{\"apiResultCode\":500}"`,
	} {
		carrier := newFakeCarrier(t, whenAsked(200, raw))
		h := newHarness(t, carrier).start()
		a := h.post("/sfintl/v1/orders", oddBody(""), false)
		fields := a.fields(t)
		if a.status != 502 || fields["error"] != "carrier_answer_unreadable" || len(fields) != 2 || strings.Contains(a.body, "Bad Gateway") {
			t.Errorf("%s: %d %s", name, a.status, a.body)
		}
	}
}

// ---- 启动 ----

func TestRefusesToStart(t *testing.T) {
	carrier := newFakeCarrier(t, nil)
	h := newHarness(t, carrier)
	base := h.args("127.0.0.1:0")
	replace := func(flag, value string) []string {
		args := append([]string(nil), base...)
		for i := range args {
			if args[i] == flag {
				args[i+1] = value
				return args
			}
		}
		t.Fatalf("没有 %s", flag)
		return nil
	}
	without := func(flag string) []string {
		var args []string
		for i := 0; i < len(base); i += 2 {
			if base[i] != flag {
				args = append(args, base[i], base[i+1])
			}
		}
		return args
	}
	with := func(extra ...string) []string { return append(append([]string(nil), base...), extra...) }
	withURL := func(url string, extra ...string) []string { return append(replace("--carrier-url", url), extra...) }
	const secret = "SECRETPW"

	cases := []struct {
		name string
		args []string
		says string
	}{
		{"no arguments", nil, "missing required flags"},
		{"no --listen", without("--listen"), "--listen"},
		{"no --tls-cert", without("--tls-cert"), "--tls-cert"},
		{"no --tls-key", without("--tls-key"), "--tls-key"},
		{"no --client-ca", without("--client-ca"), "--client-ca"},
		{"no --gateway-identity", without("--gateway-identity"), "--gateway-identity"},
		{"no --carrier-url", without("--carrier-url"), "--carrier-url"},
		{"an unexpected argument", with("serve"), "unexpected argument"},
		{"an unknown flag", with("--debug"), "flag provided but not defined"},
		{"an unreadable client CA", replace("--client-ca", "/nonexistent/ca.pem"), "client CA"},
		{"a key that does not match the certificate", replace("--tls-key", h.peers["gateway"].KeyFile), "server certificate"},
		{"an address that cannot be used", replace("--listen", "256.0.0.1:1"), ""},

		{"plain http to a name", withURL("http://api.example.test/openapi/api/dispatch"), "must be https"},
		{"plain http to a name with the exception for another host", withURL("http://api.example.test/openapi/api/dispatch", "--carrier-plain-http-host", "sandbox.example.test"), "must be https"},
		{"plain http to a name that ends like the excepted host", withURL("http://evil-sandbox.example.test/x", "--carrier-plain-http-host", "sandbox.example.test"), "must be https"},
		{"plain http to a subdomain of the excepted host", withURL("http://x.sandbox.example.test/x", "--carrier-plain-http-host", "sandbox.example.test"), "must be https"},
		{"plain http to localhost", withURL("http://localhost:8080/x"), "must be https"},
		{"plain http to localhost with an exception for it written differently", withURL("http://localhost:8080/x", "--carrier-plain-http-host", "local"), "must be https"},
		{"plain http to a private address", withURL("http://10.0.0.1/x"), "must be https"},
		{"plain http to a short loopback form", withURL("http://127.1/x"), "must be https"},
		{"a query", withURL("https://api.example.test/openapi/api/dispatch?a=1"), "query"},
		{"an empty query", withURL("https://api.example.test/openapi/api/dispatch?"), "query"},
		{"a fragment", withURL("https://api.example.test/openapi/api/dispatch#f"), "fragment"},
		{"user information", withURL("https://user:" + secret + "@api.example.test/openapi/api/dispatch"), "user information"},
		{"user information on a loopback address", withURL("http://user:" + secret + "@127.0.0.1:1/x"), "user information"},
		{"a relative URL", withURL("/openapi/api/dispatch"), "absolute URL"},
		{"a URL with only a scheme", withURL("https:"), "absolute URL"},
		{"no host", withURL("https:///x"), "absolute URL"},
		{"a scheme that is not http", withURL("ftp://api.example.test/x"), "https"},
		{"a space in the URL", withURL("https://api.example.test/a b"), "visible ASCII"},
		{"non-ASCII in the URL", withURL("https://api.example.test/é"), "visible ASCII"},
		{"a bad plain-http host with a port", withURL("https://api.example.test/x", "--carrier-plain-http-host", "a:80"), "bare host name"},
		{"a bad plain-http host with a slash", withURL("https://api.example.test/x", "--carrier-plain-http-host", "a/b"), "bare host name"},
		{"a bad plain-http host with an at sign", withURL("https://api.example.test/x", "--carrier-plain-http-host", "a@b"), "bare host name"},
		{"a bad plain-http host with a question mark", withURL("https://api.example.test/x", "--carrier-plain-http-host", "a?b"), "bare host name"},
		{"a bad plain-http host with a number sign", withURL("https://api.example.test/x", "--carrier-plain-http-host", "a#b"), "bare host name"},
		{"a bad plain-http host with a space", withURL("https://api.example.test/x", "--carrier-plain-http-host", "a b"), "bare host name"},
		{"a plain-http host that is a URL", withURL("https://api.example.test/x", "--carrier-plain-http-host", "http://sandbox.example.test"), "bare host name"},

		{"--lang fr", with("--lang", "fr"), "--lang"},
		{"--lang in the wrong case", with("--lang", "EN"), "--lang"},
		{"--lang empty", with("--lang", ""), "--lang"},
		{"--max-request-bytes 0", with("--max-request-bytes", "0"), "--max-request-bytes"},
		{"--max-request-bytes negative", with("--max-request-bytes", "-1"), "--max-request-bytes"},
		{"--max-response-bytes 0", with("--max-response-bytes", "0"), "--max-response-bytes"},
		{"--max-response-bytes negative", with("--max-response-bytes", "-5"), "--max-response-bytes"},
		{"--carrier-timeout 0", with("--carrier-timeout", "0s"), "--carrier-timeout"},
		{"--carrier-timeout negative", with("--carrier-timeout", "-1s"), "--carrier-timeout"},
		{"--carrier-timeout without a unit", with("--carrier-timeout", "8"), "carrier-timeout"},
		{"--max-request-bytes not a number", with("--max-request-bytes", "lots"), "max-request-bytes"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			var output lockedBuffer
			err := run(ctx, c.args, &output, func(net.Addr) { t.Error("拒绝启动的参数却开始接受连接了") })
			if err == nil {
				t.Fatal("启动了")
			}
			if !strings.Contains(err.Error(), c.says) && !strings.Contains(output.String(), c.says) {
				t.Errorf("错误是 %q，期望提到 %q", err, c.says)
			}
			if strings.Contains(err.Error(), secret) || strings.Contains(output.String(), secret) {
				t.Errorf("错误里有 URL 里的用户信息")
			}
			if strings.Contains(output.String(), `"msg":"provider-signer listening"`) {
				t.Error("启动日志写了")
			}
		})
	}
}

func startAndStop(t *testing.T, h *harness, args ...string) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	addr, done := make(chan net.Addr, 1), make(chan error, 1)
	go func() { done <- run(ctx, args, h.logs, func(a net.Addr) { addr <- a }) }()
	select {
	case <-addr:
	case err := <-done:
		cancel()
		t.Fatalf("服务没有启动：%v", err)
	case <-time.After(10 * time.Second):
		cancel()
		t.Fatal("服务没有在 10 秒内启动")
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("停止时返回了错误：%v", err)
	}
}

func TestStartsWithTheAcceptedCarrierURLs(t *testing.T) {
	for _, c := range []struct {
		name   string
		url    string
		extra  []string
		scheme string
		host   string
		plain  string
	}{
		{"loopback address", "http://127.0.0.1:1/openapi/api/dispatch", nil, "http", "127.0.0.1:1", ""},
		{"another loopback address", "http://127.9.9.9:2/x", nil, "http", "127.9.9.9:2", ""},
		{"IPv6 loopback", "http://[::1]:3/x", nil, "http", "[::1]:3", ""},
		{"the excepted host, never contacted", "http://sandbox.example.test/openapi/api/dispatch", []string{"--carrier-plain-http-host", "sandbox.example.test"}, "http", "sandbox.example.test", "sandbox.example.test"},
		{"the excepted host in other letter case", "http://Sandbox.Example.TEST/x", []string{"--carrier-plain-http-host", "sandbox.example.test"}, "http", "Sandbox.Example.TEST", "sandbox.example.test"},
		{"production", "https://api-ifsp.sf.global/openapi/api/dispatch", nil, "https", "api-ifsp.sf.global", ""},
		{"https with the exception set for another host", "https://api.example.test/x", []string{"--carrier-plain-http-host", "sandbox.example.test"}, "https", "api.example.test", "sandbox.example.test"},
	} {
		t.Run(c.name, func(t *testing.T) {
			carrier := newFakeCarrier(t, nil)
			h := newHarness(t, carrier)
			args := append(append(h.args("127.0.0.1:0"), "--carrier-url", c.url, "--max-request-bytes", "2048", "--max-response-bytes", "4096",
				"--carrier-timeout", "7s", "--lang", "zh-CN"), c.extra...)
			startAndStop(t, h, args...)
			var listening map[string]any
			for _, line := range h.logLines() {
				if line["msg"] == "provider-signer listening" {
					listening = line
				}
			}
			if listening == nil {
				t.Fatalf("没有启动日志：%s", h.logs)
			}
			want := map[string]any{"gateway_identity": gatewayID, "carrier_host": c.host, "carrier_scheme": c.scheme, "plain_http_host": c.plain,
				"lang": "zh-CN", "carrier_timeout": "7s", "max_request_bytes": float64(2048), "max_response_bytes": float64(4096), "operations": float64(4)}
			for name, value := range want {
				if listening[name] != value {
					t.Errorf("%s 是 %v，期望 %v", name, listening[name], value)
				}
			}
			if addr, _ := listening["addr"].(string); !strings.HasPrefix(addr, "127.0.0.1:") {
				t.Errorf("addr %v", listening["addr"])
			}
			if listening["level"] != "INFO" {
				t.Errorf("级别 %v", listening["level"])
			}
			// 地址里的路径不进日志，用户信息本来就不许有。
			if strings.Contains(h.logs.String(), "openapi/api/dispatch") {
				t.Error("启动日志里有承运商地址的路径")
			}
			if carrier.count() != 0 {
				t.Error("启动时联系了承运商")
			}
			if !strings.Contains(h.logs.String(), `"msg":"provider-signer stopped"`) {
				t.Error("没有记录停止")
			}
		})
	}
}

func TestStartsWithTheDefaults(t *testing.T) {
	o, err := parse(newHarness(t, newFakeCarrier(t, nil)).args("127.0.0.1:0"), io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if o.lang != "en" || o.carrierTimeout != 8*time.Second || o.maxRequestBytes != 1048576 || o.maxResponseBytes != 4194304 || o.plainHTTPHost != "" {
		t.Errorf("%+v", o)
	}
}

func TestStopsWhenAskedTo(t *testing.T) {
	h := newHarness(t, newFakeCarrier(t, nil)).start()
	if a := h.post("/sfintl/v1/orders", "{}", false); a.status != 200 {
		t.Fatalf("%d", a.status)
	}
	if err := h.stop(); err != nil {
		t.Fatalf("停止时返回了错误：%v", err)
	}
	if _, err := h.do(call{path: "/sfintl/v1/orders", body: "{}", headers: good()}); err == nil {
		t.Fatal("停止之后还在应答")
	}
}

// ---- 日志 ----

func TestLogsHaveOneLinePerRequestAndNoSecrets(t *testing.T) {
	carrier := newFakeCarrier(t, nil)
	h := newHarness(t, carrier)
	h.extra = []string{"--max-request-bytes", "300"}
	h.start()

	type step struct {
		name    string
		call    call
		outcome string
		status  float64
	}
	steps := []step{
		{"create", call{path: operations[0].path, body: oddBody("1"), headers: good()}, "ok", 200},
		{"cancel", call{path: operations[1].path, body: oddBody("2"), headers: good()}, "ok", 200},
		{"query", call{path: operations[2].path, body: oddBody("3"), headers: good()}, "ok", 200},
		{"print", call{path: operations[3].path, body: oddBody("3b"), headers: good()}, "ok", 200},
		{"over h2", call{path: operations[0].path, body: oddBody("4"), headers: good(), http2: true}, "ok", 200},
		{"another identity", call{peer: "other", path: operations[0].path, body: oddBody("5"), headers: good()}, "caller_not_allowed", 403},
		{"unknown path", call{path: "/nope", body: oddBody("6"), headers: good()}, "unknown_operation", 404},
		{"a query", call{path: operations[0].path + "?token=" + token, body: oddBody("7"), headers: good()}, "query_not_allowed", 400},
		{"a wrong media type", call{path: operations[0].path, body: oddBody("8"), headers: [][2]string{{"Content-Type", "text/plain"}, {"Authorization", authorization}}}, "unsupported_media_type", 415},
		{"a bad credential", call{path: operations[0].path, body: oddBody("9"), headers: [][2]string{{"Content-Type", "application/json"}, {"Authorization", "Sf-OpenApi " + appKey + ";" + token}}}, "credential_malformed", 403},
		{"a body that is too large", call{path: operations[0].path, body: `{"k":"` + bodyMarker + strings.Repeat("x", 400) + `"}`, headers: good()}, "request_too_large", 413},
		{"a body that is an array", call{path: operations[0].path, body: "[\"" + bodyMarker + "\"]", headers: good()}, "body_not_json_object", 400},
	}
	for _, s := range steps {
		if a := h.must(s.call); a.status != int(s.status) {
			t.Fatalf("%s: %d %s", s.name, a.status, a.body)
		}
	}
	// 承运商那边出各种问题：每种换一个替身的答法。
	answers := []struct {
		outcome string
		status  float64
		respond func(http.ResponseWriter, *http.Request, seenRequest)
		code    any
	}{
		{"carrier_refused", 200, whenAsked(200, `{"apiResultCode":500,"apiErrorMsg":"`+errorMarker+`"}`), float64(500)},
		{"ok_no_data", 200, whenAsked(200, `{"apiResultCode":0,"apiErrorMsg":null}`), float64(0)},
		{"carrier_status", 502, whenAsked(500, errorMarker), nil},
		{"carrier_answer_unreadable", 502, whenAsked(200, `<html>`+errorMarker+`</html>`), nil},
		{"carrier_answer_unreadable", 502, whenAsked(200, `{"apiResultCode":0,"apiResultData":"`+encryptUnder(t, "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVowMTIzNDU", appKey, `{"x":"`+businessMarker+`"}`)+`"}`), float64(0)},
	}
	mixed := make([]string, 0, len(answers))
	for _, c := range answers {
		carrier.mu.Lock()
		carrier.respond = c.respond
		carrier.mu.Unlock()
		if a := h.post(operations[1].path, oddBody("x"), false); a.status != int(c.status) {
			t.Fatalf("%s: %d %s", c.outcome, a.status, a.body)
		}
		mixed = append(mixed, c.outcome)
	}

	lines := h.callLines()
	if len(lines) != len(steps)+len(answers) {
		t.Fatalf("%d 行 signer call，期望 %d：%s", len(lines), len(steps)+len(answers), h.logs)
	}
	required := []string{"time", "level", "msg", "operation", "msg_type", "outcome", "status", "carrier_status", "elapsed_ms", "request_bytes", "response_bytes"}
	for i, line := range lines {
		for _, name := range required {
			if _, present := line[name]; !present {
				t.Errorf("第 %d 行没有 %s：%v", i+1, name, line)
			}
		}
		for name := range line {
			known := name == "api_result_code"
			for _, r := range required {
				known = known || name == r
			}
			if !known {
				t.Errorf("第 %d 行有多余的属性 %s：%v", i+1, name, line)
			}
		}
		if line["level"] != "INFO" {
			t.Errorf("第 %d 行的级别 %v", i+1, line["level"])
		}
	}
	for i, s := range steps {
		line := lines[i]
		if line["outcome"] != s.outcome || line["status"] != s.status {
			t.Errorf("%s: %v", s.name, line)
		}
		if s.outcome == "ok" {
			if line["carrier_status"] != float64(200) || line["api_result_code"] != float64(0) || line["operation"] == "" || line["msg_type"] == "" {
				t.Errorf("%s: %v", s.name, line)
			}
		} else if line["carrier_status"] != float64(0) {
			t.Errorf("%s: 没有联系承运商却记了状态：%v", s.name, line)
		}
	}
	if lines[0]["operation"] != "orders.create" || lines[0]["msg_type"] != "IECS_CREATE_ORDER" || lines[1]["operation"] != "orders.cancel" ||
		lines[2]["operation"] != "agent-numbers.query" || lines[2]["msg_type"] != "IECS_QUERY_AGENTNO" ||
		lines[3]["operation"] != "labels.print" || lines[3]["msg_type"] != "IECS_PRINT_ORDER" ||
		lines[6]["operation"] != "" || lines[6]["msg_type"] != "" {
		t.Errorf("操作名不对：%v %v %v %v %v", lines[0], lines[1], lines[2], lines[3], lines[6])
	}
	for i, c := range answers {
		line := lines[len(steps)+i]
		if line["outcome"] != mixed[i] || line["status"] != c.status {
			t.Errorf("%s: %v", c.outcome, line)
		}
		if c.code != nil && line["api_result_code"] != c.code {
			t.Errorf("%s: api_result_code %v", c.outcome, line["api_result_code"])
		}
		if c.code == nil {
			if _, present := line["api_result_code"]; present {
				t.Errorf("%s: 不知道 apiResultCode 却记了：%v", c.outcome, line)
			}
		}
	}
	if lines[len(steps)+2]["carrier_status"] != float64(500) {
		t.Errorf("%v", lines[len(steps)+2])
	}
	// 其余的泄露检查（秘密、标记、承运商收到的随机数、签名、密文）由 auditLogs 在测试结束时做。
	// 这里再确认一遍：它确实有东西可查。
	if len(carrier.requests()) < 5 {
		t.Errorf("承运商只收到 %d 个请求", len(carrier.requests()))
	}
}

// ---- 服务器的时限和上限 ----

func TestServerTimeoutsAndLimits(t *testing.T) {
	var logs lockedBuffer
	logger := slog.New(slog.NewJSONHandler(&logs, nil))
	for _, carrierTimeout := range []time.Duration{8 * time.Second, 300 * time.Millisecond, 20 * time.Second} {
		server := newServer(http.NotFoundHandler(), &tls.Config{}, carrierTimeout, logger)
		if server.ReadHeaderTimeout != 5*time.Second || server.ReadTimeout != 10*time.Second || server.IdleTimeout != 60*time.Second ||
			server.MaxHeaderBytes != 64<<10 {
			t.Errorf("时限或上限不对：%v %v %v %d", server.ReadHeaderTimeout, server.ReadTimeout, server.IdleTimeout, server.MaxHeaderBytes)
		}
		// 写答复的时限比向承运商等答复的时限长 5 秒。
		if server.WriteTimeout != carrierTimeout+5*time.Second {
			t.Errorf("承运商时限 %v，WriteTimeout %v", carrierTimeout, server.WriteTimeout)
		}
		if server.ErrorLog == nil || server.TLSConfig == nil || server.Handler == nil {
			t.Fatal("ErrorLog、TLSConfig 或 Handler 没设")
		}
	}
	// net/http 自己的日志行并入结构化日志：一行 JSON，级别 WARN。
	newServer(http.NotFoundHandler(), &tls.Config{}, time.Second, logger).ErrorLog.Printf("a complaint from net/http")
	var line map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(logs.String())), &line); err != nil {
		t.Fatalf("%q：%v", logs.String(), err)
	}
	if line["msg"] != "http server" || line["level"] != "WARN" || line["detail"] != "a complaint from net/http" {
		t.Errorf("%v", line)
	}
}

// 超过 64 KiB 的请求头被拒绝（Go 默认是 1 MiB），而且拒绝的是 net/http 自己，不进用例。
func TestHeaderSizeLimit(t *testing.T) {
	h := newHarness(t, newFakeCarrier(t, nil)).start()
	withHeader := func(size int) call {
		return call{path: "/sfintl/v1/orders", body: "{}", headers: good([2]string{"X-Padding", strings.Repeat("a", size)})}
	}
	if a := h.must(withHeader(60 << 10)); a.status != 200 {
		t.Fatalf("60 KiB 的头：%d", a.status)
	}
	if a := h.must(withHeader(70 << 10)); a.status != 431 {
		t.Fatalf("70 KiB 的头：%d", a.status)
	}
	// 被 net/http 拒绝的请求没有到过本服务的处理函数，所以没有 signer call 日志行。
	h.mu.Lock()
	h.answered--
	h.mu.Unlock()
	if h.carrier.count() != 1 {
		t.Errorf("承运商收到 %d 个请求", h.carrier.count())
	}
}

// 握手被拒绝（没有证书、来自别家 CA 的证书）时，net/http 写的日志行进了结构化日志。
func TestRejectedHandshakesAreLoggedAsWarnings(t *testing.T) {
	h := newHarness(t, newFakeCarrier(t, nil)).start()
	for _, peer := range []string{"none", "rogue"} {
		if _, err := h.do(call{peer: peer, path: "/sfintl/v1/orders", body: "{}", headers: good()}); err == nil {
			t.Fatalf("%s 得到了答复", peer)
		}
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		found := 0
		for _, line := range h.logLines() {
			if line["msg"] == "http server" && line["level"] == "WARN" && strings.Contains(line["detail"].(string), "TLS handshake error") {
				found++
			}
		}
		if found >= 2 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("握手被拒绝的日志行只有 %d 行：%s", found, h.logs)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// 停止时在途的调用先答完：承运商还没答，服务就收到了停止，网关仍然得到答复。
func TestShutdownLetsACallInFlightFinish(t *testing.T) {
	arrived := make(chan struct{})
	var once sync.Once
	carrier := newFakeCarrier(t, func(w http.ResponseWriter, r *http.Request, _ seenRequest) {
		once.Do(func() { close(arrived) })
		time.Sleep(700 * time.Millisecond)
		_, _ = io.WriteString(w, `{"apiResultCode":500}`)
	})
	h := newHarness(t, carrier).start()
	answers := make(chan answer, 1)
	go func() {
		a, err := h.do(call{path: "/sfintl/v1/orders", body: "{}", headers: good()})
		if err != nil {
			t.Errorf("在途的调用没有得到答复：%v", err)
		}
		answers <- a
	}()
	select {
	case <-arrived:
	case <-time.After(5 * time.Second):
		t.Fatal("承运商没有收到请求")
	}
	started := time.Now()
	stopped := make(chan error, 1)
	go func() { stopped <- h.stop() }()
	a := <-answers
	if a.status != 200 || a.body != `{"apiResultCode":500}` {
		t.Errorf("%d %q", a.status, a.body)
	}
	if err := <-stopped; err != nil {
		t.Errorf("停止时返回了错误：%v", err)
	}
	if time.Since(started) < 400*time.Millisecond {
		t.Errorf("停止只用了 %v：没有等在途的调用", time.Since(started))
	}
	if !strings.Contains(h.logs.String(), `"msg":"provider-signer stopped"`) {
		t.Error("没有记录停止")
	}
}

// 没有别的接口：操作表之外的路径对谁都是 404，包括健康检查和指标这类常见的名字。
func TestHasNoOtherEndpoints(t *testing.T) {
	carrier := newFakeCarrier(t, nil)
	h := newHarness(t, carrier).start()
	for _, path := range []string{"/", "/healthz", "/health", "/metrics", "/debug/pprof/", "/admin", "/v1/extauthz/check", "/sfintl", "/sfintl/v1"} {
		for _, method := range []string{"GET", "POST", "OPTIONS"} {
			a := h.must(call{method: method, path: path, body: "{}", headers: good()})
			if a.status != 404 || a.fields(t)["error"] != "unknown_operation" {
				t.Errorf("%s %s: %d %s", method, path, a.status, a.body)
			}
		}
	}
	if carrier.count() != 0 {
		t.Error("承运商收到了请求")
	}
}
