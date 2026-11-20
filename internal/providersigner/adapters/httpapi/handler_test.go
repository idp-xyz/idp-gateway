package httpapi

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"go.idp.xyz/idp-gateway/internal/platform/workloadtls/tlstest"
	"go.idp.xyz/idp-gateway/internal/providersigner/application"
	"go.idp.xyz/idp-gateway/internal/providersigner/domain"
	"go.idp.xyz/idp-gateway/internal/providersigner/ports"
)

// 下面三个值是编造的，与 domain/testdata/vectors.json 里的相同。
const (
	testAppKey = "idpgw-test-app-key-0001"
	testToken  = "auth_idpgw-test-token-0001"
	testAESKey = "MDEyMzQ1Njc4OTo7PD0+P0BBQkNERUZHSElKS0xNTk8"

	authorization = "Sf-OpenApi " + testAppKey + ";" + testToken + ";" + testAESKey
	gatewayID     = "spiffe://idp.test/egress/agentgateway"
	otherID       = "spiffe://idp.test/apps/other"
)

// carrier 是 ports.Carrier 的替身：数被调用的次数，答一个加密的信封。
type carrier struct {
	mu    sync.Mutex
	calls int
	last  ports.CarrierRequest // 最近一次收到的请求
	key   domain.Key
}

func (c *carrier) Send(_ context.Context, request ports.CarrierRequest) (ports.CarrierResponse, error) {
	c.mu.Lock()
	c.calls++
	c.last = request
	c.mu.Unlock()
	ciphertext, err := domain.Encrypt(c.key, testAppKey, []byte(`{"success":true}`), rand.Reader)
	if err != nil {
		return ports.CarrierResponse{}, err
	}
	return ports.CarrierResponse{Status: 200, Body: []byte(`{"apiResultCode":0,"apiResultData":"` + ciphertext + `"}`)}, nil
}

func (c *carrier) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.calls
}

type fixture struct {
	handler *Handler
	carrier *carrier
	logs    *bytes.Buffer
	gateway tlstest.Leaf
	other   tlstest.Leaf
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	key, err := domain.ParseKey(testAESKey)
	if err != nil {
		t.Fatal(err)
	}
	c := &carrier{key: key}
	service, err := application.New(c, application.Settings{Lang: "en", MaxRequestBytes: 64})
	if err != nil {
		t.Fatal(err)
	}
	ca := tlstest.NewCA(t, "workload CA")
	f := &fixture{carrier: c, logs: &bytes.Buffer{}, gateway: ca.Issue("gateway", []string{gatewayID}), other: ca.Issue("other", []string{otherID})}
	f.handler = New(service, gatewayID, slog.New(slog.NewJSONHandler(f.logs, nil)))
	return f
}

type attempt struct {
	method string
	target string
	peer   string // gateway、other、twoURIs 或空串（连接不是 TLS）
	header map[string][]string
	body   io.Reader
}

func (f *fixture) serve(t *testing.T, a attempt) *httptest.ResponseRecorder {
	t.Helper()
	if a.method == "" {
		a.method = http.MethodPost
	}
	if a.body == nil {
		a.body = strings.NewReader(`{"a":1}`)
	}
	request := httptest.NewRequest(a.method, a.target, a.body)
	for name, values := range a.header {
		request.Header[name] = values
	}
	switch a.peer {
	case "gateway":
		request.TLS = tlstest.PeerState(f.gateway)
	case "other":
		request.TLS = tlstest.PeerState(f.other)
	case "":
	default:
		t.Fatalf("没有这个对端 %q", a.peer)
	}
	recorder := httptest.NewRecorder()
	f.handler.ServeHTTP(recorder, request)
	return recorder
}

func jsonHeaders(extra ...string) map[string][]string {
	header := map[string][]string{"Content-Type": {"application/json"}, "Authorization": {authorization}}
	for i := 0; i+1 < len(extra); i += 2 {
		header[extra[i]] = []string{extra[i+1]}
	}
	return header
}

func code(t *testing.T, recorder *httptest.ResponseRecorder) string {
	t.Helper()
	var decoded map[string]string
	if err := json.Unmarshal(recorder.Body.Bytes(), &decoded); err != nil {
		t.Fatalf("答复不是 JSON：%q", recorder.Body.String())
	}
	return decoded["error"]
}

// 核对的顺序：身份、操作、查询串、Content-Type、凭证、正文。每个用例里，排在前面的检查都通过，
// 之后的检查全都不通过，答出来的必须是第一个不通过的那个，而且承运商不被联系。
func TestChecksRunInOrderAndTheCarrierIsNotContacted(t *testing.T) {
	const known = "/sfintl/v1/orders"
	badType := map[string][]string{"Content-Type": {"text/plain"}, "Authorization": {"Bearer x"}}
	badCredential := map[string][]string{"Content-Type": {"application/json"}}
	for _, c := range []struct {
		name   string
		a      attempt
		status int
		code   string
	}{
		{"another identity, everything else wrong too", attempt{method: "GET", target: "/nope?x=1", peer: "other", header: badType}, 403, "caller_not_allowed"},
		{"another identity on a good request", attempt{target: known, peer: "other", header: jsonHeaders()}, 403, "caller_not_allowed"},
		{"a connection that is not TLS", attempt{target: known, header: jsonHeaders()}, 403, "caller_not_allowed"},
		{"unknown path, everything after it wrong too", attempt{target: "/nope?x=1", peer: "gateway", header: badType}, 404, "unknown_operation"},
		{"GET on a known path", attempt{method: "GET", target: known + "?x=1", peer: "gateway", header: badType}, 404, "unknown_operation"},
		{"a trailing slash", attempt{target: known + "/", peer: "gateway", header: jsonHeaders()}, 404, "unknown_operation"},
		{"a longer path", attempt{target: known + "/1", peer: "gateway", header: jsonHeaders()}, 404, "unknown_operation"},
		{"the root", attempt{target: "/", peer: "gateway", header: jsonHeaders()}, 404, "unknown_operation"},
		{"a health path", attempt{method: "GET", target: "/healthz", peer: "gateway", header: jsonHeaders()}, 404, "unknown_operation"},
		{"a query, everything after it wrong too", attempt{target: known + "?x=1", peer: "gateway", header: badType}, 400, "query_not_allowed"},
		{"an empty query", attempt{target: known + "?", peer: "gateway", header: badType}, 400, "query_not_allowed"},
		{"a query on another operation", attempt{target: "/sfintl/v1/order-cancellations?a=b&c", peer: "gateway", header: jsonHeaders()}, 400, "query_not_allowed"},
		{"no Content-Type, credential wrong too", attempt{target: known, peer: "gateway", header: map[string][]string{"Authorization": {"Bearer x"}}}, 415, "unsupported_media_type"},
		{"text/plain", attempt{target: known, peer: "gateway", header: badType}, 415, "unsupported_media_type"},
		{"a media type that only starts like it", attempt{target: known, peer: "gateway", header: jsonHeaders("Content-Type", "application/jsonx")}, 415, "unsupported_media_type"},
		{"a +json type", attempt{target: known, peer: "gateway", header: jsonHeaders("Content-Type", "application/merge-patch+json")}, 415, "unsupported_media_type"},
		{"a wildcard type", attempt{target: known, peer: "gateway", header: jsonHeaders("Content-Type", "application/*")}, 415, "unsupported_media_type"},
		{"a malformed parameter", attempt{target: known, peer: "gateway", header: jsonHeaders("Content-Type", "application/json; charset")}, 415, "unsupported_media_type"},
		{"not a media type", attempt{target: known, peer: "gateway", header: jsonHeaders("Content-Type", ";;;")}, 415, "unsupported_media_type"},
		{"no credential, body too large too", attempt{target: known, peer: "gateway", header: badCredential,
			body: strings.NewReader(strings.Repeat("x", 1000))}, 403, "credential_malformed"},
		{"two credentials", attempt{target: known, peer: "gateway", header: map[string][]string{"Content-Type": {"application/json"},
			"Authorization": {authorization, authorization}}}, 403, "credential_malformed"},
		{"a body that is too large", attempt{target: known, peer: "gateway", header: jsonHeaders(), body: strings.NewReader(`{"a":"` + strings.Repeat("x", 100) + `"}`)}, 413, "request_too_large"},
		{"a body that is not an object", attempt{target: known, peer: "gateway", header: jsonHeaders(), body: strings.NewReader(`[1]`)}, 400, "body_not_json_object"},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newFixture(t)
			recorder := f.serve(t, c.a)
			if recorder.Code != c.status || code(t, recorder) != c.code || f.carrier.count() != 0 {
				t.Fatalf("%d %s，承运商被调用了 %d 次", recorder.Code, recorder.Body, f.carrier.count())
			}
			if got := recorder.Header().Get("Content-Type"); got != "application/json" || len(recorder.Header()) != 1 {
				t.Errorf("头 %v", recorder.Header())
			}
		})
	}
}

func TestServesTheThreeOperations(t *testing.T) {
	for path, id := range map[string]string{
		"/sfintl/v1/orders":               "orders.create",
		"/sfintl/v1/order-cancellations":  "orders.cancel",
		"/sfintl/v1/agent-number-queries": "agent-numbers.query",
	} {
		f := newFixture(t)
		for _, contentType := range []string{"application/json", "application/json; charset=utf-8", "Application/JSON", "application/json;charset=UTF-8"} {
			recorder := f.serve(t, attempt{target: path, peer: "gateway", header: jsonHeaders("Content-Type", contentType)})
			want := `{"apiResultCode":0,"apiResultData":{"success":true}}`
			if recorder.Code != 200 || recorder.Body.String() != want || recorder.Header().Get("Content-Type") != "application/json" || len(recorder.Header()) != 1 {
				t.Errorf("%s (%s)：%d %s %v", path, contentType, recorder.Code, recorder.Body, recorder.Header())
			}
		}
		if f.carrier.count() != 4 {
			t.Errorf("%s: 承运商被调用了 %d 次", path, f.carrier.count())
		}
		// 日志：每个请求一行。
		lines := strings.Split(strings.TrimSpace(f.logs.String()), "\n")
		if len(lines) != 4 {
			t.Fatalf("%s: %d 行日志", path, len(lines))
		}
		var line map[string]any
		if err := json.Unmarshal([]byte(lines[0]), &line); err != nil {
			t.Fatal(err)
		}
		if line["msg"] != "signer call" || line["level"] != "INFO" || line["operation"] != id || line["outcome"] != "ok" ||
			line["status"] != float64(200) || line["carrier_status"] != float64(200) || line["api_result_code"] != float64(0) ||
			line["request_bytes"] != float64(7) || line["response_bytes"] != float64(len(`{"apiResultCode":0,"apiResultData":{"success":true}}`)) {
			t.Errorf("%s: %v", path, line)
		}
	}
}

func TestLogLinesCarryTheStatedAttributesOnly(t *testing.T) {
	f := newFixture(t)
	f.serve(t, attempt{target: "/sfintl/v1/orders", peer: "gateway", header: jsonHeaders()})
	f.serve(t, attempt{target: "/nope", peer: "gateway", header: jsonHeaders()})
	f.serve(t, attempt{target: "/sfintl/v1/orders", peer: "other", header: jsonHeaders()})
	f.serve(t, attempt{target: "/sfintl/v1/order-cancellations", peer: "gateway", header: map[string][]string{"Content-Type": {"application/json"}, "Authorization": {"Sf-OpenApi bad"}}})

	lines := strings.Split(strings.TrimSpace(f.logs.String()), "\n")
	if len(lines) != 4 {
		t.Fatalf("%d 行日志：%s", len(lines), f.logs)
	}
	common := []string{"time", "level", "msg", "operation", "msg_type", "outcome", "status", "carrier_status", "elapsed_ms", "request_bytes", "response_bytes"}
	for i, want := range []struct {
		operation, msgType, outcome string
		status                      float64
		withCode                    bool
	}{
		{"orders.create", "IECS_CREATE_ORDER", "ok", 200, true},
		{"", "", "unknown_operation", 404, false},
		{"orders.create", "IECS_CREATE_ORDER", "caller_not_allowed", 403, false},
		{"orders.cancel", "IECS_CANCEL_ORDER", "credential_malformed", 403, false},
	} {
		var line map[string]any
		if err := json.Unmarshal([]byte(lines[i]), &line); err != nil {
			t.Fatal(err)
		}
		expected := len(common)
		if want.withCode {
			expected++
		}
		if len(line) != expected {
			t.Errorf("第 %d 行有 %d 个属性，期望 %d：%v", i+1, len(line), expected, line)
		}
		for _, name := range common {
			if _, present := line[name]; !present {
				t.Errorf("第 %d 行没有 %s：%v", i+1, name, line)
			}
		}
		if _, present := line["api_result_code"]; present != want.withCode {
			t.Errorf("第 %d 行的 api_result_code：%v", i+1, line)
		}
		if line["operation"] != want.operation || line["msg_type"] != want.msgType || line["outcome"] != want.outcome || line["status"] != want.status {
			t.Errorf("第 %d 行：%v", i+1, line)
		}
	}
	for _, leaked := range []string{testAppKey, testToken, testAESKey, "Sf-OpenApi", "Authorization", "success"} {
		if strings.Contains(f.logs.String(), leaked) {
			t.Errorf("日志里有 %q", leaked)
		}
	}
}

func TestPeerIdentityIsTheOnlyThingThatDecidesTheCaller(t *testing.T) {
	f := newFixture(t)
	// 请求头里自称是网关，没有用。
	recorder := f.serve(t, attempt{target: "/sfintl/v1/orders", peer: "other", header: jsonHeaders(
		"X-Forwarded-Client-Cert", gatewayID, "X-Idp-Caller", gatewayID, "X-Client-Identity", gatewayID)})
	if recorder.Code != 403 || code(t, recorder) != "caller_not_allowed" || f.carrier.count() != 0 {
		t.Fatalf("%d %s", recorder.Code, recorder.Body)
	}
}

// 没有网关身份（空串）时也不能把"没有身份"当成网关：对端没有 URI 时 PeerIdentity 是空串。
func TestAnEmptyIdentityNeverMatches(t *testing.T) {
	key, _ := domain.ParseKey(testAESKey)
	c := &carrier{key: key}
	service, err := application.New(c, application.Settings{Lang: "en", MaxRequestBytes: 64})
	if err != nil {
		t.Fatal(err)
	}
	handler := New(service, "", slog.New(slog.NewJSONHandler(io.Discard, nil)))
	request := httptest.NewRequest("POST", "/sfintl/v1/orders", strings.NewReader(`{}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", authorization)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != 403 || c.count() != 0 {
		t.Fatalf("%d %s", recorder.Code, recorder.Body)
	}
}

// 交给承运商的 msgType 和 lang 只由操作表和部署设置决定，调用方的头改不了它们。
func TestCallerHeadersDoNotChangeWhatIsSentToTheCarrier(t *testing.T) {
	for path, msgType := range map[string]string{
		"/sfintl/v1/orders":               "IECS_CREATE_ORDER",
		"/sfintl/v1/order-cancellations":  "IECS_CANCEL_ORDER",
		"/sfintl/v1/agent-number-queries": "IECS_QUERY_AGENTNO",
	} {
		f := newFixture(t)
		recorder := f.serve(t, attempt{target: path, peer: "gateway", header: jsonHeaders(
			"MsgType", "SOMETHING_ELSE", "Msgtype", "SOMETHING_ELSE", "msgType", "SOMETHING_ELSE", "Lang", "fr", "X-Msg-Type", "SOMETHING_ELSE",
			"Appkey", "caller-app-key", "Token", "caller-token", "Timestamp", "1", "Nonce", "caller-nonce", "Signature", "caller-signature")})
		if recorder.Code != 200 || f.carrier.count() != 1 {
			t.Fatalf("%s: %d %s", path, recorder.Code, recorder.Body)
		}
		sent := f.carrier.last
		if sent.MsgType != msgType || sent.Lang != "en" || sent.AppKey.Reveal() != testAppKey || sent.Token.Reveal() != testToken ||
			sent.Nonce == "caller-nonce" || sent.Signature == "caller-signature" || sent.Timestamp == "1" {
			t.Errorf("%s: 交给承运商的 msgType %q，lang %q", path, sent.MsgType, sent.Lang)
		}
	}
}
