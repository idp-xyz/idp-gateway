package application

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"testing/iotest"
	"time"

	"go.idp.xyz/idp-gateway/internal/providersigner/domain"
	"go.idp.xyz/idp-gateway/internal/providersigner/ports"
)

// 下面三个值是编造的，与 domain/testdata/vectors.json 里的相同。
const (
	testAppKey = "idpgw-test-app-key-0001"
	testToken  = "auth_idpgw-test-token-0001"
	testAESKey = "MDEyMzQ1Njc4OTo7PD0+P0BBQkNERUZHSElKS0xNTk8"

	authorization = "Sf-OpenApi " + testAppKey + ";" + testToken + ";" + testAESKey
)

var createOrder = domain.Operation{ID: "orders.create", Method: "POST", Path: "/sfintl/v1/orders", MsgType: "IECS_CREATE_ORDER"}

func testKey(t *testing.T) domain.Key {
	t.Helper()
	key, err := domain.ParseKey(testAESKey)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// fakeCarrier 是 ports.Carrier 的替身：记下每次调用，答复由 respond 决定。
type fakeCarrier struct {
	calls   []ports.CarrierRequest
	respond func(ports.CarrierRequest) (ports.CarrierResponse, error)
}

func (f *fakeCarrier) Send(_ context.Context, request ports.CarrierRequest) (ports.CarrierResponse, error) {
	f.calls = append(f.calls, request)
	return f.respond(request)
}

func answering(response ports.CarrierResponse, err error) *fakeCarrier {
	return &fakeCarrier{respond: func(ports.CarrierRequest) (ports.CarrierResponse, error) { return response, err }}
}

// counting 是个随机源：依次给出字节 0、1、2……
type counting struct{ next byte }

func (c *counting) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = c.next
		c.next++
	}
	return len(p), nil
}

func newService(t *testing.T, carrier ports.Carrier, options ...Option) *Service {
	t.Helper()
	service, err := New(carrier, Settings{Lang: "zh-HK", MaxRequestBytes: 1 << 10}, options...)
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func call(body string) Call {
	return Call{Operation: createOrder, Authorization: []string{authorization}, Body: strings.NewReader(body)}
}

func envelope(t *testing.T, key domain.Key, data string) []byte {
	t.Helper()
	ciphertext, err := domain.Encrypt(key, testAppKey, []byte(data), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return []byte(`{"apiResultCode":0,"apiErrorMsg":null,"apiResultData":"` + ciphertext + `","apiTimestamp":1763611200000}`)
}

// failureOf 解出答复里的错误：只有 error、detail，以及（有的话）carrier_status。
func failureOf(t *testing.T, result Result) (code string, carrierStatus float64) {
	t.Helper()
	var decoded map[string]any
	if err := json.Unmarshal(result.Body, &decoded); err != nil {
		t.Fatalf("答复不是 JSON：%q", result.Body)
	}
	for name := range decoded {
		if name != "error" && name != "detail" && name != "carrier_status" {
			t.Errorf("答复里有多余的成员 %q", name)
		}
	}
	if detail, _ := decoded["detail"].(string); detail == "" {
		t.Errorf("答复没有说明：%s", result.Body)
	}
	code, _ = decoded["error"].(string)
	carrierStatus, _ = decoded["carrier_status"].(float64)
	return code, carrierStatus
}

func TestHandleBuildsTheCarrierRequest(t *testing.T) {
	key := testKey(t)
	now := time.UnixMilli(1763611200123)
	carrier := answering(ports.CarrierResponse{}, nil)
	const business = `{"success": true, "msg": "<ok> & 顺丰"}`
	carrier.respond = func(ports.CarrierRequest) (ports.CarrierResponse, error) {
		return ports.CarrierResponse{Status: 200, Body: envelope(t, key, business)}, nil
	}
	service := newService(t, carrier, WithClock(func() time.Time { return now }), WithRandom(&counting{}))

	// 间距和键序都不寻常：它要原样进入明文。
	const body = "{ \"b\" :  1,\n\"a\": [ 2 , 1 ]  }\n"
	result := service.Handle(context.Background(), call(body))

	if len(carrier.calls) != 1 {
		t.Fatalf("承运商被调用了 %d 次", len(carrier.calls))
	}
	sent := carrier.calls[0]
	if sent.MsgType != "IECS_CREATE_ORDER" || sent.Lang != "zh-HK" || sent.AppKey.Reveal() != testAppKey || sent.Token.Reveal() != testToken {
		t.Errorf("请求头的值不对：%+v", sent)
	}
	if sent.Timestamp != "1763611200123" {
		t.Errorf("时间戳 %s", sent.Timestamp)
	}
	if sent.Nonce != "000102030405060708090a0b0c0d0e0f" {
		t.Errorf("随机数 %s：应当是随机源的头 16 个字节", sent.Nonce)
	}
	if plain, err := domain.Decrypt(key, testAppKey, sent.Ciphertext); err != nil || string(plain) != body {
		t.Errorf("密文解开得到 %q，%v；要的是 %q", plain, err, body)
	}
	if want := domain.Sign(testToken, sent.Timestamp, sent.Nonce, sent.Ciphertext); sent.Signature != want {
		t.Errorf("签名 %s，期望 %s", sent.Signature, want)
	}
	// 明文开头的 16 个字符是随机源的第 16 到 31 个字节（0x10 到 0x1f）映射出来的。
	if sent.Ciphertext == "" || strings.ContainsAny(sent.Ciphertext, " \n\"") {
		t.Errorf("密文 %q", sent.Ciphertext)
	}

	want := `{"apiErrorMsg":null,"apiResultCode":0,"apiResultData":` + business + `,"apiTimestamp":1763611200000}`
	if result.Status != 200 || string(result.Body) != want || result.Outcome != domain.OutcomeOK ||
		result.CarrierStatus != 200 || !result.HasAPIResultCode || result.APIResultCode != 0 || result.RequestBytes != len(body) {
		t.Errorf("结果不对：%+v\n%s", result, result.Body)
	}
}

func TestHandleCredentialComesBeforeTheBody(t *testing.T) {
	for name, values := range map[string][]string{
		"no header":       nil,
		"two headers":     {authorization, authorization},
		"two, one bad":    {authorization, "Bearer x"},
		"wrong scheme":    {"Bearer " + testToken},
		"lower case":      {strings.Replace(authorization, "Sf-OpenApi", "sf-openapi", 1)},
		"an empty header": {""},
		"bad key":         {"Sf-OpenApi " + testAppKey + ";" + testToken + ";" + testAESKey[:42]},
	} {
		carrier := answering(ports.CarrierResponse{}, errors.New("must not be called"))
		service := newService(t, carrier)
		// 凭证不对时正文一个字节也不读：读了就是在凭证之前做了正文的检查。
		body := iotest.ErrReader(errors.New("the body must not be read"))
		result := service.Handle(context.Background(), Call{Operation: createOrder, Authorization: values, Body: body})
		code, _ := failureOf(t, result)
		if result.Status != 403 || code != "credential_malformed" || result.Outcome != "credential_malformed" ||
			result.RequestBytes != 0 || len(carrier.calls) != 0 || result.CarrierStatus != 0 || result.HasAPIResultCode {
			t.Errorf("%s: %+v", name, result)
		}
	}
}

func TestHandleBody(t *testing.T) {
	const maxBytes = 12
	for _, c := range []struct {
		name      string
		body      io.Reader
		status    int
		code      string
		bytesRead int
		sent      bool
	}{
		{"exactly the limit", strings.NewReader(`{"a":"1234"}`), 200, "", 12, true},
		{"one byte over the limit", strings.NewReader(`{"a":"12345"}`), 413, "request_too_large", 13, false},
		{"far over the limit", strings.NewReader(`{"a":"` + strings.Repeat("x", 5000) + `"}`), 413, "request_too_large", 13, false},
		{"over the limit and not JSON", strings.NewReader(strings.Repeat("x", 100)), 413, "request_too_large", 13, false},
		{"an array", strings.NewReader(`[1]`), 400, "body_not_json_object", 3, false},
		{"a string", strings.NewReader(`"x"`), 400, "body_not_json_object", 3, false},
		{"a number", strings.NewReader(`1`), 400, "body_not_json_object", 1, false},
		{"two objects", strings.NewReader(`{} {}`), 400, "body_not_json_object", 5, false},
		{"empty", strings.NewReader(``), 400, "body_not_json_object", 0, false},
		{"no body at all", nil, 400, "body_not_json_object", 0, false},
		{"invalid JSON", strings.NewReader(`{"a":`), 400, "body_not_json_object", 5, false},
		{"a read error after a whole object", io.MultiReader(strings.NewReader(`{}`), iotest.ErrReader(errors.New("connection reset"))), 400, "body_not_json_object", 2, false},
		{"a read error at once", iotest.ErrReader(errors.New("connection reset")), 400, "body_not_json_object", 0, false},
		{"a timeout after a whole object", iotest.TimeoutReader(strings.NewReader(`{"a":1}`)), 400, "body_not_json_object", 7, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			key := testKey(t)
			carrier := answering(ports.CarrierResponse{Status: 200, Body: envelope(t, key, `{}`)}, nil)
			service, err := New(carrier, Settings{Lang: "en", MaxRequestBytes: maxBytes})
			if err != nil {
				t.Fatal(err)
			}
			result := service.Handle(context.Background(), Call{Operation: createOrder, Authorization: []string{authorization}, Body: c.body})
			if result.Status != c.status || result.RequestBytes != c.bytesRead || (len(carrier.calls) == 1) != c.sent {
				t.Fatalf("%+v，承运商被调用了 %d 次", result, len(carrier.calls))
			}
			if c.code != "" {
				if code, _ := failureOf(t, result); code != c.code || result.Outcome != c.code {
					t.Errorf("错误码 %q，outcome %q", code, result.Outcome)
				}
			}
		})
	}
}

func TestHandleRandomSourceFailure(t *testing.T) {
	for name, random := range map[string]io.Reader{
		"fails at once":               iotest.ErrReader(errors.New("entropy exhausted")),
		"gives the nonce, then fails": io.MultiReader(bytes.NewReader(make([]byte, 16)), iotest.ErrReader(errors.New("entropy exhausted"))),
		"short nonce":                 bytes.NewReader(make([]byte, 15)),
		"nonce and half the prefix":   io.MultiReader(bytes.NewReader(make([]byte, 24)), iotest.ErrReader(errors.New("entropy exhausted"))),
	} {
		carrier := answering(ports.CarrierResponse{}, errors.New("must not be called"))
		result := newService(t, carrier, WithRandom(random)).Handle(context.Background(), call(`{}`))
		if code, _ := failureOf(t, result); result.Status != 500 || code != "internal" || result.Outcome != "internal" || len(carrier.calls) != 0 {
			t.Errorf("%s: %+v，承运商被调用了 %d 次", name, result, len(carrier.calls))
		}
		if strings.Contains(string(result.Body), "entropy") {
			t.Errorf("%s: 答复里有底层错误的文字", name)
		}
	}
}

func TestHandleCarrierOutcomes(t *testing.T) {
	key := testKey(t)
	const secret = `{"marker":"PLAINTEXT-MARKER-91ce"}`
	genuine := envelope(t, key, secret)
	wrongKey, err := domain.ParseKey("QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVowMTIzNDU")
	if err != nil {
		t.Fatal(err)
	}
	foreign, _ := domain.Encrypt(wrongKey, testAppKey, []byte(secret), rand.Reader)
	otherApp, _ := domain.Encrypt(key, "another-app-key", []byte(secret), rand.Reader)

	refused := `{"apiResultCode": 500, "apiErrorMsg": "Access denied, token invalid", "apiTimestamp": 1}`
	noData := `{"apiResultCode":0,"apiErrorMsg":null}`
	for _, c := range []struct {
		name     string
		response ports.CarrierResponse
		err      error
		status   int
		code     string // 错误码；空表示成功交回
		carrier  int    // 错误里的 carrier_status，也是 Result.CarrierStatus
		apiCode  int64
		apiKnown bool
		outcome  string
		body     string // 成功交回时的正文；空表示不检查
	}{
		{"timeout", ports.CarrierResponse{}, ports.ErrTimeout, 504, "carrier_timeout", 0, 0, false, "carrier_timeout", ""},
		{"wrapped timeout", ports.CarrierResponse{}, fmt.Errorf("while sending: %w", ports.ErrTimeout), 504, "carrier_timeout", 0, 0, false, "carrier_timeout", ""},
		{"unreachable", ports.CarrierResponse{}, ports.ErrUnreachable, 502, "carrier_unreachable", 0, 0, false, "carrier_unreachable", ""},
		{"an unknown error", ports.CarrierResponse{}, errors.New("dial tcp 203.0.113.9:443: connect: secret-internal-text"), 502, "carrier_unreachable", 0, 0, false, "carrier_unreachable", ""},
		{"answer too large", ports.CarrierResponse{}, ports.ErrAnswerTooLarge, 502, "carrier_answer_unreadable", 200, 0, false, "carrier_answer_unreadable", ""},
		{"status 500", ports.CarrierResponse{Status: 500, Body: []byte(refused)}, nil, 502, "carrier_status", 500, 0, false, "carrier_status", ""},
		{"status 302", ports.CarrierResponse{Status: 302}, nil, 502, "carrier_status", 302, 0, false, "carrier_status", ""},
		{"status 204", ports.CarrierResponse{Status: 204}, nil, 502, "carrier_status", 204, 0, false, "carrier_status", ""},
		{"status 201", ports.CarrierResponse{Status: 201, Body: genuine}, nil, 502, "carrier_status", 201, 0, false, "carrier_status", ""},
		{"status 0", ports.CarrierResponse{Status: 0, Body: genuine}, nil, 502, "carrier_status", 0, 0, false, "carrier_status", ""},
		{"not JSON", ports.CarrierResponse{Status: 200, Body: []byte("<html>gateway error</html>")}, nil, 502, "carrier_answer_unreadable", 200, 0, false, "carrier_answer_unreadable", ""},
		{"an array", ports.CarrierResponse{Status: 200, Body: []byte(`[]`)}, nil, 502, "carrier_answer_unreadable", 200, 0, false, "carrier_answer_unreadable", ""},
		{"no result code", ports.CarrierResponse{Status: 200, Body: []byte(`{"apiResultData":null}`)}, nil, 502, "carrier_answer_unreadable", 200, 0, false, "carrier_answer_unreadable", ""},
		{"data under another key", ports.CarrierResponse{Status: 200, Body: []byte(`{"apiResultCode":0,"apiResultData":"` + foreign + `"}`)}, nil, 502, "carrier_answer_unreadable", 200, 0, true, "carrier_answer_unreadable", ""},
		{"data under another appKey", ports.CarrierResponse{Status: 200, Body: []byte(`{"apiResultCode":0,"apiResultData":"` + otherApp + `"}`)}, nil, 502, "carrier_answer_unreadable", 200, 0, true, "carrier_answer_unreadable", ""},
		{"data a number", ports.CarrierResponse{Status: 200, Body: []byte(`{"apiResultCode":0,"apiResultData":7}`)}, nil, 502, "carrier_answer_unreadable", 200, 0, true, "carrier_answer_unreadable", ""},
		{"a refusal", ports.CarrierResponse{Status: 200, Body: []byte(refused)}, nil, 200, "", 200, 500, true, "carrier_refused", refused},
		{"no data", ports.CarrierResponse{Status: 200, Body: []byte(noData)}, nil, 200, "", 200, 0, true, "ok_no_data", noData},
		{"data", ports.CarrierResponse{Status: 200, Body: genuine}, nil, 200, "", 200, 0, true, "ok", ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			carrier := answering(c.response, c.err)
			result := newService(t, carrier).Handle(context.Background(), call(`{"a":1}`))
			// 一次，不重试：不管是什么结局。
			if len(carrier.calls) != 1 {
				t.Fatalf("承运商被调用了 %d 次", len(carrier.calls))
			}
			if result.Status != c.status || result.Outcome != c.outcome || result.CarrierStatus != c.carrier ||
				result.HasAPIResultCode != c.apiKnown || result.APIResultCode != c.apiCode {
				t.Fatalf("结果不对：%+v", result)
			}
			if c.code == "" {
				if c.body != "" && string(result.Body) != c.body {
					t.Errorf("正文 %s", result.Body)
				}
				return
			}
			code, carrierStatus := failureOf(t, result)
			if code != c.code || int(carrierStatus) != c.carrier && c.code == "carrier_status" {
				t.Errorf("错误码 %q，carrier_status %v", code, carrierStatus)
			}
			if c.code != "carrier_status" && strings.Contains(string(result.Body), "carrier_status") {
				t.Errorf("只有 carrier_status 这种错误才写出 carrier_status：%s", result.Body)
			}
			// 错误答复里没有请求的任何东西，没有底层错误的文字，没有承运商的内容。
			sent := carrier.calls[0]
			for _, leaked := range []string{testAppKey, testToken, testAESKey, sent.Ciphertext, sent.Signature, sent.Nonce,
				"secret-internal-text", "203.0.113.9", "PLAINTEXT-MARKER", foreign, otherApp, "Access denied", "gateway error"} {
				if strings.Contains(string(result.Body), leaked) {
					t.Errorf("答复里有 %q：%s", leaked, result.Body)
				}
			}
		})
	}
}

func TestHandlePassesNothingOfTheCallerToTheCarrier(t *testing.T) {
	carrier := answering(ports.CarrierResponse{Status: 500}, nil)
	service := newService(t, carrier)
	service.Handle(context.Background(), Call{
		Operation:     domain.Operation{ID: "orders.cancel", Method: "POST", Path: "/sfintl/v1/order-cancellations", MsgType: "IECS_CANCEL_ORDER"},
		Authorization: []string{authorization},
		Body:          strings.NewReader(`{}`),
	})
	if len(carrier.calls) != 1 || carrier.calls[0].MsgType != "IECS_CANCEL_ORDER" || carrier.calls[0].Lang != "zh-HK" {
		t.Fatalf("%+v", carrier.calls)
	}
}

func TestNewRefusesBadSettings(t *testing.T) {
	good := Settings{Lang: "en", MaxRequestBytes: 1}
	carrier := answering(ports.CarrierResponse{}, nil)
	if _, err := New(carrier, good); err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]struct {
		carrier  ports.Carrier
		settings Settings
	}{
		"no carrier":        {nil, good},
		"unknown lang":      {carrier, Settings{Lang: "fr", MaxRequestBytes: 1}},
		"empty lang":        {carrier, Settings{MaxRequestBytes: 1}},
		"zero request size": {carrier, Settings{Lang: "en"}},
		"negative size":     {carrier, Settings{Lang: "en", MaxRequestBytes: -1}},
	} {
		if _, err := New(c.carrier, c.settings); err == nil {
			t.Errorf("%s: 没有被拒绝", name)
		}
	}
}

func TestFailures(t *testing.T) {
	all := map[string]Failure{
		"caller_not_allowed": CallerNotAllowed, "unknown_operation": UnknownOperation, "query_not_allowed": QueryNotAllowed,
		"unsupported_media_type": UnsupportedMediaType, "credential_malformed": CredentialMalformed,
		"request_too_large": RequestTooLarge, "body_not_json_object": BodyNotJSONObject, "internal": Internal,
		"carrier_timeout": CarrierTimeout, "carrier_unreachable": CarrierUnreachable, "carrier_status": CarrierStatus,
		"carrier_answer_unreadable": CarrierAnswerUnreadable,
	}
	statuses := map[string]int{
		"caller_not_allowed": 403, "unknown_operation": 404, "query_not_allowed": 400, "unsupported_media_type": 415,
		"credential_malformed": 403, "request_too_large": 413, "body_not_json_object": 400, "internal": 500,
		"carrier_timeout": 504, "carrier_unreachable": 502, "carrier_status": 502, "carrier_answer_unreadable": 502,
	}
	for code, failure := range all {
		if failure.Code != code || failure.Status != statuses[code] || failure.Detail == "" {
			t.Errorf("%s: %+v", code, failure)
		}
		result := Refuse(failure)
		if result.Status != failure.Status || result.Outcome != code || result.RequestBytes != 0 || result.CarrierStatus != 0 {
			t.Errorf("%s: %+v", code, result)
		}
		var decoded map[string]any
		if err := json.Unmarshal(result.Body, &decoded); err != nil || len(decoded) != 2 || decoded["error"] != code || decoded["detail"] != failure.Detail {
			t.Errorf("%s: %s %v", code, result.Body, err)
		}
	}
}
