package domain

import (
	"crypto/rand"
	"errors"
	"strings"
	"testing"
)

func TestIsJSONObject(t *testing.T) {
	for body, want := range map[string]bool{
		`{}`:                        true,
		`{"a":1}`:                   true,
		" \t\r\n{ \"a\" : 1 }\n":    true,
		`{"a":{"b":[1,2,{"c":3}]}}`: true,
		``:                          false,
		` `:                         false,
		`[1]`:                       false,
		`[]`:                        false,
		`"x"`:                       false,
		`1`:                         false,
		`true`:                      false,
		`null`:                      false,
		`{} {}`:                     false,
		`{}{}`:                      false,
		`{} x`:                      false,
		`x {}`:                      false,
		`{"a":1`:                    false,
		`{"a":}`:                    false,
		`{'a':1}`:                   false,
		`{"a":1,}`:                  false,
		"\ufeff{}":                  false,
		"\x00{}":                    false,
	} {
		if got := IsJSONObject([]byte(body)); got != want {
			t.Errorf("%q: %v", body, got)
		}
	}
	if IsJSONObject(nil) {
		t.Error("nil 不是 JSON 对象")
	}
}

func TestJSONInteger(t *testing.T) {
	for raw, want := range map[string]struct {
		n  int64
		ok bool
	}{
		"0": {0, true}, "-0": {0, true}, "7": {7, true}, "500": {500, true}, "1004": {1004, true}, "-1": {-1, true},
		"9223372036854775807": {9223372036854775807, true}, "-9223372036854775808": {-9223372036854775808, true},
		"9223372036854775808": {0, false}, "-9223372036854775809": {0, false}, "99999999999999999999999": {0, false},
		"": {0, false}, "-": {0, false}, "null": {0, false}, `"0"`: {0, false}, "0.0": {0, false}, "1e0": {0, false}, "1E0": {0, false},
		"1.5": {0, false}, "01": {0, false}, "00": {0, false}, "+1": {0, false}, "0x10": {0, false}, "true": {0, false},
		"[0]": {0, false}, "{}": {0, false}, " 0": {0, false}, "0 ": {0, false}, "--1": {0, false}, "1_000": {0, false},
	} {
		n, ok := jsonInteger([]byte(raw))
		if ok != want.ok || (ok && n != want.n) {
			t.Errorf("%q: %d %v", raw, n, ok)
		}
	}
}

func TestOpenAnswer(t *testing.T) {
	v := loadVectors(t)
	key := vectorKey(t, v)
	appKey := v.AppKey

	encrypt := func(t *testing.T, plain string) string {
		t.Helper()
		ciphertext, err := Encrypt(key, appKey, []byte(plain), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return ciphertext
	}
	elsewhere := func(t *testing.T, plain string, otherAppKey string) string {
		t.Helper()
		other, err := ParseKey(otherKey)
		if err != nil {
			t.Fatal(err)
		}
		ciphertext, err := Encrypt(other, otherAppKey, []byte(plain), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return ciphertext
	}
	// quote 把密文写成 JSON 字符串；有的编码器会把 "/" 写成 "\/"，所以两种写法都要能读。
	quote := func(ciphertext string) string { return `"` + ciphertext + `"` }
	quoteEscaped := func(ciphertext string) string { return `"` + strings.ReplaceAll(ciphertext, "/", `\/`) + `"` }

	t.Run("a refusal passes through byte for byte", func(t *testing.T) {
		for _, body := range []string{
			`{"apiResultCode": 500, "apiErrorMsg": "Access denied, token invalid", "apiResultData": null, "apiTimestamp": 1763611200000}`,
			"\n  {\"apiResultCode\":1001,\"apiErrorMsg\":\"x \\u003c y\"}\r\n",
			`{"apiResultCode":-1}`,
			`{"apiResultCode":700,"apiResultData":"this is not base64 and is not decrypted"}`,
			`{"apiResultCode":702,"apiResultData":{"unexpected":"object"}}`,
			`{"apiResultCode":9223372036854775807}`,
		} {
			answer, err := OpenAnswer([]byte(body), key, appKey)
			if err != nil || string(answer.Body) != body || answer.Outcome != OutcomeCarrierRefused || !answer.CodeKnown || answer.Code == 0 {
				t.Errorf("%q：%+v %v", body, answer, err)
			}
		}
		answer, _ := OpenAnswer([]byte(`{"apiResultCode":505}`), key, appKey)
		if answer.Code != 505 {
			t.Errorf("code %d", answer.Code)
		}
	})

	t.Run("code zero without data passes through byte for byte", func(t *testing.T) {
		for _, body := range []string{
			`{"apiResultCode":0}`,
			`{"apiResultCode":0,"apiResultData":null}`,
			"\n{ \"apiResultCode\" : 0 ,\n \"apiResultData\" : null , \"apiTimestamp\": 1 }\n",
			`{"apiResultCode":-0,"apiTimestamp":1}`,
		} {
			answer, err := OpenAnswer([]byte(body), key, appKey)
			if err != nil || string(answer.Body) != body || answer.Outcome != OutcomeOKNoData || !answer.CodeKnown || answer.Code != 0 {
				t.Errorf("%q：%+v %v", body, answer, err)
			}
		}
	})

	t.Run("the data is replaced by the plaintext and the other members keep their raw values", func(t *testing.T) {
		const business = "{\"success\": true,\n \"msg\": \"<ok> & 顺丰 \u2028 \\u0041\",\n \"list\": [ 1,  2.50e+3 ]}"
		for name, literal := range map[string]string{"plain": quote(encrypt(t, business)), "escaped slash": quoteEscaped(encrypt(t, business))} {
			body := `{"apiTimestamp": 12345678901234567890123, "apiResultData": ` + literal +
				`, "extra": {"k": [1,  2.50e+3 ], "n": null}, "apiResultCode": 0, "apiErrorMsg": "x \u003c y /"}`
			answer, err := OpenAnswer([]byte(body), key, appKey)
			if err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			want := `{"apiErrorMsg":"x \u003c y /","apiResultCode":0,"apiResultData":` + business +
				`,"apiTimestamp":12345678901234567890123,"extra":{"k": [1,  2.50e+3 ], "n": null}}`
			if string(answer.Body) != want {
				t.Errorf("%s:\n得到 %s\n期望 %s", name, answer.Body, want)
			}
			if answer.Outcome != OutcomeOK || !answer.CodeKnown || answer.Code != 0 {
				t.Errorf("%s: %+v", name, answer)
			}
		}
	})

	t.Run("any JSON value is acceptable as the plaintext", func(t *testing.T) {
		for _, plain := range []string{`{}`, `[]`, `[1,2]`, `"text"`, `0`, `-1.5e3`, `true`, `null`, ` {"a":1} `, "\n[ ]\n"} {
			body := `{"apiResultCode":0,"apiResultData":` + quote(encrypt(t, plain)) + `}`
			answer, err := OpenAnswer([]byte(body), key, appKey)
			want := `{"apiResultCode":0,"apiResultData":` + plain + `}`
			if err != nil || string(answer.Body) != want || answer.Outcome != OutcomeOK {
				t.Errorf("%q：%s %v", plain, answer.Body, err)
			}
		}
	})

	t.Run("member names are written without HTML escaping and sorted", func(t *testing.T) {
		body := `{"z":1,"<a>":2,"a&b":3,"é":4,"apiResultCode":0,"apiResultData":` + quote(encrypt(t, `{}`)) + `}`
		answer, err := OpenAnswer([]byte(body), key, appKey)
		want := `{"<a>":2,"a&b":3,"apiResultCode":0,"apiResultData":{},"z":1,"é":4}`
		if err != nil || string(answer.Body) != want {
			t.Errorf("%s %v", answer.Body, err)
		}
	})

	unreadable := []struct {
		name      string
		body      string
		want      error
		codeKnown bool
	}{
		{"not JSON", `not json`, errNotObject, false},
		{"empty", ``, errNotObject, false},
		{"two JSON values", `{"apiResultCode":0} {"apiResultCode":0}`, errNotObject, false},
		{"two objects without a space", `{"apiResultCode":500}{"apiResultCode":500}`, errNotObject, false},
		{"an array", `[{"apiResultCode":0}]`, errNotObject, false},
		{"a string", `"{\"apiResultCode\":0}"`, errNotObject, false},
		{"a number", `0`, errNotObject, false},
		{"truncated", `{"apiResultCode":0`, errNotObject, false},
		{"preceded by a byte order mark", "\ufeff{\"apiResultCode\":500}", errNotObject, false},
		{"code as a string", `{"apiResultCode":"0","apiResultData":null}`, errNoCode, false},
		{"code as a string of another value", `{"apiResultCode":"500"}`, errNoCode, false},
		{"code as 0.0", `{"apiResultCode":0.0}`, errNoCode, false},
		{"code as 1e0", `{"apiResultCode":1e0}`, errNoCode, false},
		{"code as 5E2", `{"apiResultCode":5E2}`, errNoCode, false},
		{"code as 500.5", `{"apiResultCode":500.5}`, errNoCode, false},
		{"code absent", `{"apiResultData":null,"apiTimestamp":1}`, errNoCode, false},
		{"code null", `{"apiResultCode":null}`, errNoCode, false},
		{"code a boolean", `{"apiResultCode":true}`, errNoCode, false},
		{"code an array", `{"apiResultCode":[0]}`, errNoCode, false},
		{"code too large for 64 bits", `{"apiResultCode":9223372036854775808}`, errNoCode, false},
		{"empty object", `{}`, errNoCode, false},
		{"data a number", `{"apiResultCode":0,"apiResultData":5}`, errDataType, true},
		{"data a boolean", `{"apiResultCode":0,"apiResultData":false}`, errDataType, true},
		{"data an object", `{"apiResultCode":0,"apiResultData":{}}`, errDataType, true},
		{"data an array", `{"apiResultCode":0,"apiResultData":[]}`, errDataType, true},
		{"data an empty string", `{"apiResultCode":0,"apiResultData":""}`, errNotDecoded, true},
		{"data not base64", `{"apiResultCode":0,"apiResultData":"not base64 at all"}`, errNotDecoded, true},
		{"data not a whole number of blocks", `{"apiResultCode":0,"apiResultData":"AAAA"}`, errNotDecoded, true},
	}
	for _, c := range unreadable {
		t.Run(c.name, func(t *testing.T) {
			answer, err := OpenAnswer([]byte(c.body), key, appKey)
			if !errors.Is(err, c.want) || !errors.Is(err, ErrAnswerUnreadable) {
				t.Fatalf("错误是 %v", err)
			}
			if answer.Body != nil || answer.Outcome != "" || answer.CodeKnown != c.codeKnown || answer.Code != 0 {
				t.Errorf("读不成的应答带着内容：%+v", answer)
			}
		})
	}

	t.Run("data that does not decrypt, and nothing of it is returned", func(t *testing.T) {
		const secret = `{"marker":"PLAINTEXT-MARKER-77aa"}`
		genuine := encrypt(t, secret)
		cases := map[string]string{
			"another key":                    elsewhere(t, secret, appKey),
			"another appKey":                 encryptWithAppKey(t, key, secret, "another-app-key"),
			"appKey that is a prefix":        encryptWithAppKey(t, key, secret, appKey[:len(appKey)-1]),
			"appKey that is an extension":    encryptWithAppKey(t, key, secret, appKey+"x"),
			"another key and another appKey": elsewhere(t, secret, "another-app-key"),
			"the last cipher block replaced": genuine[:len(genuine)-4] + "AAAA",
		}
		for name, ciphertext := range cases {
			body := `{"apiResultCode":0,"apiErrorMsg":null,"apiResultData":` + quote(ciphertext) + `}`
			answer, err := OpenAnswer([]byte(body), key, appKey)
			if !errors.Is(err, errNotDecoded) || answer.Body != nil || answer.Outcome != "" || !answer.CodeKnown || answer.Code != 0 {
				t.Errorf("%s: %+v %v", name, answer, err)
				continue
			}
			for _, leaked := range []string{ciphertext, "PLAINTEXT-MARKER", appKey} {
				if strings.Contains(err.Error(), leaked) {
					t.Errorf("%s: 错误文字里有 %q", name, leaked)
				}
			}
		}
	})

	t.Run("decrypted text that is not JSON", func(t *testing.T) {
		for _, plain := range []string{`not json`, ``, `{} x`, `{"a":1`, `{'a':1}`, `{"a":1}{"b":2}`, "\ufeff{}", `undefined`} {
			body := `{"apiResultCode":0,"apiResultData":` + quote(encrypt(t, plain)) + `}`
			answer, err := OpenAnswer([]byte(body), key, appKey)
			if !errors.Is(err, errNotJSONData) || answer.Body != nil || answer.Outcome != "" || !answer.CodeKnown {
				t.Errorf("%q：%+v %v", plain, answer, err)
			}
		}
	})
}

func encryptWithAppKey(t *testing.T, key Key, plain, appKey string) string {
	t.Helper()
	ciphertext, err := Encrypt(key, appKey, []byte(plain), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return ciphertext
}
