package domain

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strconv"
)

// 应答的结局，写进每一行日志的 outcome。
const (
	OutcomeOK             = "ok"              // apiResultCode 为 0，apiResultData 解密成功
	OutcomeCarrierRefused = "carrier_refused" // apiResultCode 不是 0，信封原样交回
	OutcomeOKNoData       = "ok_no_data"      // apiResultCode 为 0，没有 apiResultData
)

// ErrAnswerUnreadable 是承运商的应答读不成时的错误。下面每一种原因都包着它，文字固定，
// 不带密文、半解开的明文，也不带承运商写的 apiErrorMsg。
var ErrAnswerUnreadable = errors.New("carrier answer is unreadable")

var (
	errNotObject   = fmt.Errorf("%w: not exactly one JSON object", ErrAnswerUnreadable)
	errNoCode      = fmt.Errorf("%w: apiResultCode is not a JSON integer", ErrAnswerUnreadable)
	errDataType    = fmt.Errorf("%w: apiResultData is neither a string nor null", ErrAnswerUnreadable)
	errNotDecoded  = fmt.Errorf("%w: apiResultData does not decrypt", ErrAnswerUnreadable)
	errNotJSONData = fmt.Errorf("%w: decrypted apiResultData is not JSON", ErrAnswerUnreadable)
	errEncode      = fmt.Errorf("%w: answer cannot be re-encoded", ErrAnswerUnreadable)
)

// IsJSONObject 报告 body 是不是恰好一个 JSON 值，并且这个值是对象（第一个非空白字节是 '{'）。
func IsJSONObject(body []byte) bool {
	if !json.Valid(body) {
		return false
	}
	trimmed := bytes.TrimLeft(body, " \t\r\n")
	return len(trimmed) > 0 && trimmed[0] == '{'
}

// Answer 是读完承运商应答之后要交给调用方的东西。
type Answer struct {
	// Body 是要答给网关的 JSON；读不成时为 nil。
	Body []byte
	// Outcome 是 OutcomeOK、OutcomeCarrierRefused 或 OutcomeOKNoData；读不成时为空。
	Outcome string
	// Code 是信封里的 apiResultCode，CodeKnown 为真时才有意义。读不成的应答，只要读到了
	// apiResultCode（例如它是 0 而数据解不开），CodeKnown 也是真，好让日志记下它。
	Code      int64
	CodeKnown bool
}

// OpenAnswer 读承运商的应答（HTTP 200 的正文）。
//
//   - 不是恰好一个 JSON 对象，或没有 apiResultCode，或它不是 JSON 整数：读不成。
//   - apiResultCode 不是 0：正文原样交回，不解密。
//   - apiResultCode 是 0，没有 apiResultData 或它是 null：正文原样交回。
//   - apiResultCode 是 0，apiResultData 是字符串：用这次请求的密钥和 appKey 解密，明文必须是合法 JSON；
//     交回的信封里 apiResultData 的值换成这段明文，其余成员保持各自原来的原始值。
//   - 其余情况读不成。
func OpenAnswer(carrierBody []byte, key Key, appKey string) (Answer, error) {
	if !IsJSONObject(carrierBody) {
		return Answer{}, errNotObject
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(carrierBody, &members); err != nil {
		return Answer{}, errNotObject
	}
	code, ok := jsonInteger(members["apiResultCode"])
	if !ok {
		return Answer{}, errNoCode
	}
	answer := Answer{Code: code, CodeKnown: true}
	if code != 0 {
		answer.Body, answer.Outcome = carrierBody, OutcomeCarrierRefused
		return answer, nil
	}
	data, present := members["apiResultData"]
	if !present || string(data) == "null" {
		answer.Body, answer.Outcome = carrierBody, OutcomeOKNoData
		return answer, nil
	}
	var encrypted string
	if len(data) == 0 || data[0] != '"' || json.Unmarshal(data, &encrypted) != nil {
		return Answer{Code: code, CodeKnown: true}, errDataType
	}
	plain, err := Decrypt(key, appKey, encrypted)
	if err != nil {
		return Answer{Code: code, CodeKnown: true}, errNotDecoded
	}
	if !json.Valid(plain) {
		return Answer{Code: code, CodeKnown: true}, errNotJSONData
	}
	members["apiResultData"] = plain
	body, err := encodeObject(members)
	if err != nil {
		return Answer{Code: code, CodeKnown: true}, errEncode
	}
	answer.Body, answer.Outcome = body, OutcomeOK
	return answer, nil
}

// jsonInteger 读一个 JSON 整数：`-?(0|[1-9][0-9]*)`，没有小数点，没有指数，不是字符串，也能装进 int64。
// 没有这个成员（raw 为空）、null、"0"、0.0、1e0 都不是。
func jsonInteger(raw []byte) (int64, bool) {
	digits := bytes.TrimPrefix(raw, []byte("-"))
	if len(digits) == 0 || (len(digits) > 1 && digits[0] == '0') {
		return 0, false
	}
	for _, c := range digits {
		if c < '0' || c > '9' {
			return 0, false
		}
	}
	number, err := strconv.ParseInt(string(raw), 10, 64)
	return number, err == nil
}

// encodeObject 把成员按名字的字节序写成一个 JSON 对象，每个成员的值逐字节原样。
// 不能用 json.Marshal 来编码装着 RawMessage 的 map：它会把原始值压缩，还会把 <、>、& 和
// U+2028 改写成 \u 转义，解密出来的业务 JSON 就不再是承运商给的那几个字节了。
// 成员名重新编码，同样不做 HTML 转义。
func encodeObject(members map[string]json.RawMessage) ([]byte, error) {
	var out bytes.Buffer
	out.WriteByte('{')
	for i, name := range slices.Sorted(maps.Keys(members)) {
		if i > 0 {
			out.WriteByte(',')
		}
		var quoted bytes.Buffer
		encoder := json.NewEncoder(&quoted)
		encoder.SetEscapeHTML(false)
		if err := encoder.Encode(name); err != nil {
			return nil, err
		}
		out.Write(bytes.TrimSuffix(quoted.Bytes(), []byte("\n")))
		out.WriteByte(':')
		out.Write(members[name])
	}
	out.WriteByte('}')
	return out.Bytes(), nil
}
