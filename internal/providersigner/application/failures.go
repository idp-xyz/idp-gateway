package application

import "encoding/json"

// Failure 是 provider-signer 自己答出的一种错误：状态码、固定的错误码和固定的英文说明。
// Detail 从不带请求的内容、头的值或承运商的文字。
type Failure struct {
	Status int
	Code   string
	Detail string
}

// 前四个由 HTTP 适配器在用例之前核对，其余由用例产生；放在一处，错误码就只有一份清单。
var (
	CallerNotAllowed     = Failure{403, "caller_not_allowed", "The caller is not the configured gateway."}
	UnknownOperation     = Failure{404, "unknown_operation", "No operation is registered for this method and path."}
	QueryNotAllowed      = Failure{400, "query_not_allowed", "The request must not carry a query string."}
	UnsupportedMediaType = Failure{415, "unsupported_media_type", "The request body must be application/json."}

	CredentialMalformed = Failure{403, "credential_malformed", "The Authorization header does not carry a usable credential."}
	RequestTooLarge     = Failure{413, "request_too_large", "The request body is larger than the limit."}
	BodyNotJSONObject   = Failure{400, "body_not_json_object", "The request body must be exactly one JSON object."}
	Internal            = Failure{500, "internal", "The request could not be prepared."}

	CarrierTimeout          = Failure{504, "carrier_timeout", "The carrier did not answer in time."}
	CarrierUnreachable      = Failure{502, "carrier_unreachable", "The carrier could not be reached."}
	CarrierStatus           = Failure{502, "carrier_status", "The carrier answered with an unexpected HTTP status."}
	CarrierAnswerUnreadable = Failure{502, "carrier_answer_unreadable", "The carrier's answer could not be read."}
	// CarrierCircuitOpen 是被动熔断器打开时的失败：不联系承运商。
	CarrierCircuitOpen = Failure{503, "carrier_circuit_open", "The carrier circuit breaker is open."}
)

type failureBody struct {
	Error         string `json:"error"`
	Detail        string `json:"detail"`
	CarrierStatus int    `json:"carrier_status,omitempty"`
}

// body 是答给网关的 JSON。carrierStatus 非零时写进 carrier_status。
func (f Failure) body(carrierStatus int) []byte {
	encoded, err := json.Marshal(failureBody{Error: f.Code, Detail: f.Detail, CarrierStatus: carrierStatus})
	if err != nil {
		// 结构体里只有固定的字符串和整数，编码不会失败；万一失败也只答错误码。
		return []byte(`{"error":"` + f.Code + `"}`)
	}
	return encoded
}

// Refuse 把一种错误做成 Result。适配器用它答用例之前核对出的错误：请求没有进用例，
// 正文也没有读，所以 RequestBytes 是 0。
func Refuse(f Failure) Result {
	return Result{Status: f.Status, Body: f.body(0), Outcome: f.Code}
}
