// Package httpapi 是 provider-signer 面向网关的 HTTP 接口：一张写死的操作表里的几个 POST 路径，
// 此外没有任何别的接口（没有健康检查，没有指标，没有管理接口）。
//
// 调用方是谁只看 TLS 握手中已验证的客户端证书，不看任何请求头。
package httpapi

import (
	"log/slog"
	"mime"
	"net/http"
	"strings"
	"time"

	"go.idp.xyz/idp-gateway/internal/platform/workloadtls"
	"go.idp.xyz/idp-gateway/internal/providersigner/application"
	"go.idp.xyz/idp-gateway/internal/providersigner/domain"
)

// Handler 是本服务的全部 HTTP 接口。
type Handler struct {
	service *application.Service
	gateway string
	log     *slog.Logger
}

// New 构造 Handler。gatewayIdentity 是唯一被服务的对端身份（证书里的 URI）。
func New(service *application.Service, gatewayIdentity string, logger *slog.Logger) *Handler {
	return &Handler{service: service, gateway: gatewayIdentity, log: logger}
}

// ServeHTTP 按下面的顺序核对，第一个不成的就答，后面的都不做，承运商也不会被联系：
// 对端身份、操作、查询串、Content-Type；之后的凭证、正文和承运商那一跳由用例做。
// 答复里的 JSON 是本服务自己写的：错误是固定的错误码和固定的英文说明，成功是承运商信封
// （解密之后）的字节。没有任何头取自承运商的答复。
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	started := time.Now()
	// 查表只是为了让日志里有操作名；查不到时操作名为空。
	operation, known := domain.FindOperation(r.Method, r.URL.Path)
	result := h.answer(r, operation, known)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(result.Status)
	_, _ = w.Write(result.Body)
	h.record(r, operation, result, time.Since(started))
}

func (h *Handler) answer(r *http.Request, operation domain.Operation, known bool) application.Result {
	switch {
	case !h.callerAllowed(r):
		return application.Refuse(application.CallerNotAllowed)
	case !known:
		return application.Refuse(application.UnknownOperation)
	case r.URL.RawQuery != "" || strings.Contains(r.RequestURI, "?"):
		return application.Refuse(application.QueryNotAllowed)
	case !isJSON(r.Header.Get("Content-Type")):
		return application.Refuse(application.UnsupportedMediaType)
	}
	return h.service.Handle(r.Context(), application.Call{
		Operation:     operation,
		Authorization: r.Header.Values("Authorization"),
		Body:          r.Body,
	})
}

func (h *Handler) callerAllowed(r *http.Request) bool {
	identity := workloadtls.PeerIdentity(r.TLS)
	return identity != "" && identity == h.gateway
}

// isJSON 报告媒体类型是不是 application/json；charset 之类的参数允许。
func isJSON(contentType string) bool {
	mediaType, _, err := mime.ParseMediaType(contentType)
	return err == nil && mediaType == "application/json"
}

// record 为每个请求写一行日志。这里没有正文，没有 Authorization 头或它的任何一段，没有签名、
// 随机数、密文，也没有承运商写的 apiErrorMsg：属性都是固定的几项。
// response_bytes 是答给网关的正文的字节数。
func (h *Handler) record(r *http.Request, operation domain.Operation, result application.Result, elapsed time.Duration) {
	attrs := []slog.Attr{
		slog.String("operation", operation.ID),
		slog.String("msg_type", operation.MsgType),
		slog.String("outcome", result.Outcome),
		slog.Int("status", result.Status),
		slog.Int("carrier_status", result.CarrierStatus),
	}
	if result.HasAPIResultCode {
		attrs = append(attrs, slog.Int64("api_result_code", result.APIResultCode))
	}
	attrs = append(attrs,
		slog.Int64("elapsed_ms", elapsed.Milliseconds()),
		slog.Int("request_bytes", result.RequestBytes),
		slog.Int("response_bytes", len(result.Body)),
	)
	h.log.LogAttrs(r.Context(), slog.LevelInfo, "signer call", attrs...)
}
