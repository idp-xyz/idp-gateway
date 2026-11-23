package httpapi

import (
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"go.idp.xyz/idp-gateway/internal/platform/audit"
	"go.idp.xyz/idp-gateway/internal/platform/otlp"
	"go.idp.xyz/idp-gateway/internal/providersigner/application"
	"go.idp.xyz/idp-gateway/internal/providersigner/domain"
)

// Telemetry 是可选的追踪、审计和指标。零值什么都不做。
type Telemetry struct {
	Service string
	Traces  *otlp.Exporter
	Audit   *audit.FileSink
	Metrics *SignerMetrics
}

func (t Telemetry) active() bool {
	return t.Traces != nil || t.Audit != nil || t.Metrics != nil
}

// WithTelemetry 装上可选的观测。不调用时 Handler 与以前相同。
func (h *Handler) WithTelemetry(t Telemetry) *Handler {
	if t.Service == "" {
		t.Service = "idp-provider-signer"
	}
	h.tel = t
	return h
}

func (h *Handler) observe(r *http.Request, operation domain.Operation, result application.Result, elapsed time.Duration, trace otlp.TraceContext, traced bool) {
	if !h.tel.active() {
		return
	}
	origin := signerOrigin(result)
	traceID, parent, sampled := otlp.NewTraceID(), "", true
	if traced {
		traceID, parent, sampled = trace.TraceID, trace.SpanID, trace.Sampled
	}
	spanID := otlp.NewSpanID()
	if h.tel.Metrics != nil {
		h.tel.Metrics.Observe(signerSeries{
			operation: operation.ID, outcome: result.Outcome, status: strconv.Itoa(result.Status),
		}, elapsed, signerCircuit(result.Outcome))
	}
	if h.tel.Audit != nil {
		detail := map[string]string{}
		if operation.MsgType != "" {
			detail["msg_type"] = operation.MsgType
		}
		if result.CarrierStatus != 0 {
			detail["carrier_status"] = strconv.Itoa(result.CarrierStatus)
		}
		if result.HasAPIResultCode {
			detail["api_result_code"] = strconv.FormatInt(result.APIResultCode, 10)
		}
		rec := audit.Record{
			Timestamp: time.Now().UTC().Format(time.RFC3339Nano), Service: h.tel.Service, EventType: "signer_call",
			TraceID: traceID, SpanID: spanID, ParentSpanID: parent, OperationID: operation.ID,
			Method: r.Method, Path: r.URL.Path, Status: result.Status, Outcome: result.Outcome,
			FailureOrigin: origin, DurationMS: elapsed.Milliseconds(), Detail: detail,
		}
		if err := h.tel.Audit.Write(rec); err != nil && h.log != nil {
			h.log.LogAttrs(r.Context(), slog.LevelWarn, "audit write", slog.String("error", err.Error()))
		}
	}
	if h.tel.Traces != nil && sampled {
		code := otlp.StatusCodeOK
		if result.Status >= 500 {
			code = otlp.StatusCodeError
		}
		attrs := map[string]any{
			"operation":                 operation.ID,
			"msg_type":                  operation.MsgType,
			"outcome":                   result.Outcome,
			"http.response.status_code": result.Status,
		}
		if result.CarrierStatus != 0 {
			attrs["carrier_status"] = result.CarrierStatus
		}
		if result.HasAPIResultCode {
			attrs["api_result_code"] = result.APIResultCode
		}
		if origin != "" {
			attrs["failure_origin"] = origin
		}
		end := time.Now()
		h.tel.Traces.Record(otlp.Span{
			TraceID: traceID, SpanID: spanID, ParentSpanID: parent, Name: "providersigner.dispatch",
			Kind: otlp.SpanKindServer, StartTime: end.Add(-elapsed), EndTime: end,
			StatusCode: code, StatusMessage: result.Outcome, Attributes: attrs,
		})
	}
}

func signerOrigin(result application.Result) string {
	switch result.Outcome {
	case domain.OutcomeOK, domain.OutcomeOKNoData, domain.OutcomeCarrierRefused:
		return ""
	case "carrier_circuit_open":
		return "circuit_breaker"
	}
	if result.Status == http.StatusUnauthorized || result.Status == http.StatusForbidden {
		return "client_auth"
	}
	switch result.Outcome {
	case "carrier_timeout", "carrier_unreachable", "carrier_status", "carrier_answer_unreadable":
		return "upstream"
	}
	if result.Status >= 500 {
		return "upstream"
	}
	if result.Status >= 400 {
		return "client_auth"
	}
	return ""
}

// signerCircuit 报告这次调用之后熔断器该显示开还是关。-1 表示这次没碰到熔断器。
func signerCircuit(outcome string) int {
	switch outcome {
	case "carrier_circuit_open":
		return 1
	case domain.OutcomeOK, domain.OutcomeOKNoData, domain.OutcomeCarrierRefused,
		"carrier_timeout", "carrier_unreachable", "carrier_status", "carrier_answer_unreadable":
		return 0
	default:
		return -1
	}
}
