package httpapi

import (
	"log/slog"
	"net/http"
	"time"

	"go.idp.xyz/idp-gateway/internal/egressauthz/application"
	"go.idp.xyz/idp-gateway/internal/platform/audit"
	"go.idp.xyz/idp-gateway/internal/platform/otlp"
)

// Telemetry 是可选的追踪、审计和指标。零值什么都不做，已有调用保持原样。
type Telemetry struct {
	Service string
	Traces  *otlp.Exporter
	Audit   *audit.FileSink
	Metrics *AuthzMetrics
}

func (t Telemetry) active() bool {
	return t.Traces != nil || t.Audit != nil || t.Metrics != nil
}

// WithTelemetry 装上可选的观测。不调用时 Handler 与以前相同。
func (h *Handler) WithTelemetry(t Telemetry) *Handler {
	if t.Service == "" {
		t.Service = "idp-gateway-authz"
	}
	h.tel = t
	return h
}

type obsClock struct{}

func (h *Handler) observeDecision(r *http.Request, endpoint, caller string, status int, result string, in application.Input, out application.Outcome, err error) {
	if !h.tel.active() {
		return
	}
	h.emit(r, observation{
		Endpoint: endpoint, EventType: "egress_decision", SpanName: spanName(endpoint),
		Caller: caller, Status: status, Result: result, Reason: out.Reason,
		DecisionID: out.DecisionID, RouteID: in.RouteID, ProviderID: in.ProviderID,
		OperationID: in.OperationID, Environment: in.Environment, Tenant: in.Tenant,
		Subject: in.Subject, Account: out.Account, Method: r.Method, Path: r.URL.Path,
		PolicyVersion: out.PolicyVersion, RevocationEpoch: out.RevocationEpoch,
		FailureOrigin: classifyAuthz(status, result, out.Reason), Err: err,
	})
}

func (h *Handler) observeRefusal(r *http.Request, endpoint, caller string, status int, reason string, epoch uint64) {
	if !h.tel.active() || !observeThis(r, endpoint) {
		return
	}
	h.emit(r, observation{
		Endpoint: endpoint, EventType: eventType(endpoint), SpanName: spanName(endpoint),
		Caller: caller, Status: status, Result: resultDeny, Reason: reason,
		Method: r.Method, Path: r.URL.Path, PolicyVersion: h.service.PolicyVersion(),
		RevocationEpoch: epoch, FailureOrigin: classifyAuthz(status, resultDeny, reason),
	})
}

func (h *Handler) observeClientError(r *http.Request, endpoint, caller string, status int, reason string) {
	if !h.tel.active() || !observeThis(r, endpoint) {
		return
	}
	h.emit(r, observation{
		Endpoint: endpoint, EventType: eventType(endpoint), SpanName: spanName(endpoint),
		Caller: caller, Status: status, Result: "error", Reason: reason,
		Method: r.Method, Path: r.URL.Path, FailureOrigin: classifyAuthz(status, "error", reason),
	})
}

// observeMutation 记一次撤销或封禁。Reason 是调用方写的原因，只进审计；指标和 span 用 ReasonCode。
func (h *Handler) observeMutation(r *http.Request, endpoint, caller, account, operationID, action, reason, reasonCode string, status int, epoch uint64, err error) {
	if !h.tel.active() {
		return
	}
	result := "ok"
	if status >= 400 || err != nil {
		result = "error"
	}
	label := reasonCode
	if label == "" {
		label = "ok"
	}
	h.emit(r, observation{
		Endpoint: endpoint, EventType: eventType(endpoint), SpanName: spanName(endpoint),
		Caller: caller, Status: status, Result: result, Reason: reason, ReasonCode: label,
		Account: account, OperationID: operationID, Method: r.Method, Path: r.URL.Path,
		RevocationEpoch: epoch, FailureOrigin: classifyAuthz(status, result, label), Err: err,
	})
}

type observation struct {
	Endpoint        string
	EventType       string
	SpanName        string
	Caller          string
	Status          int
	Result          string
	Reason          string
	ReasonCode      string
	DecisionID      string
	RouteID         string
	ProviderID      string
	OperationID     string
	Environment     string
	Tenant          string
	Subject         string
	Account         string
	Method          string
	Path            string
	PolicyVersion   string
	RevocationEpoch uint64
	FailureOrigin   string
	Err             error
}

func (h *Handler) emit(r *http.Request, obs observation) {
	started := startedAt(r)
	elapsed := time.Since(started)
	traceID, parent, sampled := traceOf(r)
	spanID := otlp.NewSpanID()
	if h.tel.Metrics != nil {
		code := obs.ReasonCode
		if code == "" {
			code = obs.Reason
		}
		h.tel.Metrics.Observe(decisionSeries{
			endpoint: obs.Endpoint, result: obs.Result, reason: code,
			provider: obs.ProviderID, operation: obs.OperationID, environment: obs.Environment,
		}, elapsed, obs.RevocationEpoch)
	}
	if h.tel.Audit != nil {
		rec := audit.Record{
			Timestamp: time.Now().UTC().Format(time.RFC3339Nano), Service: h.tel.Service, EventType: obs.EventType,
			TraceID: traceID, SpanID: spanID, ParentSpanID: parent, DecisionID: obs.DecisionID,
			RouteID: obs.RouteID, ProviderID: obs.ProviderID, OperationID: obs.OperationID,
			Environment: obs.Environment, Tenant: obs.Tenant, Subject: obs.Subject, Account: obs.Account,
			Caller: obs.Caller, Method: obs.Method, Path: obs.Path, Status: obs.Status, Outcome: obs.Result,
			Reason: obs.Reason, FailureOrigin: obs.FailureOrigin, PolicyVersion: obs.PolicyVersion,
			RevocationEpoch: obs.RevocationEpoch, DurationMS: elapsed.Milliseconds(),
		}
		if err := h.tel.Audit.Write(rec); err != nil && h.log != nil {
			h.log.LogAttrs(r.Context(), slog.LevelWarn, "audit write", slog.String("error", err.Error()))
		}
	}
	if h.tel.Traces != nil && sampled {
		code := otlp.StatusCodeOK
		if obs.Status >= 500 || obs.Result == resultIndeterminate {
			code = otlp.StatusCodeError
		}
		reason := obs.ReasonCode
		if reason == "" {
			reason = obs.Reason
		}
		attrs := map[string]any{"http.response.status_code": obs.Status}
		putAttr(attrs, "decision_id", obs.DecisionID)
		putAttr(attrs, "result", obs.Result)
		putAttr(attrs, "reason", reason)
		putAttr(attrs, "route_id", obs.RouteID)
		putAttr(attrs, "provider_id", obs.ProviderID)
		putAttr(attrs, "operation_id", obs.OperationID)
		putAttr(attrs, "environment", obs.Environment)
		putAttr(attrs, "failure_origin", obs.FailureOrigin)
		end := time.Now()
		h.tel.Traces.Record(otlp.Span{
			TraceID: traceID, SpanID: spanID, ParentSpanID: parent, Name: obs.SpanName,
			Kind: otlp.SpanKindServer, StartTime: started, EndTime: end,
			StatusCode: code, StatusMessage: reason, Attributes: attrs,
		})
	}
}

func putAttr(attrs map[string]any, key, value string) {
	if value != "" {
		attrs[key] = value
	}
}

func traceOf(r *http.Request) (traceID, parent string, sampled bool) {
	if r != nil {
		if ctx, ok := otlp.ParseTraceparent(r.Header); ok {
			return ctx.TraceID, ctx.SpanID, ctx.Sampled
		}
	}
	return otlp.NewTraceID(), "", true
}

func startedAt(r *http.Request) time.Time {
	if r != nil {
		if v, ok := r.Context().Value(obsClock{}).(time.Time); ok && !v.IsZero() {
			return v
		}
	}
	return time.Now()
}

func observeThis(r *http.Request, endpoint string) bool {
	switch endpoint {
	case PathExtAuthz, PathDecision:
		return true
	case PathRevocations, PathOperationBans:
		return r != nil && r.Method == http.MethodPost
	default:
		return false
	}
}

func spanName(endpoint string) string {
	switch endpoint {
	case PathExtAuthz:
		return "egressauthz.check"
	case PathDecision:
		return "egressauthz.decision"
	case PathRevocations:
		return "egressauthz.revocation"
	case PathOperationBans:
		return "egressauthz.operation_ban"
	default:
		return "egressauthz.request"
	}
}

func eventType(endpoint string) string {
	switch endpoint {
	case PathRevocations:
		return "revocation_change"
	case PathOperationBans:
		return "operation_ban_change"
	default:
		return "egress_decision"
	}
}

func classifyAuthz(status int, result, reason string) string {
	if result == resultAllow && status < 400 {
		return ""
	}
	switch {
	case status == http.StatusUnauthorized:
		return "client_auth"
	case status == http.StatusTooManyRequests || reason == application.ReasonRateLimited:
		return "rate_limit"
	case status == http.StatusUnprocessableEntity:
		return "policy"
	case result == resultIndeterminate || status == http.StatusServiceUnavailable || status >= 500:
		return "pdp_or_dependency"
	case status == http.StatusForbidden || result == resultDeny:
		return "policy"
	case status >= 400 && status < 500:
		return "client_auth"
	default:
		return ""
	}
}
