// Package httpapi 把出站判定接到 HTTP 上：agentgateway 的 HTTP ExtAuthZ 交换，以及只返回
// 判定、不返回凭证的 JSON 接口。线上契约是 contracts/gatekeeper/openapi.yaml 里的
// /v1/extauthz/check 与 /v1/egress/authorizations/decision。
//
// 调用方是谁只看 TLS 握手中已验证的客户端证书，不看任何请求头。
package httpapi

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"go.idp.xyz/idp-gateway/internal/egressauthz/application"
	"go.idp.xyz/idp-gateway/internal/platform/workloadtls"
)

const (
	PathHealth   = "/healthz"
	PathExtAuthz = "/v1/extauthz/check"
	PathDecision = "/v1/egress/authorizations/decision"
)

// 网关写入的可信上下文。每一项都必须恰好出现零次或一次：出现第二份，说明有网关以外的
// 东西往请求里加了头。
const (
	headerSubject     = "X-Idp-Verified-Subject"
	headerTenant      = "X-Idp-Verified-Tenant"
	headerTokenEnv    = "X-Idp-Verified-Env"
	headerRoute       = "X-Idp-Route-Id"
	headerProvider    = "X-Idp-Provider-Id"
	headerOperation   = "X-Idp-Operation-Id"
	headerEnvironment = "X-Idp-Environment"
	headerMethod      = "X-Idp-Method"
	headerPath        = "X-Idp-Path"
	// 唯一来自调用方的输入：对账户的申请。
	headerAccount = "X-Provider-Account"
)

const (
	resultAllow         = "ALLOW"
	resultDeny          = "DENY"
	resultIndeterminate = "INDETERMINATE"

	reasonCallerUnauthenticated = "GATEWAY_WORKLOAD_UNAUTHENTICATED"
	reasonAmbiguousContext      = "AMBIGUOUS_TRUSTED_CONTEXT"
	reasonAmbiguousAccount      = "AMBIGUOUS_ACCOUNT_REQUEST"
)

// decisionTTL 是只返回判定的接口给出的有效期。
const decisionTTL = 30 * time.Second

const maxDecisionRequestBytes = 64 << 10

// Callers 是允许调用本服务的工作负载身份（证书 subjectAltName 里的 URI）。
type Callers struct {
	// Gateway 可以要判定，也可以要凭证。
	Gateway string
	// Broker 只能要判定。为空表示没有这样的调用方。
	Broker string
}

// MayCall 报告持有该身份的工作负载能否调用该路径。
func (c Callers) MayCall(path, identity string) bool {
	if identity == "" {
		return false
	}
	switch path {
	case PathExtAuthz:
		return identity == c.Gateway
	case PathDecision:
		return identity == c.Gateway || identity == c.Broker
	}
	return false
}

// Handler 是本服务的全部 HTTP 接口。
type Handler struct {
	service *application.Service
	callers Callers
	log     *slog.Logger
	now     func() time.Time
}

// New 构造 Handler。
func New(service *application.Service, callers Callers, logger *slog.Logger) *Handler {
	return &Handler{service: service, callers: callers, log: logger, now: time.Now}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case PathHealth:
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	case PathExtAuthz:
		h.extAuthz(w, r)
	case PathDecision:
		h.decision(w, r)
	default:
		writeJSON(w, http.StatusNotFound, errorBody{Error: "not_found"})
	}
}

// allowBody 是 ExtAuthZ 放行响应的正文。凭证不在正文里，只在 Authorization 响应头里。
type allowBody struct {
	DecisionID      string `json:"decision_id"`
	Result          string `json:"result"`
	ReasonCode      string `json:"reason_code"`
	PolicyVersion   string `json:"policy_version"`
	RevocationEpoch uint64 `json:"revocation_epoch"`
}

// denialBody 对应契约里的 ExtAuthzDenial。
type denialBody struct {
	Result          string `json:"result"`
	ReasonCode      string `json:"reason_code"`
	PolicyVersion   string `json:"policy_version"`
	RevocationEpoch uint64 `json:"revocation_epoch"`
}

type errorBody struct {
	Error string `json:"error"`
}

// extAuthz 是 agentgateway 的 HTTP ExtAuthZ 交换：2xx 表示放行，其余都表示不转发。
// 放行时 Authorization 响应头携带本次请求要用的 Provider 凭证。
func (h *Handler) extAuthz(w http.ResponseWriter, r *http.Request) {
	caller := workloadtls.PeerIdentity(r.TLS)
	// 只有网关可以要凭证。同一信任域里的其他工作负载，包括只能要判定的 Broker，都不行。
	if !h.callers.MayCall(PathExtAuthz, caller) {
		h.refuse(w, r, PathExtAuthz, caller, http.StatusUnauthorized, reasonCallerUnauthenticated)
		return
	}
	in, ok := trustedContext(r.Header)
	if !ok {
		h.refuse(w, r, PathExtAuthz, caller, http.StatusForbidden, reasonAmbiguousContext)
		return
	}
	accounts := r.Header.Values(headerAccount)
	if len(accounts) > 1 {
		h.refuse(w, r, PathExtAuthz, caller, http.StatusForbidden, reasonAmbiguousAccount)
		return
	}
	if len(accounts) == 1 {
		in.RequestedAccount = accounts[0]
	}

	out, credential, err := h.service.Authorize(r.Context(), in)
	switch {
	case err != nil:
		// 判定没能完成。按拒绝处理，但用 503 与策略拒绝区分开。
		writeJSON(w, http.StatusServiceUnavailable, denialBody{Result: resultIndeterminate, ReasonCode: out.Reason,
			PolicyVersion: out.PolicyVersion, RevocationEpoch: out.RevocationEpoch})
		h.record(r, PathExtAuthz, caller, http.StatusServiceUnavailable, resultIndeterminate, in, out, err)
	case !out.Allowed:
		writeJSON(w, http.StatusForbidden, denialBody{Result: resultDeny, ReasonCode: out.Reason,
			PolicyVersion: out.PolicyVersion, RevocationEpoch: out.RevocationEpoch})
		h.record(r, PathExtAuthz, caller, http.StatusForbidden, resultDeny, in, out, nil)
	default:
		w.Header().Set("Authorization", credential.Reveal())
		w.Header().Set("X-Idp-Decision-Id", out.DecisionID)
		writeJSON(w, http.StatusOK, allowBody{DecisionID: out.DecisionID, Result: resultAllow, ReasonCode: out.Reason,
			PolicyVersion: out.PolicyVersion, RevocationEpoch: out.RevocationEpoch})
		h.record(r, PathExtAuthz, caller, http.StatusOK, resultAllow, in, out, nil)
	}
}

func trustedContext(header http.Header) (application.Input, bool) {
	var in application.Input
	for name, field := range map[string]*string{
		headerSubject: &in.Subject, headerTenant: &in.Tenant, headerTokenEnv: &in.TokenEnvironment,
		headerRoute: &in.RouteID, headerProvider: &in.ProviderID, headerOperation: &in.OperationID,
		headerEnvironment: &in.Environment, headerMethod: &in.Method, headerPath: &in.Path,
	} {
		values := header.Values(name)
		if len(values) > 1 {
			return application.Input{}, false
		}
		if len(values) == 1 {
			*field = values[0]
		}
	}
	return in, true
}

// decisionRequest 对应契约里的 DecisionRequest。必填项用指针，是为了区分"没有给"和"给了空串"。
type decisionRequest struct {
	RequestID          *string `json:"request_id"`
	RouteID            *string `json:"route_id"`
	OperationID        *string `json:"operation_id"`
	ProviderID         *string `json:"provider_id"`
	RequestedAccountID *string `json:"requested_account_id"`
	Environment        *string `json:"environment"`
	Method             *string `json:"method"`
	Path               *string `json:"path"`
	ConfigDigest       *string `json:"config_digest"`
	ServiceID          string  `json:"service_id"`
	TenantID           string  `json:"tenant_id"`
	TokenEnvironment   string  `json:"token_environment"`
	// DelegatedSubject 按契约接受，目前不参与判定。
	DelegatedSubject string `json:"delegated_subject"`
}

func (d *decisionRequest) complete() bool {
	for _, required := range []*string{d.RequestID, d.RouteID, d.OperationID, d.ProviderID, d.RequestedAccountID,
		d.Environment, d.Method, d.Path, d.ConfigDigest} {
		if required == nil {
			return false
		}
	}
	return true
}

// decisionResponse 对应 contracts/gatekeeper/authz-decision.schema.json。里面没有凭证，
// 只有放行时的凭证句柄。
type decisionResponse struct {
	DecisionID       string `json:"decision_id"`
	Result           string `json:"result"`
	ReasonCode       string `json:"reason_code"`
	PolicyVersion    string `json:"policy_version"`
	RevocationEpoch  uint64 `json:"revocation_epoch"`
	RequestID        string `json:"request_id"`
	ExpiresAt        string `json:"expires_at"`
	CredentialHandle string `json:"credential_handle,omitempty"`
}

// decision 只返回判定和凭证句柄，从不返回凭证。
func (h *Handler) decision(w http.ResponseWriter, r *http.Request) {
	caller := workloadtls.PeerIdentity(r.TLS)
	if !h.callers.MayCall(PathDecision, caller) {
		h.refuse(w, r, PathDecision, caller, http.StatusUnauthorized, reasonCallerUnauthenticated)
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeJSON(w, http.StatusMethodNotAllowed, errorBody{Error: "method_not_allowed"})
		return
	}
	request, err := readDecisionRequest(w, r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid_decision_request"})
		return
	}
	in := application.Input{
		Subject: request.ServiceID, Tenant: request.TenantID, TokenEnvironment: request.TokenEnvironment,
		RouteID: *request.RouteID, ProviderID: *request.ProviderID, OperationID: *request.OperationID,
		Environment: *request.Environment, Method: *request.Method, Path: *request.Path,
		RequestedAccount: *request.RequestedAccountID,
	}
	out, err := h.service.Decide(r.Context(), in)
	result := resultDeny
	switch {
	case err != nil:
		result = resultIndeterminate
	case out.Allowed:
		result = resultAllow
	}
	writeJSON(w, http.StatusOK, decisionResponse{
		DecisionID: out.DecisionID, Result: result, ReasonCode: out.Reason, PolicyVersion: out.PolicyVersion,
		RevocationEpoch: out.RevocationEpoch, RequestID: *request.RequestID,
		ExpiresAt:        h.now().Add(decisionTTL).UTC().Format(time.RFC3339),
		CredentialHandle: out.CredentialHandle(),
	})
	h.record(r, PathDecision, caller, http.StatusOK, result, in, out, err)
}

func readDecisionRequest(w http.ResponseWriter, r *http.Request) (*decisionRequest, error) {
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxDecisionRequestBytes))
	decoder.DisallowUnknownFields()
	var request decisionRequest
	if err := decoder.Decode(&request); err != nil {
		return nil, err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("unexpected data after the request document")
	}
	if !request.complete() {
		return nil, errors.New("required field missing")
	}
	return &request, nil
}

// refuse 回答没有进入判定的请求：调用方身份不对，或可信上下文有歧义。
func (h *Handler) refuse(w http.ResponseWriter, r *http.Request, endpoint, caller string, status int, reason string) {
	writeJSON(w, status, denialBody{Result: resultDeny, ReasonCode: reason,
		PolicyVersion: h.service.PolicyVersion(), RevocationEpoch: h.service.RevocationEpoch(r.Context())})
	h.log.LogAttrs(r.Context(), slog.LevelWarn, "egress authorization refused",
		slog.String("endpoint", endpoint), slog.String("caller", caller), slog.Int("status", status),
		slog.String("result", resultDeny), slog.String("reason", reason))
}

// record 为每次判定写一行日志。这里没有任何请求头的值，也没有凭证。
func (h *Handler) record(r *http.Request, endpoint, caller string, status int, result string, in application.Input, out application.Outcome, err error) {
	level := slog.LevelInfo
	attrs := []slog.Attr{
		slog.String("endpoint", endpoint), slog.String("caller", caller), slog.Int("status", status),
		slog.String("result", result), slog.String("reason", out.Reason), slog.String("decision_id", out.DecisionID),
		slog.String("route_id", in.RouteID), slog.String("provider_id", in.ProviderID),
		slog.String("operation_id", in.OperationID), slog.String("environment", in.Environment),
		slog.String("tenant", in.Tenant), slog.String("subject", in.Subject), slog.String("account", out.Account),
		slog.String("policy_version", out.PolicyVersion), slog.Uint64("revocation_epoch", out.RevocationEpoch),
	}
	if err != nil {
		level = slog.LevelError
		attrs = append(attrs, slog.String("error", err.Error()))
	}
	h.log.LogAttrs(r.Context(), level, "egress authorization", attrs...)
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	encoded, err := json.Marshal(body)
	if err != nil {
		// 这里的正文都是本包定义的结构，编码不会失败；万一失败也不能把半截响应当作放行。
		w.Header().Del("Authorization")
		http.Error(w, `{"error":"internal"}`, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Length", strconv.Itoa(len(encoded)))
	w.WriteHeader(status)
	_, _ = w.Write(encoded)
}
