// Package httpapi 把撤销协调接到 HTTP 上。调用方是谁只看已验证的客户端证书。
// 应答和日志里没有请求正文，也没有配额键的原像。协调器不保存任何应用密钥。
package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"

	"go.idp.xyz/idp-gateway/internal/authzstate/adapters/filestore"
	"go.idp.xyz/idp-gateway/internal/authzstate/application"
	"go.idp.xyz/idp-gateway/internal/authzstate/domain"
	"go.idp.xyz/idp-gateway/internal/platform/workloadtls"
)

const (
	// PathMutate 收紧或放宽撤销/封禁。
	PathMutate = "/v1/authz-state/mutate"
	// PathSnapshot 读出当前已发布的快照。
	PathSnapshot = "/v1/authz-state/snapshot"
	// PathQuota 对一组配额键做全有或全无的扣费。
	PathQuota = "/v1/authz-state/quota"
	// PathHealth 是存活探针，握手之后答 {"ok":true}，不看身份。
	PathHealth = "/healthz"

	maxBody = 64 << 10
)

// Handler 是协调器的 HTTP 接口。authzIdentity 为空时三个业务接口一律 401。
type Handler struct {
	coord    *application.Coordinator
	identity string
	log      *slog.Logger
}

// New 构造 Handler。logger 为 nil 时不记日志。
func New(coord *application.Coordinator, authzIdentity string, logger *slog.Logger) *Handler {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	return &Handler{coord: coord, identity: authzIdentity, log: logger}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if len(r.Header.Values("Host")) > 1 {
		h.fail(w, r.URL.Path, http.StatusBadRequest, "invalid_host")
		return
	}
	if r.URL.Path == PathHealth {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			h.fail(w, r.URL.Path, http.StatusMethodNotAllowed, "method_not_allowed")
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
		return
	}
	// 身份不对就不读正文，也不改状态。
	if h.identity == "" || workloadtls.PeerIdentity(r.TLS) != h.identity {
		h.fail(w, r.URL.Path, http.StatusUnauthorized, "unauthorized")
		return
	}
	switch r.URL.Path {
	case PathMutate:
		h.post(w, r, h.mutate)
	case PathSnapshot:
		h.snapshot(w, r)
	case PathQuota:
		h.post(w, r, h.quota)
	default:
		h.fail(w, r.URL.Path, http.StatusNotFound, "not_found")
	}
}

type postFunc func(ctx context.Context, body []byte) (int, any)

func (h *Handler) post(w http.ResponseWriter, r *http.Request, fn postFunc) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		h.fail(w, r.URL.Path, http.StatusMethodNotAllowed, "method_not_allowed")
		return
	}
	body, ok := readBody(w, r)
	if !ok {
		h.log.Warn("authz state refused", "path", r.URL.Path, "status", http.StatusBadRequest, "error", "invalid")
		return
	}
	status, payload := fn(r.Context(), body)
	h.logResult(r.URL.Path, status, payload)
	writeJSON(w, status, payload)
}

func (h *Handler) snapshot(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		h.fail(w, r.URL.Path, http.StatusMethodNotAllowed, "method_not_allowed")
		return
	}
	encoded, err := filestore.Encode(h.coord.Snapshot())
	if err != nil {
		h.fail(w, r.URL.Path, http.StatusServiceUnavailable, "unavailable")
		return
	}
	h.log.Info("authz state", "path", r.URL.Path, "status", http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(encoded)
}

func (h *Handler) mutate(_ context.Context, body []byte) (int, any) {
	var req struct {
		Action      string `json:"action"`
		AccountID   string `json:"account_id"`
		OperationID string `json:"operation_id"`
		By          string `json:"by"`
		Reason      string `json:"reason"`
	}
	if !decodeObject(body, &req) {
		return http.StatusBadRequest, errBody("invalid")
	}
	result, err := h.coord.Mutate(domain.Mutation{
		Action: req.Action, AccountID: req.AccountID, OperationID: req.OperationID, By: req.By, Reason: req.Reason,
	})
	if err != nil {
		return statusOf(err), errBody(codeOf(err))
	}
	out := map[string]any{"changed": result.Changed, "epoch": result.Epoch}
	switch req.Action {
	case domain.ActionRevoke, domain.ActionRestore:
		out["revoked"] = result.Revoked
	default:
		out["banned"] = result.Banned
	}
	h.log.Info("authz state mutate",
		"action", req.Action, "account", req.AccountID, "operation", req.OperationID,
		"reason", req.Reason, "changed", result.Changed, "epoch", result.Epoch)
	return http.StatusOK, out
}

func (h *Handler) quota(_ context.Context, body []byte) (int, any) {
	var req struct {
		Charges []struct {
			Key           string `json:"key"`
			MaxRequests   int    `json:"max_requests"`
			WindowSeconds int    `json:"window_seconds"`
			Capacity      int    `json:"capacity"`
		} `json:"charges"`
	}
	if !decodeObject(body, &req) || req.Charges == nil {
		return http.StatusBadRequest, errBody("invalid")
	}
	charges := make([]domain.Charge, len(req.Charges))
	for i, charge := range req.Charges {
		charges[i] = domain.Charge{
			Key: charge.Key, MaxRequests: charge.MaxRequests, WindowSeconds: charge.WindowSeconds, Capacity: charge.Capacity,
		}
	}
	allowed, retry, err := h.coord.Quota(charges)
	if err != nil {
		return statusOf(err), errBody(codeOf(err))
	}
	out := map[string]any{"allowed": allowed}
	if !allowed {
		if retry < 1 {
			retry = 1
		}
		out["retry_after"] = retry
	}
	h.log.Info("authz state quota", "charges", len(charges), "allowed", allowed, "retry_after", retry)
	return http.StatusOK, out
}

func (h *Handler) logResult(path string, status int, payload any) {
	if status < 400 {
		return
	}
	h.log.Warn("authz state refused", "path", path, "status", status, "error", errorCode(payload))
}

func (h *Handler) fail(w http.ResponseWriter, path string, status int, code string) {
	h.log.Warn("authz state refused", "path", path, "status", status, "error", code)
	writeJSON(w, status, errBody(code))
}

func readBody(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	if r.ContentLength > maxBody {
		writeJSON(w, http.StatusBadRequest, errBody("invalid"))
		return nil, false
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, maxBody+1))
	if err != nil || len(raw) > maxBody {
		writeJSON(w, http.StatusBadRequest, errBody("invalid"))
		return nil, false
	}
	return raw, true
}

func decodeObject(raw []byte, dst any) bool {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return false
	}
	if _, err := dec.Token(); err != io.EOF {
		return false
	}
	return true
}

func statusOf(err error) int {
	switch {
	case errors.Is(err, application.ErrParameterMismatch):
		return http.StatusConflict
	case errors.Is(err, application.ErrInvalid):
		return http.StatusUnprocessableEntity
	case errors.Is(err, application.ErrStoreUnavailable), errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return http.StatusServiceUnavailable
	default:
		return http.StatusInternalServerError
	}
}

func codeOf(err error) string {
	switch {
	case errors.Is(err, application.ErrParameterMismatch):
		return "parameter_mismatch"
	case errors.Is(err, application.ErrInvalid):
		return "invalid"
	default:
		return "unavailable"
	}
}

func errBody(code string) map[string]string { return map[string]string{"error": code} }

func errorCode(payload any) string {
	body, ok := payload.(map[string]string)
	if !ok {
		return ""
	}
	return body["error"]
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	encoded, err := json.Marshal(body)
	if err != nil {
		http.Error(w, `{"error":"unavailable"}`, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write(encoded)
}
