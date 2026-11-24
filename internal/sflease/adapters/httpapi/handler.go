// Package httpapi 把租约协调接到 HTTP 上。调用方是谁只看已验证的客户端证书。
// 应答和日志里没有访问令牌原文。
package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"go.idp.xyz/idp-gateway/internal/platform/workloadtls"
	"go.idp.xyz/idp-gateway/internal/sflease/application"
)

const (
	// PathAcquire 申请一把租约或领走已经有效的令牌。
	PathAcquire = "/v1/sf-leases/acquire"
	// PathCommit 提交刚取到的令牌。
	PathCommit = "/v1/sf-leases/commit"
	// PathRelease 放弃尚未提交的锁。
	PathRelease = "/v1/sf-leases/release"
	// PathHealth 是存活探针，与 gateway-authz 一样不看身份，只答 {"ok":true}。
	PathHealth = "/healthz"

	maxBody = 64 << 10
	// maxLifetimeMs 挡住会溢出 time.Duration 的寿命。十年足够覆盖承运商的两小时令牌。
	maxLifetimeMs = int64(10 * 365 * 24 * time.Hour / time.Millisecond)
)

// Handler 是协调器的 HTTP 接口。authzIdentity 为空时三个写接口一律 401。
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
	if r.URL.Path == PathHealth && r.Method == http.MethodGet {
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
		return
	}
	// 身份不对就不读正文，也不碰租约。
	if h.identity == "" || workloadtls.PeerIdentity(r.TLS) != h.identity {
		h.fail(w, r.URL.Path, http.StatusUnauthorized, "unauthorized")
		return
	}
	switch r.URL.Path {
	case PathAcquire:
		h.post(w, r, h.acquire)
	case PathCommit:
		h.post(w, r, h.commit)
	case PathRelease:
		h.post(w, r, h.release)
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
		h.log.Warn("sf lease refused", "path", r.URL.Path, "status", http.StatusBadRequest, "error", "invalid")
		return
	}
	status, payload := fn(r.Context(), body)
	if status >= 400 {
		h.log.Warn("sf lease refused", "path", r.URL.Path, "status", status, "error", errorCode(payload))
	} else {
		h.log.Info("sf lease", "path", r.URL.Path, "status", status, "state", stateOf(payload))
	}
	writeJSON(w, status, payload)
}

func (h *Handler) acquire(ctx context.Context, body []byte) (int, any) {
	var req struct {
		LeaseKey      string `json:"lease_key"`
		HolderID      string `json:"holder_id"`
		RefreshLeadMs int64  `json:"refresh_lead_ms"`
		LockTTLMs     int64  `json:"lock_ttl_ms"`
		WaitMs        int64  `json:"wait_ms"`
	}
	if !decodeObject(body, &req) {
		return http.StatusBadRequest, errBody("invalid")
	}
	lead, ok := durationMs(req.RefreshLeadMs, 0, int64(time.Hour/time.Millisecond))
	if !ok {
		return http.StatusUnprocessableEntity, errBody("invalid")
	}
	var lock time.Duration
	if req.LockTTLMs != 0 {
		lock, ok = durationMs(req.LockTTLMs, 200, 10_000)
		if !ok {
			return http.StatusUnprocessableEntity, errBody("invalid")
		}
	}
	wait, ok := durationMs(req.WaitMs, 0, 500)
	if !ok {
		return http.StatusUnprocessableEntity, errBody("invalid")
	}
	resp, err := h.coord.Acquire(ctx, application.AcquireReq{
		LeaseKey: req.LeaseKey, HolderID: req.HolderID,
		RefreshLead: lead, LockTTL: lock, Wait: wait,
	})
	if err != nil {
		return statusOf(err), errBody(codeOf(err))
	}
	out := map[string]any{"state": resp.State}
	switch resp.State {
	case application.StateValid:
		out["token"] = resp.Token.Reveal()
		out["expires_at"] = resp.ExpiresAt.UTC().Format(time.RFC3339Nano)
		out["lifetime_ms"] = resp.Lifetime.Milliseconds()
	case application.StateFetch:
		out["fence_token"] = strconv.FormatUint(resp.FenceToken, 10)
	case application.StateWait:
		out["retry_after_ms"] = resp.RetryAfterMs
	default:
		return http.StatusInternalServerError, errBody("unavailable")
	}
	return http.StatusOK, out
}

func (h *Handler) commit(ctx context.Context, body []byte) (int, any) {
	var req struct {
		LeaseKey   string `json:"lease_key"`
		HolderID   string `json:"holder_id"`
		FenceToken string `json:"fence_token"`
		Token      string `json:"token"`
		LifetimeMs int64  `json:"lifetime_ms"`
		ExpiresAt  string `json:"expires_at"`
	}
	if !decodeObject(body, &req) {
		return http.StatusBadRequest, errBody("invalid")
	}
	fence, ok := parseFence(req.FenceToken)
	if !ok || req.LifetimeMs <= 0 || req.LifetimeMs > maxLifetimeMs {
		return http.StatusUnprocessableEntity, errBody("invalid")
	}
	expires, err := time.Parse(time.RFC3339Nano, req.ExpiresAt)
	if err != nil {
		return http.StatusUnprocessableEntity, errBody("invalid")
	}
	err = h.coord.Commit(ctx, application.CommitReq{
		LeaseKey: req.LeaseKey, HolderID: req.HolderID, FenceToken: fence,
		Token: req.Token, Lifetime: time.Duration(req.LifetimeMs) * time.Millisecond, ExpiresAt: expires,
	})
	if err != nil {
		return statusOf(err), errBody(codeOf(err))
	}
	return http.StatusOK, map[string]bool{"ok": true}
}

func (h *Handler) release(ctx context.Context, body []byte) (int, any) {
	var req struct {
		LeaseKey   string `json:"lease_key"`
		HolderID   string `json:"holder_id"`
		FenceToken string `json:"fence_token"`
	}
	if !decodeObject(body, &req) {
		return http.StatusBadRequest, errBody("invalid")
	}
	fence, ok := parseFence(req.FenceToken)
	if !ok {
		return http.StatusUnprocessableEntity, errBody("invalid")
	}
	if err := h.coord.Release(ctx, application.ReleaseReq{
		LeaseKey: req.LeaseKey, HolderID: req.HolderID, FenceToken: fence,
	}); err != nil {
		return statusOf(err), errBody(codeOf(err))
	}
	return http.StatusOK, map[string]bool{"ok": true}
}

func (h *Handler) fail(w http.ResponseWriter, path string, status int, code string) {
	h.log.Warn("sf lease refused", "path", path, "status", status, "error", code)
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

func durationMs(ms, min, max int64) (time.Duration, bool) {
	if ms < min || ms > max {
		return 0, false
	}
	return time.Duration(ms) * time.Millisecond, true
}

func parseFence(raw string) (uint64, bool) {
	if raw == "" || raw[0] < '1' || raw[0] > '9' {
		return 0, false
	}
	for i := 1; i < len(raw); i++ {
		if raw[i] < '0' || raw[i] > '9' {
			return 0, false
		}
	}
	n, err := strconv.ParseUint(raw, 10, 64)
	if err != nil || n == 0 {
		return 0, false
	}
	return n, true
}

func statusOf(err error) int {
	switch {
	case errors.Is(err, application.ErrStaleFence):
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
	case errors.Is(err, application.ErrStaleFence):
		return "stale_fence"
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

func stateOf(payload any) string {
	body, ok := payload.(map[string]any)
	if !ok {
		return ""
	}
	state, _ := body["state"].(string)
	return state
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
