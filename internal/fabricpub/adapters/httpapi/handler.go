// Package httpapi 实现 Fabric 发布意图的两个路径。
// 契约是 contracts/fabric/route-publication-intent.openapi.yaml。
package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"unicode"

	"go.idp.xyz/idp-gateway/internal/fabricpub/application"
	"go.idp.xyz/idp-gateway/internal/platform/workloadtls"
)

const (
	// PathSubmit 是 POST 收下一条发布意图的路径。
	PathSubmit = "/v1/route-intents"
	// PathStatus 是 GET 查询一条意图的路径，写在这里好跟契约对照。
	PathStatus = "/v1/route-intents/{intent_id}/status"

	maxBody = 1 << 20
)

// API 是处理器要的应用服务。*application.Service 满足它。
type API interface {
	Submit(ctx context.Context, rawBody []byte) (application.SubmitResult, error)
	Status(ctx context.Context, intentID string) (application.StatusView, bool, error)
}

type handler struct {
	api      API
	identity string
}

// acceptedBody 是 202 的正文。三个键都写上。
type acceptedBody struct {
	IntentID   string `json:"intent_id"`
	ReleaseRef string `json:"release_ref"`
	State      string `json:"state"`
}

// statusBody 是 200 的正文。五个键都写上，还没有的摘要是空串。
type statusBody struct {
	IntentID       string `json:"intent_id"`
	ReleaseRef     string `json:"release_ref"`
	DesiredDigest  string `json:"desired_digest"`
	ObservedDigest string `json:"observed_digest"`
	State          string `json:"state"`
}

type errorBody struct {
	Error  string `json:"error"`
	Reason string `json:"reason,omitempty"`
}

// NewHandler 构造只接受 fabricIdentity 这一个客户端身份的处理器。
func NewHandler(api API, fabricIdentity string) (http.Handler, error) {
	if api == nil || fabricIdentity == "" {
		return nil, errors.New("fabric http: an API and the fabric identity are required")
	}
	return &handler{api: api, identity: fabricIdentity}, nil
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if len(r.Header.Values("Host")) > 1 {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "bad_request"})
		return
	}
	if workloadtls.PeerIdentity(r.TLS) != h.identity {
		writeJSON(w, http.StatusUnauthorized, errorBody{Error: "unauthorized"})
		return
	}
	if r.URL.Path == PathSubmit {
		h.submit(w, r)
		return
	}
	if id, ok := intentID(r.URL.Path); ok {
		h.status(w, r, id)
		return
	}
	writeJSON(w, http.StatusNotFound, errorBody{Error: "not_found"})
}

func (h *handler) submit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeJSON(w, http.StatusMethodNotAllowed, errorBody{Error: "method_not_allowed"})
		return
	}
	if r.ContentLength > maxBody {
		writeJSON(w, http.StatusUnprocessableEntity, errorBody{Error: "invalid", Reason: "body_too_large"})
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBody+1))
	if err != nil {
		writeJSON(w, http.StatusUnprocessableEntity, errorBody{Error: "invalid", Reason: "body_unreadable"})
		return
	}
	if len(body) > maxBody {
		writeJSON(w, http.StatusUnprocessableEntity, errorBody{Error: "invalid", Reason: "body_too_large"})
		return
	}
	result, err := h.api.Submit(r.Context(), body)
	if err != nil {
		writeCallError(w, err)
		return
	}
	writeJSON(w, http.StatusAccepted, acceptedBody{IntentID: result.IntentID, ReleaseRef: result.ReleaseRef, State: string(result.State)})
}

func (h *handler) status(w http.ResponseWriter, r *http.Request, intentID string) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		writeJSON(w, http.StatusMethodNotAllowed, errorBody{Error: "method_not_allowed"})
		return
	}
	view, found, err := h.api.Status(r.Context(), intentID)
	if err != nil {
		writeCallError(w, err)
		return
	}
	if !found {
		writeJSON(w, http.StatusNotFound, errorBody{Error: "not_found"})
		return
	}
	writeJSON(w, http.StatusOK, statusBody{
		IntentID: view.IntentID, ReleaseRef: view.ReleaseRef, DesiredDigest: view.DesiredDigest,
		ObservedDigest: view.ObservedDigest, State: string(view.State),
	})
}

func intentID(path string) (string, bool) {
	const prefix = "/v1/route-intents/"
	const suffix = "/status"
	if !strings.HasPrefix(path, prefix) || !strings.HasSuffix(path, suffix) {
		return "", false
	}
	id := strings.TrimSuffix(strings.TrimPrefix(path, prefix), suffix)
	if id == "" || strings.Contains(id, "/") {
		return "", false
	}
	return id, true
}

func writeCallError(w http.ResponseWriter, err error) {
	var call *application.CallError
	if errors.As(err, &call) {
		switch call.Status {
		case http.StatusConflict:
			writeJSON(w, http.StatusConflict, errorBody{Error: "conflict", Reason: safeReason(call.Reason)})
		case http.StatusUnprocessableEntity:
			writeJSON(w, http.StatusUnprocessableEntity, errorBody{Error: "invalid", Reason: safeReason(call.Reason)})
		default:
			writeJSON(w, http.StatusServiceUnavailable, errorBody{Error: "unavailable"})
		}
		return
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		writeJSON(w, http.StatusServiceUnavailable, errorBody{Error: "unavailable"})
		return
	}
	writeJSON(w, http.StatusInternalServerError, errorBody{Error: "unavailable"})
}

func safeReason(reason string) string {
	reason = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, reason)
	if len(reason) > 180 {
		reason = reason[:180]
	}
	return reason
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
