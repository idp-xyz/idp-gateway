package httpapi

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"go.idp.xyz/idp-gateway/internal/egressauthz/application"
	"go.idp.xyz/idp-gateway/internal/egressauthz/ports"
	"go.idp.xyz/idp-gateway/internal/platform/workloadtls"
)

// operationBanRequest 把一个操作置为封禁或没有封禁。两项必填用指针，是为了区分"没有给"和"给了零值"；
// 封禁时还必须写原因。与撤销账户的请求同一套限制。
type operationBanRequest struct {
	OperationID *string `json:"operation_id"`
	Banned      *bool   `json:"banned"`
	Reason      string  `json:"reason"`
}

// operationBanChange 是这次调用之后的实际情况。出错时 Error 说明是哪一种。
type operationBanChange struct {
	OperationID     string `json:"operation_id"`
	Banned          bool   `json:"banned"`
	Changed         bool   `json:"changed"`
	RevocationEpoch uint64 `json:"revocation_epoch"`
	Error           string `json:"error,omitempty"`
}

// operationBanState 是整张封禁表。
type operationBanState struct {
	RevocationEpoch  uint64            `json:"revocation_epoch"`
	BannedOperations []bannedOperation `json:"banned_operations"`
}

type bannedOperation struct {
	OperationID string `json:"operation_id"`
	BannedAt    string `json:"banned_at"`
	BannedBy    string `json:"banned_by"`
	Reason      string `json:"reason"`
}

const errorUnknownOperation = "unknown_operation"

// operationBans 是封禁操作的接口（docs/adr/ADR-0012.md V1.3）：GET 读出被封禁的操作，POST 封禁或解除。
// 只有撤销者的身份能调，与改账户撤销表是同一个身份。应答里没有凭证。封禁不发布路由。
func (h *Handler) operationBans(w http.ResponseWriter, r *http.Request) {
	caller := workloadtls.PeerIdentity(r.TLS)
	if !h.callers.MayCall(PathOperationBans, caller) {
		h.refuse(w, r, PathOperationBans, caller, http.StatusUnauthorized, reasonRevokerUnauthenticated)
		return
	}
	switch r.Method {
	case http.MethodGet:
		operations, epoch, err := h.service.BannedOperations(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, errorBody{Error: "revocations_unavailable"})
			return
		}
		state := operationBanState{RevocationEpoch: epoch, BannedOperations: make([]bannedOperation, 0, len(operations))}
		for _, operation := range operations {
			state.BannedOperations = append(state.BannedOperations, bannedOperation{OperationID: operation.OperationID,
				BannedAt: operation.At.UTC().Format(time.RFC3339), BannedBy: operation.By, Reason: operation.Reason})
		}
		writeJSON(w, http.StatusOK, state)
	case http.MethodPost:
		h.changeOperationBan(w, r, caller)
	default:
		w.Header().Set("Allow", http.MethodGet+", "+http.MethodPost)
		writeJSON(w, http.StatusMethodNotAllowed, errorBody{Error: "method_not_allowed"})
	}
}

func (h *Handler) changeOperationBan(w http.ResponseWriter, r *http.Request, caller string) {
	request, err := readOperationBanRequest(w, r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "invalid_operation_ban_request"})
		return
	}
	operation, action := *request.OperationID, "lift"
	var change ports.BanChange
	if *request.Banned {
		action = "ban"
		change, err = h.service.BanOperation(r.Context(), operation, caller, request.Reason)
	} else {
		change, err = h.service.LiftOperationBan(r.Context(), operation)
	}
	status := http.StatusOK
	body := operationBanChange{OperationID: operation, Banned: change.Banned, Changed: change.Changed, RevocationEpoch: change.Epoch}
	switch {
	case err == nil:
	case errors.Is(err, application.ErrUnknownOperation):
		status, body.Error = http.StatusUnprocessableEntity, errorUnknownOperation
	case errors.Is(err, ports.ErrRevocationNotWritten):
		// 封禁已经生效，只是重启之后就没有了。调用方要知道，所以不是 200。
		status, body.Error = http.StatusInternalServerError, errorRevocationNotWritten
	default:
		status, body.Error = http.StatusInternalServerError, errorRevocationsNotChanged
	}
	writeJSON(w, status, body)

	level := slog.LevelInfo
	attrs := []slog.Attr{
		slog.String("endpoint", PathOperationBans), slog.String("caller", caller), slog.Int("status", status),
		slog.String("action", action), slog.String("operation_id", operation), slog.String("reason", request.Reason),
		slog.Bool("changed", change.Changed), slog.Bool("banned", change.Banned), slog.Uint64("revocation_epoch", change.Epoch),
	}
	if err != nil {
		level = slog.LevelError
		attrs = append(attrs, slog.String("error", err.Error()))
	}
	h.log.LogAttrs(r.Context(), level, "egress operation ban", attrs...)
}

func readOperationBanRequest(w http.ResponseWriter, r *http.Request) (*operationBanRequest, error) {
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRevocationRequestBytes))
	decoder.DisallowUnknownFields()
	var request operationBanRequest
	if err := decoder.Decode(&request); err != nil {
		return nil, err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("unexpected data after the request document")
	}
	switch {
	case request.OperationID == nil || request.Banned == nil:
		return nil, errors.New("required field missing")
	case *request.OperationID == "" || !plainText(*request.OperationID, maxAccountIDBytes):
		return nil, errors.New("operation_id is empty, too long or not plain text")
	case !plainText(request.Reason, maxReasonBytes):
		return nil, errors.New("reason is too long or not plain text")
	case *request.Banned && strings.TrimSpace(request.Reason) == "":
		return nil, errors.New("a ban needs a reason")
	}
	return &request, nil
}
