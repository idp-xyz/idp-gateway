package main

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"

	"go.idp.xyz/idp-gateway/internal/egressauthz/adapters/revokerclient"
	"go.idp.xyz/idp-gateway/internal/platform/audit"
)

const (
	maxBodyBytes   = 4 << 10
	maxIDBytes     = 256
	maxReasonBytes = 512
	defaultLimit   = 50
	maxLimit       = 200
)

type console struct {
	auditPath string
	client    *revokerclient.Client
}

func newConsole(auditPath string, client *revokerclient.Client) http.Handler {
	return &console{auditPath: auditPath, client: client}
}

func (s *console) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if len(r.Header.Values("Host")) > 1 {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	switch r.URL.Path {
	case "/v1/audit":
		s.audit(w, r)
	case "/v1/revocations":
		s.revocations(w, r)
	case "/v1/operation-bans":
		s.bans(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (s *console) audit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}
	if s.auditPath == "" {
		writeError(w, http.StatusNotFound, "audit log is not configured")
		return
	}
	limit, err := limitOf(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad request")
		return
	}
	info, err := os.Lstat(s.auditPath)
	if err != nil {
		if os.IsNotExist(err) {
			writeError(w, http.StatusNotFound, "audit log is not available")
			return
		}
		writeError(w, http.StatusInternalServerError, "audit log cannot be read")
		return
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		writeError(w, http.StatusForbidden, "audit log cannot be read")
		return
	}
	records, err := audit.ReadRecent(s.auditPath, audit.Filter{
		TraceID:    r.URL.Query().Get("trace_id"),
		DecisionID: r.URL.Query().Get("decision_id"),
		Outcome:    r.URL.Query().Get("outcome"),
	}, limit)
	if err != nil {
		status := http.StatusInternalServerError
		if os.IsNotExist(err) {
			status = http.StatusNotFound
		}
		writeError(w, status, "audit log cannot be read")
		return
	}
	if records == nil {
		records = []audit.Record{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"records": records})
}

func (s *console) revocations(w http.ResponseWriter, r *http.Request) {
	if s.client == nil {
		writeError(w, http.StatusNotFound, "revoker is not configured")
		return
	}
	switch r.Method {
	case http.MethodGet:
		s.finish(w, s.client.List(r.Context()), "list", "")
	case http.MethodPost:
		var body struct {
			AccountID string `json:"account_id"`
			Revoked   *bool  `json:"revoked"`
			Reason    string `json:"reason"`
		}
		if !decodeBody(w, r, &body) || body.Revoked == nil || !shortID(body.AccountID) || len(body.Reason) > maxReasonBytes {
			writeError(w, http.StatusBadRequest, "bad request")
			return
		}
		var (
			result revokerclient.Result
			err    error
		)
		if *body.Revoked && strings.TrimSpace(body.Reason) == "" {
			writeError(w, http.StatusBadRequest, "bad request")
			return
		}
		if *body.Revoked {
			result, err = s.client.Revoke(r.Context(), body.AccountID, body.Reason)
		} else {
			result, err = s.client.Restore(r.Context(), body.AccountID)
		}
		if err != nil {
			writeError(w, http.StatusBadRequest, "bad request")
			return
		}
		s.finish(w, result, "account", body.AccountID)
	default:
		methodNotAllowed(w, http.MethodGet+", "+http.MethodPost)
	}
}

func (s *console) bans(w http.ResponseWriter, r *http.Request) {
	if s.client == nil {
		writeError(w, http.StatusNotFound, "revoker is not configured")
		return
	}
	if r.Method != http.MethodPost {
		methodNotAllowed(w, http.MethodPost)
		return
	}
	var body struct {
		OperationID string `json:"operation_id"`
		Banned      *bool  `json:"banned"`
		Reason      string `json:"reason"`
	}
	if !decodeBody(w, r, &body) || body.Banned == nil || !shortID(body.OperationID) || len(body.Reason) > maxReasonBytes {
		writeError(w, http.StatusBadRequest, "bad request")
		return
	}
	var (
		result revokerclient.Result
		err    error
	)
	if *body.Banned && strings.TrimSpace(body.Reason) == "" {
		writeError(w, http.StatusBadRequest, "bad request")
		return
	}
	if *body.Banned {
		result, err = s.client.Ban(r.Context(), body.OperationID, body.Reason)
	} else {
		result, err = s.client.Unban(r.Context(), body.OperationID)
	}
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad request")
		return
	}
	s.finish(w, result, "operation", body.OperationID)
}

func (s *console) finish(w http.ResponseWriter, result revokerclient.Result, kind, subject string) {
	report := map[string]any{
		"outcome":     string(result.Outcome),
		"http_status": result.Status,
	}
	if result.State != nil {
		report["changed"] = result.State.Changed
		report["revocation_epoch"] = result.State.Epoch
		switch kind {
		case "operation":
			report["banned"] = result.State.Banned
			report["operation_id"] = subject
		case "account":
			report["revoked"] = result.State.Revoked
			report["account_id"] = subject
		}
	}
	if result.Table != nil {
		rows := make([]map[string]string, 0, len(result.Table.Rows))
		for _, row := range result.Table.Rows {
			rows = append(rows, map[string]string{
				"account_id": row.AccountID,
				"revoked_at": row.RevokedAt,
				"revoked_by": row.RevokedBy,
				"reason":     row.Reason,
			})
		}
		report["revocation_epoch"] = result.Table.Epoch
		report["revoked_accounts"] = rows
	}
	writeJSON(w, statusOf(result), report)
}

func statusOf(result revokerclient.Result) int {
	switch result.Outcome {
	case revokerclient.OutcomeRevoked, revokerclient.OutcomeLifted, revokerclient.OutcomeListed, revokerclient.OutcomeBanned:
		return http.StatusOK
	}
	if result.Status != 0 {
		return result.Status
	}
	return http.StatusBadGateway
}

func shortID(id string) bool {
	return id != "" && len(id) <= maxIDBytes && !strings.ContainsAny(id, "\r\n")
}

func limitOf(r *http.Request) (int, error) {
	raw := r.URL.Query().Get("limit")
	if raw == "" {
		return defaultLimit, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 1 || n > maxLimit || strconv.Itoa(n) != raw {
		return 0, errors.New("limit")
	}
	return n, nil
}

func decodeBody(w http.ResponseWriter, r *http.Request, into any) bool {
	if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		return false
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(into); err != nil {
		return false
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return false
	}
	return true
}

func methodNotAllowed(w http.ResponseWriter, allow string) {
	w.Header().Set("Allow", allow)
	writeError(w, http.StatusMethodNotAllowed, "method not allowed")
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	encoded, err := json.Marshal(body)
	if err != nil {
		http.Error(w, "bad request", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_, _ = w.Write(encoded)
}
