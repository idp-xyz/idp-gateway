package httpapi

import (
	"log/slog"
	"net/http"

	"go.idp.xyz/idp-gateway/internal/platform/workloadtls"
)

// reasonPublisherUnauthenticated 是版本接口拒绝非发布者身份时的原因码。
const reasonPublisherUnauthenticated = "PUBLISHER_WORKLOAD_UNAUTHENTICATED"

// policyVersionResponse 只带当前登记表版本。里面没有判定，也没有凭证。
type policyVersionResponse struct {
	PolicyVersion string `json:"policy_version"`
}

// policyVersion 回答 GET /v1/egress/policy-version：当前登记表的版本。
// 只有发布者的身份能调。应答里没有凭证，也不做判定、不取凭证、不改撤销表。
// 未通过身份核对的调用方看不到登记表版本。
func (h *Handler) policyVersion(w http.ResponseWriter, r *http.Request) {
	if len(r.Header.Values("Host")) > 1 {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "bad_request"})
		return
	}
	caller := workloadtls.PeerIdentity(r.TLS)
	if !h.callers.MayCall(PathPolicyVersion, caller) {
		writeJSON(w, http.StatusUnauthorized, denialBody{
			Result: resultDeny, ReasonCode: reasonPublisherUnauthenticated,
			PolicyVersion: "", RevocationEpoch: 0,
		})
		h.log.LogAttrs(r.Context(), slog.LevelWarn, "egress authorization refused",
			slog.String("endpoint", PathPolicyVersion), slog.String("caller", caller),
			slog.Int("status", http.StatusUnauthorized), slog.String("result", resultDeny),
			slog.String("reason", reasonPublisherUnauthenticated))
		return
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		writeJSON(w, http.StatusMethodNotAllowed, errorBody{Error: "method_not_allowed"})
		return
	}
	writeJSON(w, http.StatusOK, policyVersionResponse{PolicyVersion: h.service.PolicyVersion()})
}
