package httpapi

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"go.idp.xyz/idp-gateway/internal/platform/workloadtls/tlstest"
	"go.idp.xyz/idp-gateway/internal/sflease/application"
	"go.idp.xyz/idp-gateway/internal/sflease/domain"
)

const (
	authzID  = "spiffe://idp.test/egress/gateway-authz"
	otherID  = "spiffe://idp.test/egress/someone-else"
	leaseKey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	token    = "http-layer-access-token"
)

type memStore struct {
	saved map[string]domain.LeaseRecord
}

func (s *memStore) Load() (map[string]domain.LeaseRecord, error) {
	out := map[string]domain.LeaseRecord{}
	for k, v := range s.saved {
		out[k] = v
	}
	return out, nil
}

func (s *memStore) Save(records map[string]domain.LeaseRecord) error {
	out := map[string]domain.LeaseRecord{}
	for k, v := range records {
		out[k] = v
	}
	s.saved = out
	return nil
}

func newHandler(t *testing.T) (*Handler, *bytes.Buffer) {
	t.Helper()
	coord, err := application.New(&memStore{}, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	return New(coord, authzID, slog.New(slog.NewJSONHandler(&logs, nil))), &logs
}

func call(handler http.Handler, method, path, body string, peer *tlstest.Leaf, hosts ...string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if peer != nil {
		req.TLS = tlstest.PeerState(*peer)
	}
	if len(hosts) > 0 {
		req.Header["Host"] = hosts
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func TestWrongIdentityIsUnauthorizedAndDoesNotReadTheBody(t *testing.T) {
	ca := tlstest.NewCA(t, "workload CA")
	authz := ca.Issue("authz", []string{authzID})
	other := ca.Issue("other", []string{otherID})
	handler, logs := newHandler(t)
	body := `{"this is not json ` + token + `}`
	rec := call(handler, http.MethodPost, PathCommit, body, &other)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status %d %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String()+logs.String(), token) {
		t.Fatalf("token leaked: %s %s", rec.Body.String(), logs.String())
	}
	// 没读正文：同样的坏 JSON 换成对的身份，才会是 400 而不是已经提交成功。
	rec = call(handler, http.MethodPost, PathAcquire, `{"lease_key":"`+leaseKey+`","holder_id":"holder-a","refresh_lead_ms":0,"lock_ttl_ms":0,"wait_ms":0}`, &authz)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"state":"FETCH"`) {
		t.Fatalf("state changed or acquire failed: %d %s", rec.Code, rec.Body.String())
	}
}

func TestDuplicateHostAndUnknownFieldsAreRejected(t *testing.T) {
	ca := tlstest.NewCA(t, "workload CA")
	authz := ca.Issue("authz", []string{authzID})
	handler, logs := newHandler(t)
	rec := call(handler, http.MethodPost, PathAcquire, `{"token":"`+token+`"}`, &authz, "127.0.0.1", "evil.example")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("duplicate host %d %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String()+logs.String(), token) {
		t.Fatalf("duplicate host leaked token: %s %s", rec.Body.String(), logs.String())
	}
	body := `{"lease_key":"` + leaseKey + `","holder_id":"holder-a","refresh_lead_ms":0,"lock_ttl_ms":0,"wait_ms":0,"unexpected":"` + token + `"}`
	rec = call(handler, http.MethodPost, PathAcquire, body, &authz)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown field %d %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String()+logs.String(), token) {
		t.Fatalf("unknown field leaked token: %s %s", rec.Body.String(), logs.String())
	}
	rec = call(handler, http.MethodGet, PathAcquire, "", &authz)
	if rec.Code != http.StatusMethodNotAllowed || rec.Header().Get("Allow") != http.MethodPost {
		t.Fatalf("method %d allow %q", rec.Code, rec.Header().Get("Allow"))
	}
	rec = call(handler, http.MethodGet, PathHealth, "", nil)
	if rec.Code != http.StatusOK || strings.TrimSpace(rec.Body.String()) != `{"ok":true}` {
		t.Fatalf("health %d %s", rec.Code, rec.Body.String())
	}
}

func TestCommitConflictAndRoundTripDoNotLogTheToken(t *testing.T) {
	ca := tlstest.NewCA(t, "workload CA")
	authz := ca.Issue("authz", []string{authzID})
	handler, logs := newHandler(t)
	rec := call(handler, http.MethodPost, PathAcquire, `{"lease_key":"`+leaseKey+`","holder_id":"holder-a","refresh_lead_ms":0,"lock_ttl_ms":2000,"wait_ms":0}`, &authz)
	var fetched struct {
		State      string `json:"state"`
		FenceToken string `json:"fence_token"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &fetched); err != nil || fetched.State != "FETCH" || fetched.FenceToken == "" {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	expires := time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano)
	bad := `{"lease_key":"` + leaseKey + `","holder_id":"holder-b","fence_token":"` + fetched.FenceToken + `","token":"` + token + `","lifetime_ms":3600000,"expires_at":"` + expires + `"}`
	rec = call(handler, http.MethodPost, PathCommit, bad, &authz)
	if rec.Code != http.StatusConflict || strings.Contains(rec.Body.String(), token) {
		t.Fatalf("conflict %d %s", rec.Code, rec.Body.String())
	}
	good := `{"lease_key":"` + leaseKey + `","holder_id":"holder-a","fence_token":"` + fetched.FenceToken + `","token":"` + token + `","lifetime_ms":3600000,"expires_at":"` + expires + `"}`
	rec = call(handler, http.MethodPost, PathCommit, good, &authz)
	if rec.Code != http.StatusOK {
		t.Fatalf("commit %d %s", rec.Code, rec.Body.String())
	}
	rec = call(handler, http.MethodPost, PathAcquire, `{"lease_key":"`+leaseKey+`","holder_id":"holder-z","refresh_lead_ms":0,"lock_ttl_ms":0,"wait_ms":0}`, &authz)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), token) {
		t.Fatalf("reuse %d %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(logs.String(), token) {
		t.Fatalf("logs contain the token: %s", logs.String())
	}
}
