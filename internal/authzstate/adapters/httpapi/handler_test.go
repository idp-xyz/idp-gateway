package httpapi

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"go.idp.xyz/idp-gateway/internal/authzstate/application"
	"go.idp.xyz/idp-gateway/internal/authzstate/domain"
	"go.idp.xyz/idp-gateway/internal/platform/workloadtls/tlstest"
)

const (
	authzID = "spiffe://idp.test/egress/gateway-authz"
	otherID = "spiffe://idp.test/egress/someone-else"
	marker  = "BODY-MARKER-do-not-log"
	hexKey  = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
)

type memStore struct {
	mu   sync.Mutex
	snap domain.Snapshot
	fail bool
}

func (s *memStore) Load() (domain.Snapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.snap.Accounts == nil {
		s.snap.Accounts = map[string]domain.Entry{}
	}
	if s.snap.Bans == nil {
		s.snap.Bans = map[string]domain.Entry{}
	}
	return s.snap.Clone(), nil
}

func (s *memStore) Save(next domain.Snapshot) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fail {
		return errorsNew("disk")
	}
	s.snap = next.Clone()
	return nil
}

func errorsNew(text string) error { return &textError{text} }

type textError struct{ text string }

func (e *textError) Error() string { return e.text }

func newHandler(t *testing.T) (*Handler, *memStore, *bytes.Buffer) {
	t.Helper()
	store := &memStore{}
	coord, err := application.New(store, func() time.Time { return time.Unix(1_700_000_000, 0) })
	if err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	return New(coord, authzID, slog.New(slog.NewJSONHandler(&logs, nil))), store, &logs
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
	other := ca.Issue("other", []string{otherID})
	handler, _, logs := newHandler(t)
	body := `{"this is not json ` + marker + `}`
	rec := call(handler, http.MethodPost, PathMutate, body, &other)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status %d %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String()+logs.String(), marker) {
		t.Fatalf("body leaked: %s %s", rec.Body.String(), logs.String())
	}
	rec = call(handler, http.MethodPost, PathMutate, body, nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("empty identity %d %s", rec.Code, rec.Body.String())
	}
	rec = call(handler, http.MethodGet, PathHealth, "", nil)
	if rec.Code != http.StatusOK || strings.TrimSpace(rec.Body.String()) != `{"ok":true}` {
		t.Fatalf("health %d %s", rec.Code, rec.Body.String())
	}
	rec = call(handler, http.MethodPost, PathHealth, body, &other)
	if rec.Code != http.StatusMethodNotAllowed || rec.Header().Get("Allow") != http.MethodGet {
		t.Fatalf("health method %d allow %q", rec.Code, rec.Header().Get("Allow"))
	}
	if strings.Contains(logs.String(), marker) {
		t.Fatal(logs.String())
	}
}

func TestDuplicateHostIsBadRequestAndDoesNotApply(t *testing.T) {
	ca := tlstest.NewCA(t, "workload CA")
	authz := ca.Issue("authz", []string{authzID})
	handler, _, logs := newHandler(t)
	body := `{"action":"revoke","account_id":"account-blue","by":"spiffe://idp.test/revoker","reason":"` + marker + `"}`
	rec := call(handler, http.MethodPost, PathMutate, body, &authz, "127.0.0.1", "evil.example")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("duplicate host %d %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String()+logs.String(), marker) || strings.Contains(logs.String(), "account-blue") {
		t.Fatalf("duplicate host read the body: %s %s", rec.Body.String(), logs.String())
	}
	rec = call(handler, http.MethodGet, PathSnapshot, "", &authz)
	if rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), "account-blue") {
		t.Fatalf("revoke applied despite duplicate host: %d %s", rec.Code, rec.Body.String())
	}
	rec = call(handler, http.MethodGet, PathMutate, "", &authz)
	if rec.Code != http.StatusMethodNotAllowed || rec.Header().Get("Allow") != http.MethodPost {
		t.Fatalf("mutate method %d allow %q", rec.Code, rec.Header().Get("Allow"))
	}
	rec = call(handler, http.MethodPost, PathSnapshot, "", &authz)
	if rec.Code != http.StatusMethodNotAllowed || rec.Header().Get("Allow") != http.MethodGet {
		t.Fatalf("snapshot method %d allow %q", rec.Code, rec.Header().Get("Allow"))
	}
	rec = call(handler, http.MethodGet, PathQuota, "", &authz)
	if rec.Code != http.StatusMethodNotAllowed || rec.Header().Get("Allow") != http.MethodPost {
		t.Fatalf("quota method %d allow %q", rec.Code, rec.Header().Get("Allow"))
	}
}

func TestTwoClientsShareOneRevoke(t *testing.T) {
	ca := tlstest.NewCA(t, "workload CA")
	authz := ca.Issue("authz", []string{authzID})
	handler, _, logs := newHandler(t)
	body := `{"action":"revoke","account_id":"account-blue","by":"spiffe://idp.test/revoker","reason":"key leaked"}`
	rec := call(handler, http.MethodPost, PathMutate, body, &authz)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"epoch":1`) {
		t.Fatalf("mutate %d %s", rec.Code, rec.Body.String())
	}
	rec = call(handler, http.MethodGet, PathSnapshot, "", &authz)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "account-blue") || !strings.Contains(rec.Body.String(), `"epoch": 1`) && !strings.Contains(rec.Body.String(), `"epoch":1`) {
		t.Fatalf("second snapshot %d %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(logs.String(), marker) {
		t.Fatal(logs.String())
	}
}

func TestQuotaMismatchIs409AndDoesNotLoosen(t *testing.T) {
	ca := tlstest.NewCA(t, "workload CA")
	authz := ca.Issue("authz", []string{authzID})
	handler, _, logs := newHandler(t)
	tight := `{"charges":[{"key":"` + hexKey + `","max_requests":1,"window_seconds":3600,"capacity":1}]}`
	loose := `{"charges":[{"key":"` + hexKey + `","max_requests":5,"window_seconds":3600,"capacity":5,"preimage":"` + marker + `"}]}`
	rec := call(handler, http.MethodPost, PathQuota, tight, &authz)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"allowed":true`) {
		t.Fatalf("first %d %s", rec.Code, rec.Body.String())
	}
	rec = call(handler, http.MethodPost, PathQuota, loose, &authz)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown field %d %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String()+logs.String(), marker) {
		t.Fatalf("quota body leaked: %s %s", rec.Body.String(), logs.String())
	}
	mismatch := `{"charges":[{"key":"` + hexKey + `","max_requests":5,"window_seconds":3600,"capacity":5}]}`
	rec = call(handler, http.MethodPost, PathQuota, mismatch, &authz)
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "parameter_mismatch") {
		t.Fatalf("mismatch %d %s", rec.Code, rec.Body.String())
	}
	rec = call(handler, http.MethodPost, PathQuota, tight, &authz)
	var decoded struct {
		Allowed    bool `json:"allowed"`
		RetryAfter int  `json:"retry_after"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &decoded); err != nil || rec.Code != http.StatusOK || decoded.Allowed || decoded.RetryAfter < 1 {
		t.Fatalf("loosened %d %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(logs.String(), hexKey) && strings.Contains(logs.String(), "preimage") {
		t.Fatal(logs.String())
	}
}

func TestSaveFailureDoesNotPublish(t *testing.T) {
	ca := tlstest.NewCA(t, "workload CA")
	authz := ca.Issue("authz", []string{authzID})
	handler, store, _ := newHandler(t)
	body := `{"action":"revoke","account_id":"account-blue","by":"spiffe://idp.test/revoker","reason":"key leaked"}`
	if rec := call(handler, http.MethodPost, PathMutate, body, &authz); rec.Code != http.StatusOK {
		t.Fatal(rec.Body.String())
	}
	store.fail = true
	rec := call(handler, http.MethodPost, PathMutate, `{"action":"restore","account_id":"account-blue"}`, &authz)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("restore %d %s", rec.Code, rec.Body.String())
	}
	rec = call(handler, http.MethodGet, PathSnapshot, "", &authz)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "account-blue") {
		t.Fatalf("restore applied: %d %s", rec.Code, rec.Body.String())
	}
}
