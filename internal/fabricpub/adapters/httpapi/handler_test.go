package httpapi

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go.idp.xyz/idp-gateway/internal/fabricpub/application"
	"go.idp.xyz/idp-gateway/internal/fabricpub/domain"
	"go.idp.xyz/idp-gateway/internal/platform/workloadtls/tlstest"
)

const fabricID = "spiffe://idp.test/fabric/publisher"

func TestHandlerRejectsForeignIdentity(t *testing.T) {
	api := &fakeAPI{}
	h := mustHandler(t, api)
	ca := tlstest.NewCA(t, "ca")
	other := ca.Issue("other", []string{"spiffe://idp.test/someone-else"})
	rec := request(http.MethodPost, PathSubmit, `{"no":"body-was-read"}`)
	rec.TLS = tlstest.PeerState(other)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, rec)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status %d body %s", rr.Code, rr.Body.String())
	}
	if api.submits != 0 || strings.Contains(rr.Body.String(), "body-was-read") {
		t.Fatal("错误身份不该读正文或改状态")
	}
}

func TestDuplicateHostAndOversize(t *testing.T) {
	api := &fakeAPI{submit: application.SubmitResult{IntentID: "gwi-example-001", ReleaseRef: "rel", State: domain.StateDraft}}
	h := mustHandler(t, api)
	rec := authed(t, http.MethodPost, PathSubmit, `{}`)
	rec.Header["Host"] = []string{"one.example", "two.example"}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, rec)
	if rr.Code != http.StatusBadRequest || api.submits != 0 {
		t.Fatalf("重复 Host：%d submits %d", rr.Code, api.submits)
	}

	marker := strings.Repeat("Z", 32)
	body := strings.Repeat("A", maxBody) + marker
	rec = authed(t, http.MethodPost, PathSubmit, body)
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, rec)
	if rr.Code != http.StatusUnprocessableEntity || strings.Contains(rr.Body.String(), marker) || api.submits != 0 {
		t.Fatalf("超限 %d %s submits %d", rr.Code, rr.Body.String(), api.submits)
	}
}

func TestStatusCodes(t *testing.T) {
	api := &fakeAPI{}
	h := mustHandler(t, api)
	ca := tlstest.NewCA(t, "ca")
	leaf := ca.Issue("fabric", []string{fabricID})

	api.submit = application.SubmitResult{IntentID: "gwi-example-001", ReleaseRef: "fabric-release", State: domain.StateDraft}
	rr := call(t, h, leaf, http.MethodPost, PathSubmit, `{"ok":true}`)
	if rr.Code != http.StatusAccepted {
		t.Fatal(rr.Code, rr.Body.String())
	}
	assertKeys(t, rr.Body.Bytes(), "intent_id", "release_ref", "state")
	if got := decode(t, rr.Body.Bytes())["state"]; got != "DRAFT" {
		t.Fatal(got)
	}

	api.statusErr = &application.CallError{Status: 409, Reason: "generation_conflict"}
	rr = call(t, h, leaf, http.MethodPost, PathSubmit, `{}`)
	if rr.Code != http.StatusConflict || !strings.Contains(rr.Body.String(), "generation_conflict") {
		t.Fatal(rr.Code, rr.Body.String())
	}
	api.statusErr = &application.CallError{Status: 422, Reason: "schema"}
	rr = call(t, h, leaf, http.MethodPost, PathSubmit, `{}`)
	if rr.Code != http.StatusUnprocessableEntity || strings.Contains(rr.Body.String(), "secret") {
		t.Fatal(rr.Code, rr.Body.String())
	}
	api.statusErr = nil

	rr = call(t, h, leaf, http.MethodGet, "/v1/route-intents/gwi-missing/status", "")
	if rr.Code != http.StatusNotFound || strings.Contains(rr.Body.String(), "gwi-missing") {
		t.Fatal(rr.Code, rr.Body.String())
	}

	states := []string{
		"DRAFT", "VALIDATED", "APPROVED", "STAGED", "APPLYING", "OBSERVING", "ACTIVE",
		"REJECTED", "CANCELED", "FAILED", "PARTIAL", "UNKNOWN", "SUPERSEDED",
		"WITHDRAW_REQUESTED", "REVOKING", "REVOKED",
	}
	for _, state := range states {
		api.view = application.StatusView{IntentID: "gwi-example-001", ReleaseRef: "rel", State: domain.ReleaseState(state)}
		api.found = true
		rr = call(t, h, leaf, http.MethodGet, "/v1/route-intents/gwi-example-001/status", "")
		if rr.Code != http.StatusOK {
			t.Fatal(state, rr.Code, rr.Body.String())
		}
		assertKeys(t, rr.Body.Bytes(), "intent_id", "release_ref", "desired_digest", "observed_digest", "state")
		got := decode(t, rr.Body.Bytes())
		if got["state"] != state || got["desired_digest"] != "" || got["observed_digest"] != "" {
			t.Fatalf("%s -> %v", state, got)
		}
	}
	api.view.DesiredDigest = "abc"
	api.view.ObservedDigest = "abc"
	api.view.State = domain.StateActive
	rr = call(t, h, leaf, http.MethodGet, "/v1/route-intents/gwi-example-001/status", "")
	got := decode(t, rr.Body.Bytes())
	if got["desired_digest"] != "abc" || got["observed_digest"] != "abc" || got["state"] != "ACTIVE" {
		t.Fatal(got)
	}
}

func mustHandler(t *testing.T, api *fakeAPI) http.Handler {
	t.Helper()
	h, err := NewHandler(api, fabricID)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func authed(t *testing.T, method, path, body string) *http.Request {
	t.Helper()
	ca := tlstest.NewCA(t, "ca")
	leaf := ca.Issue("fabric", []string{fabricID})
	rec := request(method, path, body)
	rec.TLS = tlstest.PeerState(leaf)
	return rec
}

func call(t *testing.T, h http.Handler, leaf tlstest.Leaf, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	rec := request(method, path, body)
	rec.TLS = tlstest.PeerState(leaf)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, rec)
	return rr
}

func request(method, path, body string) *http.Request {
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	rec := httptest.NewRequest(method, path, reader)
	rec.Host = "fabric.idp.test"
	return rec
}

func assertKeys(t *testing.T, raw []byte, keys ...string) {
	t.Helper()
	got := decode(t, raw)
	if len(got) != len(keys) {
		t.Fatalf("键 %v，想要 %v", got, keys)
	}
	for _, key := range keys {
		if _, ok := got[key]; !ok {
			t.Fatalf("缺少 %s，正文 %s", key, raw)
		}
	}
}

func decode(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err, string(raw))
	}
	return doc
}

type fakeAPI struct {
	submit    application.SubmitResult
	statusErr error
	view      application.StatusView
	found     bool
	submits   int
}

func (f *fakeAPI) Submit(context.Context, []byte) (application.SubmitResult, error) {
	f.submits++
	if f.statusErr != nil {
		return application.SubmitResult{}, f.statusErr
	}
	return f.submit, nil
}

func (f *fakeAPI) Status(context.Context, string) (application.StatusView, bool, error) {
	return f.view, f.found, nil
}
