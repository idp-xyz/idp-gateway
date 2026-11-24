package httpapi

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"go.idp.xyz/idp-gateway/internal/egressauthz/adapters/memory"
	"go.idp.xyz/idp-gateway/internal/egressauthz/application"
	"go.idp.xyz/idp-gateway/internal/egressauthz/domain"
	"go.idp.xyz/idp-gateway/internal/egressauthz/ports"
	"go.idp.xyz/idp-gateway/internal/platform/workloadtls/tlstest"
)

const publisherID = "spiffe://idp.test/egress/publisher"

// memoryPolicy 是测试里可替换的登记表来源。
type memoryPolicy struct {
	policy domain.Policy
}

func (m *memoryPolicy) Current() domain.Policy { return m.policy }

func newPolicyVersionFixture(t *testing.T, publisher string) (*fixture, *memoryPolicy) {
	t.Helper()
	ca := tlstest.NewCA(t, "workload CA")
	source := &memoryPolicy{policy: domain.Policy{Version: "policy-7", Operations: []domain.Operation{{
		ProviderID: "mockcarrier", OperationID: "tracking.get", Environment: "TEST", Method: "GET",
		PathPrefix: tracking, CredentialBindingRef: binding,
		AllowedTenants: []string{"tenant-blue"}, AllowedServiceIDs: []string{"parcel-service"},
		AccountsByTenant: map[string][]string{"tenant-blue": {"account-blue"}},
	}}}}
	f := &fixture{
		credentials: staticCredentials{ports.Handle(binding, "account-blue"): blueToken},
		logs:        &bytes.Buffer{},
		peers: map[string]tlstest.Leaf{
			"gateway":   ca.Issue("gateway", []string{gatewayID}),
			"broker":    ca.Issue("broker", []string{brokerID}),
			"revoker":   ca.Issue("revoker", []string{revokerID}),
			"publisher": ca.Issue("publisher", []string{publisherID}),
			"business":  ca.Issue("business", []string{businessID}),
		},
	}
	// 构造时的登记表是过期的：版本必须来自 source，否则热重载测不出来。
	service := application.New(domain.Policy{Version: "stale"}, f.credentials, &memory.Revocations{}, application.WithPolicySource(source))
	f.handler = New(service, Callers{Gateway: gatewayID, Broker: brokerID, Revoker: revokerID, Publisher: publisher},
		slog.New(slog.NewJSONHandler(f.logs, nil)))
	return f, source
}

func TestPolicyVersionIsAbsentUntilAPublisherIsConfigured(t *testing.T) {
	f, _ := newPolicyVersionFixture(t, "")
	for _, peer := range []string{"", "gateway", "broker", "revoker", "publisher", "business"} {
		recorder := f.call(peer, http.MethodGet, PathPolicyVersion, nil, "")
		if recorder.Code != http.StatusNotFound || decode(t, recorder)["error"] != "not_found" {
			t.Errorf("%s: %d %s", peer, recorder.Code, recorder.Body)
		}
		if recorder.Header().Get("Authorization") != "" || carriesCredential(recorder) {
			t.Errorf("%s 拿到了凭证", peer)
		}
	}
}

func TestPolicyVersionIsReadableOnlyByThePublisher(t *testing.T) {
	f, source := newPolicyVersionFixture(t, publisherID)
	for _, peer := range []string{"", "gateway", "broker", "revoker"} {
		recorder := f.call(peer, http.MethodGet, PathPolicyVersion, nil, "")
		if recorder.Code != http.StatusUnauthorized {
			t.Fatalf("%s: %d %s", peer, recorder.Code, recorder.Body)
		}
		body := decode(t, recorder)
		if body["result"] != "DENY" || body["reason_code"] != reasonPublisherUnauthenticated || body["policy_version"] != "" ||
			body["revocation_epoch"] != float64(0) {
			t.Fatalf("%s: %v", peer, body)
		}
		if _, ok := body["decision_id"]; ok {
			t.Fatalf("%s 走到了判定：%v", peer, body)
		}
		if recorder.Header().Get("Authorization") != "" || carriesCredential(recorder) {
			t.Fatalf("%s 拿到了凭证", peer)
		}
	}

	posted := f.call("publisher", http.MethodPost, PathPolicyVersion, nil, `{"policy_version":"forged"}`)
	if posted.Code != http.StatusMethodNotAllowed || posted.Header().Get("Allow") != http.MethodGet || carriesCredential(posted) {
		t.Fatalf("POST: %d Allow=%q %s", posted.Code, posted.Header().Get("Allow"), posted.Body)
	}

	got := f.call("publisher", http.MethodGet, PathPolicyVersion, nil, "")
	if got.Code != http.StatusOK || decode(t, got)["policy_version"] != "policy-7" || got.Header().Get("Authorization") != "" || carriesCredential(got) {
		t.Fatalf("GET: %d %s %v", got.Code, got.Body, got.Header())
	}

	source.policy.Version = "policy-8"
	again := f.call("publisher", http.MethodGet, PathPolicyVersion, nil, "")
	if again.Code != http.StatusOK || decode(t, again)["policy_version"] != "policy-8" || again.Header().Get("Authorization") != "" {
		t.Fatalf("热重载：%d %s", again.Code, again.Body)
	}
}

func TestPublisherCannotDecideAuthorizeOrMutate(t *testing.T) {
	f, _ := newPolicyVersionFixture(t, publisherID)
	callers := Callers{Gateway: gatewayID, Broker: brokerID, Revoker: revokerID, Publisher: publisherID}
	if callers.MayCall(PathExtAuthz, publisherID) || callers.MayCall(PathDecision, publisherID) ||
		callers.MayCall(PathRevocations, publisherID) || callers.MayCall(PathOperationBans, publisherID) {
		t.Fatal("发布者被允许调用判定或改表")
	}
	if !callers.MayCall(PathPolicyVersion, publisherID) {
		t.Fatal("发布者读不到版本")
	}
	for _, identity := range []string{"", gatewayID, brokerID, revokerID} {
		if callers.MayCall(PathPolicyVersion, identity) {
			t.Fatalf("%s 能读版本", identity)
		}
	}

	extauthz := f.call("publisher", http.MethodGet, PathExtAuthz, trusted("tenant-blue"), "")
	if extauthz.Code != http.StatusUnauthorized || extauthz.Header().Get("Authorization") != "" || carriesCredential(extauthz) ||
		decode(t, extauthz)["result"] == "ALLOW" {
		t.Fatalf("extauthz: %d %s %v", extauthz.Code, extauthz.Body, extauthz.Header())
	}
	decision := f.call("publisher", http.MethodPost, PathDecision, nil, decisionJSON(nil))
	if decision.Code != http.StatusUnauthorized || decision.Header().Get("Authorization") != "" || carriesCredential(decision) ||
		decode(t, decision)["result"] == "ALLOW" {
		t.Fatalf("decision: %d %s", decision.Code, decision.Body)
	}
	revocations := f.call("publisher", http.MethodPost, PathRevocations, nil, `{"account_id":"account-blue","revoked":true,"reason":"no"}`)
	if revocations.Code != http.StatusUnauthorized || revocations.Header().Get("Authorization") != "" || carriesCredential(revocations) {
		t.Fatalf("revocations: %d %s", revocations.Code, revocations.Body)
	}
	bans := f.call("publisher", http.MethodPost, PathOperationBans, nil, `{"operation_id":"tracking.get","banned":true,"reason":"no"}`)
	if bans.Code != http.StatusUnauthorized || bans.Header().Get("Authorization") != "" || carriesCredential(bans) {
		t.Fatalf("bans: %d %s", bans.Code, bans.Body)
	}

	// 发布者的拒绝没有改判定：网关仍能拿到凭证。
	allowed := f.call("gateway", http.MethodGet, PathExtAuthz, trusted("tenant-blue"), "")
	if allowed.Code != http.StatusOK || allowed.Header().Get("Authorization") != blueToken {
		t.Fatalf("网关对照：%d %s", allowed.Code, allowed.Body)
	}
}

func TestPolicyVersionRejectsASecondHostHeader(t *testing.T) {
	f, _ := newPolicyVersionFixture(t, publisherID)
	request := httptest.NewRequest(http.MethodGet, PathPolicyVersion, nil)
	request.TLS = tlstest.PeerState(f.peers["publisher"])
	request.Header["Host"] = []string{"authz.idp.test", "evil.example"}
	recorder := httptest.NewRecorder()
	f.handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadRequest || decode(t, recorder)["error"] != "bad_request" || carriesCredential(recorder) {
		t.Fatalf("%d %s", recorder.Code, recorder.Body)
	}
}
