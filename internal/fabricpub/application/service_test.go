package application

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"go.idp.xyz/idp-gateway/internal/fabricpub/domain"
	"go.idp.xyz/idp-gateway/internal/fabricpub/ports"
)

func TestSubmitReachesActiveAndSupersedes(t *testing.T) {
	h := newHarness(t)
	first := h.submit(t, h.example)
	if first.State != domain.StateDraft {
		t.Fatalf("受理状态 %s", first.State)
	}
	h.wait(t, first.IntentID, domain.StateActive)
	view, _, _ := h.svc.Status(context.Background(), first.IntentID)
	if view.State != domain.StateActive || view.DesiredDigest == "" || view.DesiredDigest != view.ObservedDigest {
		t.Fatalf("生效视图 %+v", view)
	}
	if h.store.generation() != 1 {
		t.Fatalf("代次 %d", h.store.generation())
	}
	replay, err := h.svc.Submit(context.Background(), h.example)
	if err != nil || replay.State != domain.StateDraft || replay.IntentID != first.IntentID {
		t.Fatalf("重放 %+v %v", replay, err)
	}
	view, _, _ = h.svc.Status(context.Background(), first.IntentID)
	if view.State != domain.StateActive {
		t.Fatalf("重放之后 GET 应仍是当前状态，得到 %s", view.State)
	}

	secondBody := mutate(t, h.example, func(doc map[string]any) {
		doc["idempotency_key"] = "pub-mockcarrier-tracking-0002"
		doc["intent"].(map[string]any)["expected_generation"] = json.Number("1")
		doc["intent"].(map[string]any)["approval_ref"] = "APPROVAL-PENDING-002"
	})
	second := h.submit(t, secondBody)
	h.wait(t, second.IntentID, domain.StateActive)
	if h.store.generation() != 2 {
		t.Fatalf("第二次后代次 %d", h.store.generation())
	}
	active, superseded := 0, 0
	for _, rec := range h.store.records() {
		switch rec.State {
		case domain.StateActive:
			active++
			if rec.ObservedDigest != "digest-1" {
				t.Fatalf("observed %s", rec.ObservedDigest)
			}
		case domain.StateSuperseded:
			superseded++
		}
	}
	if active != 1 || superseded != 1 {
		t.Fatalf("active %d superseded %d", active, superseded)
	}
	if !bytes.Equal(h.policy.current(), h.policy.last) {
		t.Fatal("生效后的策略文件不是新的那一份")
	}
}

func TestConflictsDoNotConsumeTheKey(t *testing.T) {
	h := newHarness(t)
	body := mutate(t, h.example, func(doc map[string]any) {
		doc["intent"].(map[string]any)["expected_generation"] = json.Number("4")
	})
	_, err := h.svc.Submit(context.Background(), body)
	if statusOf(err) != 409 || reasonOf(err) != "generation_conflict" {
		t.Fatal(err)
	}
	if len(h.store.records()) != 0 {
		t.Fatal("代次冲突占用了键")
	}
	ok := h.submit(t, h.example)
	h.wait(t, ok.IntentID, domain.StateActive)

	other := mutate(t, h.example, func(doc map[string]any) { doc["release_ref"] = "fabric-release:other" })
	_, err = h.svc.Submit(context.Background(), other)
	if statusOf(err) != 409 || reasonOf(err) != "idempotency_key_reused" {
		t.Fatal(err)
	}

	h.pub.hold = make(chan struct{})
	inflight := mutate(t, h.example, func(doc map[string]any) {
		doc["idempotency_key"] = "pub-mockcarrier-tracking-0099"
		doc["intent"].(map[string]any)["expected_generation"] = json.Number("1")
		doc["intent"].(map[string]any)["approval_ref"] = "APPROVAL-PENDING-099"
	})
	go func() { _, _ = h.svc.Submit(context.Background(), inflight) }()
	h.wait(t, "gwi-example-001", domain.StateApproved)
	third := mutate(t, h.example, func(doc map[string]any) {
		doc["idempotency_key"] = "pub-mockcarrier-tracking-0100"
		doc["intent"].(map[string]any)["expected_generation"] = json.Number("1")
	})
	_, err = h.svc.Submit(context.Background(), third)
	if statusOf(err) != 409 || reasonOf(err) != "publish_in_progress" {
		t.Fatal(err)
	}
	close(h.pub.hold)
	h.wait(t, "gwi-example-001", domain.StateActive)
}

func TestCompileRefusalDoesNotConsumeTheKey(t *testing.T) {
	h := newHarness(t)
	h.compiler.err = fmtRefused()
	_, err := h.svc.Submit(context.Background(), h.example)
	if statusOf(err) != 422 {
		t.Fatal(err)
	}
	if len(h.store.records()) != 0 || h.store.generation() != 0 {
		t.Fatal("编译拒绝落下了记录")
	}
	h.compiler.err = nil
	got := h.submit(t, h.example)
	h.wait(t, got.IntentID, domain.StateActive)
}

func TestPublishFailures(t *testing.T) {
	h := newHarness(t)
	h.policy.cur = []byte("old-policy")
	h.pub.outcome = ports.PublishOutcome{Outcome: ports.OutcomeRefused, Replaced: false, Reason: "preflight"}
	got := h.submit(t, h.example)
	h.wait(t, got.IntentID, domain.StateRejected)
	if !bytes.Equal(h.policy.current(), []byte("old-policy")) {
		t.Fatalf("策略没有还原：%s", h.policy.current())
	}

	h = newHarness(t)
	h.policy.cur = []byte("old-policy")
	h.pub.outcome = ports.PublishOutcome{Outcome: ports.OutcomeRestored, Replaced: true, ObservedDigest: "old"}
	body := mutate(t, h.example, func(doc map[string]any) { doc["idempotency_key"] = "pub-mockcarrier-tracking-0008" })
	got = h.submit(t, body)
	h.wait(t, got.IntentID, domain.StateFailed)
	if !bytes.Equal(h.policy.current(), []byte("old-policy")) {
		t.Fatal("回滚后策略应还原")
	}

	h = newHarness(t)
	h.policy.failApply = true
	h.policy.partial = true
	body = mutate(t, h.example, func(doc map[string]any) { doc["idempotency_key"] = "pub-mockcarrier-tracking-0007" })
	got = h.submit(t, body)
	h.wait(t, got.IntentID, domain.StatePartial)

	h = newHarness(t)
	h.pub.outcome = ports.PublishOutcome{Outcome: ports.OutcomeOvertaken, Replaced: true, ObservedDigest: "somewhere"}
	body = mutate(t, h.example, func(doc map[string]any) { doc["idempotency_key"] = "pub-mockcarrier-tracking-0006" })
	got = h.submit(t, body)
	h.wait(t, got.IntentID, domain.StateUnknown)
	view, _, _ := h.svc.Status(context.Background(), got.IntentID)
	if view.State != domain.StateUnknown || view.ObservedDigest != "somewhere" {
		t.Fatalf("被收成别的结局时对外应是 UNKNOWN：%+v", view)
	}
	for _, rec := range h.store.records() {
		if rec.State == "OVERTAKEN" {
			t.Fatal("状态目录写出了 OVERTAKEN")
		}
	}
}

func TestBusyThenActiveAndTimeout(t *testing.T) {
	h := newHarness(t)
	h.pub.busyLeft = 1
	got := h.submit(t, h.example)
	h.wait(t, got.IntentID, domain.StateActive)

	h = newHarness(t)
	h.svc.poolWait = 40 * time.Millisecond
	h.pub.busyLeft = 100
	body := mutate(t, h.example, func(doc map[string]any) { doc["idempotency_key"] = "pub-mockcarrier-tracking-0011" })
	got = h.submit(t, body)
	h.wait(t, got.IntentID, domain.StateRejected)
}

func TestReconcile(t *testing.T) {
	h := newHarness(t)
	h.pub.outcome = ports.PublishOutcome{Outcome: ports.OutcomeUnknown, Replaced: true, ObservedDigest: "digest-1"}
	got := h.submit(t, h.example)
	h.wait(t, got.IntentID, domain.StateUnknown)
	h.pub.recon = ports.ReconcileOutcome{Outcome: ports.OutcomeInSync, ObservedDigest: "digest-1"}
	if err := h.svc.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	h.wait(t, got.IntentID, domain.StateActive)
	if h.store.generation() != 1 {
		t.Fatalf("对账收敛后代次 %d", h.store.generation())
	}

	h = newHarness(t)
	h.policy.cur = []byte("old-policy")
	h.pub.outcome = ports.PublishOutcome{Outcome: ports.OutcomeUnknown, Replaced: true, ObservedDigest: "other"}
	body := mutate(t, h.example, func(doc map[string]any) { doc["idempotency_key"] = "pub-mockcarrier-tracking-0012" })
	got = h.submit(t, body)
	h.wait(t, got.IntentID, domain.StateUnknown)
	h.pub.recon = ports.ReconcileOutcome{Outcome: ports.OutcomeInSync, ObservedDigest: "previous"}
	if err := h.svc.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	h.wait(t, got.IntentID, domain.StateFailed)
	if !bytes.Equal(h.policy.current(), []byte("old-policy")) {
		t.Fatal("对账回到旧快照后策略应还原")
	}
}

func TestStatusMissing(t *testing.T) {
	h := newHarness(t)
	_, found, err := h.svc.Status(context.Background(), "gwi-missing")
	if err != nil || found {
		t.Fatalf("found %v err %v", found, err)
	}
}

type harness struct {
	t        *testing.T
	svc      *Service
	store    *memStore
	compiler *fakeCompiler
	policy   *memPolicy
	pub      *fakePub
	example  []byte
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	raw, err := os.ReadFile("../../../contracts/fabric/route-publication-intent.example.json")
	if err != nil {
		t.Fatal(err)
	}
	base, err := domain.ParsePoolBase([]byte(catalogForService))
	if err != nil {
		t.Fatal(err)
	}
	bindings, err := domain.ParseBindings([]byte(bindingForService))
	if err != nil {
		t.Fatal(err)
	}
	env, err := domain.ParseEnvelope(raw)
	if err != nil {
		t.Fatal(err)
	}
	h := &harness{
		t: t, store: &memStore{}, compiler: &fakeCompiler{}, policy: &memPolicy{cur: []byte("old-policy")},
		pub:     &fakePub{digest: "digest-1", outcome: ports.PublishOutcome{Outcome: ports.OutcomeActive, ObservedDigest: "digest-1"}},
		example: raw,
	}
	svc, err := New(Config{
		TargetID: env.TargetID, Base: base, Bindings: bindings, Store: h.store,
		Compiler: h.compiler, Policies: h.policy, Publisher: h.pub,
		PoolWait: time.Second, Backoff: 5 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	h.svc = svc
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() { cancel(); svc.Close() })
	svc.Start(ctx)
	return h
}

func (h *harness) submit(t *testing.T, body []byte) SubmitResult {
	t.Helper()
	got, err := h.svc.Submit(context.Background(), body)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func (h *harness) wait(t *testing.T, intentID string, want domain.ReleaseState) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	var last StatusView
	for time.Now().Before(deadline) {
		view, found, err := h.svc.Status(context.Background(), intentID)
		if err == nil && found {
			last = view
			if view.State == want {
				return
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("intent %s 没有到 %s，停在 %+v，记录 %+v", intentID, want, last, h.store.records())
}

func statusOf(err error) int {
	var call *CallError
	if errors.As(err, &call) {
		return call.Status
	}
	return 0
}

func reasonOf(err error) string {
	var call *CallError
	if errors.As(err, &call) {
		return call.Reason
	}
	return ""
}

func fmtRefused() error { return errors.Join(ports.ErrRefused, errors.New("native")) }

func mutate(t *testing.T, raw []byte, fn func(map[string]any)) []byte {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var doc map[string]any
	if err := dec.Decode(&doc); err != nil {
		t.Fatal(err)
	}
	fn(doc)
	out, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

type memStore struct {
	mu    sync.Mutex
	state ports.State
}

func (m *memStore) Hold(context.Context) (func(), error) {
	m.mu.Lock()
	return m.mu.Unlock, nil
}

func (m *memStore) Load(context.Context) (ports.State, error) {
	raw, err := json.Marshal(m.state)
	if err != nil {
		return ports.State{}, err
	}
	var copy ports.State
	if err := json.Unmarshal(raw, &copy); err != nil {
		return ports.State{}, err
	}
	return copy, nil
}

func (m *memStore) Save(_ context.Context, state ports.State) error {
	raw, err := json.Marshal(state)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, &m.state)
}

func (m *memStore) generation() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.state.Generation
}

func (m *memStore) records() []ports.Record {
	m.mu.Lock()
	defer m.mu.Unlock()
	raw, _ := json.Marshal(m.state.Records)
	var copy []ports.Record
	_ = json.Unmarshal(raw, &copy)
	return copy
}

type fakeCompiler struct {
	mu  sync.Mutex
	err error
}

func (f *fakeCompiler) ValidateAndCompile(_ context.Context, specJSON []byte) (ports.CompiledBundle, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return ports.CompiledBundle{}, f.err
	}
	var doc struct {
		Provider struct {
			PolicyVersion string `json:"policy_version"`
		} `json:"provider"`
	}
	if err := json.Unmarshal(specJSON, &doc); err != nil {
		return ports.CompiledBundle{}, err
	}
	return ports.CompiledBundle{
		GatewayYAML: []byte("gateway: true\n"), PolicyJSON: []byte(`{"version":"` + doc.Provider.PolicyVersion + `"}`),
		GatewaySHA256: "sha", PolicyVersion: doc.Provider.PolicyVersion,
	}, nil
}

type memPolicy struct {
	mu          sync.Mutex
	cur         []byte
	last        []byte
	failApply   bool
	partial     bool
	failRestore bool
}

func (m *memPolicy) Apply(_ context.Context, next []byte, want string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	prev := append([]byte(nil), m.cur...)
	if m.failApply {
		if m.partial {
			return nil, ports.ErrPartial
		}
		return nil, errors.New("apply failed")
	}
	if want == "" {
		return nil, errors.New("missing version")
	}
	m.cur = append([]byte(nil), next...)
	m.last = append([]byte(nil), next...)
	return prev, nil
}

func (m *memPolicy) Restore(_ context.Context, previous []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failRestore {
		return errors.New("restore failed")
	}
	m.cur = append([]byte(nil), previous...)
	return nil
}

func (m *memPolicy) current() []byte {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]byte(nil), m.cur...)
}

type fakePub struct {
	mu       sync.Mutex
	digest   string
	outcome  ports.PublishOutcome
	busyLeft int
	hold     chan struct{}
	recon    ports.ReconcileOutcome
}

func (f *fakePub) Stage(ctx context.Context, _ []byte) (string, error) {
	if f.hold != nil {
		select {
		case <-f.hold:
		case <-ctx.Done():
			return "", ctx.Err()
		}
	}
	return f.digest, nil
}

func (f *fakePub) Publish(context.Context, []byte, string) (ports.PublishOutcome, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.busyLeft > 0 {
		f.busyLeft--
		return ports.PublishOutcome{Busy: true}, ports.ErrBusy
	}
	return f.outcome, nil
}

func (f *fakePub) Reconcile(context.Context) (ports.ReconcileOutcome, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.recon, nil
}

const catalogForService = `{
  "pool": {
    "name": "egress-test", "environment": "TEST", "caller_hostname": "egress-api.idp.test",
    "listen_port": 8081, "bind_address": "127.0.0.1", "readback_port": 8443,
    "admin_addr": "127.0.0.1:15000", "stats_addr": "127.0.0.1:15020", "readiness_addr": "127.0.0.1:15021",
    "publisher_identity": "spiffe://idp.test/gateway-control/publisher", "tls_dir": "tls",
    "jwt_issuer": "http://127.0.0.1:27621", "jwt_audiences": ["idp-egress-gateway"], "jwks_file": "tls/jwks.json",
    "ext_authz": {"host": "gateway-authz:9443", "hostname": "gatekeeper.idp.test", "timeout": "1s"},
    "access_log": {"provider_reference_expr": "request.id", "provider_request_expr": "response.id"}
  },
  "provider": {
    "provider_id": "mockcarrier", "policy_version": "mock-1", "enforce_tls_upstream": true,
    "credential_scheme": "Bearer ", "credential_binding_ref": "gatekeeper:mockcarrier-test",
    "upstream_host": "mockcarrier.example", "upstream_port": 443, "rewrite_authority": "mockcarrier.example",
    "route_timeout": "9s"
  },
  "access": {
    "allowed_tenants": ["TENANT-ID-BLUE"],
    "accounts_by_tenant": {"TENANT-ID-BLUE": ["account-blue"]},
    "allowed_service_ids": ["CLIENT-ID-BLUE"]
  },
  "routes": [{
    "intent_id": "gwi-catalog-tracking", "route_id": "mock-tracking", "operation_id": "tracking.get",
    "method": "GET", "logical_path": "/providers/mockcarrier/v1/tracking", "path_match_mode": "exact",
    "rewrite_path_prefix": "/v1/tracking", "expected_generation": 0, "approval_ref": "APPROVAL-PENDING-001",
    "authz_profile": "provider-account-allowlist-v1", "redirect_policy": "DENY", "upstream_tls": "VERIFY_REQUIRED",
    "provider_account_strategy": "GATEKEEPER_DECISION_BINDING", "transport": "HTTP",
    "policy_bundle_ref": "policy:egress-standard-v1"
  }]
}`

const bindingForService = `{
  "binding_id": "bind-mockcarrier", "provider_id": "mockcarrier", "environment": "TEST",
  "auth_scheme": "API_KEY", "account_resolution": "GATEKEEPER_AUTHORIZED_ACCOUNT",
  "gateway_workload_id": "spiffe://idp.test/egress/gateway",
  "authorized_credential_ref": "gatekeeper:mockcarrier-test", "approval_ref": "APPROVAL-PENDING-001"
}`
