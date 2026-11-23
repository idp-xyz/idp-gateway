package httpapi

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"go.idp.xyz/idp-gateway/internal/platform/audit"
	"go.idp.xyz/idp-gateway/internal/platform/otlp"
)

func TestTelemetryStaysOffTheMTLSHandlerAndStripsSecrets(t *testing.T) {
	const parent = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
	const callerAuthorization = "Bearer caller-token-should-not-be-logged"
	bodies := make(chan []byte, 1)
	collector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		bodies <- body
		w.WriteHeader(http.StatusOK)
	}))
	defer collector.Close()
	exp, err := otlp.NewExporter(otlp.Config{
		Endpoint: collector.URL + "/v1/traces", ServiceName: "idp-gateway-authz", ServiceVersion: "test",
		BatchSize: 1, FlushInterval: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = exp.Close(t.Context()) })
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	sink, err := audit.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sink.Close() })
	metrics := NewAuthzMetrics(nil, func() (uint64, uint64, uint64) { return exp.Stats() })
	f := newFixture(t)
	f.handler.WithTelemetry(Telemetry{Traces: exp, Audit: sink, Metrics: metrics})

	headers := append(trusted("tenant-blue"),
		[2]string{"traceparent", parent},
		[2]string{"Authorization", callerAuthorization},
	)
	recorder := f.call("gateway", "GET", PathExtAuthz, headers, "")
	if recorder.Code != http.StatusOK || len(recorder.Header().Values("Authorization")) != 1 {
		t.Fatalf("response %d %v", recorder.Code, recorder.Header())
	}
	if strings.Contains(recorder.Header().Get("Authorization"), callerAuthorization) {
		t.Fatal("caller credential was echoed")
	}

	var body []byte
	select {
	case body = <-bodies:
	case <-time.After(2 * time.Second):
		t.Fatal("span was not exported")
	}
	text := string(body)
	for _, secret := range []string{callerAuthorization, "provider-token", "Authorization", "account-blue", "tenant-blue"} {
		if strings.Contains(text, secret) {
			t.Fatalf("span contains %q: %s", secret, text)
		}
	}
	for _, needle := range []string{`"traceId":"4bf92f3577b34da6a3ce929d0e0e4736"`, `"parentSpanId":"00f067aa0ba902b7"`, `"name":"egressauthz.check"`, "ACTIVE_ACCOUNT_GRANT", "mockcarrier"} {
		if !strings.Contains(text, needle) {
			t.Fatalf("span missing %s: %s", needle, text)
		}
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	auditText := string(raw)
	if strings.Contains(auditText, callerAuthorization) || strings.Contains(auditText, "provider-token") || strings.Contains(auditText, "Authorization") {
		t.Fatalf("audit leaked: %s", auditText)
	}
	if !strings.Contains(auditText, `"event_type":"egress_decision"`) || !strings.Contains(auditText, `"account":"account-blue"`) || !strings.Contains(auditText, `"trace_id":"4bf92f3577b34da6a3ce929d0e0e4736"`) {
		t.Fatalf("audit %s", auditText)
	}

	metricsRec := httptest.NewRecorder()
	metrics.ServeHTTP(metricsRec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if metricsRec.Code != http.StatusOK || metricsRec.Header().Get("Content-Type") != "text/plain; version=0.0.4; charset=utf-8" {
		t.Fatalf("metrics %d %s", metricsRec.Code, metricsRec.Header().Get("Content-Type"))
	}
	prom := metricsRec.Body.String()
	for _, secret := range []string{"account-blue", "tenant-blue", "parcel-service", "provider-token", callerAuthorization} {
		if strings.Contains(prom, secret) {
			t.Fatalf("metrics contain %q: %s", secret, prom)
		}
	}
	for _, needle := range []string{
		`idp_gateway_authz_decisions_total{endpoint="/v1/extauthz/check",result="ALLOW",reason="ACTIVE_ACCOUNT_GRANT",provider_id="mockcarrier",operation_id="tracking.get",environment="TEST"} 1`,
		`idp_gateway_authz_decision_duration_seconds_bucket{le="0.001"}`,
		`idp_gateway_authz_decision_duration_seconds_bucket{le="+Inf"}`,
		"idp_gateway_authz_revocation_epoch ",
		"idp_gateway_authz_otlp_spans_exported_total ",
	} {
		if !strings.Contains(prom, needle) {
			t.Fatalf("metrics missing %s:\n%s", needle, prom)
		}
	}
	other := httptest.NewRecorder()
	f.handler.ServeHTTP(other, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if other.Code != http.StatusNotFound {
		t.Fatalf("mTLS handler served /metrics: %d", other.Code)
	}
	denied := httptest.NewRecorder()
	metrics.ServeHTTP(denied, httptest.NewRequest(http.MethodPost, "/metrics", nil))
	if denied.Code != http.StatusMethodNotAllowed {
		t.Fatalf("metrics method %d", denied.Code)
	}
}

func TestRefusalIsAuditedAsClientAuth(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	sink, err := audit.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer sink.Close()
	f := newFixture(t)
	f.handler.WithTelemetry(Telemetry{Audit: sink})
	recorder := f.call("business", "GET", PathExtAuthz, trusted("tenant-blue"), "")
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("%d", recorder.Code)
	}
	recent, err := audit.ReadRecent(path, audit.Filter{EventType: "egress_decision", Outcome: "DENY"}, 5)
	if err != nil || len(recent) != 1 || recent[0].FailureOrigin != "client_auth" || recent[0].Reason != reasonCallerUnauthenticated {
		t.Fatalf("%+v %v", recent, err)
	}
}
