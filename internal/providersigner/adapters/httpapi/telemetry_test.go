package httpapi

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"go.idp.xyz/idp-gateway/internal/platform/audit"
	"go.idp.xyz/idp-gateway/internal/platform/otlp"
)

func TestSignerTelemetryLinksTraceparentAndOmitsSecrets(t *testing.T) {
	const parent = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
	bodies := make(chan []byte, 1)
	collector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		bodies <- body
		w.WriteHeader(http.StatusOK)
	}))
	defer collector.Close()
	exp, err := otlp.NewExporter(otlp.Config{
		Endpoint: collector.URL + "/v1/traces", ServiceName: "idp-provider-signer",
		BatchSize: 1, FlushInterval: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = exp.Close(t.Context()) })
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	sink, err := audit.Open(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sink.Close() })
	metrics := NewSignerMetrics(func() (uint64, uint64, uint64) { return exp.Stats() })
	f := newFixture(t)
	f.handler.WithTelemetry(Telemetry{Traces: exp, Audit: sink, Metrics: metrics})

	header := jsonHeaders("Traceparent", parent)
	recorder := f.serve(t, attempt{target: "/sfintl/v1/orders", peer: "gateway", header: header})
	if recorder.Code != http.StatusOK {
		t.Fatalf("%d %s", recorder.Code, recorder.Body)
	}
	logged := map[string]any{}
	lines := strings.Split(strings.TrimSpace(f.logs.String()), "\n")
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &logged); err != nil {
		t.Fatal(err)
	}
	if logged["msg"] != "signer call" || logged["traceparent"] != parent || logged["trace_id"] != "4bf92f3577b34da6a3ce929d0e0e4736" {
		t.Fatalf("log %#v", logged)
	}
	var body []byte
	select {
	case body = <-bodies:
	case <-time.After(2 * time.Second):
		t.Fatal("span was not exported")
	}
	text := string(body)
	for _, secret := range []string{testAppKey, testToken, testAESKey, "Sf-OpenApi", authorization} {
		if strings.Contains(text, secret) {
			t.Fatalf("span contains %q", secret)
		}
	}
	for _, needle := range []string{`"name":"providersigner.dispatch"`, `"parentSpanId":"00f067aa0ba902b7"`, `"stringValue":"orders.create"`, `"stringValue":"ok"`} {
		if !strings.Contains(text, needle) {
			t.Fatalf("span missing %s: %s", needle, text)
		}
	}
	recent, err := audit.ReadRecent(auditPath, audit.Filter{EventType: "signer_call", Outcome: "ok"}, 5)
	if err != nil || len(recent) != 1 || recent[0].FailureOrigin != "" || recent[0].TraceID != "4bf92f3577b34da6a3ce929d0e0e4736" {
		t.Fatalf("audit %+v %v", recent, err)
	}
	metricsRec := httptest.NewRecorder()
	metrics.ServeHTTP(metricsRec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	prom := metricsRec.Body.String()
	if !strings.Contains(prom, `idp_gateway_signer_calls_total{operation="orders.create",outcome="ok",status="200"} 1`) ||
		!strings.Contains(prom, "idp_gateway_signer_circuit_open 0") ||
		!strings.Contains(prom, `idp_gateway_signer_call_duration_seconds_bucket{le="+Inf"}`) {
		t.Fatalf("metrics:\n%s", prom)
	}
	for _, secret := range []string{testAppKey, testToken, testAESKey, authorization} {
		if strings.Contains(prom, secret) {
			t.Fatalf("metrics contain %q", secret)
		}
	}
	missing := f.serve(t, attempt{method: http.MethodGet, target: "/metrics", peer: "gateway", header: jsonHeaders()})
	if missing.Code != http.StatusNotFound || strings.Contains(missing.Body.String(), "idp_gateway_signer_calls_total") {
		t.Fatalf("signer handler served /metrics: %d %s", missing.Code, missing.Body)
	}
}
