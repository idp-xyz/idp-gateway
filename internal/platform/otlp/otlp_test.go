package otlp

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestParseTraceparent(t *testing.T) {
	const valid = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
	ctx, ok := ParseTraceparentValue(valid)
	if !ok || !ctx.Sampled || ctx.TraceID != "4bf92f3577b34da6a3ce929d0e0e4736" || ctx.SpanID != "00f067aa0ba902b7" {
		t.Fatalf("valid: %+v %v", ctx, ok)
	}
	unsampled, ok := ParseTraceparentValue("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-00")
	if !ok || unsampled.Sampled {
		t.Fatalf("flags 00 should be unsampled: %+v", unsampled)
	}
	sampledOther, ok := ParseTraceparentValue("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-03")
	if !ok || !sampledOther.Sampled {
		t.Fatal("lowest flag bit is sampled")
	}
	for _, raw := range []string{
		"",
		"00-00000000000000000000000000000000-00f067aa0ba902b7-01",
		"00-4bf92f3577b34da6a3ce929d0e0e4736-0000000000000000-01",
		"00-4BF92F3577B34DA6A3CE929D0E0E4736-00f067aa0ba902b7-01",
		"01-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
		"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01-extra",
		valid + "\n",
		"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-0g",
		strings.Repeat("a", 129),
	} {
		if _, ok := ParseTraceparentValue(raw); ok {
			t.Errorf("accepted %q", raw)
		}
	}
	header := make(http.Header)
	header.Add("Traceparent", "not-a-trace")
	header.Add("Traceparent", valid)
	header.Add("Traceparent", "00-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-bbbbbbbbbbbbbbbb-00")
	got, ok := ParseTraceparent(header)
	if !ok || got.TraceID != "4bf92f3577b34da6a3ce929d0e0e4736" {
		t.Fatalf("first valid value: %+v %v", got, ok)
	}
	if _, ok := ParseTraceparent(nil); ok {
		t.Fatal("nil header")
	}
	if _, ok := ParseTraceparent(http.Header{}); ok {
		t.Fatal("empty header")
	}
}

func TestNewIDsRoundTrip(t *testing.T) {
	traceID, spanID := NewTraceID(), NewSpanID()
	if len(traceID) != 32 || len(spanID) != 16 || traceID == zeroTraceID || spanID == zeroSpanID {
		t.Fatalf("ids %s %s", traceID, spanID)
	}
	raw := FormatTraceparent(traceID, spanID, true)
	ctx, ok := ParseTraceparentValue(raw)
	if !ok || !ctx.Sampled || ctx.TraceID != traceID || ctx.SpanID != spanID {
		t.Fatalf("round trip %s -> %+v %v", raw, ctx, ok)
	}
	if !strings.HasSuffix(FormatTraceparent(traceID, spanID, false), "-00") {
		t.Fatal("unsampled flags")
	}
}

func TestEndpointValidation(t *testing.T) {
	if _, err := NewExporter(Config{Endpoint: "http://127.0.0.1:4318/v1/traces"}); err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{
		"",
		"ftp://127.0.0.1/v1/traces",
		"http://user:pass@127.0.0.1/v1/traces",
		"http://127.0.0.1/v1/traces?x=1",
		"http://127.0.0.1/v1/traces#frag",
		"http:///v1/traces",
		"127.0.0.1:4318/v1/traces",
		"http://127.0.0.1/v1/traces\n",
	} {
		if _, err := NewExporter(Config{Endpoint: raw}); err == nil {
			t.Errorf("accepted %q", raw)
		}
	}
}

func TestExportBatchAndStripSecrets(t *testing.T) {
	var bodies [][]byte
	got := make(chan struct{}, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/json" || r.URL.Path != "/v1/traces" {
			t.Errorf("request %s %s %s", r.Method, r.URL.Path, r.Header.Get("Content-Type"))
		}
		body, _ := io.ReadAll(r.Body)
		bodies = append(bodies, body)
		select {
		case got <- struct{}{}:
		default:
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	exp := newTestExporter(t, srv.URL+"/v1/traces", Config{BatchSize: 2, FlushInterval: time.Hour, ServiceName: "idp-gateway-authz", ServiceVersion: "test"})
	start := time.Date(2026, 11, 23, 1, 2, 3, 4, time.UTC)
	end := start.Add(1500 * time.Microsecond)
	long := strings.Repeat("x", 600) + "\r\n"
	exp.Record(Span{
		TraceID: "4bf92f3577b34da6a3ce929d0e0e4736", SpanID: "aaaaaaaaaaaaaaaa", ParentSpanID: "00f067aa0ba902b7",
		Name: "egressauthz.check", Kind: SpanKindServer, StartTime: start, EndTime: end,
		StatusCode: StatusCodeOK, StatusMessage: "ACTIVE_ACCOUNT_GRANT",
		Attributes: map[string]any{
			"decision_id":               "dec-1",
			"http.response.status_code": 200,
			"sampled":                   true,
			"Authorization":             "Bearer provider-token",
			"api_key":                   "secret-value",
			"session_token":             "tok",
			"credential_binding_ref":    "gatekeeper:wanb",
			"encoding_aes_key":          "aes-key",
			"note":                      long,
			"route_id":                  "wanb\r\nexpress",
		},
	})
	exp.Record(Span{
		TraceID: "4bf92f3577b34da6a3ce929d0e0e4736", SpanID: "bbbbbbbbbbbbbbbb",
		Name: "egressauthz.check", Kind: SpanKindServer, StartTime: start, EndTime: end, StatusCode: StatusCodeError,
	})
	select {
	case <-got:
	case <-time.After(2 * time.Second):
		t.Fatal("batch was not exported")
	}
	if err := exp.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(bodies) != 1 {
		t.Fatalf("posts %d", len(bodies))
	}
	raw := string(bodies[0])
	for _, secret := range []string{"provider-token", "secret-value", "gatekeeper:wanb", "aes-key", "Bearer"} {
		if strings.Contains(raw, secret) {
			t.Fatalf("exported secret %q in %s", secret, raw)
		}
	}
	var doc map[string]any
	if err := json.Unmarshal(bodies[0], &doc); err != nil {
		t.Fatal(err)
	}
	spans := doc["resourceSpans"].([]any)[0].(map[string]any)["scopeSpans"].([]any)[0].(map[string]any)["spans"].([]any)
	if len(spans) != 2 {
		t.Fatalf("spans %#v", spans)
	}
	first := spans[0].(map[string]any)
	if first["traceId"] != "4bf92f3577b34da6a3ce929d0e0e4736" || first["parentSpanId"] != "00f067aa0ba902b7" || first["spanId"] != "aaaaaaaaaaaaaaaa" {
		t.Fatalf("ids %#v", first)
	}
	if first["startTimeUnixNano"] != "1763863323000000004" && !isDigits(first["startTimeUnixNano"]) {
		t.Fatalf("start %#v", first["startTimeUnixNano"])
	}
	if _, ok := first["startTimeUnixNano"].(string); !ok {
		t.Fatalf("start type %T", first["startTimeUnixNano"])
	}
	if _, ok := first["endTimeUnixNano"].(string); !ok {
		t.Fatal("end is not a string")
	}
	attrs := attributeMap(t, first["attributes"])
	if attrs["decision_id"].(map[string]any)["stringValue"] != "dec-1" {
		t.Fatalf("decision %#v", attrs["decision_id"])
	}
	if attrs["http.response.status_code"].(map[string]any)["intValue"] != "200" {
		t.Fatalf("status %#v", attrs["http.response.status_code"])
	}
	if attrs["sampled"].(map[string]any)["boolValue"] != true {
		t.Fatalf("bool %#v", attrs["sampled"])
	}
	note := attrs["note"].(map[string]any)["stringValue"].(string)
	if len(note) > 512 || strings.ContainsAny(note, "\r\n") {
		t.Fatalf("note %q", note)
	}
	if attrs["route_id"].(map[string]any)["stringValue"] != "wanbexpress" {
		t.Fatalf("route %#v", attrs["route_id"])
	}
	for _, key := range []string{"Authorization", "api_key", "session_token", "credential_binding_ref", "encoding_aes_key"} {
		if _, ok := attrs[key]; ok {
			t.Fatalf("sensitive key %s survived", key)
		}
	}
	resource := doc["resourceSpans"].([]any)[0].(map[string]any)["resource"].(map[string]any)
	resAttrs := attributeMap(t, resource["attributes"])
	if resAttrs["service.name"].(map[string]any)["stringValue"] != "idp-gateway-authz" {
		t.Fatalf("service %#v", resAttrs)
	}
	scope := doc["resourceSpans"].([]any)[0].(map[string]any)["scopeSpans"].([]any)[0].(map[string]any)["scope"].(map[string]any)
	if scope["name"] != scopeName {
		t.Fatalf("scope %#v", scope)
	}
	status := first["status"].(map[string]any)
	if status["code"] != float64(StatusCodeOK) || status["message"] != "ACTIVE_ACCOUNT_GRANT" {
		t.Fatalf("status %#v", status)
	}
	exported, dropped, failed := exp.Stats()
	if exported != 2 || dropped != 0 || failed != 0 {
		t.Fatalf("stats %d %d %d", exported, dropped, failed)
	}
}

func TestRecordDoesNotBlockWhenCollectorIsUnreachable(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}
	exp := newTestExporter(t, "http://"+addr+"/v1/traces", Config{BatchSize: 1, FlushInterval: 10 * time.Millisecond, Timeout: 200 * time.Millisecond})
	span := Span{TraceID: NewTraceID(), SpanID: NewSpanID(), Name: "check", Kind: SpanKindServer, StartTime: time.Now(), EndTime: time.Now(), StatusCode: StatusCodeOK}
	started := time.Now()
	exp.Record(span)
	if time.Since(started) > 50*time.Millisecond {
		t.Fatalf("Record blocked for %s", time.Since(started))
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		_, _, failed := exp.Stats()
		if failed > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("unreachable collector did not count a failure")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestFullBufferDropsWithoutBlocking(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-started:
		default:
			close(started)
		}
		<-release
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	exp := newTestExporter(t, srv.URL+"/v1/traces", Config{BatchSize: 1, BufferSize: 1, FlushInterval: time.Hour, Timeout: 5 * time.Second})
	exp.Record(Span{TraceID: NewTraceID(), SpanID: NewSpanID(), Name: "a", Kind: SpanKindInternal, StartTime: time.Now(), EndTime: time.Now()})
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("export did not start")
	}
	done := make(chan struct{})
	go func() {
		exp.Record(Span{TraceID: NewTraceID(), SpanID: NewSpanID(), Name: "b", Kind: SpanKindInternal, StartTime: time.Now(), EndTime: time.Now()})
		exp.Record(Span{TraceID: NewTraceID(), SpanID: NewSpanID(), Name: "c", Kind: SpanKindInternal, StartTime: time.Now(), EndTime: time.Now()})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(200 * time.Millisecond):
		t.Fatal("Record blocked on a full buffer")
	}
	if exp.Dropped() == 0 {
		t.Fatal("expected a dropped span")
	}
	close(release)
}

func TestCloseFlushesPendingSpans(t *testing.T) {
	got := make(chan []byte, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		got <- body
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	exp := newTestExporter(t, srv.URL+"/v1/traces", Config{BatchSize: 32, FlushInterval: time.Hour})
	exp.Record(Span{TraceID: NewTraceID(), SpanID: NewSpanID(), Name: "pending", Kind: SpanKindClient, StartTime: time.Now(), EndTime: time.Now(), StatusCode: StatusCodeOK})
	if err := exp.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	select {
	case body := <-got:
		if !strings.Contains(string(body), `"name":"pending"`) {
			t.Fatalf("body %s", body)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not flush")
	}
	before := exp.Dropped()
	exp.Record(Span{TraceID: NewTraceID(), SpanID: NewSpanID(), Name: "late", Kind: SpanKindClient, StartTime: time.Now(), EndTime: time.Now()})
	if exp.Dropped() != before+1 {
		t.Fatalf("dropped %d -> %d", before, exp.Dropped())
	}
	if err := exp.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestCloseHonorsDeadlineWhileCollectorHangs(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
		w.WriteHeader(http.StatusOK)
	}))
	defer func() {
		close(release)
		srv.Close()
	}()
	exp := newTestExporter(t, srv.URL+"/v1/traces", Config{BatchSize: 1, FlushInterval: time.Hour, Timeout: 5 * time.Second})
	exp.Record(Span{TraceID: NewTraceID(), SpanID: NewSpanID(), Name: "hang", Kind: SpanKindServer, StartTime: time.Now(), EndTime: time.Now()})
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	started := time.Now()
	err := exp.Close(ctx)
	if time.Since(started) > time.Second {
		t.Fatalf("Close blocked for %s: %v", time.Since(started), err)
	}
}

func newTestExporter(t *testing.T, endpoint string, cfg Config) *Exporter {
	t.Helper()
	cfg.Endpoint = endpoint
	exp, err := NewExporter(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = exp.Close(ctx)
	})
	return exp
}

func attributeMap(t *testing.T, raw any) map[string]any {
	t.Helper()
	out := map[string]any{}
	for _, item := range raw.([]any) {
		attr := item.(map[string]any)
		out[attr["key"].(string)] = attr["value"]
	}
	return out
}

func isDigits(v any) bool {
	s, ok := v.(string)
	if !ok || s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
