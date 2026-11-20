package domain

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"
)

const (
	trustedRoute       = "gwi-example-001"
	trustedTenant      = "tenant-blue"
	trustedEnvironment = "TEST"
)

var fixedNow = time.Date(2026, 11, 10, 8, 5, 0, 0, time.UTC)

func TestValidSample(t *testing.T) {
	assertAuth(t, grant(t), fixedNow, true, "APPROVED_BOUND_SCOPE")
}

func TestCrossTenantDenied(t *testing.T) {
	allowed, reason := AuthorizeCapture(grant(t), trustedRoute, "tenant-other", trustedEnvironment, fixedNow)
	if allowed || reason != "SCOPE_MISMATCH" {
		t.Fatalf("AuthorizeCapture() = (%v, %s), want (false, SCOPE_MISMATCH)", allowed, reason)
	}
}

func TestScopeMismatch(t *testing.T) {
	sample := grant(t)
	assertAuth(t, nil, fixedNow, false, "SCOPE_MISMATCH")
	assertAuth(t, map[string]any{}, fixedNow, false, "SCOPE_MISMATCH")

	wrongRoute := cloneMap(t, sample)
	wrongRoute["route_ref"] = "gwi-other"
	assertAuth(t, wrongRoute, fixedNow, false, "SCOPE_MISMATCH")

	wrongEnv := cloneMap(t, sample)
	wrongEnv["environment"] = "PROD"
	assertAuth(t, wrongEnv, fixedNow, false, "SCOPE_MISMATCH")

	wrongType := cloneMap(t, sample)
	wrongType["tenant_ref"] = 12
	assertAuth(t, wrongType, fixedNow, false, "SCOPE_MISMATCH")
}

func TestSamePersonApproved(t *testing.T) {
	// 2026-11-19 起不检查职责分离，同一个人批准可以通过。
	sample := cloneMap(t, grant(t))
	sample["approved_by"] = sample["requested_by"]
	assertAuth(t, sample, fixedNow, true, "APPROVED_BOUND_SCOPE")
}

func TestApprovedByMayBeEmpty(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{"approved_by missing", func(g map[string]any) { delete(g, "approved_by") }},
		{"approved_by empty", func(g map[string]any) { g["approved_by"] = "" }},
		{"approved_by blank", func(g map[string]any) { g["approved_by"] = "   " }},
		{"approved_by null", func(g map[string]any) { g["approved_by"] = nil }},
		{"approved_by not a string", func(g map[string]any) { g["approved_by"] = []any{"security-reviewer-b"} }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sample := cloneMap(t, grant(t))
			tc.mutate(sample)
			assertAuth(t, sample, fixedNow, true, "APPROVED_BOUND_SCOPE")
		})
	}
}

func TestRequestedByMustBePresent(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{"requested_by missing", func(g map[string]any) { delete(g, "requested_by") }},
		{"requested_by empty", func(g map[string]any) { g["requested_by"] = "" }},
		{"requested_by blank", func(g map[string]any) { g["requested_by"] = "   " }},
		{"requested_by null", func(g map[string]any) { g["requested_by"] = nil }},
		{"requested_by not a string", func(g map[string]any) { g["requested_by"] = []any{"engineer-a"} }},
		{"both missing", func(g map[string]any) {
			delete(g, "approved_by")
			delete(g, "requested_by")
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sample := cloneMap(t, grant(t))
			tc.mutate(sample)
			assertAuth(t, sample, fixedNow, false, "APPROVAL_IDENTITY_MISSING")
		})
	}
}

func TestSamePersonUnderAnotherSpelling(t *testing.T) {
	for _, approver := range []string{"Engineer-A", "ENGINEER-A", " engineer-a ", "engineer-a\t"} {
		t.Run(approver, func(t *testing.T) {
			sample := cloneMap(t, grant(t))
			sample["approved_by"] = approver
			assertAuth(t, sample, fixedNow, true, "APPROVED_BOUND_SCOPE")
		})
	}
}

func TestExpiredDenied(t *testing.T) {
	now := time.Date(2026, 11, 10, 9, 0, 0, 0, time.UTC)
	assertAuth(t, grant(t), now, false, "OUTSIDE_APPROVED_WINDOW")
}

func TestWindowBound(t *testing.T) {
	sample := cloneMap(t, grant(t))
	sample["expires_at"] = "2026-11-10T08:30:00Z"
	assertAuth(t, sample, fixedNow, false, "WINDOW_EXCEEDED")
}

func TestWindowAndClockBoundaries(t *testing.T) {
	t.Run("exactly 900 seconds stays approved", func(t *testing.T) {
		assertAuth(t, grant(t), fixedNow, true, "APPROVED_BOUND_SCOPE")
	})
	t.Run("one second over the maximum", func(t *testing.T) {
		sample := cloneMap(t, grant(t))
		sample["expires_at"] = "2026-11-10T08:15:01Z"
		assertAuth(t, sample, fixedNow, false, "WINDOW_EXCEEDED")
	})
	t.Run("end equal to start", func(t *testing.T) {
		sample := cloneMap(t, grant(t))
		sample["expires_at"] = sample["start_at"]
		assertAuth(t, sample, fixedNow, false, "WINDOW_EXCEEDED")
	})
	t.Run("now equal to start is inside", func(t *testing.T) {
		now := time.Date(2026, 11, 10, 8, 0, 0, 0, time.UTC)
		assertAuth(t, grant(t), now, true, "APPROVED_BOUND_SCOPE")
	})
	t.Run("now equal to end is outside", func(t *testing.T) {
		now := time.Date(2026, 11, 10, 8, 15, 0, 0, time.UTC)
		assertAuth(t, grant(t), now, false, "OUTSIDE_APPROVED_WINDOW")
	})
	t.Run("now before start", func(t *testing.T) {
		now := time.Date(2026, 11, 10, 7, 59, 59, 0, time.UTC)
		assertAuth(t, grant(t), now, false, "OUTSIDE_APPROVED_WINDOW")
	})
	t.Run("now in another zone is the same instant", func(t *testing.T) {
		cst := time.FixedZone("CST", 8*3600)
		now := time.Date(2026, 11, 10, 16, 5, 0, 0, cst)
		assertAuth(t, grant(t), now, true, "APPROVED_BOUND_SCOPE")
	})
	t.Run("offset timestamps are compared in UTC", func(t *testing.T) {
		sample := cloneMap(t, grant(t))
		sample["start_at"] = "2026-11-10T16:00:00+08:00"
		sample["expires_at"] = "2026-11-10T16:15:00+08:00"
		assertAuth(t, sample, fixedNow, true, "APPROVED_BOUND_SCOPE")
	})
}

func TestInvalidCaptureTimestamps(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{"naive", func(g map[string]any) { g["start_at"] = "2026-11-10T08:00:00" }},
		{"lowercase z", func(g map[string]any) { g["start_at"] = "2026-11-10T08:00:00z" }},
		{"garbage", func(g map[string]any) { g["expires_at"] = "yesterday" }},
		{"missing", func(g map[string]any) { delete(g, "start_at") }},
		{"not a string", func(g map[string]any) { g["expires_at"] = 1 }},
		{"empty", func(g map[string]any) { g["start_at"] = "" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sample := cloneMap(t, grant(t))
			tc.mutate(sample)
			assertAuth(t, sample, fixedNow, false, "INVALID_CAPTURE_TIMESTAMPS")
		})
	}
}

func TestParseUTCMatchesReference(t *testing.T) {
	accepted := []struct {
		in   string
		want time.Time
	}{
		{"2026-11-10T08:00:00Z", time.Date(2026, 11, 10, 8, 0, 0, 0, time.UTC)},
		{"2026-11-10T08:00:00+00:00", time.Date(2026, 11, 10, 8, 0, 0, 0, time.UTC)},
		{"2026-11-10T08:00:00.123Z", time.Date(2026, 11, 10, 8, 0, 0, 123000000, time.UTC)},
		{"2026-11-10T08:00:00.123456+00:00", time.Date(2026, 11, 10, 8, 0, 0, 123456000, time.UTC)},
		{"2026-11-10T08:00:00+08:00", time.Date(2026, 11, 10, 0, 0, 0, 0, time.UTC)},
		{"2026-11-10 08:00:00+00:00", time.Date(2026, 11, 10, 8, 0, 0, 0, time.UTC)},
		{"2026-11-10T08:00:00+00:00:00", time.Date(2026, 11, 10, 8, 0, 0, 0, time.UTC)},
		{"2026-11-10T08:00:00+00", time.Date(2026, 11, 10, 8, 0, 0, 0, time.UTC)},
		{"2026-11-10T08:00:00.123+0000", time.Date(2026, 11, 10, 8, 0, 0, 123000000, time.UTC)},
		{"2026-11-10T08:00+0000", time.Date(2026, 11, 10, 8, 0, 0, 0, time.UTC)},
		{"2026-11-10 08:00+00:00", time.Date(2026, 11, 10, 8, 0, 0, 0, time.UTC)},
		{"2026-11-10T08:00:00.123456789+00:00", time.Date(2026, 11, 10, 8, 0, 0, 123456000, time.UTC)},
		{"2026-11-10T08:00:00,123+00:00", time.Date(2026, 11, 10, 8, 0, 0, 123000000, time.UTC)},
	}
	for _, tc := range accepted {
		t.Run(tc.in, func(t *testing.T) {
			got, err := parseUTC(tc.in)
			if err != nil {
				t.Fatal(err)
			}
			if !got.Equal(tc.want) {
				t.Fatalf("parseUTC() = %s, want %s", got.Format(time.RFC3339Nano), tc.want.Format(time.RFC3339Nano))
			}
		})
	}
	for _, in := range []any{"2026-11-10T08:00:00z", "2026-11-10T08:00:00", "", nil, 1} {
		if _, err := parseUTC(in); err == nil {
			t.Fatalf("%v was accepted", in)
		}
	}
}

func TestLimitMustBeAnIntegerInRange(t *testing.T) {
	rejected := []struct {
		name  string
		value any
	}{
		{"string", "16384"},
		{"nil", nil},
		{"bool", true},
		{"fraction", 1.5},
		{"whole float", float64(16384)},
		{"negative", -1},
		{"too big", 65537},
		{"list", []any{1}},
		{"object", map[string]any{}},
	}
	for _, tc := range rejected {
		t.Run(tc.name, func(t *testing.T) {
			sample := cloneMap(t, grant(t))
			sample["max_bytes_per_message"] = tc.value
			assertAuth(t, sample, fixedNow, false, "UNSAFE_LIMIT")
		})
	}
	t.Run("missing", func(t *testing.T) {
		sample := cloneMap(t, grant(t))
		delete(sample, "max_bytes_per_message")
		assertAuth(t, sample, fixedNow, false, "UNSAFE_LIMIT")
	})
	accepted := []struct {
		name  string
		value any
	}{
		{"zero", 0},
		{"max", 65536},
		{"zero json number", json.Number("0")},
		{"max json number", json.Number("65536")},
	}
	for _, tc := range accepted {
		t.Run(tc.name, func(t *testing.T) {
			sample := cloneMap(t, grant(t))
			sample["max_bytes_per_message"] = tc.value
			assertAuth(t, sample, fixedNow, true, "APPROVED_BOUND_SCOPE")
		})
	}
}

func TestTokenHeaderDropped(t *testing.T) {
	got := SanitizeHeaders(map[string]any{
		"Authorization": "Bearer secret",
		"Cookie":        "jwt=secret",
		"X-Api-Key":     "secret",
		"Content-Type":  "application/json",
		"X-Client-Id":   "private",
		"X-Request-ID":  "r-42",
	})
	want := map[string]string{"content-type": "application/json", "x-request-id": "r-42"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("SanitizeHeaders() = %#v, want %#v", got, want)
	}
}

func TestAllowlistedNamesAreRecordedLowercase(t *testing.T) {
	got := SanitizeHeaders(map[string]any{"Content-Type": "application/json", "X-Correlation-ID": "t-1"})
	want := map[string]string{"content-type": "application/json", "x-correlation-id": "t-1"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("SanitizeHeaders() = %#v, want %#v", got, want)
	}
	for _, name := range AllowedHeaders() {
		got = SanitizeHeaders(map[string]any{strings.ToUpper(name): "value-1"})
		want = map[string]string{name: "value-1"}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("%s: got %#v", name, got)
		}
	}
}

func TestHeaderValueShape(t *testing.T) {
	if got := SanitizeHeaders(map[string]any{"content-type": 1, "x-request-id": "ok"}); !reflect.DeepEqual(got, map[string]string{"x-request-id": "ok"}) {
		t.Fatalf("non-string value kept: %#v", got)
	}
	if _, ok := SanitizeHeaders(map[string]any{"content-type": strings.Repeat("a", 256)})["content-type"]; ok {
		t.Fatal("256-character value was kept")
	}
	if got := SanitizeHeaders(map[string]any{"content-type": strings.Repeat("a", 255)}); got["content-type"] == "" {
		t.Fatal("255-character value was dropped")
	}
	if got := SanitizeHeaders(map[string]any{"content-type": strings.Repeat("测", 100)}); utf8RuneCount(got["content-type"]) != 100 {
		t.Fatal("rune length was measured in bytes")
	}
	if _, ok := SanitizeHeaders(map[string]any{"content-type": strings.Repeat("测", 256)})["content-type"]; ok {
		t.Fatal("256-rune value was kept")
	}
	if len(SanitizeHeaders(nil)) != 0 {
		t.Fatal("nil headers did not become an empty map")
	}
}

func TestBodyCannotLeak(t *testing.T) {
	body := map[string]any{"name": "Sensitive Person", "address": "sensitive"}
	out := SanitizedEvidence(map[string]any{"Authorization": "Bearer jwt"}, body, grant(t))
	if out.BodySampleSanitized != nil {
		t.Fatal("body sample was stored")
	}
	if out.BodyStatus != "NOT_CAPTURED" || out.ProductionPayloadCaptureEnabled {
		t.Fatalf("body status = %s, capture enabled = %v", out.BodyStatus, out.ProductionPayloadCaptureEnabled)
	}
	if !out.CaptureGrantPresent {
		t.Fatal("grant was present")
	}
	if _, ok := out.SanitizedHeaders["authorization"]; ok {
		t.Fatal("authorization header was kept")
	}
	assertNoBody(t, out, "Sensitive", "Bearer")

	absent := SanitizedEvidence(map[string]any{"Content-Type": "application/json"}, []byte("Sensitive Person"), nil)
	if absent.CaptureGrantPresent || absent.ProductionPayloadCaptureEnabled || absent.BodyStatus != "NOT_CAPTURED" {
		t.Fatalf("%+v", absent)
	}
	assertNoBody(t, absent, "Sensitive")

	emptyGrant := SanitizedEvidence(nil, "Sensitive Person", map[string]any{})
	if emptyGrant.CaptureGrantPresent {
		t.Fatal("empty grant counted as present")
	}
	assertNoBody(t, emptyGrant, "Sensitive")
}

func TestDeliveredExamplesAreConsistent(t *testing.T) {
	assertIssues(t, event(t, "diagnostic-event.paired-200.example.json"))
	assertIssues(t, event(t, "diagnostic-event.example.json"))
}

func TestStageReportedTwice(t *testing.T) {
	sample := event(t, "diagnostic-event.example.json")
	stages := sample["stages"].([]any)
	stages[1] = cloneMap(t, stages[0].(map[string]any))
	assertIssues(t, sample, "DUPLICATE_STAGE")
}

func TestUnobservedStageCarryingObservations(t *testing.T) {
	fields := []struct {
		name  string
		value any
	}{
		{"http_status", 200},
		{"body_sha256", strings.Repeat("a", 64)},
		{"body_sample_sanitized", "{}"},
		{"sanitized_headers", map[string]any{"content-type": "application/json"}},
		{"grpc_status", 0},
		{"bytes_observed", 1},
		{"body_total_bytes", 1},
		{"body_captured_bytes", 1},
		{"content_type", "application/json"},
		{"provider_request_id_sanitized", "REQ-1"},
	}
	for _, status := range []string{"NOT_SENT", "NOT_OBSERVED"} {
		for _, field := range fields {
			t.Run(status+" "+field.name, func(t *testing.T) {
				sample := event(t, "diagnostic-event.example.json")
				stage := sample["stages"].([]any)[2].(map[string]any)
				stage["status"] = status
				stage[field.name] = field.value
				assertIssues(t, sample, "UNOBSERVED_STAGE_HAS_OBSERVATIONS")
			})
		}
	}
}

func TestNotSentOutcomeWithAnUpstreamExchange(t *testing.T) {
	sample := event(t, "diagnostic-event.paired-200.example.json")
	sample["business_outcome"] = "NOT_SENT"
	assertIssues(t, sample, "NOT_SENT_OUTCOME_WITH_UPSTREAM_EXCHANGE")
}

func TestNotSentWithoutUpstreamExchangeIsConsistent(t *testing.T) {
	sample := event(t, "diagnostic-event.example.json")
	sample["business_outcome"] = "NOT_SENT"
	stage := sample["stages"].([]any)[1].(map[string]any)
	stage["status"] = "NOT_OBSERVED"
	assertIssues(t, sample)
}

func TestSuccessOutcomeWithoutAnUpstreamResponse(t *testing.T) {
	sample := event(t, "diagnostic-event.example.json")
	sample["business_outcome"] = "SUCCESS"
	assertIssues(t, sample, "SUCCESS_OUTCOME_WITHOUT_UPSTREAM_RESPONSE")

	t.Run("stage absent", func(t *testing.T) {
		paired := event(t, "diagnostic-event.paired-200.example.json")
		raw := paired["stages"].([]any)
		kept := make([]any, 0, len(raw))
		for _, item := range raw {
			stage := item.(map[string]any)
			if stage["stage"] != "UPSTREAM_RESPONSE" {
				kept = append(kept, stage)
			}
		}
		paired["stages"] = kept
		assertIssues(t, paired, "SUCCESS_OUTCOME_WITHOUT_UPSTREAM_RESPONSE")
	})
}

func TestSemanticIssuesAreSorted(t *testing.T) {
	sample := event(t, "diagnostic-event.example.json")
	stages := sample["stages"].([]any)
	stages[1] = cloneMap(t, stages[0].(map[string]any))
	upstream := stages[2].(map[string]any)
	upstream["http_status"] = 200
	sample["business_outcome"] = "SUCCESS"
	assertIssues(t, sample,
		"DUPLICATE_STAGE",
		"SUCCESS_OUTCOME_WITHOUT_UPSTREAM_RESPONSE",
		"UNOBSERVED_STAGE_HAS_OBSERVATIONS",
	)
}

func TestSchemaVocabulary(t *testing.T) {
	schema := loadObject(t, filepath.Join(repoRoot(t), "contracts/gateway/diagnostic-event.schema.json"))
	defs := objectField(t, schema, "$defs")
	headerNames := stringList(t, objectField(t, defs, "sanitized_header_name"), "enum")
	sort.Strings(headerNames)
	if !reflect.DeepEqual(headerNames, AllowedHeaders()) {
		t.Fatalf("headers schema %v reference %v", headerNames, AllowedHeaders())
	}
	properties := objectField(t, schema, "properties")
	stageItems := objectField(t, objectField(t, properties, "stages"), "items")
	stage := objectField(t, objectField(t, stageItems, "properties"), "stage")
	if !reflect.DeepEqual(stringList(t, stage, "enum"), StageNames()) {
		t.Fatalf("stages schema %v reference %v", stringList(t, stage, "enum"), StageNames())
	}
}

func assertAuth(t *testing.T, sample map[string]any, now time.Time, allowed bool, reason string) {
	t.Helper()
	gotAllowed, gotReason := AuthorizeCapture(sample, trustedRoute, trustedTenant, trustedEnvironment, now)
	if gotAllowed != allowed || gotReason != reason {
		t.Fatalf("AuthorizeCapture() = (%v, %s), want (%v, %s)", gotAllowed, gotReason, allowed, reason)
	}
}

func assertIssues(t *testing.T, sample map[string]any, want ...string) {
	t.Helper()
	got := EventSemanticErrors(sample)
	if want == nil {
		want = []string{}
	}
	sort.Strings(want)
	if len(got) == 0 && len(want) == 0 {
		return
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("issues = %#v, want %#v", got, want)
	}
}

func assertNoBody(t *testing.T, out Evidence, forbidden ...string) {
	t.Helper()
	raw, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	for _, word := range forbidden {
		if strings.Contains(text, word) {
			t.Fatalf("evidence contains %q: %s", word, text)
		}
	}
}

func utf8RuneCount(s string) int { return len([]rune(s)) }

func grant(t *testing.T) map[string]any {
	t.Helper()
	return loadObject(t, filepath.Join(repoRoot(t), "contracts/gateway/policies/diagnostic-capture.example.json"))
}

func event(t *testing.T, name string) map[string]any {
	t.Helper()
	return loadObject(t, filepath.Join(repoRoot(t), "contracts/gateway", name))
}

func loadObject(t *testing.T, path string) map[string]any {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var obj map[string]any
	if err := dec.Decode(&obj); err != nil {
		t.Fatal(err)
	}
	return obj
}

func cloneMap(t *testing.T, in map[string]any) map[string]any {
	t.Helper()
	data, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var out map[string]any
	if err := dec.Decode(&out); err != nil {
		t.Fatal(err)
	}
	return out
}

func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found")
		}
		dir = parent
	}
}

func objectField(t *testing.T, obj map[string]any, key string) map[string]any {
	t.Helper()
	value, ok := obj[key].(map[string]any)
	if !ok {
		t.Fatalf("%s is not an object", key)
	}
	return value
}

func stringList(t *testing.T, obj map[string]any, key string) []string {
	t.Helper()
	raw, ok := obj[key].([]any)
	if !ok {
		t.Fatalf("%s is not an array", key)
	}
	out := make([]string, 0, len(raw))
	for _, item := range raw {
		text, ok := item.(string)
		if !ok {
			t.Fatalf("%s contains a non-string", key)
		}
		out = append(out, text)
	}
	return out
}
