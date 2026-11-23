package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestFileModeAndRefusalOfWorldReadableFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	sink, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode %o", info.Mode().Perm())
	}
	if err := sink.Close(); err != nil {
		t.Fatal(err)
	}

	open := filepath.Join(dir, "open.jsonl")
	if err := os.WriteFile(open, []byte("keep\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(open); err == nil || !strings.Contains(err.Error(), "readable by others") {
		t.Fatalf("world-readable file: %v", err)
	}
	info, err = os.Stat(open)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o077 == 0 {
		t.Fatalf("refused file was tightened to %o", info.Mode().Perm())
	}
	body, err := os.ReadFile(open)
	if err != nil || string(body) != "keep\n" {
		t.Fatalf("file changed: %q %v", body, err)
	}
}

func TestWriteStripsSensitiveDetailAndBreaks(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	sink, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	err = sink.Write(Record{
		Timestamp: "2026-11-23T09:00:00.1Z", Service: "idp-gateway-authz", EventType: "egress_decision",
		DecisionID: "dec-1", Reason: "ok\r\nmore", Path: "/v1/extauthz/check",
		Detail: map[string]string{
			"note":                   "hello\nworld",
			"Authorization":          "Bearer secret",
			"api_key":                "k",
			"credential_binding_ref": "gatekeeper:wanb",
			"route_id":               strings.Repeat("r", 600),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := sink.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	if strings.Contains(text, "Bearer") || strings.Contains(text, "gatekeeper:wanb") || strings.Contains(text, "\nhello") {
		t.Fatalf("sensitive or broken line: %s", text)
	}
	if strings.Count(text, "\n") != 1 || !strings.HasSuffix(text, "\n") {
		t.Fatalf("not one json line: %q", text)
	}
	var rec Record
	if err := json.Unmarshal(bytesTrimNewline(raw), &rec); err != nil {
		t.Fatal(err)
	}
	if rec.Reason != "okmore" || rec.Detail["note"] != "helloworld" {
		t.Fatalf("%+v", rec)
	}
	if len(rec.Detail["route_id"]) > 512 {
		t.Fatalf("route_id len %d", len(rec.Detail["route_id"]))
	}
	if _, ok := rec.Detail["Authorization"]; ok {
		t.Fatal("authorization kept")
	}
}

func TestConcurrentWritesAreValidJSONL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	sink, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	const n = 32
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			rec := Record{Timestamp: "2026-11-23T09:00:00Z", Service: "idp-gateway-authz", EventType: "egress_decision", DecisionID: "dec"}
			rec.Status = 200
			if err := sink.Write(rec); err != nil {
				t.Errorf("write: %v", err)
			}
		}(i)
	}
	wg.Wait()
	if err := sink.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n")
	if len(lines) != n {
		t.Fatalf("lines %d", len(lines))
	}
	for _, line := range lines {
		var rec Record
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("line %q: %v", line, err)
		}
		if rec.EventType != "egress_decision" || rec.Status != 200 {
			t.Fatalf("%+v", rec)
		}
	}
}

func TestReadRecentFiltersNewestFirst(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	sink, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	records := []Record{
		{Timestamp: "2026-11-23T09:00:00Z", Service: "idp-gateway-authz", EventType: "egress_decision", TraceID: "a", Outcome: "ALLOW", Reason: "ACTIVE_ACCOUNT_GRANT"},
		{Timestamp: "2026-11-23T09:00:01Z", Service: "idp-gateway-authz", EventType: "revocation_change", TraceID: "b", Outcome: "ok", Reason: "rotated"},
		{Timestamp: "2026-11-23T09:00:02Z", Service: "idp-provider-signer", EventType: "signer_call", TraceID: "c", Outcome: "ok", Reason: "ok"},
		{Timestamp: "2026-11-23T09:00:03Z", Service: "idp-gateway-authz", EventType: "egress_decision", TraceID: "d", Outcome: "DENY", Reason: "ACCOUNT_NOT_GRANTED"},
	}
	for _, rec := range records {
		if err := sink.Write(rec); err != nil {
			t.Fatal(err)
		}
	}
	if err := sink.Close(); err != nil {
		t.Fatal(err)
	}
	recent, err := ReadRecent(path, Filter{}, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(recent) != 2 || recent[0].TraceID != "d" || recent[1].TraceID != "c" {
		t.Fatalf("newest %+v", recent)
	}
	filtered, err := ReadRecent(path, Filter{Service: "idp-gateway-authz", EventType: "egress_decision", Outcome: "ALLOW"}, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(filtered) != 1 || filtered[0].TraceID != "a" {
		t.Fatalf("filter %+v", filtered)
	}
	denied, err := ReadRecent(path, Filter{Reason: "ACCOUNT_NOT_GRANTED"}, 10)
	if err != nil || len(denied) != 1 || denied[0].TraceID != "d" {
		t.Fatalf("reason %+v %v", denied, err)
	}
	none, err := ReadRecent(path, Filter{}, 0)
	if err != nil || none != nil {
		t.Fatalf("limit 0 %+v %v", none, err)
	}
}

func bytesTrimNewline(raw []byte) []byte {
	if len(raw) > 0 && raw[len(raw)-1] == '\n' {
		return raw[:len(raw)-1]
	}
	return raw
}
