package domain

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"testing"
)

func exampleEnvelope(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile("../../../contracts/fabric/route-publication-intent.example.json")
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func mutateEnvelope(t *testing.T, raw []byte, fn func(map[string]any)) []byte {
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

func intentOf(t *testing.T, doc map[string]any) map[string]any {
	t.Helper()
	intent, ok := doc["intent"].(map[string]any)
	if !ok {
		t.Fatal("intent 不是对象")
	}
	return intent
}

func codeOf(err error) string {
	var inv *Invalid
	if errors.As(err, &inv) {
		return inv.Code
	}
	if err == nil {
		return ""
	}
	return err.Error()
}

func TestEnvelopeExample(t *testing.T) {
	env, err := ParseEnvelope(exampleEnvelope(t))
	if err != nil {
		t.Fatal(err)
	}
	if env.Intent.IntentID != "gwi-example-001" || env.Intent.TrafficClass != "EGRESS" || env.Intent.AllowedMethods[0] != "GET" {
		t.Fatalf("解析结果 %+v", env.Intent)
	}
	if env.Hash == "" || len(env.Canonical) == 0 {
		t.Fatal("没有规范化正文")
	}
	again, err := ParseEnvelope(env.Canonical)
	if err != nil {
		t.Fatal(err)
	}
	if again.Hash != env.Hash {
		t.Fatalf("再编码之后摘要变了 %s %s", env.Hash, again.Hash)
	}
}

func TestEnvelopeHashIgnoresKeyOrder(t *testing.T) {
	raw := exampleEnvelope(t)
	reordered := mutateEnvelope(t, raw, func(map[string]any) {})
	left, err := ParseEnvelope(raw)
	if err != nil {
		t.Fatal(err)
	}
	right, err := ParseEnvelope(reordered)
	if err != nil {
		t.Fatal(err)
	}
	if left.Hash != right.Hash || !bytes.Equal(left.Canonical, right.Canonical) {
		t.Fatal("键顺序影响了规范化摘要")
	}
}

func TestEnvelopeRejectsAPIKey(t *testing.T) {
	raw := mutateEnvelope(t, exampleEnvelope(t), func(doc map[string]any) {
		intentOf(t, doc)["api_key"] = "secret-value"
	})
	_, err := ParseEnvelope(raw)
	if codeOf(err) != "sensitive_key" {
		t.Fatalf("api_key 真值应拒绝，得到 %v", err)
	}
}

func TestEnvelopeRejectsShape(t *testing.T) {
	base := exampleEnvelope(t)
	cases := []struct {
		name string
		raw  []byte
		code string
	}{
		{"duplicate key", []byte(`{"idempotency_key":"pub-mockcarrier-tracking-0001","idempotency_key":"pub-mockcarrier-tracking-0002","release_ref":"fabric-release-0001","target_id":"fabric-target-test","intent":{}}`), "duplicate_key"},
		{"trailing", append(append([]byte{}, base...), '\n', '{', '}'), "trailing_json"},
		{"env", mutateEnvelope(t, base, func(doc map[string]any) { intentOf(t, doc)["contract_ref"] = "consumer-${HOME}" }), "env_reference"},
		{"dollar name", mutateEnvelope(t, base, func(doc map[string]any) { intentOf(t, doc)["approval_ref"] = "$HOME-APPROVAL" }), "env_reference"},
		{"unknown", mutateEnvelope(t, base, func(doc map[string]any) { doc["note"] = "x" }), "unknown_field"},
		{"approval on envelope", mutateEnvelope(t, base, func(doc map[string]any) { doc["approval_ref"] = "APPROVAL-1" }), "unknown_field"},
		{"two methods", mutateEnvelope(t, base, func(doc map[string]any) {
			intentOf(t, doc)["allowed_methods"] = []any{"GET", "POST"}
		}), "schema"},
		{"ingress", mutateEnvelope(t, base, func(doc map[string]any) { intentOf(t, doc)["traffic_class"] = "INGRESS" }), "schema"},
		{"prod plain", mutateEnvelope(t, base, func(doc map[string]any) {
			in := intentOf(t, doc)
			in["environment"] = "PROD"
			in["gateway_pool"] = "egress-prod"
			in["upstream_tls"] = "PLAIN_HTTP_SANDBOX_EXCEPTION"
		}), "schema"},
		{"short key", mutateEnvelope(t, base, func(doc map[string]any) { doc["idempotency_key"] = "short-key" }), "schema"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseEnvelope(tc.raw)
			if codeOf(err) != tc.code {
				t.Fatalf("got %q (%v), want %s", codeOf(err), err, tc.code)
			}
		})
	}
}
