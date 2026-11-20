package domain

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestExamplesPassPreflight(t *testing.T) {
	root := repoRoot(t)
	registry := loadRegistry(t, filepath.Join(root, "contracts/gateway/policies/egress-policy.example.json"))
	var all []map[string]any
	for _, name := range []string{
		"contracts/gateway/route-intent.example.json",
		"contracts/gateway/route-intent.ingress.example.json",
		"contracts/gateway/route-intent.ai.example.json",
	} {
		obj := loadObject(t, filepath.Join(root, name))
		report := Evaluate(nil, []map[string]any{obj}, registry, PreflightOptions{})
		if report.Status != StatusPreflightOK || report.IssueCount != 0 {
			t.Fatalf("%s: %+v", name, report.Issues)
		}
		if report.NativeAgentgatewayConfigGenerated || report.NativeAgentgatewaySchemaValidated || report.NetworkDNSAllowlistValidated {
			t.Fatalf("%s: preflight claimed a native or network check", name)
		}
		all = append(all, obj)
	}
	together := Evaluate(nil, all, registry, PreflightOptions{})
	if together.IssueCount != 0 {
		t.Fatalf("three pools: %+v", together.Issues)
	}
}

func TestInvalidIntentsRejected(t *testing.T) {
	root := repoRoot(t)
	registry := loadRegistry(t, filepath.Join(root, "contracts/gateway/policies/egress-policy.example.json"))
	var cases []struct {
		Case   string         `json:"case"`
		Intent map[string]any `json:"intent"`
	}
	data, err := os.ReadFile(filepath.Join(root, "tests/contracts/invalid-route-intents.json"))
	if err != nil {
		t.Fatal(err)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := dec.Decode(&cases); err != nil {
		t.Fatal(err)
	}
	if len(cases) == 0 {
		t.Fatal("no invalid cases")
	}
	for _, item := range cases {
		report := Evaluate(nil, []map[string]any{item.Intent}, registry, PreflightOptions{})
		if report.IssueCount == 0 || report.Status != StatusReject {
			t.Errorf("%s was accepted", item.Case)
		}
	}
}

func TestPreflightNegativeCases(t *testing.T) {
	root := repoRoot(t)
	registry := loadRegistry(t, filepath.Join(root, "contracts/gateway/policies/egress-policy.example.json"))
	base := loadObject(t, filepath.Join(root, "contracts/gateway/route-intent.example.json"))
	ingress := loadObject(t, filepath.Join(root, "contracts/gateway/route-intent.ingress.example.json"))

	t.Run("reserved and literal upstreams", func(t *testing.T) {
		for _, host := range []string{"localhost", "metadata.google.internal", "internal.test", "127.0.0.1", "169.254.169.254", "myservice.internal"} {
			obj := cloneMap(base)
			obj["upstream_hostname"] = host
			if Evaluate(nil, []map[string]any{obj}, registry, PreflightOptions{}).IssueCount == 0 {
				t.Errorf("%s was accepted", host)
			}
		}
	})
	t.Run("ip literal code", func(t *testing.T) {
		obj := cloneMap(base)
		obj["upstream_hostname"] = "127.0.0.1"
		if !hasReason(Evaluate(nil, []map[string]any{obj}, registry, PreflightOptions{}), "IP_LITERAL_UPSTREAM_DENIED") {
			t.Fatal("127.0.0.1 did not produce IP_LITERAL_UPSTREAM_DENIED")
		}
	})
	t.Run("noncanonical", func(t *testing.T) {
		for _, path := range []string{"/providers/%2e%2e/", "/providers/../", "/providers//api"} {
			obj := cloneMap(base)
			obj["logical_path"] = path
			if Evaluate(nil, []map[string]any{obj}, registry, PreflightOptions{}).IssueCount == 0 {
				t.Errorf("%s was accepted", path)
			}
		}
		obj := cloneMap(base)
		obj["logical_path"] = "/providers/%2e%2e/"
		if !hasReason(Evaluate(nil, []map[string]any{obj}, registry, PreflightOptions{}), "NON_CANONICAL_LOGICAL_PATH") {
			t.Fatal("percent-encoded dot was not NON_CANONICAL_LOGICAL_PATH")
		}
	})
	t.Run("sni", func(t *testing.T) {
		obj := cloneMap(base)
		obj["upstream_sni"] = "evil.example"
		if !hasReason(Evaluate(nil, []map[string]any{obj}, registry, PreflightOptions{}), "SNI_HOST_MISMATCH_REQUIRES_SIGNED_EXCEPTION") {
			t.Fatal("sni mismatch accepted")
		}
	})
	t.Run("credential key", func(t *testing.T) {
		obj := cloneMap(base)
		obj["api_key"] = "secret"
		if !hasReason(Evaluate(nil, []map[string]any{obj}, registry, PreflightOptions{}), "CREDENTIAL_VALUE_IN_INTENT") {
			t.Fatal("api_key was not reported")
		}
	})
	t.Run("exact conflict", func(t *testing.T) {
		other := cloneMap(base)
		other["intent_id"] = "gwi-collision-002"
		report := Evaluate(nil, []map[string]any{base, other}, registry, PreflightOptions{})
		if !hasCode(report, "EXACT_ROUTE_CONFLICT") {
			t.Fatalf("conflict missing: %+v", report.Issues)
		}
	})
	t.Run("env isolation", func(t *testing.T) {
		other := cloneMap(base)
		other["intent_id"] = "gwi-same-route-prod"
		other["environment"] = "PROD"
		if hasCode(Evaluate(nil, []map[string]any{base, other}, registry, PreflightOptions{}), "EXACT_ROUTE_CONFLICT") {
			t.Fatal("different environments were treated as one route")
		}
	})
	t.Run("prefix overlap", func(t *testing.T) {
		wide := cloneMap(base)
		wide["intent_id"] = "gwi-wide-route"
		wide["logical_path"] = "/providers/mockcarrier/v1"
		wide["operation_id"] = "tracking.list"
		if !hasCode(Evaluate(nil, []map[string]any{base, wide}, registry, PreflightOptions{}), "PREFIX_ROUTE_OVERLAP") {
			t.Fatal("nested prefixes were accepted")
		}
		wide["route_priority"] = json.Number("1")
		basePri := cloneMap(base)
		basePri["route_priority"] = json.Number("2")
		if hasCode(Evaluate(nil, []map[string]any{basePri, wide}, registry, PreflightOptions{}), "PREFIX_ROUTE_OVERLAP") {
			t.Fatal("distinct priorities were still an overlap")
		}
	})
	t.Run("head and options", func(t *testing.T) {
		obj := cloneMap(ingress)
		obj["allowed_methods"] = []any{"HEAD", "OPTIONS"}
		if Evaluate(nil, []map[string]any{obj}, registry, PreflightOptions{}).IssueCount != 0 {
			t.Fatal("HEAD and OPTIONS were rejected")
		}
	})
	t.Run("plain http stays denied without an allowance", func(t *testing.T) {
		obj := cloneMap(base)
		obj["upstream_tls"] = PlainHTTPSandboxException
		if Evaluate(nil, []map[string]any{obj}, registry, PreflightOptions{}).IssueCount == 0 {
			t.Fatal("plain HTTP was accepted in strict preflight")
		}
	})
}

func TestIntentsHashMatchesCPython(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not on PATH")
	}
	root := repoRoot(t)
	cmd := exec.Command(python, "-c", `
import hashlib, json, pathlib, sys
root = pathlib.Path(sys.argv[1])
intent = json.loads((root / "contracts/gateway/route-intent.example.json").read_text())
registry = json.loads((root / "contracts/gateway/policies/egress-policy.example.json").read_text())
def canon(doc):
    return json.dumps(doc, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()
print(hashlib.sha256(canon([intent])).hexdigest())
print(hashlib.sha256(canon(registry)).hexdigest())
`, root)
	out, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) != 2 {
		t.Fatalf("python output %q", out)
	}
	obj := loadObject(t, filepath.Join(root, "contracts/gateway/route-intent.example.json"))
	registry := loadRegistry(t, filepath.Join(root, "contracts/gateway/policies/egress-policy.example.json"))
	report := Evaluate(nil, []map[string]any{obj}, registry, PreflightOptions{})
	if report.IntentsSHA256 != lines[0] || report.ProviderRegistrySHA256 != lines[1] {
		t.Fatalf("hash mismatch\ngo   %s %s\npy   %s %s", report.IntentsSHA256, report.ProviderRegistrySHA256, lines[0], lines[1])
	}
}

func TestRegistryMisses(t *testing.T) {
	root := repoRoot(t)
	registry := loadRegistry(t, filepath.Join(root, "contracts/gateway/policies/egress-policy.example.json"))
	base := loadObject(t, filepath.Join(root, "contracts/gateway/route-intent.example.json"))
	cases := []struct {
		name string
		edit func(map[string]any)
		code string
	}{
		{"provider", func(m map[string]any) { m["provider_id"] = "othercarrier" }, "PROVIDER_NOT_REGISTERED"},
		{"upstream", func(m map[string]any) { m["upstream_port"] = json.Number("8443") }, "UPSTREAM_NOT_REGISTERED_FOR_PROVIDER"},
		{"operation", func(m map[string]any) { m["operation_id"] = "tracking.put" }, "OPERATION_NOT_REGISTERED"},
		{"credential", func(m map[string]any) { m["credential_binding_ref"] = "gatekeeper:other" }, "CREDENTIAL_BINDING_NOT_REGISTERED"},
	}
	for _, item := range cases {
		obj := cloneMap(base)
		item.edit(obj)
		if !hasReason(Evaluate(nil, []map[string]any{obj}, registry, PreflightOptions{}), item.code) {
			t.Errorf("%s: missing %s", item.name, item.code)
		}
	}
}

func hasReason(report Report, reason string) bool {
	for _, issue := range report.Issues {
		if issue.Reason == reason {
			return true
		}
	}
	return false
}

func hasCode(report Report, code string) bool {
	for _, issue := range report.Issues {
		if issue.Code == code {
			return true
		}
	}
	return false
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

func loadRegistry(t *testing.T, path string) *Registry {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	registry, err := ParseRegistry(data)
	if err != nil {
		t.Fatal(err)
	}
	return registry
}

func cloneMap(in map[string]any) map[string]any {
	data, err := json.Marshal(in)
	if err != nil {
		panic(err)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var out map[string]any
	if err := dec.Decode(&out); err != nil {
		panic(err)
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
