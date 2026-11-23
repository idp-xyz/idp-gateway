package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCompileCommandUsage(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), []string{"compile"}, &stdout, &stderr, nil); code != exitUsage || stdout.Len() != 0 {
		t.Fatalf("code %d out %q err %q", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stderr.String(), "--spec") {
		t.Fatalf("help/usage missing --spec: %s", stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	if code := run(context.Background(), []string{"compile", "--help"}, &stdout, &stderr, nil); code != exitUsage || !strings.Contains(stderr.String(), "-preflight-only") {
		t.Fatalf("help code %d %q %q", code, stdout.String(), stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	if code := run(context.Background(), nil, &stdout, &stderr, nil); code != exitUsage || !strings.Contains(stderr.String(), "gateway-control compile --spec") {
		t.Fatalf("root usage code %d %s", code, stderr.String())
	}
}

func TestCompileCommandRefusesAndPreflight(t *testing.T) {
	dir := t.TempDir()
	spec := filepath.Join(dir, "spec.json")
	if err := os.WriteFile(spec, []byte(`{"pool":{"name":"egress-prod","environment":"PROD"}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), []string{"compile", "--spec", spec, "--output-gateway", filepath.Join(dir, "g.yaml"), "--output-policy", filepath.Join(dir, "p.json")}, &stdout, &stderr, nil)
	if code != exitNotDone {
		t.Fatalf("code %d out %s err %s", code, stdout.String(), stderr.String())
	}
	var line map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &line); err != nil {
		t.Fatal(err)
	}
	if line["outcome"] != "REFUSED" {
		t.Fatalf("line %#v", line)
	}
	if _, err := os.Stat(filepath.Join(dir, "g.yaml")); !os.IsNotExist(err) {
		t.Fatal("gateway file was written after refusal")
	}

	root := repoRoot(t)
	stdout.Reset()
	stderr.Reset()
	code = run(context.Background(), []string{"compile", "--preflight-only", "--intents", filepath.Join(root, "contracts/gateway/route-intent.example.json"), "--provider-registry", filepath.Join(root, "contracts/gateway/policies/egress-policy.example.json")}, &stdout, &stderr, nil)
	if code != exitActive || stderr.Len() != 0 {
		t.Fatalf("preflight code %d %s %s", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), `"status": "STATIC_PREFLIGHT_OK_NOT_DEPLOYABLE"`) {
		t.Fatalf("report %s", stdout.String())
	}

	stdout.Reset()
	bad := filepath.Join(dir, "bad.json")
	raw := loadFile(t, filepath.Join(root, "contracts/gateway/route-intent.example.json"))
	raw = bytes.Replace(raw, []byte(`"mockcarrier.example"`), []byte(`"127.0.0.1"`), 1)
	if err := os.WriteFile(bad, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	code = run(context.Background(), []string{"compile", "--preflight-only", "--intents", bad, "--provider-registry", filepath.Join(root, "contracts/gateway/policies/egress-policy.example.json")}, &stdout, &stderr, nil)
	if code != exitNotDone || !strings.Contains(stdout.String(), "IP_LITERAL_UPSTREAM_DENIED") {
		t.Fatalf("bad preflight code %d %s", code, stdout.String())
	}
}

func TestCompileIngressExample(t *testing.T) {
	root := repoRoot(t)
	dir := t.TempDir()
	spec := filepath.Join(root, "contracts/gateway/ingress-compile-spec.example.json")
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), []string{
		"compile", "--spec", spec,
		"--output-gateway", filepath.Join(dir, "gateway.yaml"),
		"--output-policy", filepath.Join(dir, "policy.json"),
	}, &stdout, &stderr, nil)
	if code != exitActive {
		t.Fatalf("code %d out %s err %s", code, stdout.String(), stderr.String())
	}
	var line map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &line); err != nil {
		t.Fatal(err)
	}
	if line["outcome"] != "COMPILED" || line["routes"] != float64(2) || line["native_validated"] != false {
		t.Fatalf("line %#v", line)
	}
	gw, err := os.ReadFile(filepath.Join(dir, "gateway.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(gw), "name: 'public-shipments-get-get'") || !strings.Contains(string(gw), "name: 'public-shipments-get-head'") {
		t.Fatalf("gateway yaml missing example routes:\n%s", gw)
	}
	for _, needle := range []string{"name: 'read-back'", "exact: '/config_dump'", "exact: '/api/runtime'", "host: '127.0.0.1:15000'", "requestTimeout: '2s'"} {
		if !strings.Contains(string(gw), needle) {
			t.Fatalf("gateway yaml missing %s:\n%s", needle, gw)
		}
	}
}

func TestCompileIngressExampleNative(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(home, ".local", "opt", "agentgateway", "1.7.0", "agentgateway")
	if _, err := os.Stat(binary); err != nil {
		t.Skip("pinned agentgateway 1.7.0 is not installed")
	}
	root := repoRoot(t)
	dir := t.TempDir()
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), []string{
		"compile",
		"--spec", filepath.Join(root, "contracts/gateway/ingress-compile-spec.example.json"),
		"--output-gateway", filepath.Join(dir, "gateway.yaml"),
		"--output-policy", filepath.Join(dir, "policy.json"),
		"--agentgateway", binary,
		"--lock-file", filepath.Join(root, "deploy", "agentgateway", "agentgateway.lock.json"),
	}, &stdout, &stderr, nil)
	if code != exitActive {
		t.Fatalf("code %d out %s err %s", code, stdout.String(), stderr.String())
	}
	var line map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &line); err != nil {
		t.Fatal(err)
	}
	if line["native_validated"] != true || line["routes"] != float64(2) {
		t.Fatalf("line %#v", line)
	}
}

func TestCompileAIExampleNative(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(home, ".local", "opt", "agentgateway", "1.7.0", "agentgateway")
	if _, err := os.Stat(binary); err != nil {
		t.Skip("pinned agentgateway 1.7.0 is not installed")
	}
	root := repoRoot(t)
	dir := t.TempDir()
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), []string{
		"compile",
		"--spec", filepath.Join(root, "contracts/gateway/ai-compile-spec.example.json"),
		"--output-gateway", filepath.Join(dir, "gateway.yaml"),
		"--output-policy", filepath.Join(dir, "policy.json"),
		"--agentgateway", binary,
		"--lock-file", filepath.Join(root, "deploy", "agentgateway", "agentgateway.lock.json"),
	}, &stdout, &stderr, nil)
	if code != exitActive {
		t.Fatalf("code %d out %s err %s", code, stdout.String(), stderr.String())
	}
	var line map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &line); err != nil {
		t.Fatal(err)
	}
	if line["native_validated"] != true || line["routes"] != float64(1) {
		t.Fatalf("line %#v stderr %s", line, stderr.String())
	}
}

func loadFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
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
