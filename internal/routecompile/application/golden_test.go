package application

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"go.idp.xyz/idp-gateway/internal/routecompile/domain"
)

func TestGoldenCarriersMatchHandWrittenConfig(t *testing.T) {
	root := moduleRoot(t)
	for _, name := range []string{"wanbexpress", "sfintl"} {
		t.Run(name, func(t *testing.T) {
			dir := filepath.Join(root, "deploy", "providers", name)
			spec := readSpec(t, filepath.Join(dir, "compile-spec.json"))
			art, err := domain.Compile(spec)
			if err != nil {
				t.Fatal(err)
			}
			if art.RouteCount != 4 {
				t.Fatalf("routes %d", art.RouteCount)
			}
			gotYAML, err := parseYAML(art.GatewayYAML)
			if err != nil {
				t.Fatal(err)
			}
			wantYAML, err := parseYAML(readBytes(t, filepath.Join(dir, "agentgateway.yaml")))
			if err != nil {
				t.Fatalf("golden yaml: %v", err)
			}
			if diff := diffValues(wantYAML, gotYAML); diff != "" {
				t.Fatalf("gateway yaml differs:\n%s", diff)
			}
			var gotPolicy, wantPolicy any
			if err := json.Unmarshal(art.PolicyJSON, &gotPolicy); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(readBytes(t, filepath.Join(dir, "policy.example.json")), &wantPolicy); err != nil {
				t.Fatal(err)
			}
			if diff := diffValues(wantPolicy, gotPolicy); diff != "" {
				t.Fatalf("policy json differs:\n%s", diff)
			}
			assertPyYAMLEqual(t, dir, art)
		})
	}
}

func assertPyYAMLEqual(t *testing.T, dir string, art domain.CompiledArtifacts) {
	t.Helper()
	python := "/home/tops/workspace/idp-gateway/.venv/bin/python"
	if _, err := os.Stat(python); err != nil {
		t.Log("venv python missing; structural comparison used the Go parser only")
		return
	}
	tmp := t.TempDir()
	gw := filepath.Join(tmp, "compiled.yaml")
	pol := filepath.Join(tmp, "compiled.json")
	if err := os.WriteFile(gw, art.GatewayYAML, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pol, art.PolicyJSON, 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(python, "-c", `
import json, sys, yaml
gw, golden_gw, pol, golden_pol = sys.argv[1:]
a, b = yaml.safe_load(open(gw)), yaml.safe_load(open(golden_gw))
c, d = json.load(open(pol)), json.load(open(golden_pol))
print("yaml", a == b)
print("policy", c == d)
if a != b or c != d:
    sys.exit(1)
`, gw, filepath.Join(dir, "agentgateway.yaml"), pol, filepath.Join(dir, "policy.example.json"))
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("pyyaml comparison failed: %v\n%s", err, out)
	}
}

func readSpec(t *testing.T, path string) domain.CompileSpec {
	t.Helper()
	spec, err := domain.ParseSpec(readBytes(t, path))
	if err != nil {
		t.Fatal(err)
	}
	return spec
}

func readBytes(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func moduleRoot(t *testing.T) string {
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

func diffValues(want, got any) string {
	var lines []string
	walkDiff("", want, got, &lines)
	if len(lines) > 30 {
		lines = append(lines[:30], fmt.Sprintf("... %d more", len(lines)-30))
	}
	return strings.Join(lines, "\n")
}

func walkDiff(path string, want, got any, lines *[]string) {
	if len(*lines) > 40 {
		return
	}
	switch w := want.(type) {
	case map[string]any:
		g, ok := got.(map[string]any)
		if !ok {
			*lines = append(*lines, fmt.Sprintf("%s: type %T != %T", path, want, got))
			return
		}
		keys := map[string]struct{}{}
		for k := range w {
			keys[k] = struct{}{}
		}
		for k := range g {
			keys[k] = struct{}{}
		}
		ordered := make([]string, 0, len(keys))
		for k := range keys {
			ordered = append(ordered, k)
		}
		sort.Strings(ordered)
		for _, k := range ordered {
			next := path + "." + k
			wv, wok := w[k]
			gv, gok := g[k]
			switch {
			case !wok:
				*lines = append(*lines, fmt.Sprintf("%s: unexpected %#v", next, gv))
			case !gok:
				*lines = append(*lines, fmt.Sprintf("%s: missing, want %#v", next, wv))
			default:
				walkDiff(next, wv, gv, lines)
			}
		}
	case []any:
		g, ok := got.([]any)
		if !ok {
			*lines = append(*lines, fmt.Sprintf("%s: type %T != %T", path, want, got))
			return
		}
		if len(w) != len(g) {
			*lines = append(*lines, fmt.Sprintf("%s: len %d != %d", path, len(w), len(g)))
		}
		n := len(w)
		if len(g) < n {
			n = len(g)
		}
		for i := 0; i < n; i++ {
			walkDiff(fmt.Sprintf("%s[%d]", path, i), w[i], g[i], lines)
		}
	default:
		if !reflect.DeepEqual(want, got) {
			*lines = append(*lines, fmt.Sprintf("%s: %#v != %#v", path, want, got))
		}
	}
}
