package binaryvalidator

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"go.idp.xyz/idp-gateway/internal/routecompile/domain"
)

func TestCompiledCarriersPassValidateOnly(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(home, ".local", "opt", "agentgateway", "1.7.0", "agentgateway")
	if _, err := os.Stat(binary); err != nil {
		t.Skip("pinned agentgateway 1.7.0 is not installed")
	}
	root := moduleRoot(t)
	validator := Validator{Binary: binary, LockFile: filepath.Join(root, "deploy", "agentgateway", "agentgateway.lock.json")}
	for _, name := range []string{"wanbexpress", "sfintl"} {
		t.Run(name, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join(root, "deploy", "providers", name, "compile-spec.json"))
			if err != nil {
				t.Fatal(err)
			}
			spec, err := domain.ParseSpec(data)
			if err != nil {
				t.Fatal(err)
			}
			art, err := domain.Compile(spec)
			if err != nil {
				t.Fatal(err)
			}
			if err := validator.Validate(context.Background(), art.GatewayYAML, "", ""); err != nil {
				t.Fatal(err)
			}
		})
	}
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
