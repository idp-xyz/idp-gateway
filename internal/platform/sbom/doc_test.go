package sbom_test

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"go.idp.xyz/idp-gateway/internal/platform/sbom"
)

// TestCheckedInDocument 用 `go list -m` 和 `go version` 重写文档，和
// deploy/sbom/idp-gateway.cdx.json 逐字节比较。go.mod 里多出来的 require
// 若不是文档中的组件，同样失败。
func TestCheckedInDocument(t *testing.T) {
	mod := listMainModule(t)
	stdlib := readGoVersion(t)
	got, err := sbom.Document(mod.Path, mod.Version, stdlib)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(mod.Dir, "deploy", "sbom", "idp-gateway.cdx.json")
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("deploy/sbom/idp-gateway.cdx.json 与 go list -m、go version 不一致\n模块 %s %s\n标准库 %s\n--- 现算 ---\n%s--- 文件 ---\n%s", mod.Path, mod.Version, stdlib, got, want)
	}
	goMod, err := os.ReadFile(filepath.Join(mod.Dir, "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	missing, err := sbom.MissingRequires(want, goMod)
	if err != nil {
		t.Fatal(err)
	}
	if len(missing) != 0 {
		t.Fatalf("go.mod 的 require 不在文档里：%v", missing)
	}
}

type mainModule struct {
	Path    string
	Version string
	Dir     string
	Main    bool
}

func listMainModule(t *testing.T) mainModule {
	t.Helper()
	out := command(t, "go", "list", "-m", "-json")
	var mod mainModule
	if err := json.Unmarshal(out, &mod); err != nil {
		t.Fatalf("go list -m: %v\n%s", err, out)
	}
	if !mod.Main || mod.Path == "" || mod.Dir == "" {
		t.Fatalf("go list -m 没有给出主模块：%s", out)
	}
	return mod
}

func readGoVersion(t *testing.T) string {
	t.Helper()
	ver, err := sbom.ParseGoVersion(string(command(t, "go", "version")))
	if err != nil {
		t.Fatal(err)
	}
	return ver
}

func command(t *testing.T, name string, args ...string) []byte {
	t.Helper()
	cmd := exec.Command(name, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("%s %v: %v\n%s", name, args, err, stderr.Bytes())
	}
	return stdout.Bytes()
}
