package container

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestOverlayEnvReplacesAnInheritedVariable(t *testing.T) {
	got := overlayEnv([]string{"GATEWAY_IMAGE=old", "KEEP=1", "GATEWAY_IMAGE=older"}, []string{"GATEWAY_IMAGE=new"})
	if !reflect.DeepEqual(got, []string{"KEEP=1", "GATEWAY_IMAGE=new"}) {
		t.Fatalf("%v", got)
	}
	if got := overlayEnv([]string{"A=1"}, nil); !reflect.DeepEqual(got, []string{"A=1"}) {
		t.Fatalf("没有要盖过的：%v", got)
	}
}

func TestAssignEnvRewritesOnlyTheNamedSetting(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pool.env")
	original := "# pool\nPOOL_DIR=/srv/idp\nGATEWAY_IMAGE=old\nFRONT_IMAGE=kept\n"
	if err := os.WriteFile(path, []byte(original), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}
	if err := assignEnv(path, "GATEWAY_IMAGE", "new"); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "# pool\nPOOL_DIR=/srv/idp\nGATEWAY_IMAGE=new\nFRONT_IMAGE=kept\n" {
		t.Fatalf("写成了 %q", got)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o640 {
		t.Fatalf("权限是 %o", info.Mode().Perm())
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("目录里留下了 %v", entries)
	}
}

func TestAssignEnvDoesNotAppendAMissingSetting(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pool.env")
	original := "# GATEWAY_IMAGE=only-a-comment\nPOOL_DIR=/srv/idp\n"
	if err := os.WriteFile(path, []byte(original), 0o644); err != nil {
		t.Fatal(err)
	}
	err := assignEnv(path, "GATEWAY_IMAGE", "new")
	if err == nil || !strings.Contains(err.Error(), "GATEWAY_IMAGE is not set") {
		t.Fatalf("得到 %v", err)
	}
	got, readErr := os.ReadFile(path)
	if readErr != nil || string(got) != original {
		t.Fatalf("文件变成了 %q（%v）", got, readErr)
	}
}
