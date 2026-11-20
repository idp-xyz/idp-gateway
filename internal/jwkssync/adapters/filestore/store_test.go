package filestore

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func Test读写与覆盖(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "jwks.json")
	store, err := New(path, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	data, exists, err := store.Read()
	if err != nil || exists || data != nil {
		t.Fatalf("还不存在：%v %v %q", err, exists, data)
	}
	first := []byte("{\"keys\":[{\"kid\":\"a\",\"kty\":\"RSA\"}]}\n")
	if err := store.Write(first); err != nil {
		t.Fatal(err)
	}
	data, exists, err = store.Read()
	if err != nil || !exists || !bytes.Equal(data, first) {
		t.Fatalf("第一次：%v %v %q", err, exists, data)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o644 {
		t.Fatalf("权限是 %o", info.Mode().Perm())
	}
	second := []byte("{\"keys\":[]}\n")
	if err := store.Write(second); err != nil {
		t.Fatal(err)
	}
	data, _, err = store.Read()
	if err != nil || !bytes.Equal(data, second) {
		t.Fatalf("覆盖之后是 %q（%v）", data, err)
	}
	left, err := filepath.Glob(filepath.Join(dir, ".jwks-*.tmp"))
	if err != nil || len(left) != 0 {
		t.Fatalf("留下了临时文件 %v（%v）", left, err)
	}
	tight, err := New(filepath.Join(dir, "tight.json"), 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := tight.Write(second); err != nil {
		t.Fatal(err)
	}
	info, err = os.Stat(tight.path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("0600 写成了 %o", info.Mode().Perm())
	}
}

func Test拒绝不合格的路径和权限(t *testing.T) {
	if _, err := New("", 0o644); err == nil {
		t.Fatal("空路径应被拒绝")
	}
	if _, err := New(filepath.Join(t.TempDir(), "jwks.json"), 0o755); err == nil {
		t.Fatal("0755 应被拒绝")
	}
	if _, err := New(filepath.Join(t.TempDir(), "jwks.json"), 0o640); err == nil {
		t.Fatal("0640 应被拒绝")
	}
}

func Test目录不存在时写不进去(t *testing.T) {
	store, err := New(filepath.Join(t.TempDir(), "missing", "jwks.json"), 0o644)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Write([]byte("{}\n")); err == nil {
		t.Fatal("目录不存在时应失败")
	}
}
