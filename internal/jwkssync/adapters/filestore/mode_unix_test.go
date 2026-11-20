//go:build unix

package filestore

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func Test权限不受umask影响(t *testing.T) {
	previous := syscall.Umask(0o077)
	defer syscall.Umask(previous)
	path := filepath.Join(t.TempDir(), "jwks.json")
	store, err := New(path, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Write([]byte("{\"keys\":[]}\n")); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o644 {
		t.Fatalf("umask 077 之下写成了 %o，应是 0644", info.Mode().Perm())
	}
}
