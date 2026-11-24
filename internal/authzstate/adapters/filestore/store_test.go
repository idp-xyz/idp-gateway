package filestore

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStateFileRejectsSymlinkAndGroupRead(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "state.json")
	if _, err := Open(good); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(good)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("created mode %04o", info.Mode().Perm())
	}
	if err := os.Chmod(good, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(good); err == nil || !strings.Contains(err.Error(), "group or others") {
		t.Fatal(err)
	}
	if err := os.Chmod(good, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "state.link")
	if err := os.Symlink(good, link); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(link); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatal(err)
	}
}
