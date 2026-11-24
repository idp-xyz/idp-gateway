package filestate

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"go.idp.xyz/idp-gateway/internal/fabricpub/ports"
)

func privateDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestOpenRejectsLooseAndMissingPaths(t *testing.T) {
	if _, err := Open(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("不存在的目录应拒绝")
	}
	dir := privateDir(t)
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(dir); err == nil {
		t.Fatal("0755 应拒绝")
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "not-a-dir")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(file); err == nil {
		t.Fatal("文件应拒绝")
	}
	link := filepath.Join(dir, "link")
	dest := privateDir(t)
	if err := os.Symlink(dest, link); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(link); err == nil {
		t.Fatal("符号链接应拒绝")
	}
}

func TestSaveAndLoad(t *testing.T) {
	dir := privateDir(t)
	store, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	empty, err := store.Load(context.Background())
	if err != nil || empty.Generation != 0 || empty.Idempotency == nil {
		t.Fatalf("空状态 %+v %v", empty, err)
	}
	release, err := store.Hold(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	state := ports.State{Generation: 3, Idempotency: map[string]ports.Idempotency{"k": {Hash: "abc", IntentID: "gwi-example-001", ReleaseRef: "rel"}}}
	if err := store.Save(context.Background(), state); err != nil {
		t.Fatal(err)
	}
	release()
	info, err := os.Stat(filepath.Join(dir, stateName))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("state.json 权限 %o", info.Mode().Perm())
	}
	again, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := again.Load(context.Background())
	if err != nil || loaded.Generation != 3 || loaded.Idempotency["k"].IntentID != "gwi-example-001" {
		t.Fatalf("恢复 %+v %v", loaded, err)
	}
	matches, err := filepath.Glob(filepath.Join(dir, ".state-*.tmp"))
	if err != nil || len(matches) != 0 {
		t.Fatalf("临时文件还在：%v %v", matches, err)
	}
}

func TestHoldExcludesASecondCaller(t *testing.T) {
	dir := privateDir(t)
	store, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	release, err := store.Hold(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer cancel()
	if _, err := store.Hold(ctx); err == nil {
		t.Fatal("第二个人不该在锁还被占着时拿到它")
	}
	release()
	release, err = store.Hold(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	release()
}

func TestConcurrentUpdates(t *testing.T) {
	dir := privateDir(t)
	store, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	const n = 20
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			release, err := store.Hold(context.Background())
			if err != nil {
				t.Error(err)
				return
			}
			defer release()
			state, err := store.Load(context.Background())
			if err != nil {
				t.Error(err)
				return
			}
			state.Generation++
			if err := store.Save(context.Background(), state); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	loaded, err := store.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Generation != n {
		t.Fatalf("并发之后代次 %d，想要 %d", loaded.Generation, n)
	}
}
