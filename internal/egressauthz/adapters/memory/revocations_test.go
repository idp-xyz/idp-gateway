package memory

import (
	"context"
	"sync"
	"testing"
)

func TestRevocations(t *testing.T) {
	var r Revocations
	ctx := context.Background()
	state := func(account string) (bool, uint64) {
		revoked, epoch, err := r.State(ctx, account)
		if err != nil {
			t.Fatal(err)
		}
		return revoked, epoch
	}

	if revoked, epoch := state("a"); revoked || epoch != 0 {
		t.Fatalf("零值：%v %d", revoked, epoch)
	}
	r.Revoke("a")
	r.Revoke("a") // 重复撤销不是状态变化
	if revoked, epoch := state("a"); !revoked || epoch != 1 {
		t.Fatalf("撤销后：%v %d", revoked, epoch)
	}
	if revoked, _ := state("b"); revoked {
		t.Fatal("撤销 a 影响了 b")
	}
	r.Restore("b") // 没撤销过的账户
	r.Restore("a")
	if revoked, epoch := state("a"); revoked || epoch != 2 {
		t.Fatalf("恢复后：%v %d", revoked, epoch)
	}
	r.RestoreAll() // 没有撤销时不动代次
	r.Revoke("a")
	r.Revoke("b")
	if len(r.Revoked()) != 2 {
		t.Fatal(r.Revoked())
	}
	r.RestoreAll()
	if epoch, _ := r.Epoch(ctx); epoch != 5 || len(r.Revoked()) != 0 {
		t.Fatalf("全部恢复后：代次 %d，%v", epoch, r.Revoked())
	}
}

func TestRevocationsConcurrentUse(t *testing.T) {
	var r Revocations
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				r.Revoke("a")
				_, _, _ = r.State(context.Background(), "a")
				r.Restore("a")
				_ = r.Revoked()
			}
		}()
	}
	wg.Wait()
}
