package filestore

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"go.idp.xyz/idp-gateway/internal/egressauthz/ports"
)

const nothingRevoked = `{"epoch": 0, "revoked_accounts": {}}`

func loadRevocations(t *testing.T, path string) *Revocations {
	t.Helper()
	ledger, err := LoadRevocations(path)
	if err != nil {
		t.Fatal(err)
	}
	return ledger
}

// onDisk 另开一份，读出文件里此刻的表：这就是重启之后会有的状态。
func onDisk(t *testing.T, path string) ([]ports.RevokedAccount, uint64) {
	t.Helper()
	accounts, epoch, err := loadRevocations(t, path).Revoked(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return accounts, epoch
}

func names(accounts []ports.RevokedAccount) string {
	ids := make([]string, 0, len(accounts))
	for _, account := range accounts {
		ids = append(ids, account.AccountID)
	}
	return strings.Join(ids, ",")
}

func fileInfo(t *testing.T, path string) os.FileInfo {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return info
}

func TestRevocationsAreKeptInTheFile(t *testing.T) {
	ctx := context.Background()
	path := writeFile(t, `{"epoch": 4, "revoked_accounts": {"account-old":
		{"at": "2026-11-01T16:00:00+08:00", "by": "spiffe://idp.test/someone", "reason": "left over"}}}`, 0o600)
	ledger := loadRevocations(t, path)
	ledger.now = func() time.Time { return time.Date(2026, 11, 18, 5, 6, 7, 999, time.UTC) }

	// 读进来的就是文件里的：代次接着数，不从 0 开始。
	if revoked, epoch, err := ledger.State(ctx, "account-old"); err != nil || !revoked || epoch != 4 {
		t.Fatalf("文件里撤销过的账户：%v %d %v", revoked, epoch, err)
	}
	if revoked, _, _ := ledger.State(ctx, "account-blue"); revoked {
		t.Fatal("没有撤销过的账户被当成撤销了")
	}

	// 撤销：立刻生效，代次加一，文件里也有了。
	change, err := ledger.Revoke(ctx, "account-blue", "spiffe://idp.test/revoker", "key leaked")
	if err != nil || change != (ports.RevocationChange{Changed: true, Revoked: true, Epoch: 5}) {
		t.Fatalf("撤销：%+v %v", change, err)
	}
	if revoked, epoch, _ := ledger.State(ctx, "account-blue"); !revoked || epoch != 5 {
		t.Fatalf("撤销之后：%v %d", revoked, epoch)
	}
	want := []ports.RevokedAccount{
		{AccountID: "account-blue", At: time.Date(2026, 11, 18, 5, 6, 7, 0, time.UTC), By: "spiffe://idp.test/revoker", Reason: "key leaked"},
		{AccountID: "account-old", At: time.Date(2026, 11, 1, 8, 0, 0, 0, time.UTC), By: "spiffe://idp.test/someone", Reason: "left over"},
	}
	if inMemory, epoch, _ := ledger.Revoked(ctx); !reflect.DeepEqual(inMemory, want) || epoch != 5 {
		t.Fatalf("内存里的表：%+v，代次 %d", inMemory, epoch)
	}
	if written, epoch := onDisk(t, path); !reflect.DeepEqual(written, want) || epoch != 5 {
		t.Fatalf("文件里的表：%+v，代次 %d", written, epoch)
	}
	if mode := fileInfo(t, path).Mode().Perm(); mode != 0o600 {
		t.Fatalf("写出来的文件权限是 %04o", mode)
	}
	if _, err := os.Stat(path + ".next"); !os.IsNotExist(err) {
		t.Fatalf("临时文件留下了：%v", err)
	}

	// 重复撤销：什么都不变，文件也不重写；记着的仍是头一次是谁、为什么。
	before := fileInfo(t, path)
	change, err = ledger.Revoke(ctx, "account-blue", "spiffe://idp.test/someone-else", "again")
	if err != nil || change != (ports.RevocationChange{Revoked: true, Epoch: 5}) {
		t.Fatalf("重复撤销：%+v %v", change, err)
	}
	if !os.SameFile(before, fileInfo(t, path)) {
		t.Fatal("重复撤销重写了文件")
	}
	if inMemory, _, _ := ledger.Revoked(ctx); !reflect.DeepEqual(inMemory, want) {
		t.Fatalf("重复撤销改了记录：%+v", inMemory)
	}

	// 恢复：代次再加一，文件里没有它了。
	change, err = ledger.Restore(ctx, "account-blue")
	if err != nil || change != (ports.RevocationChange{Changed: true, Epoch: 6}) {
		t.Fatalf("恢复：%+v %v", change, err)
	}
	if revoked, epoch, _ := ledger.State(ctx, "account-blue"); revoked || epoch != 6 {
		t.Fatalf("恢复之后：%v %d", revoked, epoch)
	}
	if written, epoch := onDisk(t, path); names(written) != "account-old" || epoch != 6 {
		t.Fatalf("恢复之后文件里的表：%s，代次 %d", names(written), epoch)
	}

	// 重复恢复、恢复一个没撤销过的账户：什么都不变，文件也不重写。
	before = fileInfo(t, path)
	for _, account := range []string{"account-blue", "account-never-revoked", ""} {
		change, err = ledger.Restore(ctx, account)
		if err != nil || change != (ports.RevocationChange{Epoch: 6}) {
			t.Fatalf("恢复 %q：%+v %v", account, change, err)
		}
	}
	if !os.SameFile(before, fileInfo(t, path)) {
		t.Fatal("什么都没变的恢复重写了文件")
	}

	if _, err := ledger.Revoke(ctx, "", "spiffe://idp.test/revoker", "no account"); err == nil {
		t.Fatal("撤销一个空账户被接受了")
	}
	if epoch, err := ledger.Epoch(ctx); err != nil || epoch != 6 {
		t.Fatalf("代次：%d %v", epoch, err)
	}
}

func TestRevocationsFileMustExistBePrivateAndWellFormed(t *testing.T) {
	// 没有撤销是一份写着空表的文件。
	if ledger, err := LoadRevocations(writeFile(t, nothingRevoked, 0o600)); err != nil {
		t.Fatalf("空表：%v", err)
	} else if accounts, epoch, _ := ledger.Revoked(context.Background()); len(accounts) != 0 || epoch != 0 {
		t.Fatalf("空表读成了：%+v %d", accounts, epoch)
	}
	// 没有文件不是"没有撤销"：文件丢了不能等于全部恢复。
	if _, err := LoadRevocations(filepath.Join(t.TempDir(), "missing.json")); err == nil {
		t.Fatal("不存在的文件被当成了空表")
	}

	for _, mode := range []os.FileMode{0o640, 0o604, 0o644, 0o660, 0o666} {
		if _, err := LoadRevocations(writeFile(t, nothingRevoked, mode)); err == nil || !strings.Contains(err.Error(), "readable by others") {
			t.Errorf("权限 %04o：%v", mode, err)
		}
	}
	for _, mode := range []os.FileMode{0o600, 0o400} {
		if _, err := LoadRevocations(writeFile(t, nothingRevoked, mode)); err != nil {
			t.Errorf("权限 %04o: %v", mode, err)
		}
	}

	entry := `{"at": "2026-11-18T05:00:00Z", "by": "x", "reason": "y"}`
	for name, content := range map[string]string{
		"空文件":           ``,
		"不是 JSON":       `nothing revoked`,
		"顶层是数组":         `[]`,
		"顶层是 null":      `null`,
		"没有代次":          `{"revoked_accounts": {}}`,
		"没有表":           `{"epoch": 3}`,
		"表是 null":       `{"epoch": 3, "revoked_accounts": null}`,
		"表是数组":          `{"epoch": 3, "revoked_accounts": ["account-blue"]}`,
		"代次是负数":         `{"epoch": -1, "revoked_accounts": {}}`,
		"代次是字符串":        `{"epoch": "3", "revoked_accounts": {}}`,
		"代次是小数":         `{"epoch": 3.5, "revoked_accounts": {}}`,
		"有不认识的字段":       `{"epoch": 3, "revoked_accounts": {}, "restore_all": true}`,
		"条目里有不认识的字段":    `{"epoch": 3, "revoked_accounts": {"account-blue": {"at": "2026-11-18T05:00:00Z", "revoked": false}}}`,
		"条目是 true":      `{"epoch": 3, "revoked_accounts": {"account-blue": true}}`,
		"条目没有时刻":        `{"epoch": 3, "revoked_accounts": {"account-blue": {"by": "x", "reason": "y"}}}`,
		"时刻不是 RFC 3339": `{"epoch": 3, "revoked_accounts": {"account-blue": {"at": "yesterday"}}}`,
		"空账户":           `{"epoch": 3, "revoked_accounts": {"": ` + entry + `}}`,
		"文件后面还有内容":      `{"epoch": 3, "revoked_accounts": {}} {"epoch": 0, "revoked_accounts": {}}`,
		"对象没有写完":        `{"epoch": 3, "revoked_accounts": {"account-blue": ` + entry,
	} {
		if ledger, err := LoadRevocations(writeFile(t, content, 0o600)); err == nil {
			accounts, epoch, _ := ledger.Revoked(context.Background())
			t.Errorf("%s: 被接受了，读成 %+v，代次 %d", name, accounts, epoch)
		}
	}
	// 条目里只有时刻是必填的：手工写的初始文件不一定写得出是谁、为什么。
	if ledger, err := LoadRevocations(writeFile(t, `{"epoch": 1, "revoked_accounts": {"account-blue": {"at": "2026-11-18T05:00:00Z"}}}`, 0o600)); err != nil {
		t.Errorf("只有时刻的条目：%v", err)
	} else if revoked, epoch, _ := ledger.State(context.Background(), "account-blue"); !revoked || epoch != 1 {
		t.Errorf("只有时刻的条目读成了：%v %d", revoked, epoch)
	}
}

// 文件写不成的时候，只往收紧的方向偏：撤销照样生效，恢复不生效。
func TestRevocationsOnlyTightenWhenTheFileCannotBeWritten(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root 写得进只读的目录，这条测试在它手里看不出什么")
	}
	ctx := context.Background()
	path := writeFile(t, nothingRevoked, 0o600)
	directory := filepath.Dir(path)
	writable := func(yes bool) {
		t.Helper()
		mode := os.FileMode(0o500)
		if yes {
			mode = 0o700
		}
		if err := os.Chmod(directory, mode); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { _ = os.Chmod(directory, 0o700) })
	ledger := loadRevocations(t, path)
	state := func(account string) (bool, uint64) {
		revoked, epoch, _ := ledger.State(ctx, account)
		return revoked, epoch
	}

	// 撤销写不成：照样生效，错误里说明没有写下去；文件里还没有。
	writable(false)
	change, err := ledger.Revoke(ctx, "account-blue", "spiffe://idp.test/revoker", "key leaked")
	if !errors.Is(err, ports.ErrRevocationNotWritten) || change != (ports.RevocationChange{Changed: true, Revoked: true, Epoch: 1}) {
		t.Fatalf("写不成的撤销：%+v %v", change, err)
	}
	if revoked, epoch := state("account-blue"); !revoked || epoch != 1 {
		t.Fatalf("写不成的撤销没有生效：%v %d", revoked, epoch)
	}
	if written, epoch := onDisk(t, path); len(written) != 0 || epoch != 0 {
		t.Fatalf("文件却变了：%s，代次 %d", names(written), epoch)
	}
	// 再发一次同一个撤销：仍然写不成，仍然说出来；状态不再变。
	change, err = ledger.Revoke(ctx, "account-blue", "spiffe://idp.test/revoker", "key leaked")
	if !errors.Is(err, ports.ErrRevocationNotWritten) || change != (ports.RevocationChange{Revoked: true, Epoch: 1}) {
		t.Fatalf("重发写不成的撤销：%+v %v", change, err)
	}
	// 目录又能写了：重发同一个撤销，就把它写下去了。
	writable(true)
	change, err = ledger.Revoke(ctx, "account-blue", "spiffe://idp.test/revoker", "key leaked")
	if err != nil || change != (ports.RevocationChange{Revoked: true, Epoch: 1}) {
		t.Fatalf("目录能写之后重发：%+v %v", change, err)
	}
	if written, epoch := onDisk(t, path); names(written) != "account-blue" || epoch != 1 {
		t.Fatalf("重发之后文件里的表：%s，代次 %d", names(written), epoch)
	}

	// 恢复写不成：不恢复。内存里和文件里都还是撤销着的。错误不是"撤销没写下去"那一种。
	writable(false)
	change, err = ledger.Restore(ctx, "account-blue")
	if err == nil || errors.Is(err, ports.ErrRevocationNotWritten) || change != (ports.RevocationChange{Revoked: true, Epoch: 1}) {
		t.Fatalf("写不成的恢复：%+v %v", change, err)
	}
	if revoked, epoch := state("account-blue"); !revoked || epoch != 1 {
		t.Fatalf("写不成的恢复却生效了：%v %d", revoked, epoch)
	}

	// 一次没写成的撤销，由下一次写成的改动一并写下去。
	if _, err := ledger.Revoke(ctx, "account-green", "spiffe://idp.test/revoker", "second"); !errors.Is(err, ports.ErrRevocationNotWritten) {
		t.Fatalf("第二个写不成的撤销：%v", err)
	}
	writable(true)
	change, err = ledger.Revoke(ctx, "account-red", "spiffe://idp.test/revoker", "third")
	if err != nil || change != (ports.RevocationChange{Changed: true, Revoked: true, Epoch: 3}) {
		t.Fatalf("第三个撤销：%+v %v", change, err)
	}
	if written, epoch := onDisk(t, path); names(written) != "account-blue,account-green,account-red" || epoch != 3 {
		t.Fatalf("最后文件里的表：%s，代次 %d", names(written), epoch)
	}
	// 恢复写成的时候也一样：之前没写成的撤销在写下去的那张表里。
	writable(false)
	if _, err := ledger.Revoke(ctx, "account-grey", "spiffe://idp.test/revoker", "fourth"); !errors.Is(err, ports.ErrRevocationNotWritten) {
		t.Fatalf("第四个写不成的撤销：%v", err)
	}
	writable(true)
	if change, err = ledger.Restore(ctx, "account-red"); err != nil || change != (ports.RevocationChange{Changed: true, Epoch: 5}) {
		t.Fatalf("恢复：%+v %v", change, err)
	}
	if written, epoch := onDisk(t, path); names(written) != "account-blue,account-green,account-grey" || epoch != 5 {
		t.Fatalf("恢复之后文件里的表：%s，代次 %d", names(written), epoch)
	}
}

// 上一次留下的临时文件不碍事，它的权限也不会带到新文件上。
func TestRevocationsReplaceALeftOverTemporaryFile(t *testing.T) {
	path := writeFile(t, nothingRevoked, 0o600)
	if err := os.WriteFile(path+".next", []byte("left over from a write that was cut short"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path+".next", 0o644); err != nil {
		t.Fatal(err)
	}
	ledger := loadRevocations(t, path)
	if _, err := ledger.Revoke(context.Background(), "account-blue", "spiffe://idp.test/revoker", "key leaked"); err != nil {
		t.Fatal(err)
	}
	if mode := fileInfo(t, path).Mode().Perm(); mode != 0o600 {
		t.Fatalf("新文件的权限是 %04o", mode)
	}
	if _, err := os.Stat(path + ".next"); !os.IsNotExist(err) {
		t.Fatalf("临时文件还在：%v", err)
	}
	if written, epoch := onDisk(t, path); names(written) != "account-blue" || epoch != 1 {
		t.Fatalf("文件里的表：%s，代次 %d", names(written), epoch)
	}
}

// 一边有人改撤销表，一边有很多判定在读：一直被撤销着的账户，没有哪一次读成没撤销；代次不往回走。
func TestRevocationsAreReadWhileTheyChange(t *testing.T) {
	ctx := context.Background()
	path := writeFile(t, nothingRevoked, 0o600)
	ledger := loadRevocations(t, path)
	if _, err := ledger.Revoke(ctx, "account-green", "spiffe://idp.test/revoker", "stays revoked"); err != nil {
		t.Fatal(err)
	}

	const readers, changes = 8, 100
	var wg sync.WaitGroup
	var mu sync.Mutex
	var problems []string
	done := make(chan struct{})
	for range readers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var last uint64
			for {
				select {
				case <-done:
					return
				default:
				}
				revoked, epoch, err := ledger.State(ctx, "account-green")
				_, _, _ = ledger.State(ctx, "account-blue")
				var problem string
				switch {
				case err != nil:
					problem = err.Error()
				case !revoked:
					problem = "一直被撤销着的账户读成了没撤销"
				case epoch < last:
					problem = "代次往回走了"
				}
				last = epoch
				if problem != "" {
					mu.Lock()
					problems = append(problems, problem)
					mu.Unlock()
				}
			}
		}()
	}
	for range changes {
		if _, err := ledger.Revoke(ctx, "account-blue", "spiffe://idp.test/revoker", "on"); err != nil {
			t.Error(err)
		}
		if _, err := ledger.Restore(ctx, "account-blue"); err != nil {
			t.Error(err)
		}
	}
	close(done)
	wg.Wait()
	if len(problems) > 0 {
		t.Fatalf("%d 次不对，头一次：%s", len(problems), problems[0])
	}
	if written, epoch := onDisk(t, path); names(written) != "account-green" || epoch != 1+2*changes {
		t.Fatalf("最后文件里的表：%s，代次 %d", names(written), epoch)
	}
}
