package filestore

import (
	"context"
	"errors"
	"maps"
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

// 两个账本打开同一份文件。前一个写完之后，后一个自己不封、不撤销，下一次读就看得见。
func TestAnotherLedgerSeesARevokeAndABan(t *testing.T) {
	ctx := context.Background()
	path := writeFile(t, nothingRevoked, 0o600)
	first := loadRevocations(t, path)
	second := loadRevocations(t, path)
	first.now = func() time.Time { return time.Date(2026, 11, 21, 2, 3, 4, 0, time.UTC) }

	if _, err := first.Revoke(ctx, "account-blue", "spiffe://idp.test/revoker", "key leaked"); err != nil {
		t.Fatal(err)
	}
	revoked, banned, epoch, err := second.View(ctx, "account-blue", "tracking.get")
	if err != nil || !revoked || banned || epoch != 1 {
		t.Fatalf("另一个进程的下一次判定：revoked=%v banned=%v epoch=%d err=%v", revoked, banned, epoch, err)
	}
	accounts, epoch, err := second.Revoked(ctx)
	if err != nil || names(accounts) != "account-blue" || accounts[0].Reason != "key leaked" || epoch != 1 {
		t.Fatalf("另一个进程的撤销表：%s，代次 %d，%v", names(accounts), epoch, err)
	}

	if _, err := first.Ban(ctx, "tracking.get", "spiffe://idp.test/revoker", "abuse"); err != nil {
		t.Fatal(err)
	}
	revoked, banned, epoch, err = second.View(ctx, "account-blue", "tracking.get")
	if err != nil || !revoked || !banned || epoch != 2 {
		t.Fatalf("封禁之后：revoked=%v banned=%v epoch=%d err=%v", revoked, banned, epoch, err)
	}
	operations, epoch, err := second.Banned(ctx)
	if err != nil || len(operations) != 1 || operations[0].OperationID != "tracking.get" || operations[0].Reason != "abuse" || epoch != 2 {
		t.Fatalf("另一个进程的封禁表：%+v，代次 %d，%v", operations, epoch, err)
	}
	if _, banned, _, err := second.View(ctx, "account-blue", "labels.print"); err != nil || banned {
		t.Fatalf("没被封的操作：banned=%v err=%v", banned, err)
	}

	// 没有 banned_operations 的旧文件换上来，仍然能读，封禁表是空的。
	replaceFile(t, path, `{"epoch": 7, "revoked_accounts": {"account-old": {"at": "2026-11-01T00:00:00Z", "by": "x", "reason": "left"}}}`, 0o600)
	revoked, banned, epoch, err = second.View(ctx, "account-old", "tracking.get")
	if err != nil || !revoked || banned || epoch != 7 {
		t.Fatalf("旧文件：revoked=%v banned=%v epoch=%d err=%v", revoked, banned, epoch, err)
	}
	if revoked, _, _, err := second.View(ctx, "account-blue", "tracking.get"); err != nil || revoked {
		t.Fatalf("旧文件还留着换掉之前的账户：%v %v", revoked, err)
	}
}

// 内存里有没写下去的撤销时，磁盘上更旧或是空的那一份不能把它盖掉。
func TestUnwrittenRevokeIsNotReplacedByTheFile(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root 写得进只读的目录，这条测试在它手里看不出什么")
	}
	ctx := context.Background()
	path := writeFile(t, nothingRevoked, 0o600)
	directory := filepath.Dir(path)
	ledger := loadRevocations(t, path)
	if err := os.Chmod(directory, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(directory, 0o700) })

	if _, err := ledger.Revoke(ctx, "account-blue", "spiffe://idp.test/revoker", "key leaked"); !errors.Is(err, ports.ErrRevocationNotWritten) {
		t.Fatal(err)
	}
	if revoked, _, epoch, err := ledger.View(ctx, "account-blue", "tracking.get"); err != nil || !revoked || epoch != 1 {
		t.Fatalf("空文件把没写下去的撤销盖掉了：revoked=%v epoch=%d err=%v", revoked, epoch, err)
	}
	if written, epoch := onDisk(t, path); len(written) != 0 || epoch != 0 {
		t.Fatalf("文件不该有这次撤销：%s，代次 %d", names(written), epoch)
	}

	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	replaceFile(t, path, `{"epoch": 0, "revoked_accounts": {"account-old": {"at": "2026-11-01T00:00:00Z", "by": "x", "reason": "old"}}}`, 0o600)
	revoked, _, epoch, err := ledger.View(ctx, "account-blue", "tracking.get")
	if err != nil || !revoked || epoch != 1 {
		t.Fatalf("更旧的文件把撤销盖掉了：revoked=%v epoch=%d err=%v", revoked, epoch, err)
	}
	if revoked, _, _, err := ledger.View(ctx, "account-old", "tracking.get"); err != nil || revoked {
		t.Fatalf("更旧的文件被读进了内存：%v %v", revoked, err)
	}

	if err := os.Chmod(directory, 0o500); err != nil {
		t.Fatal(err)
	}
	if _, err := ledger.Ban(ctx, "tracking.get", "spiffe://idp.test/revoker", "abuse"); !errors.Is(err, ports.ErrRevocationNotWritten) {
		t.Fatal(err)
	}
	revoked, banned, epoch, err := ledger.View(ctx, "account-blue", "tracking.get")
	if err != nil || !revoked || !banned || epoch != 2 {
		t.Fatalf("没写下去的封禁：revoked=%v banned=%v epoch=%d err=%v", revoked, banned, epoch, err)
	}
}

// 重读读不成时留下原来的表，这一次读返回错误，不把表清掉。
func TestAFailedReloadKeepsThePreviousTable(t *testing.T) {
	ctx := context.Background()
	const original = `{"epoch": 2, "revoked_accounts": {"account-blue": {"at": "2026-11-18T05:00:00Z", "by": "x", "reason": "y"}}}`
	path := writeFile(t, original, 0o600)
	ledger := loadRevocations(t, path)

	replaceFile(t, path, `{`, 0o600)
	if _, _, _, err := ledger.View(ctx, "account-blue", "tracking.get"); err == nil {
		t.Fatal("读不懂的文件被当成读成了")
	}
	if _, ok := ledger.revoked["account-blue"]; !ok || ledger.epoch != 2 {
		t.Fatalf("读不懂的重读把表清了：%v 代次 %d", ledger.revoked, ledger.epoch)
	}
	if _, _, _, err := ledger.View(ctx, "account-blue", "tracking.get"); err == nil {
		t.Fatal("同一份坏文件第二次被当成读成了")
	}
	if _, ok := ledger.revoked["account-blue"]; !ok || ledger.epoch != 2 {
		t.Fatal("第二次把表清了")
	}

	replaceFile(t, path, original, 0o644)
	if _, _, _, err := ledger.View(ctx, "account-blue", "tracking.get"); err == nil || !strings.Contains(err.Error(), "readable by others") {
		t.Fatalf("别人能读的文件：%v", err)
	}
	if _, _, err := ledger.Revoked(ctx); err == nil {
		t.Fatal("Revoked 在重读失败时没有返回错误")
	}
	if _, _, err := ledger.Banned(ctx); err == nil {
		t.Fatal("Banned 在重读失败时没有返回错误")
	}
	if _, ok := ledger.revoked["account-blue"]; !ok || ledger.epoch != 2 {
		t.Fatal("权限不对的重读把表清了")
	}

	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := ledger.View(ctx, "account-blue", "tracking.get"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("文件不在了：%v", err)
	}
	if _, ok := ledger.revoked["account-blue"]; !ok || ledger.epoch != 2 {
		t.Fatal("文件不在了就把表清了")
	}

	replaceFile(t, path, `{"epoch": 3, "revoked_accounts": {"account-blue": {"at": "2026-11-18T05:00:00Z", "by": "x", "reason": "y"}}, "banned_operations": {"tracking.get": {"at": "2026-11-21T00:00:00Z", "by": "x", "reason": "abuse"}}}`, 0o600)
	revoked, banned, epoch, err := ledger.View(ctx, "account-blue", "tracking.get")
	if err != nil || !revoked || !banned || epoch != 3 {
		t.Fatalf("好文件换回来：revoked=%v banned=%v epoch=%d err=%v", revoked, banned, epoch, err)
	}
}

// 身份、修改时间和大小都没变时不重读。就地改写变了大小和修改时间，下一次读看得见。
func TestAnUnchangedRevocationFileIsNotReread(t *testing.T) {
	ctx := context.Background()
	const original = `{"epoch": 1, "revoked_accounts": {"account-blue": {"at": "2026-11-18T05:00:00Z", "by": "x", "reason": "y"}}}`
	path := writeFile(t, original, 0o600)
	ledger := loadRevocations(t, path)
	before := fileInfo(t, path)

	mutated := strings.ReplaceAll(original, "account-blue", "account-red1")
	if len(mutated) != len(original) {
		t.Fatalf("就地替换改变了长度：%d %d", len(mutated), len(original))
	}
	file, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, err = file.Write([]byte(mutated))
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, before.ModTime(), before.ModTime()); err != nil {
		t.Fatal(err)
	}
	if !sameFile(before, fileInfo(t, path)) {
		t.Fatal("身份、修改时间或大小变了，无法证明没重读")
	}
	revoked, _, epoch, err := ledger.View(ctx, "account-blue", "tracking.get")
	if err != nil || !revoked || epoch != 1 {
		t.Fatalf("没变的文件被重读了：revoked=%v epoch=%d err=%v", revoked, epoch, err)
	}
	if revoked, _, _, err := ledger.View(ctx, "account-red1", "tracking.get"); err != nil || revoked {
		t.Fatalf("没变的文件读出了新账户：%v %v", revoked, err)
	}

	const rewritten = `{"epoch": 2, "revoked_accounts": {"account-red": {"at": "2026-11-18T05:00:00Z", "by": "x", "reason": "y"}}}`
	inplace := fileInfo(t, path)
	file, err = os.OpenFile(path, os.O_WRONLY|os.O_TRUNC, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, err = file.Write([]byte(rewritten))
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		t.Fatal(err)
	}
	after := fileInfo(t, path)
	if !os.SameFile(inplace, after) {
		t.Fatal("就地改写换成了另一个文件")
	}
	if sameFile(inplace, after) {
		t.Fatal("就地改写没有改变大小或修改时间")
	}
	revoked, _, epoch, err = ledger.View(ctx, "account-red", "tracking.get")
	if err != nil || !revoked || epoch != 2 {
		t.Fatalf("就地改写没有被看见：revoked=%v epoch=%d err=%v", revoked, epoch, err)
	}
	if revoked, _, _, err := ledger.View(ctx, "account-blue", "tracking.get"); err != nil || revoked {
		t.Fatalf("就地改写之后旧账户还在：%v %v", revoked, err)
	}
}

// 权限变了也要重读。就地 chmod 不换 inode，修改时间也不一定变。
func TestARevocationFileThatBecomesReadableByOthersIsReread(t *testing.T) {
	ctx := context.Background()
	path := writeFile(t, `{"epoch": 1, "revoked_accounts": {"account-blue": {"at": "2026-11-18T05:00:00Z", "by": "x", "reason": "y"}}}`, 0o600)
	ledger := loadRevocations(t, path)
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := ledger.View(ctx, "account-blue", "tracking.get"); err == nil || !strings.Contains(err.Error(), "readable by others") {
		t.Fatalf("别人能读的文件：%v", err)
	}
	if _, ok := ledger.revoked["account-blue"]; !ok || ledger.epoch != 1 {
		t.Fatal("权限不对的重读把表清了")
	}
}

// 两个进程先后各撤销一个账户。后写的那一份必须还留着先写的账户。
func TestTwoLedgersDoNotDropEachOthersRevokes(t *testing.T) {
	ctx := context.Background()
	path := writeFile(t, nothingRevoked, 0o600)
	first := loadRevocations(t, path)
	second := loadRevocations(t, path)

	if _, err := first.Revoke(ctx, "account-blue", "spiffe://idp.test/revoker", "one"); err != nil {
		t.Fatal(err)
	}
	if _, err := second.Revoke(ctx, "account-red", "spiffe://idp.test/revoker", "two"); err != nil {
		t.Fatal(err)
	}
	if written, epoch := onDisk(t, path); names(written) != "account-blue,account-red" || epoch != 2 {
		t.Fatalf("两份撤销：%s，代次 %d", names(written), epoch)
	}
	if mode := fileInfo(t, path+".lock").Mode().Perm(); mode != 0o600 {
		t.Fatalf("锁文件权限是 %04o", mode)
	}
	revoked, _, epoch, err := first.View(ctx, "account-red", "tracking.get")
	if err != nil || !revoked || epoch != 2 {
		t.Fatalf("先写的进程看见后写的：revoked=%v epoch=%d err=%v", revoked, epoch, err)
	}

	change, err := second.Restore(ctx, "account-blue")
	if err != nil || change != (ports.RevocationChange{Changed: true, Epoch: 3}) {
		t.Fatalf("另一个进程恢复：%+v %v", change, err)
	}
	if written, epoch := onDisk(t, path); names(written) != "account-red" || epoch != 3 {
		t.Fatalf("恢复之后：%s，代次 %d", names(written), epoch)
	}
	if revoked, _, _, err := first.View(ctx, "account-blue", "tracking.get"); err != nil || revoked {
		t.Fatalf("先写的进程还留着已经恢复的账户：%v %v", revoked, err)
	}
}

// 两个进程先后各封禁一个操作，后写的不会把先写的封禁拿掉。解除也只拿掉那一个。
func TestTwoLedgersDoNotDropEachOthersBans(t *testing.T) {
	ctx := context.Background()
	path := writeFile(t, nothingRevoked, 0o600)
	first := loadRevocations(t, path)
	second := loadRevocations(t, path)

	if _, err := first.Ban(ctx, "tracking.get", "spiffe://idp.test/revoker", "one"); err != nil {
		t.Fatal(err)
	}
	if _, err := second.Ban(ctx, "labels.print", "spiffe://idp.test/revoker", "two"); err != nil {
		t.Fatal(err)
	}
	operations, epoch, err := first.Banned(ctx)
	if err != nil || epoch != 2 || len(operations) != 2 || operations[0].OperationID != "labels.print" || operations[1].OperationID != "tracking.get" {
		t.Fatalf("两份封禁：%+v，代次 %d，%v", operations, epoch, err)
	}
	change, err := second.Lift(ctx, "tracking.get")
	if err != nil || change != (ports.BanChange{Changed: true, Epoch: 3}) {
		t.Fatalf("另一个进程解除：%+v %v", change, err)
	}
	operations, epoch, err = first.Banned(ctx)
	if err != nil || epoch != 3 || len(operations) != 1 || operations[0].OperationID != "labels.print" {
		t.Fatalf("解除之后：%+v，代次 %d，%v", operations, epoch, err)
	}
}

func TestAdoptReplacesTheLocalEpochWithTheCoordinatorSnapshot(t *testing.T) {
	ctx := context.Background()
	path := writeFile(t, `{"epoch": 4, "revoked_accounts": {"account-old":
		{"at": "2026-11-01T00:00:00Z", "by": "x", "reason": "left"}}}`, 0o600)
	ledger := loadRevocations(t, path)
	at := time.Date(2026, 11, 24, 1, 2, 3, 0, time.UTC)
	if err := ledger.Adopt(1, []ports.RevokedAccount{{
		AccountID: "account-blue", At: at, By: "spiffe://idp.test/revoker", Reason: "key leaked",
	}}, nil); err != nil {
		t.Fatal(err)
	}
	revoked, _, epoch, err := ledger.View(ctx, "account-blue", "tracking.get")
	if err != nil || !revoked || epoch != 1 {
		t.Fatalf("内存：revoked=%v epoch=%d err=%v", revoked, epoch, err)
	}
	if revoked, _, _, err := ledger.View(ctx, "account-old", "tracking.get"); err != nil || revoked {
		t.Fatal("旧账户还在")
	}
	written, epoch := onDisk(t, path)
	if names(written) != "account-blue" || epoch != 1 || written[0].Reason != "key leaked" {
		t.Fatalf("文件：%s 代次 %d %+v", names(written), epoch, written)
	}
	if _, err := ledger.Revoke(ctx, "account-green", "spiffe://idp.test/revoker", "again"); err != nil {
		t.Fatal(err)
	}
	if epoch, err := ledger.Epoch(ctx); err != nil || epoch != 2 {
		t.Fatalf("Adopt 之后的撤销：%d %v", epoch, err)
	}
	if err := ledger.Adopt(1, []ports.RevokedAccount{{AccountID: "", At: at}}, nil); err == nil {
		t.Fatal("空账户被接受了")
	}
}

// 内存里还有没写下去的撤销时，下一次写要把磁盘上其他进程多出来的条目补上，同时留下这份内存。
func TestAnUnwrittenRevokeIsKeptWhenTheOtherLedgerWrites(t *testing.T) {
	ctx := context.Background()
	path := writeFile(t, nothingRevoked, 0o600)
	first := loadRevocations(t, path)
	second := loadRevocations(t, path)
	if _, err := first.Revoke(ctx, "account-blue", "spiffe://idp.test/revoker", "written"); err != nil {
		t.Fatal(err)
	}
	first.mu.Lock()
	kept := maps.Clone(first.revoked)
	kept["account-keep"] = revocation{at: time.Date(2026, 11, 21, 0, 0, 0, 0, time.UTC), by: "x", reason: "keep"}
	first.revoked = kept
	first.unwritten = true
	first.mu.Unlock()

	if _, err := second.Revoke(ctx, "account-red", "spiffe://idp.test/revoker", "other"); err != nil {
		t.Fatal(err)
	}
	if _, err := first.Revoke(ctx, "account-green", "spiffe://idp.test/revoker", "again"); err != nil {
		t.Fatal(err)
	}
	if written, epoch := onDisk(t, path); names(written) != "account-blue,account-green,account-keep,account-red" || epoch != 3 {
		t.Fatalf("并进去的表：%s，代次 %d", names(written), epoch)
	}
}
