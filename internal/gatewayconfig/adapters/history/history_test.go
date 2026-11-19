package history

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"go.idp.xyz/idp-gateway/internal/gatewayconfig/domain"
	"go.idp.xyz/idp-gateway/internal/gatewayconfig/ports"
)

var _ ports.History = (*History)(nil)

var base = time.Date(2026, 11, 19, 10, 0, 0, 0, time.UTC)

func snap(t *testing.T, content string) domain.Snapshot {
	t.Helper()
	snapshot, err := domain.NewSnapshot([]byte(content))
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func open(t *testing.T) (*History, string) {
	t.Helper()
	dir := t.TempDir()
	h, err := New(dir, "main")
	if err != nil {
		t.Fatal(err)
	}
	return h, dir
}

func begin(t *testing.T, h *History, content, previous string) uint64 {
	t.Helper()
	start := domain.ReleaseStart{
		Snapshot: snap(t, content), Expected: "digest-" + content, Command: "publish", At: base,
		By: domain.Initiator{Workload: "spiffe://idp.test/gateway-control/publisher", Account: "ops (uid 1000)"}, Note: "first try",
	}
	if previous != "" {
		start.Previous = snap(t, previous)
	}
	number, err := h.Begin(context.Background(), start)
	if err != nil {
		t.Fatal(err)
	}
	return number
}

func advance(t *testing.T, h *History, number uint64, state domain.ReleaseState, name string) {
	t.Helper()
	if err := h.Advance(context.Background(), number, domain.ReleaseStep{State: state, Name: name, At: base.Add(time.Second)}); err != nil {
		t.Fatal(err)
	}
}

func readLog(t *testing.T, dir string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, LogName))
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func TestBeginAppendsAReadableReleaseAndAdvanceAddsSteps(t *testing.T) {
	h, dir := open(t)
	number := begin(t, h, "two", "one")
	advance(t, h, number, domain.StateApplying, domain.StepReplaceFile)
	advance(t, h, number, domain.StateObserving, "")
	if err := h.Advance(context.Background(), number, domain.ReleaseStep{State: domain.StateActive, At: base.Add(2 * time.Second),
		Facts: &domain.StepFacts{Digest: "digest-two", Version: "1.7.0", Revision: "26f5aebe"}}); err != nil {
		t.Fatal(err)
	}

	// 一个新的 History 实例读同一个目录：落盘的东西读得回来。
	again, err := New(dir, "main")
	if err != nil {
		t.Fatal(err)
	}
	release, err := again.Get(context.Background(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if release.Number != 1 || release.Pool != "main" || release.Snapshot != snap(t, "two").ID() || release.Previous != snap(t, "one").ID() ||
		release.Expected != "digest-two" || release.Command != "publish" || release.Note != "first try" ||
		release.By.Workload != "spiffe://idp.test/gateway-control/publisher" || release.By.Account != "ops (uid 1000)" {
		t.Fatalf("记录读回来不对：%+v", release)
	}
	var states []string
	for _, step := range release.Steps {
		states = append(states, string(step.State)+"/"+step.Name)
	}
	if strings.Join(states, " ") != "STAGED/ APPLYING/replace-file OBSERVING/ ACTIVE/" || release.State() != domain.StateActive || !release.Settled() ||
		!release.Replaced() || release.Restarted() || !release.ReachedActive() {
		t.Fatalf("步骤不对：%v", states)
	}
	if facts := release.Facts(); facts == nil || facts.Digest != "digest-two" || facts.Version != "1.7.0" {
		t.Fatalf("结局的事实：%+v", facts)
	}
	if !release.StartedAt().Equal(base) || !release.FinishedAt().Equal(base.Add(2*time.Second)) {
		t.Fatalf("起止时刻：%v %v", release.StartedAt(), release.FinishedAt())
	}
	if lines := strings.Count(readLog(t, dir), "\n"); lines != 4 {
		t.Fatalf("日志有 %d 行，要 4 行", lines)
	}
}

func TestEveryLineIsFlushedWholeAndEndsWithANewline(t *testing.T) {
	h, dir := open(t)
	number := begin(t, h, "one", "")
	advance(t, h, number, domain.StateApplying, domain.StepReplaceFile)
	raw := readLog(t, dir)
	if !strings.HasSuffix(raw, "\n") {
		t.Fatal("最后一行没有换行结尾")
	}
	for _, text := range strings.Split(strings.TrimSuffix(raw, "\n"), "\n") {
		if !strings.HasPrefix(text, "{") || !strings.HasSuffix(text, "}") || strings.Contains(text, "\n") {
			t.Fatalf("不是单独的一行 JSON：%q", text)
		}
	}
}

func TestANumberIsOneMoreThanTheLargestAndNeverRepeats(t *testing.T) {
	h, _ := open(t)
	for want := uint64(1); want <= 5; want++ {
		if got := begin(t, h, fmt.Sprint("snapshot-", want), ""); got != want {
			t.Fatalf("第 %d 条拿到编号 %d", want, got)
		}
	}
	// 另一个池共用同一个目录：它自己从 1 起，不影响这个池。
	other, err := New(h.dir, "other")
	if err != nil {
		t.Fatal(err)
	}
	if got := begin(t, other, "x", ""); got != 1 {
		t.Fatalf("另一个池的第一条是 %d", got)
	}
	if got := begin(t, h, "six", ""); got != 6 {
		t.Fatalf("这个池的下一条是 %d", got)
	}
	list, _ := h.List(context.Background())
	if len(list) != 6 {
		t.Fatalf("这个池有 %d 条", len(list))
	}
	for i, release := range list {
		if release.Number != uint64(i+1) {
			t.Fatalf("第 %d 条的编号是 %d", i, release.Number)
		}
	}
}

func TestALastLineWithoutANewlineIsIgnoredAndCutOffBeforeTheNextAppend(t *testing.T) {
	h, dir := open(t)
	number := begin(t, h, "one", "")
	advance(t, h, number, domain.StateApplying, domain.StepReplaceFile)
	whole := readLog(t, dir)
	// 一次崩溃：下一行只写了一半，连换行也没有。
	torn := `{"format":1,"pool":"main","release":1,"at":"2026-11-19T10:00:05Z","state":"OBSERV`
	if err := os.WriteFile(filepath.Join(dir, LogName), []byte(whole+torn), 0o600); err != nil {
		t.Fatal(err)
	}
	release, err := h.Get(context.Background(), 1)
	if err != nil {
		t.Fatalf("没写完的最后一行不该算历史坏了：%v", err)
	}
	if release.State() != domain.StateApplying || len(release.Steps) != 2 {
		t.Fatalf("没写完的那一行被当成了一条：%v", release.Steps)
	}
	// 一个完整的 JSON 值，只是少了换行：同样算没写完。
	complete := `{"format":1,"pool":"main","release":1,"at":"2026-11-19T10:00:05Z","state":"ACTIVE"}`
	if err := os.WriteFile(filepath.Join(dir, LogName), []byte(whole+complete), 0o600); err != nil {
		t.Fatal(err)
	}
	if release, _ := h.Get(context.Background(), 1); release.State() != domain.StateApplying {
		t.Fatalf("少了换行的完整一行被当成了一条：%v", release.State())
	}
	// 下一次追加之前把尾巴截掉，不能把新的一行接在它后面。
	advance(t, h, number, domain.StateObserving, "")
	raw := readLog(t, dir)
	if strings.Contains(raw, "ACTIVE") || !strings.HasPrefix(raw, whole) || !strings.HasSuffix(raw, "\n") || strings.Count(raw, "\n") != 3 {
		t.Fatalf("追加之后日志是：%q", raw)
	}
	if release, err := h.Get(context.Background(), 1); err != nil || release.State() != domain.StateObserving {
		t.Fatalf("%v %v", release.State(), err)
	}
}

func TestAnUnreadableLineInTheMiddleIsAnErrorNotSkipped(t *testing.T) {
	good1 := `{"format":1,"pool":"main","release":1,"at":"2026-11-19T10:00:00Z","state":"STAGED","start":{"snapshot":"` + strings.Repeat("a", 64) + `","command":"publish"}}`
	good2 := `{"format":1,"pool":"main","release":1,"at":"2026-11-19T10:00:01Z","state":"APPLYING","step":"replace-file"}`
	for name, middle := range map[string]string{
		"不是 JSON":     `this is not json`,
		"空行":          ``,
		"格式不认识":       `{"format":2,"pool":"main","release":1,"at":"2026-11-19T10:00:00Z","state":"ACTIVE"}`,
		"有不认识的字段":     `{"format":1,"pool":"main","release":1,"at":"2026-11-19T10:00:00Z","state":"ACTIVE","surprise":true}`,
		"状态不认识":       `{"format":1,"pool":"main","release":1,"at":"2026-11-19T10:00:00Z","state":"DONE"}`,
		"没有开始过的一条的步骤": `{"format":1,"pool":"main","release":7,"at":"2026-11-19T10:00:00Z","state":"ACTIVE"}`,
		"JSON 后面还有东西": good2 + ` {}`,
		"编号重复":        good1,
	} {
		t.Run(name, func(t *testing.T) {
			h, dir := open(t)
			content := good1 + "\n" + middle + "\n" + good2 + "\n"
			if err := os.WriteFile(filepath.Join(dir, LogName), []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := h.List(context.Background()); !errors.Is(err, ports.ErrHistoryDamaged) {
				t.Fatalf("List：%v", err)
			}
			// 写之前也要先读得懂：坏了的日志不再追加。
			if _, err := h.Begin(context.Background(), domain.ReleaseStart{Snapshot: snap(t, "x"), Command: "publish", At: base}); !errors.Is(err, ports.ErrHistoryDamaged) {
				t.Fatalf("Begin：%v", err)
			}
			if err := h.Advance(context.Background(), 1, domain.ReleaseStep{State: domain.StateObserving, At: base}); !errors.Is(err, ports.ErrHistoryDamaged) {
				t.Fatalf("Advance：%v", err)
			}
			if got := readLog(t, dir); got != content {
				t.Fatal("坏了的日志被改动了")
			}
		})
	}
}

func TestASnapshotIsStoredOnceImmutablyAndVerifiedWhenRead(t *testing.T) {
	h, dir := open(t)
	begin(t, h, "two", "one")
	two, one := snap(t, "two"), snap(t, "one")
	path := filepath.Join(dir, SnapshotsDir, two.ID()+".yaml")
	got, err := h.Snapshot(context.Background(), two.ID())
	if err != nil || string(got.Content()) != "two" || got.ID() != two.ID() {
		t.Fatalf("%v %v", got, err)
	}
	// 动手之前放着的那一份也存下了。
	if got, err := h.Snapshot(context.Background(), one.ID()); err != nil || string(got.Content()) != "one" {
		t.Fatalf("上一份：%v %v", got, err)
	}
	// 同一份再存一次：不重写（文件的时刻不变）。
	before, _ := os.Stat(path)
	time.Sleep(10 * time.Millisecond)
	begin(t, h, "two", "")
	after, _ := os.Stat(path)
	if !before.ModTime().Equal(after.ModTime()) {
		t.Fatal("已经有的快照被重写了")
	}
	// 被人改过：读不出来，也不被盖掉。
	if err := os.WriteFile(path, []byte("tampered"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := h.Snapshot(context.Background(), two.ID()); !errors.Is(err, ports.ErrSnapshotDamaged) {
		t.Fatalf("被改过的快照读出来了：%v", err)
	}
	if _, err := h.Begin(context.Background(), domain.ReleaseStart{Snapshot: two, Command: "publish", At: base}); !errors.Is(err, ports.ErrSnapshotDamaged) {
		t.Fatalf("存一份已经被改过的：%v", err)
	}
	if raw, _ := os.ReadFile(path); string(raw) != "tampered" {
		t.Fatal("被改过的快照文件被盖掉了")
	}
	// 没有的，和不是 ID 的。
	if _, err := h.Snapshot(context.Background(), strings.Repeat("0", 64)); !errors.Is(err, ports.ErrSnapshotNotFound) {
		t.Fatalf("没有存过的：%v", err)
	}
	if _, err := h.Snapshot(context.Background(), "../../etc/passwd"); !errors.Is(err, ports.ErrSnapshotNotFound) {
		t.Fatalf("路径当成了 ID：%v", err)
	}
}

func TestPermissionsAreOwnerOnly(t *testing.T) {
	old := setUmask(0)
	defer setUmask(old) // 不受 umask 影响
	h, dir := open(t)
	number := begin(t, h, "two", "one")
	advance(t, h, number, domain.StateApplying, domain.StepReplaceFile)
	check := func(path string, want os.FileMode) {
		t.Helper()
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != want {
			t.Errorf("%s 的权限是 %o，要 %o", path, info.Mode().Perm(), want)
		}
	}
	check(filepath.Join(dir, LogName), 0o600)
	check(filepath.Join(dir, SnapshotsDir), 0o700)
	check(filepath.Join(dir, SnapshotsDir, snap(t, "two").ID()+".yaml"), 0o600)
	check(filepath.Join(dir, SnapshotsDir, snap(t, "one").ID()+".yaml"), 0o600)
	// 没有留下临时文件。
	entries, _ := os.ReadDir(filepath.Join(dir, SnapshotsDir))
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".tmp") {
			t.Errorf("留下了临时文件 %s", entry.Name())
		}
	}
}

func TestTheDirectoryMustExistAndIsNotCreated(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "typo", "history")
	if _, err := New(missing, "main"); err == nil || !strings.Contains(err.Error(), "must exist") {
		t.Fatalf("不存在的目录：%v", err)
	}
	if _, err := os.Stat(filepath.Dir(missing)); err == nil {
		t.Fatal("上级目录被创建了")
	}
	file := filepath.Join(t.TempDir(), "file")
	_ = os.WriteFile(file, nil, 0o600)
	if _, err := New(file, "main"); err == nil {
		t.Fatal("文件被当成了目录")
	}
	for _, bad := range []string{"", "a b", "../x", strings.Repeat("p", 65)} {
		if _, err := New(t.TempDir(), bad); err == nil {
			t.Errorf("池的标识 %q 被接受了", bad)
		}
	}
}

func TestAnUnwritableDirectoryFailsTheWrite(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root 不受目录权限限制")
	}
	h, dir := open(t)
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(dir, 0o700)
	if _, err := h.Begin(context.Background(), domain.ReleaseStart{Snapshot: snap(t, "x"), Command: "publish", At: base}); err == nil {
		t.Fatal("写不进去的目录没有报错")
	}
}

func TestConcurrentWritersNeverSplitALine(t *testing.T) {
	h, dir := open(t)
	number := begin(t, h, "one", "")
	// 两个写入方（两个适配器实例，同一个目录），本该靠池的锁一个接一个；就算没有，一行也不能被写成两半。
	other, err := New(dir, "main")
	if err != nil {
		t.Fatal(err)
	}
	var wait sync.WaitGroup
	const each = 40
	for _, writer := range []*History{h, other} {
		wait.Add(1)
		go func() {
			defer wait.Done()
			for i := 0; i < each; i++ {
				step := domain.ReleaseStep{State: domain.StateApplying, Name: strings.Repeat("x", 200), At: base}
				if err := writer.Advance(context.Background(), number, step); err != nil {
					t.Error(err)
					return
				}
			}
		}()
	}
	wait.Wait()
	release, err := h.Get(context.Background(), number)
	if err != nil {
		t.Fatalf("并发写之后日志读不懂：%v", err)
	}
	if len(release.Steps) != 1+2*each {
		t.Fatalf("有 %d 步，要 %d", len(release.Steps), 1+2*each)
	}
}

func TestConcurrentBeginsInOneProcessGetDistinctNumbers(t *testing.T) {
	h, _ := open(t)
	var wait sync.WaitGroup
	var mu sync.Mutex
	seen := map[uint64]bool{}
	for i := 0; i < 20; i++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			number, err := h.Begin(context.Background(), domain.ReleaseStart{Snapshot: snap(t, fmt.Sprint("s", i)), Command: "publish", At: base})
			if err != nil {
				t.Error(err)
				return
			}
			mu.Lock()
			defer mu.Unlock()
			if seen[number] {
				t.Errorf("编号 %d 给了两次", number)
			}
			seen[number] = true
		}()
	}
	wait.Wait()
}

func TestAdvancingAReleaseThatDoesNotExistIsAnError(t *testing.T) {
	h, dir := open(t)
	begin(t, h, "one", "")
	before := readLog(t, dir)
	if err := h.Advance(context.Background(), 9, domain.ReleaseStep{State: domain.StateActive, At: base}); !errors.Is(err, ports.ErrReleaseNotFound) {
		t.Fatalf("%v", err)
	}
	if err := h.Advance(context.Background(), 1, domain.ReleaseStep{State: domain.StateStaged, At: base}); err == nil {
		t.Fatal("STAGED 被当成了一步")
	}
	if readLog(t, dir) != before {
		t.Fatal("不该写的东西写进去了")
	}
	if _, err := h.Get(context.Background(), 9); !errors.Is(err, ports.ErrReleaseNotFound) {
		t.Fatalf("%v", err)
	}
}

func TestAnEmptyHistoryListsNothing(t *testing.T) {
	h, dir := open(t)
	list, err := h.List(context.Background())
	if err != nil || len(list) != 0 {
		t.Fatalf("%v %v", list, err)
	}
	if _, err := os.Stat(filepath.Join(dir, LogName)); err == nil {
		t.Fatal("读一个空的历史建了日志文件")
	}
}

func TestSupersededIsDerivedWhenReadNotWritten(t *testing.T) {
	h, dir := open(t)
	for _, content := range []string{"one", "two", "three"} {
		number := begin(t, h, content, "")
		advance(t, h, number, domain.StateActive, "")
	}
	failed := begin(t, h, "four", "")
	advance(t, h, failed, domain.StateFailed, "")
	if strings.Contains(readLog(t, dir), "SUPERSEDED") {
		t.Fatal("SUPERSEDED 被写进了日志")
	}
	list, _ := h.List(context.Background())
	derived := domain.DeriveSuperseded(list)
	var shown []string
	for _, release := range derived {
		shown = append(shown, string(release.ShownState()))
	}
	if strings.Join(shown, " ") != "SUPERSEDED SUPERSEDED ACTIVE FAILED" || derived[0].SupersededBy != 2 || derived[1].SupersededBy != 3 {
		t.Fatalf("%v", shown)
	}
	if last, ok := domain.LastActive(list); !ok || last.Number != 3 {
		t.Fatalf("最后一条 ACTIVE：%v %v", last.Number, ok)
	}
}
