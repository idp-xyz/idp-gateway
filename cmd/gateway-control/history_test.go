package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"go.idp.xyz/idp-gateway/internal/gatewayconfig/adapters/history"
	"go.idp.xyz/idp-gateway/internal/gatewayconfig/application"
	"go.idp.xyz/idp-gateway/internal/gatewayconfig/domain"
	"go.idp.xyz/idp-gateway/internal/gatewayconfig/ports"
)

// 发布历史的命令行这一面（docs/adr/ADR-0013.md）：--history-dir、--pool、--note、
// releases、release、rollback，和"不给 --history-dir 时与没有历史时一字不差"。

const testAccount = "ops (uid 1000)"

// historyHarness 是 harness 加上一个历史目录。
type historyHarness struct {
	*harness
	dir string
	// 用来换掉 openHistory：flaky 不为 nil 时，每次打开的历史都包上它。
	wrap func(ports.History) ports.History
}

func newHistoryHarness(t *testing.T) *historyHarness {
	t.Helper()
	h := &historyHarness{harness: newHarness(t), dir: t.TempDir()}
	oldOpen, oldAccount := openHistory, currentAccount
	openHistory = func(dir, pool string) (ports.History, error) {
		real, err := history.New(dir, pool)
		if err != nil {
			return nil, err
		}
		if h.wrap != nil {
			return h.wrap(real), nil
		}
		return real, nil
	}
	currentAccount = func() string { return testAccount }
	t.Cleanup(func() { openHistory, currentAccount = oldOpen, oldAccount })
	return h
}

// with 在命令的参数后面加上历史的三个参数。
func (h *historyHarness) with(args []string, extra ...string) []string {
	return append(append([]string(nil), args...), append([]string{"--history-dir", h.dir, "--pool", "main"}, extra...)...)
}

func (h *historyHarness) publishH(content string, extra ...string) result {
	h.t.Helper()
	return h.run(h.with(h.args(h.snapshot(content)), extra...))
}

func (h *historyHarness) restartH(content string, extra ...string) result {
	h.t.Helper()
	return h.run(h.with(h.restartArgs(h.snapshot(content)), extra...))
}

func (h *historyHarness) rollbackArgs(to int, extra ...string) []string {
	args := h.restartArgs("")
	args[0] = "rollback"
	return h.with(args, append([]string{"--to", strconv.Itoa(to)}, extra...)...)
}

func (h *historyHarness) readArgs(command string, extra ...string) []string {
	return append([]string{command, "--history-dir", h.dir, "--pool", "main"}, extra...)
}

// runRaw 跑一条命令，不把标准输出当成 outcome 来解（releases、release 的 JSON 是另一种）。
func (h *historyHarness) runRaw(args []string) result {
	h.t.Helper()
	var stdout, stderr bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	r := result{code: run(ctx, args, &stdout, &stderr, h.docker.run)}
	r.stdout, r.stderr = stdout.String(), stderr.String()
	return r
}

func (h *historyHarness) releases() (result, releasesReport) {
	h.t.Helper()
	r := h.runRaw(h.readArgs("releases", "--config-dir", h.poolDir))
	var report releasesReport
	if r.code == exitActive {
		if err := json.Unmarshal([]byte(r.stdout), &report); err != nil {
			h.t.Fatalf("%v：%q", err, r.stdout)
		}
	}
	return r, report
}

func (h *historyHarness) release(number int) (result, releaseDetailReport) {
	h.t.Helper()
	r := h.runRaw(h.readArgs("release", "--id", strconv.Itoa(number)))
	var report releaseDetailReport
	if r.stdout != "" {
		if err := json.Unmarshal([]byte(r.stdout), &report); err != nil {
			h.t.Fatalf("%v：%q", err, r.stdout)
		}
	}
	return r, report
}

func (h *historyHarness) log() string {
	h.t.Helper()
	raw, err := os.ReadFile(filepath.Join(h.dir, history.LogName))
	if err != nil {
		return ""
	}
	return string(raw)
}

// stepNames 是一条记录的各步：STAGED APPLYING(replace-file) …
func stepNames(detail *releaseDetail) string {
	var parts []string
	for _, step := range detail.Steps {
		part := step.State
		if step.Step != "" {
			part += "(" + step.Step + ")"
		}
		parts = append(parts, part)
	}
	return strings.Join(parts, " ")
}

// flaky 是一个写到第 N 次就失败的历史：包着真的那一个，所以失败之前写的都是真的。
type flaky struct {
	ports.History
	mu     *sync.Mutex
	writes *int
	only   map[int]bool
	from   int
}

func (f flaky) fails() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	*f.writes++
	return (f.from > 0 && *f.writes >= f.from) || f.only[*f.writes]
}

func (f flaky) Begin(ctx context.Context, start domain.ReleaseStart) (uint64, error) {
	if f.fails() {
		return 0, errors.New("history: no space left on device")
	}
	return f.History.Begin(ctx, start)
}

func (f flaky) Advance(ctx context.Context, number uint64, step domain.ReleaseStep) error {
	if f.fails() {
		return errors.New("history: no space left on device")
	}
	return f.History.Advance(ctx, number, step)
}

func (h *historyHarness) failWrites(from int, only ...int) {
	var mu sync.Mutex
	writes := 0
	set := map[int]bool{}
	for _, n := range only {
		set[n] = true
	}
	h.wrap = func(real ports.History) ports.History {
		return flaky{History: real, mu: &mu, writes: &writes, only: set, from: from}
	}
}

// ---- 不给 --history-dir 时 ----

// touchy 是一个一碰就失败的历史：不给 --history-dir 的命令不该打开历史，更不该读写它。
type touchy struct{ t *testing.T }

func (c touchy) fail() { c.t.Error("没有给 --history-dir，却碰了历史") }
func (c touchy) Begin(context.Context, domain.ReleaseStart) (uint64, error) {
	c.fail()
	return 0, errors.New("touched")
}
func (c touchy) Advance(context.Context, uint64, domain.ReleaseStep) error {
	c.fail()
	return errors.New("touched")
}
func (c touchy) Snapshot(context.Context, string) (domain.Snapshot, error) {
	c.fail()
	return domain.Snapshot{}, errors.New("touched")
}
func (c touchy) List(context.Context) ([]domain.Release, error) {
	c.fail()
	return nil, errors.New("touched")
}
func (c touchy) Get(context.Context, uint64) (domain.Release, error) {
	c.fail()
	return domain.Release{}, errors.New("touched")
}

func TestWithoutAHistoryDirNothingTouchesAHistory(t *testing.T) {
	h := newHarness(t)
	opened := 0
	oldOpen := openHistory
	openHistory = func(string, string) (ports.History, error) {
		opened++
		return touchy{t}, nil
	}
	defer func() { openHistory = oldOpen }()

	// 发布、再发布一次、需要重启的、带重启的、对账（放回去的和对得上的）、place：一样都不碰历史。
	type named struct {
		name string
		r    result
	}
	for _, c := range []named{
		{"publish", h.publish(two)},
		{"publish again", h.publish(two)},
		{"publish refused", h.publish(unloadable)},
		{"publish needs", h.publish(needsRestart)},
		{"restart", h.restart(needsRestart)},
		{"restart confirmed", h.run(h.restartArgs(""))},
		{"reconcile in sync", h.reconcile()},
		{"place", h.run(h.placeArgs())},
	} {
		name, r := c.name, c.r
		if strings.Contains(r.stdout, `"release"`) || strings.Contains(r.stdout, "history_settled") || strings.Contains(r.stderr, "history") {
			t.Errorf("%s：输出里有历史的痕迹：%s%s", name, r.stdout, r.stderr)
		}
	}
	h.place(one) // 绕过发布器改了池
	if r := h.reconcile(); r.code != exitRestored || strings.Contains(r.stdout, "release") {
		t.Fatalf("%d %s", r.code, r.stdout)
	}
	if opened != 0 {
		t.Fatalf("历史被打开了 %d 次", opened)
	}
}

func TestTheOutputWithoutAHistoryDirHasTheOldKeysAndASilentStandardError(t *testing.T) {
	h := newHarness(t)
	for _, r := range []result{h.publish(two), h.publish(two), h.restart(needsRestart), h.reconcile()} {
		var raw map[string]any
		if err := json.Unmarshal([]byte(r.stdout), &raw); err != nil {
			t.Fatal(err)
		}
		for _, key := range []string{"release", "history_settled", "warnings"} {
			if _, ok := raw[key]; ok {
				t.Errorf("没有历史时输出里多了 %s", key)
			}
		}
		if r.stderr != "" || r.code != exitActive {
			t.Errorf("退出码 %d，标准错误 %q", r.code, r.stderr)
		}
	}
}

func TestHistoryFlagsAreCheckedTogether(t *testing.T) {
	h := newHarness(t)
	base := h.args(h.snapshot(two))
	cases := map[string][]string{
		"--pool 没有 --history-dir":   append(append([]string(nil), base...), "--pool", "main"),
		"--note 没有 --history-dir":   append(append([]string(nil), base...), "--note", "hello"),
		"空的 --history-dir":          append(append([]string(nil), base...), "--history-dir", ""),
		"--history-dir 没有 --pool":   append(append([]string(nil), base...), "--history-dir", t.TempDir()),
		"坏的池名":                      append(append([]string(nil), base...), "--history-dir", t.TempDir(), "--pool", "a b"),
		"备注太长":                      append(append([]string(nil), base...), "--history-dir", t.TempDir(), "--pool", "main", "--note", strings.Repeat("x", 513)),
		"备注里有换行":                    append(append([]string(nil), base...), "--history-dir", t.TempDir(), "--pool", "main", "--note", "two\nlines"),
		"备注里有控制字符":                  append(append([]string(nil), base...), "--history-dir", t.TempDir(), "--pool", "main", "--note", "bell\a"),
		"备注不是 UTF-8":                append(append([]string(nil), base...), "--history-dir", t.TempDir(), "--pool", "main", "--note", "\xff\xfe"),
		"rollback 没有 --history-dir": append(replaced(h.restartArgs(""), "restart", "rollback")[:0:0], append(h.restartArgs(""), "--to", "1")...),
	}
	cases["rollback 没有 --history-dir"][0] = "rollback"
	for name, args := range cases {
		r := h.run(args)
		if r.code != exitUsage || r.stdout != "" || r.stderr == "" {
			t.Errorf("%s：退出码 %d，标准错误 %q", name, r.code, r.stderr)
		}
		if h.inPlace() != one || len(h.docker.commands) != 0 {
			t.Fatalf("%s：池被碰过", name)
		}
	}
	// 刚好 512 字节、里面有中文的备注可以。
	good := strings.Repeat("x", 512-len("备注")) + "备注"
	hh := newHistoryHarness(t)
	if r := hh.publishH(two, "--note", good); r.code != exitActive {
		t.Fatalf("512 字节的备注：%d %s", r.code, r.stderr)
	}
	if _, detail := hh.release(1); detail.Release == nil || detail.Release.Note != good {
		t.Fatalf("%+v", detail.Release)
	}
}

// ---- 记下来 ----

func TestAPublicationWithAHistoryDirIsRecordedAndReported(t *testing.T) {
	h := newHistoryHarness(t)
	r := h.publishH(two, "--note", "moving routes")
	if r.code != exitActive || r.stderr != "" || r.report.Outcome != "ACTIVE" || r.report.Release != 1 {
		t.Fatalf("退出码 %d，标准错误 %q，标准输出 %s", r.code, r.stderr, r.stdout)
	}
	if h.inPlace() != two || len(h.leftovers()) != 0 {
		t.Fatalf("配置目录里是 %q，另外留下了 %v", h.inPlace(), h.leftovers())
	}
	// 历史目录：日志，和两份快照（这一份和上一份）。
	entries, _ := os.ReadDir(filepath.Join(h.dir, "snapshots"))
	if len(entries) != 2 {
		t.Fatalf("存下 %d 份快照", len(entries))
	}
	if lines := strings.Count(h.log(), "\n"); lines != 4 {
		t.Fatalf("日志 %d 行：%s", lines, h.log())
	}
	_, detail := h.release(1)
	d := detail.Release
	if detail.Outcome != "SHOWN" || d == nil || d.State != "ACTIVE" || d.Command != "publish" || d.Snapshot != id(two) || d.Previous != id(one) ||
		!d.Replaced || d.Restarted || d.Note != "moving routes" || d.NoteStatus == "" || d.ObservedDigest == "" || d.ExpectedDigest != d.ObservedDigest ||
		d.Version != "1.7.0" || d.Reason != "" || d.RouteIntent != "" {
		t.Fatalf("%+v", d)
	}
	if stepNames(d) != "STAGED APPLYING(replace-file) OBSERVING ACTIVE" {
		t.Fatalf("各步 %s", stepNames(d))
	}
	// 发起人的两项：证书里的工作负载身份，和操作系统账号；都说明了没有核实。
	if d.Initiator.Workload != publisherID || d.Initiator.Account != testAccount || !strings.Contains(d.Initiator.Status, "nobody verified") {
		t.Fatalf("%+v", d.Initiator)
	}
	if !strings.Contains(d.NoteStatus, "nobody verified") {
		t.Fatalf("%q", d.NoteStatus)
	}
}

func TestTheInitiatorIsLeftEmptyWhenTheCertificateHasNoSingleURI(t *testing.T) {
	for name, uris := range map[string][]string{"没有": nil, "两个": {publisherID, "spiffe://idp.test/other"}} {
		h := newHistoryHarness(t)
		leaf := h.ca.Issue("publisher-"+strconv.Itoa(len(uris)), uris)
		args := replaced(replaced(h.args(h.snapshot(two)), "--tls-cert", leaf.CertFile), "--tls-key", leaf.KeyFile)
		r := h.run(h.with(args))
		if r.code != exitActive || r.report.Release != 1 {
			t.Fatalf("%s：证书没有唯一的 URI 不该拒绝发布：%d %s", name, r.code, r.stderr)
		}
		_, detail := h.release(1)
		if detail.Release.Initiator.Workload != "" || detail.Release.Initiator.Account != testAccount {
			t.Fatalf("%s：%+v", name, detail.Release.Initiator)
		}
	}
}

func TestAReleaseLineOnDisk(t *testing.T) {
	h := newHistoryHarness(t)
	h.publishH(two, "--note", "moving routes")
	lines := strings.Split(strings.TrimSuffix(h.log(), "\n"), "\n")
	if len(lines) != 4 {
		t.Fatal(lines)
	}
	for _, line := range lines {
		var raw map[string]any
		if err := json.Unmarshal([]byte(line), &raw); err != nil || raw["pool"] != "main" || raw["release"] != float64(1) || raw["format"] != float64(1) {
			t.Fatalf("%v %q", err, line)
		}
	}
	if !strings.Contains(lines[0], `"state":"STAGED"`) || !strings.Contains(lines[0], `"note":"moving routes"`) ||
		!strings.Contains(lines[0], `"initiator_workload":"`+publisherID+`"`) || !strings.Contains(lines[1], `"step":"replace-file"`) ||
		!strings.Contains(lines[3], `"state":"ACTIVE"`) || !strings.Contains(lines[3], `"observed_digest"`) {
		t.Fatalf("%s", strings.Join(lines, "\n"))
	}
}

func TestAHistoryThatCannotBeWrittenBeforeAnythingIsDoneStopsWithExitOne(t *testing.T) {
	// 历史目录不存在：不自动创建，报错，池没有被碰过（连离线加载都没有做）。
	h := newHistoryHarness(t)
	missing := filepath.Join(t.TempDir(), "no-such", "history")
	r := h.run(append(h.args(h.snapshot(two)), "--history-dir", missing, "--pool", "main"))
	if r.code != exitError || r.stdout != "" || !strings.Contains(r.stderr, "history") || !strings.Contains(r.stderr, "must exist") {
		t.Fatalf("退出码 %d，标准错误 %q", r.code, r.stderr)
	}
	if _, err := os.Stat(filepath.Dir(missing)); err == nil {
		t.Fatal("历史目录的上级被创建了")
	}
	if h.inPlace() != one || len(h.docker.commands) != 0 || len(h.leftovers()) != 0 {
		t.Fatalf("池被碰过：%v %v", h.docker.commands, h.leftovers())
	}

	// 日志坏了（中间有读不懂的行）：不猜，退出码 1，池没有被碰过，没有记录。
	logPath := filepath.Join(h.dir, history.LogName)
	damaged := "not json\n{\"format\":1}\n"
	if err := os.WriteFile(logPath, []byte(damaged), 0o600); err != nil {
		t.Fatal(err)
	}
	r = h.publishH(two)
	if r.code != exitError || r.stdout != "" || !strings.Contains(r.stderr, "history") || !strings.Contains(r.stderr, "damaged") {
		t.Fatalf("退出码 %d，标准错误 %q", r.code, r.stderr)
	}
	if h.inPlace() != one || len(h.leftovers()) != 0 {
		t.Fatalf("池被碰过：%v", h.leftovers())
	}
	if _, err := os.Stat(filepath.Join(h.poolDir, recordFile)); err == nil {
		t.Fatal("池的记录被写了")
	}
	if raw, _ := os.ReadFile(logPath); string(raw) != damaged {
		t.Fatal("坏了的日志被改动了")
	}
	// releases、release 也一样：退出码 1，没有 JSON。
	for _, args := range [][]string{h.readArgs("releases", "--config-dir", h.poolDir), h.readArgs("release", "--id", "1")} {
		if r := h.runRaw(args); r.code != exitError || r.stdout != "" || !strings.Contains(r.stderr, "damaged") {
			t.Fatalf("%v：%d %q", args[0], r.code, r.stderr)
		}
	}
}

func TestEachStepIsWrittenBeforeItIsTaken(t *testing.T) {
	// 第 1、2 次写（STAGED、APPLYING）写不进去：退出码 1，池没有被碰过。
	for _, from := range []int{1, 2} {
		h := newHistoryHarness(t)
		h.failWrites(from)
		r := h.publishH(two)
		if r.code != exitError || r.stdout != "" || !strings.Contains(r.stderr, "history") || !strings.Contains(r.stderr, "no space left") {
			t.Fatalf("从第 %d 次写起：退出码 %d，标准错误 %q", from, r.code, r.stderr)
		}
		if h.inPlace() != one || len(h.leftovers()) != 0 {
			t.Fatalf("从第 %d 次写起：池被碰过：%v", from, h.leftovers())
		}
		if _, err := os.Stat(filepath.Join(h.poolDir, recordFile)); err == nil {
			t.Fatalf("从第 %d 次写起：池的记录被写了", from)
		}
	}

	// 第 3 次（OBSERVING）写不进去：发布照常成功，标准错误里说一句。
	h := newHistoryHarness(t)
	h.failWrites(0, 3)
	r := h.publishH(two)
	if r.code != exitActive || r.report.Outcome != "ACTIVE" || h.inPlace() != two || !strings.Contains(r.stderr, "OBSERVING") {
		t.Fatalf("退出码 %d，标准错误 %q", r.code, r.stderr)
	}
	h.wrap = nil
	if _, detail := h.release(1); stepNames(detail.Release) != "STAGED APPLYING(replace-file) ACTIVE" {
		t.Fatalf("%s", stepNames(detail.Release))
	}
}

func TestAnActiveLineThatCannotBeWrittenIsExitEightAndPublishingAgainCompletesTheHistory(t *testing.T) {
	h := newHistoryHarness(t)
	h.failWrites(0, 4)
	r := h.publishH(two)
	if r.code != exitActiveNotRecorded || r.report.Outcome != "ACTIVE_NOT_RECORDED" || r.report.Release != 1 {
		t.Fatalf("退出码 %d，%s%s", r.code, r.stdout, r.stderr)
	}
	// 标准错误说清楚：池已经在跑这份快照，历史停在哪一步，再跑一次是安全的。
	for _, want := range []string{"ACTIVE_NOT_RECORDED", "already runs snapshot " + id(two)[:12], "release 1 stops at OBSERVING", "again is safe"} {
		if !strings.Contains(r.stderr, want) {
			t.Errorf("标准错误里没有 %q：%s", want, r.stderr)
		}
	}
	// 池确实是 ACTIVE：文件、池的记录。
	if h.inPlace() != two {
		t.Fatal("池里不是 two")
	}
	if _, err := os.Stat(filepath.Join(h.poolDir, recordFile)); err != nil {
		t.Fatal(err)
	}

	// 再跑一次同样的命令：补全那一条，不开新的。
	h.wrap = nil
	again := h.publishH(two)
	if again.code != exitActive || again.report.Outcome != "ACTIVE" || again.report.Release != 1 || again.report.Replaced || again.stderr != "" {
		t.Fatalf("退出码 %d，%s%s", again.code, again.stdout, again.stderr)
	}
	_, detail := h.release(1)
	if stepNames(detail.Release) != "STAGED APPLYING(replace-file) OBSERVING ACTIVE(publish-again)" {
		t.Fatalf("%s", stepNames(detail.Release))
	}
	if _, list := h.releases(); len(list.Releases) != 1 {
		t.Fatalf("历史里有 %d 条", len(list.Releases))
	}
}

func TestReconcileCompletesAReleaseThatStoppedHalfway(t *testing.T) {
	h := newHistoryHarness(t)
	h.failWrites(0, 4)
	if r := h.publishH(two); r.code != exitActiveNotRecorded {
		t.Fatalf("%d %s", r.code, r.stderr)
	}
	h.wrap = nil
	r := h.run(h.with(h.reconcileArgs()))
	if r.code != exitActive || r.report.Outcome != "IN_SYNC" || len(r.report.HistorySettled) != 1 || r.report.HistorySettled[0] != 1 || r.stderr != "" {
		t.Fatalf("退出码 %d，%s%s", r.code, r.stdout, r.stderr)
	}
	_, detail := h.release(1)
	if detail.Release.State != "ACTIVE" || stepNames(detail.Release) != "STAGED APPLYING(replace-file) OBSERVING ACTIVE(reconcile)" {
		t.Fatalf("%s", stepNames(detail.Release))
	}
	// 再对一次：没有什么要补的，输出里没有 history_settled。
	if r := h.run(h.with(h.reconcileArgs())); strings.Contains(r.stdout, "history_settled") {
		t.Fatalf("%s", r.stdout)
	}

	// 历史坏了：对账的结局和退出码不变，标准错误里说一句。
	h.place(one) // 池被人改了
	if err := os.WriteFile(filepath.Join(h.dir, history.LogName), []byte("garbage\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	r = h.run(h.with(h.reconcileArgs()))
	if r.code != exitRestored || r.report.Outcome != "RESTORED" || !strings.Contains(r.stderr, "history") {
		t.Fatalf("退出码 %d，%s%s", r.code, r.stdout, r.stderr)
	}
}

func TestRestartIsRecordedWithBothApplyingSteps(t *testing.T) {
	h := newHistoryHarness(t)
	r := h.restartH(needsRestart)
	if r.code != exitActive || r.report.Release != 1 || !r.report.Restarted {
		t.Fatalf("%d %s%s", r.code, r.stdout, r.stderr)
	}
	_, detail := h.release(1)
	d := detail.Release
	if stepNames(d) != "STAGED APPLYING(replace-file) APPLYING(restart-gateway) OBSERVING ACTIVE" || d.Command != "restart" || !d.Replaced || !d.Restarted ||
		len(d.Restart) != 1 || d.Restart[0] != "terminationMaxDeadline" {
		t.Fatalf("%s %+v", stepNames(d), d)
	}
	// 重启那一行写不进去：不重启，把上一份放回去。
	h2 := newHistoryHarness(t)
	h2.failWrites(0, 3)
	r = h2.restartH(needsRestart)
	if r.code != exitRestored || r.report.Restarted || h2.pool.restarts != 0 || h2.inPlace() != one || !strings.Contains(r.report.Reason, "history") {
		t.Fatalf("退出码 %d，%s%s", r.code, r.stdout, r.stderr)
	}
}

// ---- 回滚 ----

func TestRollbackGoesBackThroughTheFullPublishPath(t *testing.T) {
	h := newHistoryHarness(t)
	h.publishH(two)
	h.publishH(three())
	before := h.log()

	r := h.run(h.rollbackArgs(1, "--note", "bad routes"))
	if r.code != exitActive || r.report.Outcome != "ACTIVE" || r.report.Release != 3 || h.inPlace() != two {
		t.Fatalf("退出码 %d，%s%s", r.code, r.stdout, r.stderr)
	}
	_, detail := h.release(3)
	d := detail.Release
	if d.Command != "rollback" || d.RolledBackTo != 1 || d.Snapshot != id(two) || d.Note != "bad routes" || stepNames(d) != "STAGED APPLYING(replace-file) OBSERVING ACTIVE" {
		t.Fatalf("%+v %s", d, stepNames(d))
	}
	// 之前的行一个字都没有变：日志只多了新的那几行。
	if !strings.HasPrefix(h.log(), before) {
		t.Fatal("回滚改了日志里已有的行")
	}
}

func three() string {
	return `{"config":{"terminationMaxDeadline":"45s"},"routes":["one","two","three"]}`
}

func TestRollbackRefusesWhatCannotBeRolledBackTo(t *testing.T) {
	h := newHistoryHarness(t)
	h.publishH(two)                   // 1 ACTIVE
	failed := h.publishH(onlyOffline) // 2 FAILED（池里加载不了，收回去）
	if failed.code != exitRestored {
		t.Fatalf("%d %s%s", failed.code, failed.stdout, failed.stderr)
	}
	log := h.log()

	for name, c := range map[string]struct {
		to   int
		want string
	}{
		"FAILED 的": {2, "never reached ACTIVE"},
		"没有这个编号":   {9, "no release 9"},
		"就是现在放着的":  {1, "nothing to roll back"},
	} {
		r := h.run(h.rollbackArgs(c.to))
		if r.code != exitNotDone || r.report.Outcome != "REFUSED" || !strings.Contains(r.report.Reason, c.want) || h.inPlace() != two {
			t.Errorf("%s：退出码 %d，%s%s", name, r.code, r.stdout, r.stderr)
		}
		if h.log() != log {
			t.Errorf("%s：被拒绝的回滚写了历史", name)
		}
	}
}

func TestRollbackToWhatNeedsARestartDefaultsToRestartRequired(t *testing.T) {
	h := newHistoryHarness(t)
	h.publishH(two)          // 1：45 秒
	h.restartH(needsRestart) // 2：90 秒（重启过）
	log := h.log()

	r := h.run(h.rollbackArgs(1))
	if r.code != exitNotDone || r.report.Outcome != "RESTART_REQUIRED" || len(r.report.Restart) != 1 || h.inPlace() != needsRestart || h.log() != log {
		t.Fatalf("退出码 %d，%s%s", r.code, r.stdout, r.stderr)
	}
	restarts := h.pool.restarts
	r = h.run(h.rollbackArgs(1, "--with-restart"))
	if r.code != exitActive || !r.report.Restarted || h.inPlace() != two || h.pool.restarts != restarts+1 || r.report.Release != 3 {
		t.Fatalf("退出码 %d，%s%s", r.code, r.stdout, r.stderr)
	}
	if _, detail := h.release(3); stepNames(detail.Release) != "STAGED APPLYING(replace-file) APPLYING(restart-gateway) OBSERVING ACTIVE" || detail.Release.RolledBackTo != 1 {
		t.Fatalf("%s", stepNames(detail.Release))
	}
	// --with-restart 要有网关容器。
	args := h.rollbackArgs(1, "--with-restart")
	for i := range args {
		if args[i] == "--container" {
			args = append(args[:i], args[i+2:]...)
			break
		}
	}
	if r := h.run(args); r.code != exitUsage || !strings.Contains(r.stderr, "--container") {
		t.Fatalf("%d %q", r.code, r.stderr)
	}
}

func TestRollbackToASnapshotWhoseFileWasChangedTouchesNothing(t *testing.T) {
	h := newHistoryHarness(t)
	h.publishH(two)
	h.publishH(three())
	path := filepath.Join(h.dir, "snapshots", id(two)+".yaml")
	if err := os.WriteFile(path, []byte("tampered"), 0o600); err != nil {
		t.Fatal(err)
	}
	log := h.log()
	commands := len(h.docker.commands)
	r := h.run(h.rollbackArgs(1))
	if r.code != exitError || r.stdout != "" || !strings.Contains(r.stderr, "SHA-256") || h.inPlace() != three() || h.log() != log || len(h.docker.commands) != commands {
		t.Fatalf("退出码 %d，标准错误 %q", r.code, r.stderr)
	}
	// 快照文件不见了：同样。
	_ = os.Remove(path)
	if r := h.run(h.rollbackArgs(1)); r.code != exitError || h.inPlace() != three() {
		t.Fatalf("退出码 %d，标准错误 %q", r.code, r.stderr)
	}
}

func TestRollbackToASnapshotTheImageCannotLoadAnymoreIsRefused(t *testing.T) {
	h := newHistoryHarness(t)
	h.publishH(two)
	h.publishH(three())
	// 离线加载的临时容器现在认不得 two 了：它起来就退出，说它加载不了。
	refusing := func(ctx context.Context, env []string, argv ...string) (string, error) {
		if argv[0] == "inspect" && strings.Contains(argv[2], ".State.Running") {
			if content, err := os.ReadFile(h.docker.file()); err == nil && string(content) == two {
				return "false 1\n", nil
			}
		}
		return h.docker.run(ctx, env, argv...)
	}
	log := h.log()
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), h.rollbackArgs(1), &stdout, &stderr, refusing)
	var report outcome
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatalf("%v：%q", err, stdout.String())
	}
	if code != exitNotDone || report.Outcome != "REFUSED" || report.Reason != loadError || h.inPlace() != three() || h.log() != log {
		t.Fatalf("退出码 %d，%s%s", code, stdout.String(), stderr.String())
	}
}

// ---- releases 和 release ----

func TestReleasesListsEachReleaseAndDerivesSuperseded(t *testing.T) {
	h := newHistoryHarness(t)
	h.publishH(two, "--note", "first")
	h.publishH(three())
	h.publishH(unloadable)  // REFUSED：不记
	h.publishH(onlyOffline) // FAILED

	r, list := h.releases()
	if r.code != exitActive || list.Outcome != "LISTED" || list.Pool != "main" || len(list.Releases) != 3 {
		t.Fatalf("退出码 %d，%s%s", r.code, r.stdout, r.stderr)
	}
	first, second, third := list.Releases[0], list.Releases[1], list.Releases[2]
	if first.Number != 1 || first.State != "SUPERSEDED" || first.RecordedState != "ACTIVE" || first.SupersededBy != 2 || !first.HasNote ||
		first.Snapshot != id(two)[:12] || first.InitiatorWorkload != publisherID || first.InitiatorAccount != testAccount ||
		first.StartedAt == "" || first.FinishedAt == "" || first.Command != "publish" {
		t.Fatalf("%+v", first)
	}
	if second.State != "ACTIVE" || second.SupersededBy != 0 || second.HasNote || third.State != "FAILED" {
		t.Fatalf("%+v %+v", second, third)
	}
	if strings.Contains(h.log(), "SUPERSEDED") {
		t.Fatal("SUPERSEDED 被写进了历史")
	}
	// 池的记录和历史里最后一条 ACTIVE 对得上。
	if list.Comparison.Status != "match" || list.PoolRecord.Status != "present" || list.PoolRecord.Snapshot != id(three())[:12] ||
		list.Comparison.HistoryLastActive == nil || list.Comparison.HistoryLastActive.Number != 2 {
		t.Fatalf("%+v %+v", list.PoolRecord, list.Comparison)
	}
	if r.stderr != "" {
		t.Fatalf("对得上时标准错误里不该有话：%q", r.stderr)
	}
}

func TestReleasesPointsOutWhenTheHistoryAndThePoolsRecordDisagree(t *testing.T) {
	// 绕过历史发布一次（不给 --history-dir）：池的记录是新的，历史里最后一条 ACTIVE 是旧的。
	h := newHistoryHarness(t)
	h.publishH(two)
	h.publish(three())
	r, list := h.releases()
	if r.code != exitActive || list.Comparison.Status != "mismatch" || !strings.Contains(list.Comparison.Detail, id(three())[:12]) ||
		!strings.Contains(list.Comparison.Detail, "last ACTIVE release is 1") ||
		!strings.Contains(r.stderr, "do not agree") {
		t.Fatalf("退出码 %d，%+v，标准错误 %q", r.code, list.Comparison, r.stderr)
	}

	// 池没有记录，历史里有 ACTIVE。
	if err := os.Remove(filepath.Join(h.poolDir, recordFile)); err != nil {
		t.Fatal(err)
	}
	r, list = h.releases()
	if list.Comparison.Status != "mismatch" || list.PoolRecord.Status != "absent" || !strings.Contains(list.Comparison.Detail, "no confirmed record") {
		t.Fatalf("%+v %+v", list.PoolRecord, list.Comparison)
	}

	// 池的记录读不成样子：写在输出里，不当成命令的错。
	if err := os.WriteFile(filepath.Join(h.poolDir, recordFile), []byte("{broken"), 0o600); err != nil {
		t.Fatal(err)
	}
	r, list = h.releases()
	if r.code != exitActive || list.Comparison.Status != "record_unreadable" || list.PoolRecord.Status != "unreadable" || list.PoolRecord.Error == "" {
		t.Fatalf("%d %+v %+v", r.code, list.PoolRecord, list.Comparison)
	}
}

func TestReleasesOfAnEmptyHistory(t *testing.T) {
	// 历史是空的，池也没有记录：没有什么可比的。
	h := newHistoryHarness(t)
	if err := os.Remove(filepath.Join(h.poolDir, recordFile)); err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	r, list := h.releases()
	if r.code != exitActive || len(list.Releases) != 0 || list.Comparison.Status != "nothing_to_compare" || list.PoolRecord.Status != "absent" || list.Comparison.HistoryLastActive != nil {
		t.Fatalf("%d %s", r.code, r.stdout)
	}
	if !strings.Contains(r.stderr, "has no release") {
		t.Fatalf("%q", r.stderr)
	}
	// 输出里 releases 是空数组，不是 null。
	if !strings.Contains(r.stdout, `"releases": []`) {
		t.Fatalf("%s", r.stdout)
	}

	// 历史是空的，池却有记录（发布时没有给 --history-dir，或者历史丢了）：对不上，明说。
	h.publish(two)
	r, list = h.releases()
	if list.Comparison.Status != "mismatch" || !strings.Contains(list.Comparison.Detail, "no ACTIVE release") || !strings.Contains(r.stderr, "do not agree") {
		t.Fatalf("%+v %q", list.Comparison, r.stderr)
	}
}

func TestReleaseShowsOneReleaseWithEveryStep(t *testing.T) {
	h := newHistoryHarness(t)
	h.publishH(onlyOffline) // FAILED，原因里是网关的话
	r, detail := h.release(1)
	d := detail.Release
	if r.code != exitActive || detail.Outcome != "SHOWN" || d == nil || d.State != "FAILED" || !strings.Contains(d.Reason, "cannot load") && d.Reason == "" {
		t.Fatalf("%d %s", r.code, r.stdout)
	}
	if stepNames(d) != "STAGED APPLYING(replace-file) OBSERVING FAILED" || !d.Replaced || d.FinishedAt == "" {
		t.Fatalf("%s", stepNames(d))
	}
	for _, step := range d.Steps {
		if _, err := time.Parse(time.RFC3339Nano, step.At); err != nil {
			t.Fatalf("%q：%v", step.At, err)
		}
	}
	// 没有这个编号：NOT_FOUND，退出码 3。
	r, detail = h.release(7)
	if r.code != exitNotDone || detail.Outcome != "NOT_FOUND" || detail.Release != nil || !strings.Contains(r.stderr, "no release 7") {
		t.Fatalf("%d %s%s", r.code, r.stdout, r.stderr)
	}
}

func TestTheReadOnlyCommandsCheckTheirFlagsAndNeverTakeThePoolsLock(t *testing.T) {
	h := newHistoryHarness(t)
	h.publishH(two)
	for name, args := range map[string][]string{
		"releases 没有 --config-dir": h.readArgs("releases"),
		"release 没有 --id":          h.readArgs("release"),
		"release --id 0":           h.readArgs("release", "--id", "0"),
		"没有 --history-dir":         {"releases", "--pool", "main", "--config-dir", h.poolDir},
		"没有 --pool":                {"release", "--history-dir", h.dir, "--id", "1"},
		"池名不对":                     append(h.readArgs("release", "--id", "1"), "--pool", "a b"),
	} {
		if r := h.runRaw(args); r.code != exitUsage || r.stdout != "" || r.stderr == "" {
			t.Errorf("%s：%d %q", name, r.code, r.stderr)
		}
	}
	// 别的发布正占着池时，只读的命令照样读得到（不占锁）。
	release := h.hold()
	defer release()
	if r, list := h.releases(); r.code != exitActive || len(list.Releases) != 1 {
		t.Fatalf("池被占着时 releases：%d %s", r.code, r.stderr)
	}
	if r, _ := h.release(1); r.code != exitActive {
		t.Fatalf("池被占着时 release：%d %s", r.code, r.stderr)
	}
	// 历史目录不存在：退出码 1。
	missing := filepath.Join(t.TempDir(), "nope")
	if r := h.runRaw([]string{"release", "--history-dir", missing, "--pool", "main", "--id", "1"}); r.code != exitError || !strings.Contains(r.stderr, "history") {
		t.Fatalf("%d %q", r.code, r.stderr)
	}
}

func TestTheNewCommandsAreListedInTheUsage(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), nil, &stdout, &stderr, nil); code != exitUsage ||
		!strings.Contains(stderr.String(), "usage: gateway-control publish|restart|reconcile|place|keep [flags]") ||
		!strings.Contains(stderr.String(), "releases|release|rollback") {
		t.Fatalf("%d %q", code, stderr.String())
	}
}

func TestExitCodeEightIsOnlyForActiveNotRecorded(t *testing.T) {
	if exitActiveNotRecorded != 8 || exitRevokedNotWritten == exitActiveNotRecorded {
		t.Fatal("退出码 8 被占用了")
	}
	for _, outcome := range []string{"ACTIVE", "REFUSED", "RESTORED", "UNKNOWN", "IN_SYNC"} {
		if exitCode(application.Outcome(outcome)) == exitActiveNotRecorded {
			t.Errorf("%s 的退出码是 8", outcome)
		}
	}
}

func TestKeepWithAHistoryDirCompletesTheStuckReleaseOnItsFirstReconcile(t *testing.T) {
	h := newHistoryHarness(t)
	h.failWrites(0, 4)
	if r := h.publishH(two); r.code != exitActiveNotRecorded {
		t.Fatalf("%d %s", r.code, r.stderr)
	}
	h.wrap = nil
	h.compose()
	k := h.keep("--history-dir", h.dir, "--pool", "main")
	first := k.next("开头的那一行", func(tended) bool { return true })
	if first.Reconcile == nil || first.Reconcile.Outcome != "IN_SYNC" || len(first.Reconcile.HistorySettled) != 1 || first.Reconcile.HistorySettled[0] != 1 {
		t.Fatalf("%+v / %+v", first, first.Reconcile)
	}
	if code := k.stop(); code != exitActive {
		t.Fatalf("退出码 %d", code)
	}
	if _, detail := h.release(1); detail.Release.State != "ACTIVE" || stepNames(detail.Release) != "STAGED APPLYING(replace-file) OBSERVING ACTIVE(reconcile)" {
		t.Fatalf("%s", stepNames(detail.Release))
	}
}

func TestKeepRefusesAMissingHistoryDirectoryWithExitOne(t *testing.T) {
	h := newHistoryHarness(t)
	h.compose()
	var stdout, stderr bytes.Buffer
	args := append(h.keepArgs(), "--history-dir", filepath.Join(t.TempDir(), "nope"), "--pool", "main")
	if code := run(context.Background(), args, &stdout, &stderr, h.docker.run); code != exitError || !strings.Contains(stderr.String(), "history") || stdout.Len() != 0 {
		t.Fatalf("%d %q", code, stderr.String())
	}
}

// 输出里的名字是给别的程序读的，不随 Go 里的名字变。
func TestTheKeysOfTheReadOnlyCommandsAreFixed(t *testing.T) {
	h := newHistoryHarness(t)
	h.publishH(two, "--note", "n")
	keys := func(raw map[string]any) []string {
		var names []string
		for key := range raw {
			names = append(names, key)
		}
		sort.Strings(names)
		return names
	}
	r, _ := h.releases()
	var list struct {
		Releases []map[string]any `json:"releases"`
	}
	if err := json.Unmarshal([]byte(r.stdout), &list); err != nil {
		t.Fatal(err)
	}
	want := []string{"command", "finished_at", "has_note", "initiator_account", "initiator_workload", "number", "recorded_state", "snapshot", "started_at", "state"}
	if got := keys(list.Releases[0]); !reflect.DeepEqual(got, want) {
		t.Fatalf("releases 一行的键是 %v", got)
	}
	r, _ = h.release(1)
	var shown struct {
		Release map[string]any `json:"release"`
	}
	if err := json.Unmarshal([]byte(r.stdout), &shown); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"number", "state", "snapshot", "previous", "started_at", "finished_at", "replaced", "restarted", "restart", "expected_digest",
		"observed_digest", "version", "revision", "reason", "initiator", "note", "note_status", "route_intent", "steps"} {
		if _, ok := shown.Release[key]; !ok {
			t.Errorf("release 里没有 %s：%v", key, keys(shown.Release))
		}
	}
	initiator, _ := shown.Release["initiator"].(map[string]any)
	if got := keys(initiator); !reflect.DeepEqual(got, []string{"os_account", "status", "workload_identity"}) {
		t.Fatalf("发起人的键是 %v", got)
	}
}
