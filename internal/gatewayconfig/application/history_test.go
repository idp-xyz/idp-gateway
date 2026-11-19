package application

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"go.idp.xyz/idp-gateway/internal/gatewayconfig/domain"
	"go.idp.xyz/idp-gateway/internal/gatewayconfig/ports"
)

// 这一份测试的是发布历史接在发布、重启、对账、回滚上的样子（docs/adr/ADR-0013.md）。
// 池的替身用的是 publish_test.go 里的那个；历史是下面这个内存里的替身，能"写到第 N 步就失败"。

// memHistory 是一个内存里的历史。写（Begin、Advance）一次算一步，从 1 数。
type memHistory struct {
	p         *pool
	releases  []domain.Release
	snapshots map[string]domain.Snapshot
	writes    int
	reads     int
	// failFrom：从第几次写起，每一次都失败（盘满了）；failOnly：只有这几次失败（偶发）。
	failFrom int
	failOnly map[int]bool
	listErr  error
	getErr   error
	snapErr  error
}

func newHistory(p *pool) *memHistory {
	return &memHistory{p: p, snapshots: map[string]domain.Snapshot{}, failOnly: map[int]bool{}}
}

func (h *memHistory) failing() bool {
	return (h.failFrom > 0 && h.writes >= h.failFrom) || h.failOnly[h.writes]
}

func (h *memHistory) Begin(_ context.Context, start domain.ReleaseStart) (uint64, error) {
	h.writes++
	if h.failing() {
		h.p.events = append(h.p.events, "history FAILED-WRITE STAGED")
		return 0, errors.New("no space left on device")
	}
	h.snapshots[start.Snapshot.ID()] = start.Snapshot
	if !start.Previous.IsZero() {
		h.snapshots[start.Previous.ID()] = start.Previous
	}
	number := uint64(len(h.releases) + 1)
	h.releases = append(h.releases, domain.Release{
		Number: number, Pool: "main", Snapshot: start.Snapshot.ID(), Previous: start.Previous.ID(), Expected: start.Expected,
		Command: start.Command, By: start.By, Note: start.Note, RolledBackTo: start.RolledBackTo,
		Steps: []domain.ReleaseStep{{State: domain.StateStaged, At: start.At}},
	})
	h.p.events = append(h.p.events, "history STAGED")
	return number, nil
}

func (h *memHistory) Advance(_ context.Context, number uint64, step domain.ReleaseStep) error {
	h.writes++
	label := string(step.State)
	if step.Name != "" {
		label += " " + step.Name
	}
	if h.failing() {
		h.p.events = append(h.p.events, "history FAILED-WRITE "+label)
		return errors.New("no space left on device")
	}
	if number == 0 || number > uint64(len(h.releases)) {
		return ports.ErrReleaseNotFound
	}
	release := &h.releases[number-1]
	release.Steps = append(release.Steps, step)
	h.p.events = append(h.p.events, "history "+label)
	return nil
}

func (h *memHistory) Snapshot(_ context.Context, id string) (domain.Snapshot, error) {
	h.reads++
	if h.snapErr != nil {
		return domain.Snapshot{}, h.snapErr
	}
	snapshot, ok := h.snapshots[id]
	if !ok {
		return domain.Snapshot{}, ports.ErrSnapshotNotFound
	}
	return snapshot, nil
}

func (h *memHistory) List(context.Context) ([]domain.Release, error) {
	h.reads++
	if h.listErr != nil {
		return nil, h.listErr
	}
	return append([]domain.Release(nil), h.releases...), nil
}

func (h *memHistory) Get(_ context.Context, number uint64) (domain.Release, error) {
	h.reads++
	if h.getErr != nil {
		return domain.Release{}, h.getErr
	}
	if number == 0 || number > uint64(len(h.releases)) {
		return domain.Release{}, ports.ErrReleaseNotFound
	}
	return h.releases[number-1], nil
}

// seed 直接放一条已有的记录：content 是它的快照，states 是它的各步（第一步必须是 STAGED），
// 每一步比上一步晚一秒，从池的假时钟现在这一刻起。
func (h *memHistory) seed(t *testing.T, content string, states ...domain.ReleaseState) uint64 {
	t.Helper()
	snapshot := snap(t, content)
	h.snapshots[snapshot.ID()] = snapshot
	number := uint64(len(h.releases) + 1)
	release := domain.Release{Number: number, Pool: "main", Snapshot: snapshot.ID(), Command: "publish"}
	for i, state := range states {
		release.Steps = append(release.Steps, domain.ReleaseStep{State: state, At: h.p.now.Add(time.Duration(i) * time.Second)})
	}
	h.releases = append(h.releases, release)
	return number
}

// summary 是第 number 条的各步：STAGED APPLYING(replace-file) OBSERVING ACTIVE。
func (h *memHistory) summary(number uint64) string {
	var parts []string
	for _, step := range h.releases[number-1].Steps {
		part := string(step.State)
		if step.Name != "" {
			part += "(" + step.Name + ")"
		}
		parts = append(parts, part)
	}
	return strings.Join(parts, " ")
}

// stamping 让池的记录像目录那样记下确认的时刻。
type stamping struct{ *pool }

func (s stamping) Confirm(ctx context.Context, confirmation domain.Confirmation) error {
	confirmation.At = s.pool.now
	return s.pool.Confirm(ctx, confirmation)
}

var initiated = domain.Initiator{Workload: "spiffe://idp.test/gateway-control/publisher", Account: "ops (uid 1000)"}

func (p *pool) publisherWith(h ports.History) *Publisher {
	publisher, err := New(p, stamping{p}, p, Timing{Settle: time.Second, Timeout: 10 * time.Second, Interval: 100 * time.Millisecond})
	if err != nil {
		p.t.Fatal(err)
	}
	p.clock(&publisher.watch)
	return publisher.WithProcess(p).WithHistory(h, ReleaseMeta{Command: "publish", By: initiated, Note: "because"})
}

func (p *pool) reconcilerWith(h ports.History) *Reconciler {
	return p.reconciler().WithHistory(h)
}

func publishH(t *testing.T, p *pool, h *memHistory, content string) Result {
	t.Helper()
	result, err := p.publisherWith(h).Publish(context.Background(), snap(t, content))
	if err != nil {
		t.Fatalf("Publish: %v", err)
	}
	return result
}

func restartH(t *testing.T, p *pool, h *memHistory, content string) Result {
	t.Helper()
	publisher := p.publisherWith(h)
	publisher.meta.Command = "restart"
	result, err := publisher.Restart(context.Background(), snap(t, content))
	if err != nil {
		t.Fatalf("Restart: %v", err)
	}
	return result
}

func reconcileH(t *testing.T, p *pool, h *memHistory) Result {
	t.Helper()
	result, err := p.reconcilerWith(h).Reconcile(context.Background())
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	return result
}

// before 报告 events 里 a 是不是在 b 之前，两个都要有。
func before(t *testing.T, events []string, a, b string) {
	t.Helper()
	index := func(want string) int {
		for i, event := range events {
			if event == want {
				return i
			}
		}
		t.Fatalf("没有 %q：%v", want, events)
		return -1
	}
	if index(a) >= index(b) {
		t.Fatalf("%q 应当在 %q 之前：%v", a, b, events)
	}
}

func count(events []string, prefix string) int {
	n := 0
	for _, event := range events {
		if strings.HasPrefix(event, prefix) {
			n++
		}
	}
	return n
}

// ---- ADR-0013 第 2 条那张表：各种结局记成什么 ----

func TestAPublishedReleaseIsRecordedStagedApplyingObservingActive(t *testing.T) {
	p := newPool(t, "one", twoSnapshots)
	h := newHistory(p)
	result := publishH(t, p, h, "two")

	if result.Outcome != OutcomeActive || !result.Replaced || result.Release != 1 || len(result.Warnings) != 0 {
		t.Fatalf("%+v", result)
	}
	if got := h.summary(1); got != "STAGED APPLYING(replace-file) OBSERVING ACTIVE" {
		t.Fatalf("历史里是 %s", got)
	}
	release := h.releases[0]
	if release.Snapshot != snap(t, "two").ID() || release.Previous != snap(t, "one").ID() || release.Expected != "digest-two" ||
		release.Command != "publish" || release.By != initiated || release.Note != "because" || release.RolledBackTo != 0 {
		t.Fatalf("%+v", release)
	}
	if !release.Replaced() || release.Restarted() || release.Facts().Digest != "digest-two" || release.Facts().Version != version {
		t.Fatalf("%+v", release.Facts())
	}
	// 一份快照和上一份的全文都存下了。
	if _, ok := h.snapshots[snap(t, "two").ID()]; !ok || len(h.snapshots) != 2 {
		t.Fatalf("存下的快照 %d 份", len(h.snapshots))
	}
	// 先写后做：每一步之前先有它的那一行。
	before(t, p.events, "history STAGED", "history APPLYING replace-file")
	before(t, p.events, "history APPLYING replace-file", "confirm one") // 接手：记下原来放着的那一份
	before(t, p.events, "history APPLYING replace-file", "put two")
	before(t, p.events, "put two", "history OBSERVING")
	before(t, p.events, "history OBSERVING", "confirm two")
	before(t, p.events, "confirm two", "history ACTIVE")
}

func TestARestartedReleaseHasTwoApplyingSteps(t *testing.T) {
	p := newPool(t, "one", restartSnapshots)
	h := newHistory(p)
	result := restartH(t, p, h, "two deadline=46")

	if result.Outcome != OutcomeActive || !result.Replaced || !result.Restarted || result.Release != 1 {
		t.Fatalf("%+v", result)
	}
	if got := h.summary(1); got != "STAGED APPLYING(replace-file) APPLYING(restart-gateway) OBSERVING ACTIVE" {
		t.Fatalf("历史里是 %s", got)
	}
	if release := h.releases[0]; !release.Replaced() || !release.Restarted() || !reflect.DeepEqual(release.Facts().Restart, []string{setting}) {
		t.Fatalf("%+v", release)
	}
	before(t, p.events, "history APPLYING replace-file", "put two deadline=46")
	before(t, p.events, "put two deadline=46", "history APPLYING restart-gateway")
	before(t, p.events, "history APPLYING restart-gateway", "restart")
	before(t, p.events, "restart", "history OBSERVING")
	before(t, p.events, "history OBSERVING", "history ACTIVE")
}

func TestARestartWithoutReplacingTheFileHasOnlyTheRestartStep(t *testing.T) {
	// 文件已经是这一份，网关也在跑它，只差启动设置：没有换文件这一步。
	p := newPool(t, "one", restartSnapshots)
	file := snap(t, "one deadline=46")
	p.file = &file
	h := newHistory(p)
	result := restartH(t, p, h, "one deadline=46")

	if result.Outcome != OutcomeActive || result.Replaced || !result.Restarted || len(p.puts) != 0 {
		t.Fatalf("%+v，写了 %v", result, p.puts)
	}
	if got := h.summary(1); got != "STAGED APPLYING(restart-gateway) OBSERVING ACTIVE" {
		t.Fatalf("历史里是 %s", got)
	}
	before(t, p.events, "history APPLYING restart-gateway", "restart")
}

func TestPublishingWhatIsAlreadyInPlaceIsRecordedStagedActiveWithoutReplacing(t *testing.T) {
	for name, p := range map[string]*pool{
		"记录里没有它":  newPool(t, "one", twoSnapshots),
		"记录里已经是它": newPool(t, "one", twoSnapshots).confirmed("one"),
	} {
		h := newHistory(p)
		result := publishH(t, p, h, "one")
		if result.Outcome != OutcomeActive || result.Replaced || len(p.puts) != 0 || result.Release != 1 {
			t.Fatalf("%s：%+v", name, result)
		}
		if got := h.summary(1); got != "STAGED ACTIVE" || h.releases[0].Replaced() {
			t.Fatalf("%s：历史里是 %s", name, got)
		}
		before(t, p.events, "history STAGED", "history ACTIVE")
		if name == "记录里没有它" {
			before(t, p.events, "history STAGED", "confirm one") // 池的记录也是动手，也先写历史
		}
	}
}

func TestCompletingWhatAnEarlierPublicationLeftIsRecordedStagedObservingActive(t *testing.T) {
	p := newPool(t, "two", offRecordSnapshots).confirmed("one")
	h := newHistory(p)
	result := publishH(t, p, h, "two")

	if result.Outcome != OutcomeActive || result.Replaced || len(p.puts) != 0 || result.Release != 1 {
		t.Fatalf("%+v", result)
	}
	if got := h.summary(1); got != "STAGED OBSERVING ACTIVE" || h.releases[0].Replaced() {
		t.Fatalf("历史里是 %s", got)
	}
}

func TestACompletionThePoolDoesNotReportIsFailedAndSaysItWasNotTouched(t *testing.T) {
	p := newPool(t, "two", offRecordSnapshots).confirmed("one")
	p.running = loaded("digest-one") // 网关一直没有去加载它
	h := newHistory(p)
	result := publishH(t, p, h, "two")

	if result.Outcome != OutcomePoolNotReady || result.Replaced {
		t.Fatalf("%+v", result)
	}
	if got := h.summary(1); got != "STAGED OBSERVING FAILED" || h.releases[0].Replaced() || h.releases[0].State() != domain.StateFailed {
		t.Fatalf("历史里是 %s", got)
	}
	if reason := h.releases[0].Reason(); !strings.Contains(reason, "does not report it running") {
		t.Fatalf("原因 %q", reason)
	}
}

func TestARestoredPublicationIsFailedWithTheGatewaysReason(t *testing.T) {
	p := newPool(t, "one", twoSnapshots)
	p.onlyOffline["two"] = true
	h := newHistory(p)
	result := publishH(t, p, h, "two")

	if result.Outcome != OutcomeRestored || result.Release != 1 {
		t.Fatalf("%+v", result)
	}
	if got := h.summary(1); got != "STAGED APPLYING(replace-file) OBSERVING FAILED" {
		t.Fatalf("历史里是 %s", got)
	}
	if reason := h.releases[0].Reason(); !strings.Contains(reason, "cannot load two") {
		t.Fatalf("原因 %q", reason)
	}
	if !h.releases[0].Replaced() || !h.releases[0].Settled() {
		t.Fatalf("%+v", h.releases[0])
	}
}

func TestAnUnknownPublicationIsUnknownAndStaysOpen(t *testing.T) {
	p := newPool(t, "one", twoSnapshots)
	p.onlyOffline["two"] = true
	p.failPut[2] = errors.New("read-only file system") // 放回去也放不回
	h := newHistory(p)
	result := publishH(t, p, h, "two")

	if result.Outcome != OutcomeUnknown || result.Release != 1 {
		t.Fatalf("%+v", result)
	}
	if got := h.summary(1); got != "STAGED APPLYING(replace-file) OBSERVING UNKNOWN" || h.releases[0].Settled() {
		t.Fatalf("历史里是 %s（UNKNOWN 不是结局，它在等对账）", got)
	}
}

func TestWhatIsRefusedBeforeTheHandsGoOnTheWorkIsNotRecorded(t *testing.T) {
	cases := map[string]func(t *testing.T) (*pool, string, bool){
		"REFUSED：加载不了": func(t *testing.T) (*pool, string, bool) { return newPool(t, "one", twoSnapshots), "broken", false },
		"REFUSED：带环境变量": func(t *testing.T) (*pool, string, bool) {
			return newPool(t, "one", twoSnapshots), "name: $SESSION_KEY", false
		},
		"RESTART_REQUIRED": func(t *testing.T) (*pool, string, bool) {
			return newPool(t, "one", map[string]string{"one": "digest-one", "one deadline=46": "digest-one"}), "one deadline=46", false
		},
		"POOL_NOT_READY：对不上记录": func(t *testing.T) (*pool, string, bool) {
			return newPool(t, "two", offRecordSnapshots).confirmed("one"), "three", false
		},
		"POOL_NOT_READY：网关加载失败": func(t *testing.T) (*pool, string, bool) {
			p := newPool(t, "one", twoSnapshots)
			p.running.Synchronized, p.running.LastError = false, "earlier failure"
			return p, "two", false
		},
	}
	for name, build := range cases {
		p, content, _ := build(t)
		h := newHistory(p)
		result := publishH(t, p, h, content)
		if result.Outcome == OutcomeActive || result.Release != 0 || h.writes != 0 || len(h.releases) != 0 || len(p.puts) != 0 {
			t.Errorf("%s：%+v，历史写了 %d 次", name, result, h.writes)
		}
	}
	// restart 也一样。
	p := newPool(t, "one", restartSnapshots)
	h := newHistory(p)
	if result := restartH(t, p, h, "two"); result.Outcome != OutcomeRefused || h.writes != 0 {
		t.Fatalf("%+v", result)
	}
}

func TestReconcileAndPlaceNeverStartAReleaseOfTheirOwn(t *testing.T) {
	p := newPool(t, "two", threeSnapshots).confirmed("one")
	h := newHistory(p)
	if result := reconcileH(t, p, h); result.Outcome != OutcomeRestored {
		t.Fatalf("%+v", result)
	}
	if len(h.releases) != 0 || h.writes != 0 {
		t.Fatalf("对账开了新的一条：%d 条，写了 %d 次", len(h.releases), h.writes)
	}
}

// ---- 先写后做：写到第 N 步就失败 ----

func TestPublishFailsStepByStepWhenTheHistoryCannotBeWritten(t *testing.T) {
	// 第 1 次写是 STAGED，第 2 次是 APPLYING：写不进去，这一步不做，池什么都没有被动。
	for n, want := range map[int]string{1: "", 2: "STAGED"} {
		p := newPool(t, "one", twoSnapshots)
		h := newHistory(p)
		h.failFrom = n
		_, err := p.publisherWith(h).Publish(context.Background(), snap(t, "two"))
		if err == nil || !strings.Contains(err.Error(), "history") || !strings.Contains(err.Error(), "nothing") && n == 1 {
			t.Fatalf("第 %d 步：得到 %v", n, err)
		}
		if len(p.puts) != 0 || len(p.confirms) != 0 || string(p.file.Content()) != "one" || p.record != nil || p.restarts != 0 {
			t.Fatalf("第 %d 步：池被碰过：写了 %v，记了 %v", n, p.puts, p.confirms)
		}
		got := ""
		if len(h.releases) > 0 {
			got = h.summary(1)
		}
		if got != want {
			t.Fatalf("第 %d 步：历史停在 %q", n, got)
		}
		if p.held {
			t.Fatal("没有放开池")
		}
	}
}

func TestTheObservingLineNeverStopsAPublication(t *testing.T) {
	// 只有 OBSERVING（第 3 次写）写不进去：发布照常成功，历史里有 STAGED、APPLYING 和 ACTIVE；不收回快照。
	p := newPool(t, "one", twoSnapshots)
	h := newHistory(p)
	h.failOnly[3] = true
	result := publishH(t, p, h, "two")
	if result.Outcome != OutcomeActive || !reflect.DeepEqual(p.puts, []string{"two"}) || p.recorded() != "two" || string(p.file.Content()) != "two" {
		t.Fatalf("%+v，写了 %v", result, p.puts)
	}
	if got := h.summary(1); got != "STAGED APPLYING(replace-file) ACTIVE" {
		t.Fatalf("历史里是 %s", got)
	}
	if len(result.Warnings) != 1 || !strings.Contains(result.Warnings[0], "OBSERVING") {
		t.Fatalf("警告 %v", result.Warnings)
	}

	// OBSERVING 之后一直写不进去：发布成功，只是收尾也写不进去，是 ACTIVE_NOT_RECORDED；历史停在 APPLYING。
	p = newPool(t, "one", twoSnapshots)
	h = newHistory(p)
	h.failFrom = 3
	result = publishH(t, p, h, "two")
	if result.Outcome != OutcomeActiveNotRecorded || p.recorded() != "two" || len(p.puts) != 1 || h.summary(1) != "STAGED APPLYING(replace-file)" {
		t.Fatalf("%+v，写了 %v，历史 %s", result, p.puts, h.summary(1))
	}
}

func TestAnActiveLineThatCannotBeWrittenIsActiveNotRecorded(t *testing.T) {
	p := newPool(t, "one", twoSnapshots)
	h := newHistory(p)
	h.failOnly[4] = true
	result := publishH(t, p, h, "two")

	if result.Outcome != OutcomeActiveNotRecorded || result.Release != 1 || !result.Replaced {
		t.Fatalf("%+v", result)
	}
	// 池确实是 ACTIVE：文件、记录、网关都是 two。
	if p.recorded() != "two" || string(p.file.Content()) != "two" || result.Observed.Digest != "digest-two" {
		t.Fatalf("池：记录 %q，文件 %s", p.recorded(), p.file.Content())
	}
	if got := h.summary(1); got != "STAGED APPLYING(replace-file) OBSERVING" {
		t.Fatalf("历史停在 %s", got)
	}
	for _, want := range []string{"already runs snapshot " + snap(t, "two").ShortID(), "release 1 stops at OBSERVING", "again is safe", "no space left on device"} {
		if !strings.Contains(result.Reason, want) {
			t.Errorf("说明里没有 %q：%s", want, result.Reason)
		}
	}
}

func TestRestartFailsStepByStepWhenTheHistoryCannotBeWritten(t *testing.T) {
	// 第 1 次写 STAGED，第 2 次写换文件的 APPLYING：写不进去，什么都没动。
	for _, n := range []int{1, 2} {
		p := newPool(t, "one", restartSnapshots)
		h := newHistory(p)
		h.failFrom = n
		if _, err := p.publisherWith(h).Restart(context.Background(), snap(t, "two deadline=46")); err == nil {
			t.Fatalf("第 %d 步：没有报错", n)
		}
		if len(p.puts) != 0 || len(p.confirms) != 0 || p.restarts != 0 || string(p.file.Content()) != "one" {
			t.Fatalf("第 %d 步：池被碰过：%v", n, p.events)
		}
	}

	// 第 3 次写是"重启网关"的 APPLYING：它写不进去就不重启；文件已经换上去了，把上一份放回去。
	p := newPool(t, "one", restartSnapshots)
	h := newHistory(p)
	h.failOnly[3] = true
	result := restartH(t, p, h, "two deadline=46")
	if result.Outcome != OutcomeRestored || result.Restarted || p.restarts != 0 || !strings.Contains(result.Reason, "history") {
		t.Fatalf("%+v", result)
	}
	if !reflect.DeepEqual(p.puts, []string{"two deadline=46", "one"}) || string(p.file.Content()) != "one" || p.recorded() != "one" {
		t.Fatalf("写了 %v，目录里是 %s，记录 %q", p.puts, p.file.Content(), p.recorded())
	}
	if got := h.summary(1); got != "STAGED APPLYING(replace-file) FAILED" {
		t.Fatalf("历史里是 %s", got)
	}

	// 放回去也放不回：UNKNOWN，原因里有历史写不进去。
	p = newPool(t, "one", restartSnapshots)
	p.failPut[2] = errors.New("read-only file system")
	h = newHistory(p)
	h.failOnly[3] = true
	result = restartH(t, p, h, "two deadline=46")
	if result.Outcome != OutcomeUnknown || p.restarts != 0 || !strings.Contains(result.Reason, "history") {
		t.Fatalf("%+v", result)
	}

	// 目录里已经是这一份，没有换文件这一步：重启网关就是第一步（第 2 次写）。写不进去，什么都没动。
	p = newPool(t, "one", restartSnapshots)
	file := snap(t, "one deadline=46")
	p.file = &file
	h = newHistory(p)
	h.failFrom = 2
	if _, err := p.publisherWith(h).Restart(context.Background(), file); err == nil || p.restarts != 0 || len(p.confirms) != 0 {
		t.Fatalf("得到 %v，重启 %d 次", err, p.restarts)
	}
}

func TestRestartObservingAndActiveLines(t *testing.T) {
	// OBSERVING（第 4 次写）写不进去：重启照做，发布成功。
	p := newPool(t, "one", restartSnapshots)
	h := newHistory(p)
	h.failOnly[4] = true
	result := restartH(t, p, h, "two deadline=46")
	if result.Outcome != OutcomeActive || p.restarts != 1 || h.summary(1) != "STAGED APPLYING(replace-file) APPLYING(restart-gateway) ACTIVE" {
		t.Fatalf("%+v，历史 %s", result, h.summary(1))
	}
	// 收尾（第 5 次写）写不进去：ACTIVE_NOT_RECORDED，提示里说再跑 restart 没有用。
	p = newPool(t, "one", restartSnapshots)
	h = newHistory(p)
	h.failOnly[5] = true
	result = restartH(t, p, h, "two deadline=46")
	if result.Outcome != OutcomeActiveNotRecorded || p.recorded() != "two deadline=46" || !strings.Contains(result.Reason, "would not complete it") {
		t.Fatalf("%+v", result)
	}
}

func TestAnOutcomeThatCannotBeWrittenKeepsItsOwnExitStatus(t *testing.T) {
	// RESTORED、UNKNOWN 本来就是非零：结局不变，警告里说一句。
	p := newPool(t, "one", twoSnapshots)
	p.onlyOffline["two"] = true
	h := newHistory(p)
	h.failFrom = 4 // 最后的 FAILED 写不进去
	result := publishH(t, p, h, "two")
	if result.Outcome != OutcomeRestored || len(result.Warnings) != 1 || !strings.Contains(result.Warnings[0], "RESTORED") || h.summary(1) != "STAGED APPLYING(replace-file) OBSERVING" {
		t.Fatalf("%+v，历史 %s", result, h.summary(1))
	}
}

// ---- 补结局 ----

func TestReconcileGivesTheNewestOpenReleaseItsOutcomeFromThePoolsRecord(t *testing.T) {
	// 记录确认的正是它的快照，确认的时刻在它开始之后：ACTIVE。
	for _, stuck := range [][]domain.ReleaseState{
		{domain.StateStaged},
		{domain.StateStaged, domain.StateApplying},
		{domain.StateStaged, domain.StateApplying, domain.StateObserving},
		{domain.StateStaged, domain.StateApplying, domain.StateObserving, domain.StateUnknown},
	} {
		p := newPool(t, "two", twoSnapshots).confirmed("two")
		h := newHistory(p)
		h.seed(t, "two", stuck...)
		p.record.At = p.now.Add(time.Minute)
		result := reconcileH(t, p, h)
		if result.Outcome != OutcomeInSync || !reflect.DeepEqual(result.Settled, []uint64{1}) || len(result.Warnings) != 0 {
			t.Fatalf("%v：%+v", stuck, result)
		}
		release := h.releases[0]
		last := release.Steps[len(release.Steps)-1]
		if release.State() != domain.StateActive || last.Name != domain.StepReconcile || last.Facts == nil || last.Facts.Digest != "digest-two" {
			t.Fatalf("%v：补上的是 %+v", stuck, last)
		}
	}
}

func TestReconcileThatPutAnotherSnapshotBackMakesTheOpenReleaseFailed(t *testing.T) {
	// 放在那里的是 two，记录说确认的是 one：对账把 one 放回去（RESTORED）。停在半路的 two 没有生效。
	p := newPool(t, "two", twoSnapshots).confirmed("one")
	h := newHistory(p)
	h.seed(t, "two", domain.StateStaged, domain.StateApplying)
	result := reconcileH(t, p, h)
	if result.Outcome != OutcomeRestored || !reflect.DeepEqual(result.Settled, []uint64{1}) {
		t.Fatalf("%+v", result)
	}
	if h.releases[0].State() != domain.StateFailed || !strings.Contains(h.releases[0].Reason(), "did not take effect") {
		t.Fatalf("%+v", h.releases[0].Steps)
	}

	// 池本来就是记录的样子（IN_SYNC），这一条的快照没有放上去过：一样。
	p = newPool(t, "one", twoSnapshots).confirmed("one")
	h = newHistory(p)
	h.seed(t, "two", domain.StateStaged)
	if result := reconcileH(t, p, h); result.Outcome != OutcomeInSync || h.releases[0].State() != domain.StateFailed {
		t.Fatalf("%+v，历史 %s", result, h.summary(1))
	}
}

func TestReconcileThatCannotSayWhatTheGatewayRunsDoesNotSettleAnything(t *testing.T) {
	// 读不到网关：UNKNOWN。记录确认的就是它的快照也不补：没有读到网关，说不出它在不在生效。
	p := newPool(t, "two", twoSnapshots).confirmed("two")
	h := newHistory(p)
	h.seed(t, "two", domain.StateStaged, domain.StateApplying)
	p.record.At = p.now.Add(time.Minute)
	p.unreadable = func(time.Time) bool { return true }
	result := reconcileH(t, p, h)
	if result.Outcome != OutcomeUnknown || len(result.Settled) != 0 || h.writes != 0 || h.releases[0].Settled() {
		t.Fatalf("%+v，历史 %s", result, h.summary(1))
	}

	// 没有可以拿来对的记录，或者记录是在另一个构建上做的：UNCONFIRMED，不补。
	p = newPool(t, "two", twoSnapshots)
	h = newHistory(p)
	h.seed(t, "two", domain.StateStaged)
	if result := reconcileH(t, p, h); result.Outcome != OutcomeUnconfirmed || h.writes != 0 {
		t.Fatalf("%+v", result)
	}
	p = newPool(t, "two", twoSnapshots).confirmed("two")
	p.record.Revision = "0000000"
	p.record.At = p.now.Add(time.Minute)
	h = newHistory(p)
	h.seed(t, "two", domain.StateStaged)
	if result := reconcileH(t, p, h); result.Outcome != OutcomeUnconfirmed || h.writes != 0 {
		t.Fatalf("%+v", result)
	}
}

func TestReconcileRestartPendingStillSettlesTheRelease(t *testing.T) {
	// 带重启的发布做到一半：文件和运行配置都是它的，启动设置要重启才到位。记录确认的是它：ACTIVE。
	p := newPool(t, "one", threeSnapshots).confirmed("one")
	p.running.Settings["terminationMaxDeadline"] = `"46s"`
	h := newHistory(p)
	h.seed(t, "one", domain.StateStaged, domain.StateApplying)
	p.record.At = p.now.Add(time.Minute)
	result := reconcileH(t, p, h)
	if result.Outcome != OutcomeRestartPending || h.releases[0].State() != domain.StateActive ||
		!reflect.DeepEqual(h.releases[0].Facts().Restart, []string{setting}) {
		t.Fatalf("%+v，历史 %s", result, h.summary(1))
	}
}

func TestOnlyTheNewestReleaseIsSettledByTheRecordTheOlderOnesAreOvertaken(t *testing.T) {
	// 两条都没有结局：最新的那条按记录补；更早的那条被后来的发布越过，结局不明，不是 FAILED。
	p := newPool(t, "two", twoSnapshots).confirmed("two")
	h := newHistory(p)
	h.seed(t, "one", domain.StateStaged, domain.StateApplying)
	h.seed(t, "two", domain.StateStaged, domain.StateApplying, domain.StateObserving)
	p.record.At = p.now.Add(time.Minute)
	result := reconcileH(t, p, h)
	if !reflect.DeepEqual(result.Settled, []uint64{1, 2}) {
		t.Fatalf("%+v", result)
	}
	if h.releases[1].State() != domain.StateActive {
		t.Fatalf("最新的一条：%s", h.summary(2))
	}
	first := h.releases[0]
	if first.State() != domain.StateOvertaken || first.State() == domain.StateFailed || !first.Settled() ||
		!strings.Contains(first.Reason(), "later release (2)") || !strings.Contains(first.Reason(), "not known") {
		t.Fatalf("更早的一条：%s %q", h.summary(1), first.Reason())
	}

	// 最新的一条已经有结局：更早的没有结局的照样被越过，最新的不动。
	p = newPool(t, "two", twoSnapshots).confirmed("two")
	h = newHistory(p)
	h.seed(t, "one", domain.StateStaged)
	h.seed(t, "two", domain.StateStaged, domain.StateActive)
	result = reconcileH(t, p, h)
	if !reflect.DeepEqual(result.Settled, []uint64{1}) || h.releases[0].State() != domain.StateOvertaken || h.summary(2) != "STAGED ACTIVE" {
		t.Fatalf("%+v，历史 %s | %s", result, h.summary(1), h.summary(2))
	}

	// 都有结局：什么都不写。再对一次也不写（补过的不重复补）。
	if again := reconcileH(t, p, h); len(again.Settled) != 0 {
		t.Fatalf("%+v", again)
	}
}

func TestAConfirmationOlderThanTheReleaseDoesNotSettleItAsActive(t *testing.T) {
	// 同一份快照先后发布了两次，第二次中途被杀：记录里是第一次的确认，早于第二条开始。不补成 ACTIVE，也不补别的。
	p := newPool(t, "two", twoSnapshots).confirmed("two")
	p.record.At = p.now.Add(-time.Hour)
	h := newHistory(p)
	h.seed(t, "two", domain.StateStaged, domain.StateApplying)
	result := reconcileH(t, p, h)
	if result.Outcome != OutcomeInSync || len(result.Settled) != 0 || h.writes != 0 || h.releases[0].Settled() {
		t.Fatalf("%+v，历史 %s", result, h.summary(1))
	}
	if len(result.Warnings) != 1 || !strings.Contains(result.Warnings[0], "not after the release started") {
		t.Fatalf("警告 %v", result.Warnings)
	}
	// 没有确认的时刻（记录读不出时刻）：同样保守。
	p.record.At = time.Time{}
	if result := reconcileH(t, p, h); len(result.Settled) != 0 || h.writes != 0 {
		t.Fatalf("%+v", result)
	}
}

func TestAHistoryThatCannotBeUpdatedNeverChangesTheReconcileOutcome(t *testing.T) {
	build := func() (*pool, *memHistory) {
		p := newPool(t, "two", twoSnapshots).confirmed("one")
		h := newHistory(p)
		h.seed(t, "two", domain.StateStaged, domain.StateApplying)
		return p, h
	}
	p, h := build()
	h.listErr = errors.New("the release history is damaged")
	result := reconcileH(t, p, h)
	if result.Outcome != OutcomeRestored || len(result.Warnings) != 1 || !strings.Contains(result.Warnings[0], "damaged") || string(p.file.Content()) != "one" {
		t.Fatalf("%+v", result)
	}
	p, h = build()
	h.failFrom = 1
	result = reconcileH(t, p, h)
	if result.Outcome != OutcomeRestored || len(result.Warnings) != 1 || !strings.Contains(result.Warnings[0], "could not be brought up to date") || h.releases[0].Settled() {
		t.Fatalf("%+v", result)
	}
}

func TestReconcileWithoutAHistoryDoesNotTouchOne(t *testing.T) {
	p := newPool(t, "two", twoSnapshots).confirmed("one")
	result := reconcile(t, p)
	if result.Outcome != OutcomeRestored || result.Release != 0 || result.Settled != nil || result.Warnings != nil {
		t.Fatalf("%+v", result)
	}
}

// ---- ACTIVE_NOT_RECORDED 之后再跑一次 ----

func TestPublishingAgainAfterActiveNotRecordedCompletesTheStuckReleaseInsteadOfOpeningANewOne(t *testing.T) {
	p := newPool(t, "one", twoSnapshots)
	h := newHistory(p)
	h.failOnly[4] = true
	first := publishH(t, p, h, "two")
	if first.Outcome != OutcomeActiveNotRecorded {
		t.Fatalf("%+v", first)
	}
	p.puts, p.events = nil, nil
	confirmed := len(p.confirms)

	// 再跑一次同样的命令：目录里已经是这一份，池的记录也是：补全历史，不动池。
	again := publishH(t, p, h, "two")
	if again.Outcome != OutcomeActive || again.Replaced || again.Release != 1 || !reflect.DeepEqual(again.Settled, []uint64{1}) || len(p.puts) != 0 || len(p.confirms) != confirmed {
		t.Fatalf("%+v，写了 %v", again, p.puts)
	}
	if len(h.releases) != 1 || h.summary(1) != "STAGED APPLYING(replace-file) OBSERVING ACTIVE(publish-again)" {
		t.Fatalf("历史 %d 条：%s", len(h.releases), h.summary(1))
	}
	if last := h.releases[0].Steps[3]; last.Name != domain.StepRerun {
		t.Fatalf("补上的那一行：%+v", last)
	}

	// 已经补全了，再跑一次：这时才是新的一条（STAGED 到 ACTIVE，没有换文件）。
	third := publishH(t, p, h, "two")
	if third.Outcome != OutcomeActive || third.Release != 2 || h.summary(2) != "STAGED ACTIVE" {
		t.Fatalf("%+v，历史 %s", third, h.summary(2))
	}
}

func TestPublishingAgainOpensANewReleaseWhenTheStuckOneCannotBeTold(t *testing.T) {
	// 停着的那条是另一份快照的：不碰它（留给对账），这一次是新的一条。
	p := newPool(t, "one", twoSnapshots).confirmed("one")
	h := newHistory(p)
	h.seed(t, "two", domain.StateStaged, domain.StateApplying)
	result := publishH(t, p, h, "one")
	if result.Outcome != OutcomeActive || result.Release != 2 || len(result.Settled) != 0 || h.summary(1) != "STAGED APPLYING" || h.summary(2) != "STAGED ACTIVE" {
		t.Fatalf("%+v，历史 %s | %s", result, h.summary(1), h.summary(2))
	}

	// 记录确认的时刻早于停着的那条开始：同样不认。
	p = newPool(t, "one", twoSnapshots).confirmed("one")
	p.record.At = p.now.Add(-time.Hour)
	h = newHistory(p)
	h.seed(t, "one", domain.StateStaged, domain.StateObserving)
	result = publishH(t, p, h, "one")
	if result.Release != 2 || h.summary(1) != "STAGED OBSERVING" {
		t.Fatalf("%+v，历史 %s", result, h.summary(1))
	}
}

// ---- 回滚 ----

// rollbackFixture 是一个池和它的历史：1 是 one（ACTIVE，被取代了），2 是 two（FAILED），3 是 three（ACTIVE，现在放着的）。
func rollbackFixture(t *testing.T, snapshots map[string]string) (*pool, *memHistory) {
	t.Helper()
	p := newPool(t, "three", snapshots).confirmed("three")
	h := newHistory(p)
	h.seed(t, "one", domain.StateStaged, domain.StateApplying, domain.StateObserving, domain.StateActive)
	h.seed(t, "two", domain.StateStaged, domain.StateApplying, domain.StateObserving, domain.StateFailed)
	h.seed(t, "three", domain.StateStaged, domain.StateApplying, domain.StateObserving, domain.StateActive)
	return p, h
}

func (p *pool) rollbackPublisher(h ports.History) *Publisher {
	publisher := p.publisherWith(h)
	publisher.meta.Command = "rollback"
	return publisher
}

func TestRollbackIsANewPublicationOfAnEarlierSnapshotAndEditsNothingBefore(t *testing.T) {
	p, h := rollbackFixture(t, offRecordSnapshots)
	before := append([]domain.Release(nil), h.releases...)
	result, err := p.rollbackPublisher(h).Rollback(context.Background(), 1, false)
	if err != nil {
		t.Fatal(err)
	}
	if result.Outcome != OutcomeActive || !result.Replaced || result.Release != 4 || result.Snapshot != snap(t, "one").ID() {
		t.Fatalf("%+v", result)
	}
	if string(p.file.Content()) != "one" || p.recorded() != "one" || !reflect.DeepEqual(p.puts, []string{"one"}) {
		t.Fatalf("池：文件 %s，记录 %q，写了 %v", p.file.Content(), p.recorded(), p.puts)
	}
	// 新的一条，指向被取出的编号；之前的三条一个字都没有变。
	if got := h.summary(4); got != "STAGED APPLYING(replace-file) OBSERVING ACTIVE" || h.releases[3].RolledBackTo != 1 || h.releases[3].Command != "rollback" {
		t.Fatalf("新的一条：%s %+v", got, h.releases[3])
	}
	if !reflect.DeepEqual(h.releases[:3], before) {
		t.Fatal("回滚改了历史里已有的行")
	}
	// 走的是 publish 的全套检查：离线加载，池读了回读。
	if p.staged != 1 {
		t.Fatalf("离线加载 %d 次", p.staged)
	}
}

func TestRollbackOnlyGoesBackToAReleaseThatWasActive(t *testing.T) {
	p, h := rollbackFixture(t, offRecordSnapshots)
	for number, want := range map[uint64]string{2: "never reached ACTIVE", 99: "no release 99"} {
		result, err := p.rollbackPublisher(h).Rollback(context.Background(), number, false)
		if err != nil || result.Outcome != OutcomeRefused || !strings.Contains(result.Reason, want) || len(p.events) != 0 || h.writes != 0 || len(h.releases) != 3 {
			t.Fatalf("%d：%+v（%v），做过的事 %v", number, result, err, p.events)
		}
	}
	// UNKNOWN 的也不行。
	h.seed(t, "two", domain.StateStaged, domain.StateApplying, domain.StateUnknown)
	if result, _ := p.rollbackPublisher(h).Rollback(context.Background(), 4, false); result.Outcome != OutcomeRefused || len(p.events) != 0 {
		t.Fatalf("%+v", result)
	}
	// 到过 ACTIVE、后来被越过的可以（回滚的第一个测试已经做了）；到过 ACTIVE 的 SUPERSEDED 同理。
}

func TestRollbackToWhatIsInPlaceNowIsRefusedWithoutLoadingAnything(t *testing.T) {
	p, h := rollbackFixture(t, offRecordSnapshots)
	result, err := p.rollbackPublisher(h).Rollback(context.Background(), 3, false)
	if err != nil || result.Outcome != OutcomeRefused || !strings.Contains(result.Reason, "nothing to roll back") || result.Replaced {
		t.Fatalf("%+v（%v）", result, err)
	}
	if p.staged != 0 || len(p.events) != 0 || h.writes != 0 || len(h.releases) != 3 {
		t.Fatalf("离线加载 %d 次，做过的事 %v，历史写了 %d 次", p.staged, p.events, h.writes)
	}
}

func TestRollbackToASnapshotThatNeedsARestartIsRestartRequiredUnlessAskedToRestart(t *testing.T) {
	snapshots := map[string]string{"one": "digest-one", "two": "digest-two", "three": "digest-three", "one deadline=46": "digest-one"}
	build := func() (*pool, *memHistory) {
		p := newPool(t, "three", snapshots).confirmed("three")
		h := newHistory(p)
		h.seed(t, "one deadline=46", domain.StateStaged, domain.StateApplying, domain.StateObserving, domain.StateActive)
		h.seed(t, "three", domain.StateStaged, domain.StateApplying, domain.StateObserving, domain.StateActive)
		return p, h
	}
	p, h := build()
	result, err := p.rollbackPublisher(h).Rollback(context.Background(), 1, false)
	if err != nil || result.Outcome != OutcomeRestartRequired || !reflect.DeepEqual(result.Restart, []string{setting}) || len(p.puts) != 0 || h.writes != 0 || len(h.releases) != 2 {
		t.Fatalf("%+v（%v）", result, err)
	}

	p, h = build()
	result, err = p.rollbackPublisher(h).Rollback(context.Background(), 1, true)
	if err != nil || result.Outcome != OutcomeActive || !result.Restarted || p.restarts != 1 || result.Release != 3 {
		t.Fatalf("%+v（%v）", result, err)
	}
	if got := h.summary(3); got != "STAGED APPLYING(replace-file) APPLYING(restart-gateway) OBSERVING ACTIVE" || h.releases[2].RolledBackTo != 1 || h.releases[2].Command != "rollback" {
		t.Fatalf("%s %+v", got, h.releases[2])
	}

	// --with-restart 而用不着重启：restart 的结局，REFUSED。
	p, h = rollbackFixture(t, offRecordSnapshots)
	if result, _ := p.rollbackPublisher(h).Rollback(context.Background(), 1, true); result.Outcome != OutcomeRefused || p.restarts != 0 || len(h.releases) != 3 {
		t.Fatalf("%+v", result)
	}
}

func TestRollbackToASnapshotThatIsDamagedOrCannotBeReadTouchesNothing(t *testing.T) {
	for name, spoil := range map[string]func(*memHistory){
		"快照文件被改过": func(h *memHistory) { h.snapErr = ports.ErrSnapshotDamaged },
		"快照文件不见了": func(h *memHistory) { h.snapErr = ports.ErrSnapshotNotFound },
		"历史读不了":   func(h *memHistory) { h.getErr = ports.ErrHistoryDamaged },
	} {
		p, h := rollbackFixture(t, offRecordSnapshots)
		spoil(h)
		result, err := p.rollbackPublisher(h).Rollback(context.Background(), 1, false)
		if err == nil || result.Outcome != "" || len(p.events) != 0 || p.staged != 0 || h.writes != 0 {
			t.Errorf("%s：%+v（%v），做过的事 %v", name, result, err, p.events)
		}
	}
}

func TestRollbackToASnapshotTheCurrentImageCannotLoadIsRefusedNotBypassed(t *testing.T) {
	// 离线加载是现在的镜像做的：一份老快照它不认了，REFUSED，池没有被碰过，历史里没有新的一条。
	p, h := rollbackFixture(t, map[string]string{"three": "digest-three"}) // one 不在表里：加载不了
	result, err := p.rollbackPublisher(h).Rollback(context.Background(), 1, false)
	if err != nil || result.Outcome != OutcomeRefused || len(p.puts) != 0 || h.writes != 0 || len(h.releases) != 3 || p.staged != 1 {
		t.Fatalf("%+v（%v），写了 %v，离线加载 %d 次", result, err, p.puts, p.staged)
	}
}

func TestRollbackNeedsAHistory(t *testing.T) {
	p := newPool(t, "one", twoSnapshots)
	if _, err := p.publisher().Rollback(context.Background(), 1, false); err == nil {
		t.Fatal("没有历史的回滚被接受了")
	}
}

func TestRollbackStillWritesBeforeItActs(t *testing.T) {
	p, h := rollbackFixture(t, offRecordSnapshots)
	h.failFrom = 4 // 第 4 次写（累计）是新的一条的 STAGED
	h.writes = 3
	if _, err := p.rollbackPublisher(h).Rollback(context.Background(), 1, false); err == nil || len(p.puts) != 0 || string(p.file.Content()) != "three" {
		t.Fatalf("得到 %v，写了 %v", err, p.puts)
	}
}

func TestNoteAndInitiatorAreRecordedAsGiven(t *testing.T) {
	p := newPool(t, "one", twoSnapshots)
	h := newHistory(p)
	publishH(t, p, h, "two")
	if h.releases[0].Note != "because" || h.releases[0].By != initiated {
		t.Fatalf("%+v", h.releases[0])
	}
}

func TestStepNamesAndStatesFollowTheDomainVocabulary(t *testing.T) {
	for state, settled := range map[domain.ReleaseState]bool{
		domain.StateStaged: false, domain.StateApplying: false, domain.StateObserving: false, domain.StateUnknown: false,
		domain.StateActive: true, domain.StateFailed: true, domain.StateOvertaken: true,
	} {
		if state.Settled() != settled || !state.Known() {
			t.Errorf("%s", state)
		}
	}
	if domain.StateSuperseded.Known() {
		t.Error("SUPERSEDED 不写进历史")
	}
	if got := fmt.Sprint(domain.StateOvertaken); got == string(domain.StateFailed) {
		t.Error("OVERTAKEN 借用了 FAILED")
	}
}
