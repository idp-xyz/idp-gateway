package application

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"go.idp.xyz/idp-gateway/internal/gatewayconfig/domain"
	"go.idp.xyz/idp-gateway/internal/gatewayconfig/ports"
)

const (
	version  = "1.7.0"
	revision = "26f5aebe"
)

func snap(t *testing.T, content string) domain.Snapshot {
	t.Helper()
	snapshot, err := domain.NewSnapshot([]byte(content))
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}

// loaded 是一个网关加载某份配置之后报告的样子。
func loaded(digest string) domain.Observation {
	return domain.Observation{Digest: digest, Synchronized: true, StorageMode: domain.StorageReadOnly,
		Version: version, Revision: revision, Settings: domain.Settings{"terminationMaxDeadline": `"45s"`, "dns": `"here"`}}
}

// startedWith 是一个网关从某份内容启动之后报告的样子：内容里写着 deadline=46 的，启动设置里那一项是 46 秒。
func startedWith(content, digest string) domain.Observation {
	observation := loaded(digest)
	if strings.Contains(content, "deadline=46") {
		observation.Settings["terminationMaxDeadline"] = `"46s"`
	}
	return observation
}

// pool 模拟一个池：目录里的一个文件，和一个监视它、过一会儿才重载的网关。它同时是离线加载的
// 那个网关。时间是假的，只在发布器等待时往前走。
type pool struct {
	t        *testing.T
	now      time.Time
	reloadIn time.Duration
	// loads：一份内容加载出来的运行配置摘要。不在表里的内容网关加载不了。
	loads map[string]string
	// onlyOffline：离线加载得了、池里的网关却加载不了的内容（池里缺它引用的文件）。
	onlyOffline map[string]bool

	file     *domain.Snapshot
	reloadAt *time.Time
	running  domain.Observation

	held        bool
	puts        []string
	staged      int
	stagingErr  error
	failPut     map[int]error // 第几次 Put（从 1 数）返回什么错误
	unreadable  func(now time.Time) bool
	afterReload func()
	// afterObserve 在每次读到之后调用，参数是从开始到现在过了多久。
	afterObserve func(elapsed time.Duration)
	cancel       context.CancelFunc
	cancelAt     time.Duration
	started      time.Time

	// 记录：这个池上最后一次得到确认的发布。
	record      *domain.Confirmation
	recordErr   error         // 读记录时返回的错误
	confirms    []string      // 记下过的各条（快照的内容）
	failConfirm map[int]error // 第几次 Confirm（从 1 数）返回什么错误

	// 网关进程。
	restarts    int
	failRestart map[int]error   // 第几次 Restart（从 1 数）返回什么错误
	cannotStart map[string]bool // 重载得了、拿它启动却起不来的内容
	verifyErr   error
	down        bool // 网关没有在跑
	// lingering：第几次重启（从 1 数）的命令返回之后，旧的进程还接着答话多久。
	// 重启的命令返回了，不等于答话的已经是新的进程。
	lingering  map[int]time.Duration
	takeoverAt *time.Time // 新的进程到这一刻才开始答话

	// events 按先后记下对池做过的事。
	events []string
}

func newPool(t *testing.T, current string, loads map[string]string) *pool {
	t.Helper()
	start := time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC)
	p := &pool{t: t, now: start, started: start, reloadIn: 300 * time.Millisecond, loads: loads, onlyOffline: map[string]bool{}, failPut: map[int]error{},
		failConfirm: map[int]error{}, failRestart: map[int]error{}, cannotStart: map[string]bool{}, lingering: map[int]time.Duration{}}
	if current != "" {
		snapshot := snap(t, current)
		p.file = &snapshot
		p.running = startedWith(current, loads[current])
	}
	return p
}

// confirmed 让这个池带着一条记录：content 是在这个池上得到确认的，当时网关报告的是它加载出来的样子。
func (p *pool) confirmed(content string) *pool {
	p.t.Helper()
	confirmation, err := domain.ConfirmedBy(snap(p.t, content), startedWith(content, p.loads[content]))
	if err != nil {
		p.t.Fatal(err)
	}
	p.record = &confirmation
	return p
}

// adopted 让这个池带着一条接手来的记录：发布器第一次动它时，放在那里的是 content。
func (p *pool) adopted(content string) *pool {
	p.t.Helper()
	found, err := domain.FoundInPlace(snap(p.t, content), startedWith(content, p.loads[content]))
	if err != nil {
		p.t.Fatal(err)
	}
	p.record = &found
	return p
}

// clock 把假的时间接到等待上。
func (p *pool) clock(w *watch) {
	w.now = func() time.Time { return p.now }
	w.sleep = func(ctx context.Context, d time.Duration) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		p.now = p.now.Add(d)
		if p.cancel != nil && p.now.Sub(p.started) >= p.cancelAt {
			p.cancel()
		}
		return nil
	}
}

func (p *pool) publisher() *Publisher {
	publisher, err := New(p, p, p, Timing{Settle: time.Second, Timeout: 10 * time.Second, Interval: 100 * time.Millisecond})
	if err != nil {
		p.t.Fatal(err)
	}
	p.clock(&publisher.watch)
	return publisher.WithProcess(p)
}

func (p *pool) elapsed() time.Duration { return p.now.Sub(p.started) }

// Staging
func (p *pool) Load(_ context.Context, snapshot domain.Snapshot) (domain.Observation, error) {
	p.staged++
	if !p.held {
		p.t.Error("离线加载时没有占着这个池")
	}
	if p.stagingErr != nil {
		return domain.Observation{}, p.stagingErr
	}
	digest, ok := p.loads[string(snapshot.Content())]
	if !ok {
		return domain.Observation{}, &ports.RejectedError{Reason: "routes[2]: unknown field"}
	}
	observation := startedWith(string(snapshot.Content()), digest)
	observation.Settings["dns"] = `"elsewhere"` // 离线加载在另一个环境里
	if strings.Contains(string(snapshot.Content()), "storage=file") {
		observation.StorageMode = "file"
	}
	return observation, nil
}

// Delivery
func (p *pool) Hold(context.Context) (func(), error) {
	if p.held {
		return nil, ports.ErrBusy
	}
	p.held = true
	return func() { p.held = false }, nil
}

func (p *pool) Current(context.Context) (domain.Snapshot, bool, error) {
	if p.file == nil {
		return domain.Snapshot{}, false, nil
	}
	return *p.file, true, nil
}

func (p *pool) Put(ctx context.Context, snapshot domain.Snapshot) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !p.held {
		p.t.Error("换文件时没有占着这个池")
	}
	p.puts = append(p.puts, string(snapshot.Content()))
	p.events = append(p.events, "put "+string(snapshot.Content()))
	if err := p.failPut[len(p.puts)]; err != nil {
		return err
	}
	p.file = &snapshot
	at := p.now.Add(p.reloadIn)
	p.reloadAt = &at
	return nil
}

func (p *pool) Confirmed(context.Context) (domain.Confirmation, bool, error) {
	if !p.held {
		p.t.Error("读记录时没有占着这个池")
	}
	if p.recordErr != nil {
		return domain.Confirmation{}, false, p.recordErr
	}
	if p.record == nil {
		return domain.Confirmation{}, false, nil
	}
	return *p.record, true, nil
}

func (p *pool) Confirm(ctx context.Context, confirmation domain.Confirmation) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !p.held {
		p.t.Error("记录时没有占着这个池")
	}
	p.confirms = append(p.confirms, string(confirmation.Snapshot.Content()))
	p.events = append(p.events, "confirm "+string(confirmation.Snapshot.Content()))
	if err := p.failConfirm[len(p.confirms)]; err != nil {
		return err
	}
	p.record = &confirmation
	return nil
}

// Process
func (p *pool) Verify(context.Context) error {
	p.events = append(p.events, "verify")
	return p.verifyErr
}

// Restart 让网关从目录里的文件重新启动：启动设置跟着文件走；文件加载不了时它起不来。
func (p *pool) Restart(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	p.restarts++
	p.events = append(p.events, "restart")
	if err := p.failRestart[p.restarts]; err != nil {
		return err
	}
	if linger := p.lingering[p.restarts]; linger > 0 {
		at := p.now.Add(linger)
		p.takeoverAt = &at // 在那之前，旧的进程照常看着文件、照常答话
		return nil
	}
	p.comeUp()
	return nil
}

// comeUp 让一个新的进程从目录里现在的文件起来，接手答话。
func (p *pool) comeUp() {
	p.reloadAt, p.takeoverAt = nil, nil
	content := string(p.file.Content())
	digest, ok := p.loads[content]
	if p.down = !ok || p.onlyOffline[content] || p.cannotStart[content]; !p.down {
		p.running = startedWith(content, digest)
	}
}

// ReadBack
func (p *pool) Observe(ctx context.Context) (domain.Observation, error) {
	if err := ctx.Err(); err != nil {
		return domain.Observation{}, err
	}
	if p.takeoverAt != nil && !p.now.Before(*p.takeoverAt) {
		p.comeUp()
	}
	if p.reloadAt != nil && !p.now.Before(*p.reloadAt) {
		p.reloadAt = nil
		content := string(p.file.Content())
		if digest, ok := p.loads[content]; ok && !p.onlyOffline[content] {
			p.running.Digest, p.running.Synchronized, p.running.LastError = digest, true, ""
		} else {
			p.running.Synchronized, p.running.LastError = false, "cannot load "+content // 在跑的仍是上一份
		}
		if p.afterReload != nil {
			p.afterReload()
		}
	}
	if p.down || (p.unreadable != nil && p.unreadable(p.now)) {
		return domain.Observation{}, errors.New("connection refused")
	}
	if p.afterObserve != nil {
		p.afterObserve(p.elapsed())
	}
	return p.running, nil
}

// recorded 是记录里的那份快照的内容；没有记录时为空。
func (p *pool) recorded() string {
	if p.record == nil {
		return ""
	}
	return string(p.record.Snapshot.Content())
}

func publish(t *testing.T, p *pool, content string) Result {
	t.Helper()
	result, err := p.publisher().Publish(context.Background(), snap(t, content))
	if err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if p.held {
		t.Error("发布返回之后还占着这个池")
	}
	return result
}

var twoSnapshots = map[string]string{"one": "digest-one", "two": "digest-two"}

func TestPublishReplacesTheFileAndWaitsForTheGatewayToReportIt(t *testing.T) {
	p := newPool(t, "one", twoSnapshots)
	result := publish(t, p, "two")

	if result.Outcome != OutcomeActive || !result.Replaced || result.Reason != "" {
		t.Fatalf("%+v", result)
	}
	if result.Snapshot != snap(t, "two").ID() || result.Previous != snap(t, "one").ID() || result.Expected != "digest-two" || result.Observed.Digest != "digest-two" {
		t.Fatalf("%+v", result)
	}
	if !reflect.DeepEqual(p.puts, []string{"two"}) || string(p.file.Content()) != "two" {
		t.Fatalf("写了 %v，目录里是 %s", p.puts, p.file.Content())
	}
	// 网关 0.3 秒就换好了，但 1 秒之前读到的不算数。
	if p.elapsed() != time.Second {
		t.Fatalf("等了 %s", p.elapsed())
	}
}

func TestASnapshotTheGatewayCannotLoadNeverReachesThePool(t *testing.T) {
	p := newPool(t, "one", twoSnapshots)
	result := publish(t, p, "broken")

	if result.Outcome != OutcomeRefused || result.Reason != "routes[2]: unknown field" || result.Replaced || result.Expected != "" {
		t.Fatalf("%+v", result)
	}
	if len(p.puts) != 0 || string(p.file.Content()) != "one" {
		t.Fatalf("池被碰过：%v", p.puts)
	}
}

// 带环境变量的快照，离线加载得了也不发布：它在池里是什么，要看池里那个进程的环境。
func TestASnapshotThatRefersToTheEnvironmentIsRefusedWithoutBeingLoaded(t *testing.T) {
	const content = "routes:\n- name: tenant-$SESSION_KEY\n- name: ${HOME}\n"
	p := newPool(t, "one", map[string]string{"one": "digest-one", content: "digest-two"})
	result := publish(t, p, content)

	if result.Outcome != OutcomeRefused || !strings.Contains(result.Reason, "($SESSION_KEY, ${HOME})") || result.Replaced || result.Expected != "" {
		t.Fatalf("%+v", result)
	}
	if p.staged != 0 || len(p.puts) != 0 {
		t.Fatalf("离线加载 %d 次，写了 %v", p.staged, p.puts)
	}
	// 字面的 $ 写成 $$，照常发布。
	const literal = "routes:\n- name: price-in-$$\n"
	p = newPool(t, "one", map[string]string{"one": "digest-one", literal: "digest-two"})
	if result := publish(t, p, literal); result.Outcome != OutcomeActive {
		t.Fatalf("%+v", result)
	}
}

func TestASnapshotWithoutReadOnlyStorageIsRefused(t *testing.T) {
	p := newPool(t, "one", map[string]string{"one": "digest-one", "two storage=file": "digest-two"})
	result := publish(t, p, "two storage=file")

	if result.Outcome != OutcomeRefused || !strings.Contains(result.Reason, `storage mode "file"`) || len(p.puts) != 0 {
		t.Fatalf("%+v，写了 %v", result, p.puts)
	}
}

func TestAPoolThatIsNotInACleanStateIsLeftAlone(t *testing.T) {
	for name, spoil := range map[string]func(*pool){
		"网关上一次加载失败": func(p *pool) { p.running.Synchronized, p.running.LastError = false, "earlier failure" },
		"存储不是只读":    func(p *pool) { p.running.StorageMode = "file" },
	} {
		p := newPool(t, "one", twoSnapshots)
		spoil(p)
		result := publish(t, p, "two")
		if result.Outcome != OutcomePoolNotReady || result.Reason == "" || result.Replaced || len(p.puts) != 0 {
			t.Errorf("%s：%+v，写了 %v", name, result, p.puts)
		}
	}
}

func TestChangesThatNeedARestartAreNotPublished(t *testing.T) {
	// 启动设置不同。离线加载那边的 dns 也不同，但那是随环境变的，不算。
	p := newPool(t, "one", map[string]string{"one": "digest-one", "one deadline=46": "digest-one"})
	result := publish(t, p, "one deadline=46")
	if result.Outcome != OutcomeRestartRequired || !reflect.DeepEqual(result.Restart, []string{"terminationMaxDeadline"}) || len(p.puts) != 0 {
		t.Fatalf("%+v，写了 %v", result, p.puts)
	}

	// 池里跑的是另一个构建。
	p = newPool(t, "one", twoSnapshots)
	p.running.Revision = "0000000"
	result = publish(t, p, "two")
	if result.Outcome != OutcomeRestartRequired || !strings.Contains(result.Reason, "0000000") || len(p.puts) != 0 {
		t.Fatalf("%+v，写了 %v", result, p.puts)
	}
}

func TestPublishingWhatIsAlreadyActiveWritesNothing(t *testing.T) {
	p := newPool(t, "one", twoSnapshots)
	result := publish(t, p, "one")
	if result.Outcome != OutcomeActive || result.Replaced || len(p.puts) != 0 || p.elapsed() != 0 {
		t.Fatalf("%+v，写了 %v，等了 %s", result, p.puts, p.elapsed())
	}
}

// 目录里已经是这份文件，网关在跑的却是另一份（它没有看到文件变了）：文件相同不算已经生效，要再换一次。
func TestTheSameFileInPlaceIsNotEnoughWhenTheGatewayRunsSomethingElse(t *testing.T) {
	p := newPool(t, "two", twoSnapshots)
	p.running = loaded("digest-one")
	result := publish(t, p, "two")
	if result.Outcome != OutcomeActive || !result.Replaced || !reflect.DeepEqual(p.puts, []string{"two"}) || result.Observed.Digest != "digest-two" {
		t.Fatalf("%+v，写了 %v", result, p.puts)
	}
}

func TestASnapshotThePoolCannotLoadIsReplacedByThePreviousOne(t *testing.T) {
	p := newPool(t, "one", twoSnapshots)
	p.onlyOffline["two"] = true
	result := publish(t, p, "two")

	if result.Outcome != OutcomeRestored || !result.Replaced || !strings.Contains(result.Reason, "cannot load two") {
		t.Fatalf("%+v", result)
	}
	if !reflect.DeepEqual(p.puts, []string{"two", "one"}) || string(p.file.Content()) != "one" {
		t.Fatalf("写了 %v，目录里是 %s", p.puts, p.file.Content())
	}
	if result.Observed.Digest != "digest-one" || !result.Observed.Synchronized {
		t.Fatalf("最后读到的是 %+v", result.Observed)
	}
	// 网关一报告加载失败就放回去，不等到时限：1 秒时看到失败，再过 1 秒确认放回。
	if p.elapsed() != 2*time.Second {
		t.Fatalf("等了 %s", p.elapsed())
	}
}

// 放回去之后，网关过了观察期还在报告上一次（坏文件的）加载失败：它只是还没重载，要接着等。
func TestWhilePuttingBackAReportedFailureIsNotFinal(t *testing.T) {
	p := newPool(t, "one", twoSnapshots)
	p.onlyOffline["two"] = true
	p.afterReload = func() { p.reloadIn = 1500 * time.Millisecond } // 第二次重载慢
	result := publish(t, p, "two")

	if result.Outcome != OutcomeRestored || !result.Observed.Synchronized || result.Observed.Digest != "digest-one" {
		t.Fatalf("%+v", result)
	}
	// 1 秒时看到失败并放回；放回之后 1.5 秒网关才重载。
	if p.elapsed() != 2500*time.Millisecond {
		t.Fatalf("等了 %s", p.elapsed())
	}
}

// 新旧两份的运行配置相同时，换上去的那一刻网关报告的就已经"对"了。那不说明它加载过新文件：
// 0.3 秒后它才去加载，而且失败了。
func TestAnEarlyMatchIsNotTakenAsProofThatTheFileWasLoaded(t *testing.T) {
	p := newPool(t, "one", map[string]string{"one": "digest-one", "one, rewritten": "digest-one"})
	p.onlyOffline["one, rewritten"] = true
	result := publish(t, p, "one, rewritten")

	if result.Outcome != OutcomeRestored || !reflect.DeepEqual(p.puts, []string{"one, rewritten", "one"}) {
		t.Fatalf("%+v，写了 %v", result, p.puts)
	}
}

func TestAGatewayThatNeverReportsTheSnapshotGetsThePreviousOneBack(t *testing.T) {
	p := newPool(t, "one", twoSnapshots)
	p.reloadIn = time.Hour // 网关没有看到文件变了
	result := publish(t, p, "two")

	// 放回去的那一份和网关一直在跑的是同一份，所以读得到确认。
	if result.Outcome != OutcomeRestored || !strings.Contains(result.Reason, "expected digest digest-two") || !strings.Contains(result.Reason, "waited 10s") {
		t.Fatalf("%+v", result)
	}
	if !reflect.DeepEqual(p.puts, []string{"two", "one"}) || p.elapsed() != 11*time.Second {
		t.Fatalf("写了 %v，等了 %s", p.puts, p.elapsed())
	}
}

func TestWhenThePreviousSnapshotCannotBeConfirmedTheOutcomeIsUnknown(t *testing.T) {
	// 放回去之后读不到网关。
	p := newPool(t, "one", twoSnapshots)
	p.onlyOffline["two"] = true
	p.afterReload = func() {
		if string(p.file.Content()) == "two" {
			since := p.now
			p.unreadable = func(now time.Time) bool { return now.After(since.Add(900 * time.Millisecond)) }
		}
	}
	result := publish(t, p, "two")
	if result.Outcome != OutcomeUnknown || !strings.Contains(result.Reason, "put back but not confirmed") || !strings.Contains(result.Reason, "connection refused") {
		t.Fatalf("%+v", result)
	}
	if !reflect.DeepEqual(p.puts, []string{"two", "one"}) {
		t.Fatalf("写了 %v", p.puts)
	}

	// 放不回去。
	p = newPool(t, "one", twoSnapshots)
	p.onlyOffline["two"] = true
	p.failPut[2] = errors.New("disk full")
	result = publish(t, p, "two")
	if result.Outcome != OutcomeUnknown || !strings.Contains(result.Reason, "disk full") || string(p.file.Content()) != "two" {
		t.Fatalf("%+v，目录里是 %s", result, p.file.Content())
	}

	// 原来那里什么都没有：没有可放回去的。
	p = newPool(t, "", twoSnapshots)
	p.running = loaded("digest-zero") // 网关在跑，但目录里的文件不见了
	p.onlyOffline["two"] = true
	result = publish(t, p, "two")
	if result.Outcome != OutcomeUnknown || result.Previous != "" || !strings.Contains(result.Reason, "nothing was put back") || !reflect.DeepEqual(p.puts, []string{"two"}) {
		t.Fatalf("%+v，写了 %v", result, p.puts)
	}
}

func TestAFailedWriteIsFollowedByPuttingThePreviousSnapshotBack(t *testing.T) {
	p := newPool(t, "one", twoSnapshots)
	p.failPut[1] = errors.New("short write")
	result := publish(t, p, "two")
	if result.Outcome != OutcomeRestored || !strings.Contains(result.Reason, "short write") || !reflect.DeepEqual(p.puts, []string{"two", "one"}) {
		t.Fatalf("%+v，写了 %v", result, p.puts)
	}
}

func TestCancellationAfterTheFileWasReplacedStillPutsThePreviousOneBack(t *testing.T) {
	p := newPool(t, "one", twoSnapshots)
	p.reloadIn = 5 * time.Second
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p.cancel, p.cancelAt = cancel, 2*time.Second

	result, err := p.publisher().Publish(ctx, snap(t, "two"))
	if err != nil {
		t.Fatal(err)
	}
	if result.Outcome != OutcomeRestored || !strings.Contains(result.Reason, "interrupted") {
		t.Fatalf("%+v", result)
	}
	if !reflect.DeepEqual(p.puts, []string{"two", "one"}) || string(p.file.Content()) != "one" || result.Observed.Digest != "digest-one" {
		t.Fatalf("写了 %v，目录里是 %s，最后读到 %+v", p.puts, p.file.Content(), result.Observed)
	}
}

func TestPublishFailsBeforeTouchingThePoolWhenItCannotLookFirst(t *testing.T) {
	// 另一次发布占着这个池。
	p := newPool(t, "one", twoSnapshots)
	p.held = true
	if _, err := p.publisher().Publish(context.Background(), snap(t, "two")); !errors.Is(err, ports.ErrBusy) {
		t.Fatalf("得到 %v", err)
	}
	if p.staged != 0 || len(p.puts) != 0 {
		t.Fatalf("没占到池却做了事：离线加载 %d 次，写了 %v", p.staged, p.puts)
	}

	// 离线加载这一步没做成（不是网关拒绝了快照）：说明不了快照的好坏，不往下走，也不报成 REFUSED。
	p = newPool(t, "one", twoSnapshots)
	p.stagingErr = errors.New("docker: cannot start the container")
	if result, err := p.publisher().Publish(context.Background(), snap(t, "two")); err == nil || !strings.Contains(err.Error(), "staging: docker") || result.Outcome != "" {
		t.Fatalf("得到 %+v, %v", result, err)
	}
	if len(p.puts) != 0 || p.held {
		t.Fatalf("写了 %v，held=%t", p.puts, p.held)
	}

	// 发布之前读不到网关。
	p = newPool(t, "one", twoSnapshots)
	p.unreadable = func(time.Time) bool { return true }
	if _, err := p.publisher().Publish(context.Background(), snap(t, "two")); err == nil || !strings.Contains(err.Error(), "read-back before publishing") {
		t.Fatalf("得到 %v", err)
	}
	if len(p.puts) != 0 || p.held {
		t.Fatalf("写了 %v，held=%t", p.puts, p.held)
	}

	// 没有内容的快照。
	p = newPool(t, "one", twoSnapshots)
	if _, err := p.publisher().Publish(context.Background(), domain.Snapshot{}); err == nil || p.staged != 0 {
		t.Fatalf("得到 %v", err)
	}
}

func TestNewRefusesUnusableArguments(t *testing.T) {
	p := newPool(t, "one", twoSnapshots)
	good := DefaultTiming()
	if _, err := New(p, p, p, good); err != nil {
		t.Fatal(err)
	}
	for name, build := range map[string]func() (*Publisher, error){
		"没有离线加载": func() (*Publisher, error) { return New(nil, p, p, good) },
		"没有下发":   func() (*Publisher, error) { return New(p, nil, p, good) },
		"没有回读":   func() (*Publisher, error) { return New(p, p, nil, good) },
		"间隔为零":   func() (*Publisher, error) { return New(p, p, p, Timing{Settle: time.Second, Timeout: time.Minute}) },
		"时限比观察期还短": func() (*Publisher, error) {
			return New(p, p, p, Timing{Settle: time.Minute, Timeout: time.Second, Interval: time.Second})
		},
	} {
		if _, err := build(); err == nil {
			t.Errorf("%s：被接受了", name)
		}
	}
}

// 发布成功才记下来；第一次动一个池之前，先把当时放在那里的记成第一条。
func TestAConfirmedPublicationIsRecorded(t *testing.T) {
	p := newPool(t, "one", twoSnapshots)
	if result := publish(t, p, "two"); result.Outcome != OutcomeActive {
		t.Fatalf("%+v", result)
	}
	if want := []string{"confirm one", "put two", "confirm two"}; !reflect.DeepEqual(p.events, want) {
		t.Fatalf("做过的事是 %v", p.events)
	}
	if p.recorded() != "two" || p.record.Digest != "digest-two" || !p.record.Holds(p.running) || p.record.Adopted || p.record.Startup == nil {
		t.Fatalf("记录是 %+v", p.record)
	}

	// 没有生效的不记：记录里仍是上一份。
	p = newPool(t, "one", twoSnapshots)
	p.onlyOffline["two"] = true
	if result := publish(t, p, "two"); result.Outcome != OutcomeRestored {
		t.Fatalf("%+v", result)
	}
	if want := []string{"confirm one", "put two", "put one"}; !reflect.DeepEqual(p.events, want) || p.recorded() != "one" || p.record.Digest != "digest-one" {
		t.Fatalf("做过的事是 %v，记录是 %+v", p.events, p.record)
	}
	// 那一条是接手来的：放在那里的是它，网关在跑它，别的没有核对过。
	if !p.record.Adopted || p.record.Startup != nil {
		t.Fatalf("记录是 %+v", p.record)
	}

	// 已经有记录的池：不再记"上一份"，只在成功之后换成新的。
	p = newPool(t, "one", twoSnapshots).confirmed("one")
	if result := publish(t, p, "two"); result.Outcome != OutcomeActive || !reflect.DeepEqual(p.events, []string{"put two", "confirm two"}) {
		t.Fatalf("%+v，做过的事是 %v", result, p.events)
	}
}

// 第一条记录写不下来：还没有动过池，就此停下。
func TestWithoutAFirstRecordThePoolIsNotTouched(t *testing.T) {
	p := newPool(t, "one", twoSnapshots)
	p.failConfirm[1] = errors.New("read-only file system")
	if _, err := p.publisher().Publish(context.Background(), snap(t, "two")); err == nil || !strings.Contains(err.Error(), "read-only file system") {
		t.Fatalf("得到 %v", err)
	}
	if len(p.puts) != 0 || p.held {
		t.Fatalf("写了 %v，held=%t", p.puts, p.held)
	}

	// 记录读不成样子：既不能当它没有，也不能照着它做。
	p = newPool(t, "one", twoSnapshots)
	p.recordErr = errors.New("the record is damaged")
	if _, err := p.publisher().Publish(context.Background(), snap(t, "two")); err == nil || !strings.Contains(err.Error(), "damaged") || len(p.puts) != 0 {
		t.Fatalf("得到 %v，写了 %v", err, p.puts)
	}
}

var offRecordSnapshots = map[string]string{"one": "digest-one", "two": "digest-two", "three": "digest-three", "one deadline=46": "digest-one"}

// 放在那里的不是记录里确认过的那一份：上一次发布没有做完，或者有别人写过。这时不发布别的。
func TestWhatIsInPlaceMustBeTheConfirmedSnapshot(t *testing.T) {
	p := newPool(t, "two", offRecordSnapshots).confirmed("one") // 网关加载了 two，也报告成功，但没有人确认过它
	result := publish(t, p, "three")
	if result.Outcome != OutcomePoolNotReady || !strings.Contains(result.Reason, "reconcile") || !strings.Contains(result.Reason, snap(t, "one").ShortID()) ||
		result.Replaced || len(p.events) != 0 || p.recorded() != "one" {
		t.Fatalf("%+v，做过的事是 %v", result, p.events)
	}
	if result.Previous != snap(t, "two").ID() || result.Expected != "digest-three" || result.Observed.Digest != "digest-two" {
		t.Fatalf("%+v", result)
	}

	// 文件不见了：连正要发布的也不是。
	p = newPool(t, "one", offRecordSnapshots).confirmed("one")
	p.file = nil
	if result := publish(t, p, "one"); result.Outcome != OutcomePoolNotReady || len(p.events) != 0 {
		t.Fatalf("%+v，做过的事是 %v", result, p.events)
	}

	// 放在那里的正是要发布的这一份，但它要重启才到位：这不是一次发布补得完的，先对账。
	p = newPool(t, "one deadline=46", offRecordSnapshots).confirmed("one")
	p.running.Settings["terminationMaxDeadline"] = `"45s"` // 网关没有重启过
	result = publish(t, p, "one deadline=46")
	if result.Outcome != OutcomePoolNotReady || len(result.Restart) != 0 || len(p.events) != 0 {
		t.Fatalf("%+v，做过的事是 %v", result, p.events)
	}
}

// 放在那里的不是记录的那一份，却正是要发布的这一份：上一次发布它时换上去了，没来得及记。
// 网关确认它在生效就补记，不用先收回去。
func TestPublishingWhatWasLeftInPlaceCompletesIt(t *testing.T) {
	p := newPool(t, "two", offRecordSnapshots).confirmed("one")
	result := publish(t, p, "two")
	if result.Outcome != OutcomeActive || result.Replaced || result.Reason != "" || !reflect.DeepEqual(p.events, []string{"confirm two"}) {
		t.Fatalf("%+v，做过的事是 %v", result, p.events)
	}
	if p.recorded() != "two" || p.record.Adopted || !p.record.Holds(p.running) || result.Previous != snap(t, "two").ID() || result.Observed.Digest != "digest-two" {
		t.Fatalf("%+v，记录是 %+v", result, p.record)
	}
	// 那个文件可能刚刚才换上去：和刚换上去时一样，过了观察期读到的才算数。
	if p.elapsed() != time.Second {
		t.Fatalf("等了 %s", p.elapsed())
	}

	// 网关还没有加载它（文件是 0.2 秒前才换上去的）：等它。
	p = newPool(t, "two", offRecordSnapshots).confirmed("one")
	p.running = loaded("digest-one")
	at := p.now.Add(100 * time.Millisecond)
	p.reloadAt = &at
	if result := publish(t, p, "two"); result.Outcome != OutcomeActive || len(p.puts) != 0 || p.recorded() != "two" {
		t.Fatalf("%+v，写了 %v，记录是 %q", result, p.puts, p.recorded())
	}

	// 网关加载不了它，或者一直没有去加载：不认，也不动它，留给对账。加载失败是网关自己报告的，不用等到时限。
	for name, c := range map[string]struct {
		spoil  func(*pool)
		waited time.Duration
	}{
		"加载不了": {func(p *pool) {
			p.onlyOffline["two"] = true
			at := p.now.Add(100 * time.Millisecond)
			p.reloadAt = &at
		}, time.Second},
		"一直没有加载": {func(*pool) {}, 10 * time.Second},
	} {
		p = newPool(t, "two", offRecordSnapshots).confirmed("one")
		p.running = loaded("digest-one")
		c.spoil(p)
		result := publish(t, p, "two")
		if result.Outcome != OutcomePoolNotReady || !strings.Contains(result.Reason, "does not report it running") || !strings.Contains(result.Reason, "reconcile") ||
			len(p.events) != 0 || p.recorded() != "one" || p.elapsed() != c.waited {
			t.Errorf("%s：%+v，做过的事是 %v，等了 %s", name, result, p.events, p.elapsed())
		}
	}

	// 等的时候被叫停：什么都没动，报错。
	p = newPool(t, "two", offRecordSnapshots).confirmed("one")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p.cancel, p.cancelAt = cancel, 500*time.Millisecond
	if _, err := p.publisher().Publish(ctx, snap(t, "two")); err == nil || !strings.Contains(err.Error(), "interrupted") || len(p.events) != 0 {
		t.Fatalf("得到 %v，做过的事是 %v", err, p.events)
	}

	// 记不下来：什么都没动，报错。
	p = newPool(t, "two", offRecordSnapshots).confirmed("one")
	p.failConfirm[1] = errors.New("no space left on device")
	if _, err := p.publisher().Publish(context.Background(), snap(t, "two")); err == nil || !strings.Contains(err.Error(), "could not be recorded: no space left on device") ||
		len(p.puts) != 0 || p.recorded() != "one" {
		t.Fatalf("得到 %v，写了 %v，记录是 %q", err, p.puts, p.recorded())
	}
}

// 生效了却记不下来：不算数，收回去。留着的话，下一次对账会把它当成没做完的发布。
func TestAPublicationThatCannotBeRecordedIsTakenBack(t *testing.T) {
	p := newPool(t, "one", twoSnapshots).confirmed("one")
	p.failConfirm[1] = errors.New("no space left on device")
	result := publish(t, p, "two")
	if result.Outcome != OutcomeRestored || !strings.Contains(result.Reason, "could not be recorded: no space left on device") {
		t.Fatalf("%+v", result)
	}
	if !reflect.DeepEqual(p.puts, []string{"two", "one"}) || p.recorded() != "one" || result.Observed.Digest != "digest-one" {
		t.Fatalf("写了 %v，记录是 %q，最后读到 %+v", p.puts, p.recorded(), result.Observed)
	}
}

// 已经在生效的那一份再发布一次：配置不再写；记录里没有它时补上，有了就不再动。
func TestPublishingWhatIsAlreadyActiveRecordsItOnce(t *testing.T) {
	p := newPool(t, "one", twoSnapshots)
	if result := publish(t, p, "one"); result.Outcome != OutcomeActive || !reflect.DeepEqual(p.events, []string{"confirm one"}) {
		t.Fatalf("%+v，做过的事是 %v", result, p.events)
	}
	if result := publish(t, p, "one"); result.Outcome != OutcomeActive || len(p.events) != 1 {
		t.Fatalf("%+v，做过的事是 %v", result, p.events)
	}
	// 记录是在网关的另一个构建上做的：摘要没法比，重新记一次。
	p.record.Revision = "0000000"
	if result := publish(t, p, "one"); result.Outcome != OutcomeActive || len(p.events) != 2 || p.record.Revision != revision {
		t.Fatalf("%+v，做过的事是 %v", result, p.events)
	}
	// 记录里的启动设置不是网关现在的这一套（确认之后网关带着同样的设置重启过，只是记录旧了）：重新记一次。
	p.record.Startup["terminationMaxDeadline"] = "another fingerprint"
	if result := publish(t, p, "one"); result.Outcome != OutcomeActive || len(p.events) != 3 || len(p.record.PendingRestart(p.running)) != 0 {
		t.Fatalf("%+v，做过的事是 %v", result, p.events)
	}
	// 记录是接手来的：这一次核对过了，换成确认过的。
	p = newPool(t, "one", twoSnapshots).adopted("one")
	if result := publish(t, p, "one"); result.Outcome != OutcomeActive || !reflect.DeepEqual(p.events, []string{"confirm one"}) || p.record.Adopted || p.record.Startup == nil {
		t.Fatalf("%+v，做过的事是 %v，记录是 %+v", result, p.events, p.record)
	}
	// 补不上：池没有被碰过，报错。
	p = newPool(t, "one", twoSnapshots)
	p.failConfirm[1] = errors.New("read-only file system")
	if _, err := p.publisher().Publish(context.Background(), snap(t, "one")); err == nil || len(p.puts) != 0 {
		t.Fatalf("得到 %v，写了 %v", err, p.puts)
	}
}

// 网关刚确认，发布器就被叫停：已经生效的照样记下来，不因为这一下又收回去。
func TestCancellationRightAfterTheConfirmationStillRecordsIt(t *testing.T) {
	p := newPool(t, "one", twoSnapshots).confirmed("one")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p.afterObserve = func(elapsed time.Duration) {
		if elapsed >= time.Second {
			cancel()
		}
	}
	result, err := p.publisher().Publish(ctx, snap(t, "two"))
	if err != nil || result.Outcome != OutcomeActive || p.recorded() != "two" || !reflect.DeepEqual(p.puts, []string{"two"}) {
		t.Fatalf("%+v（%v），写了 %v，记录是 %q", result, err, p.puts, p.recorded())
	}
}
