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
	cancel      context.CancelFunc
	cancelAt    time.Duration
	started     time.Time
}

func newPool(t *testing.T, current string, loads map[string]string) *pool {
	t.Helper()
	start := time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC)
	p := &pool{t: t, now: start, started: start, reloadIn: 300 * time.Millisecond, loads: loads, onlyOffline: map[string]bool{}, failPut: map[int]error{}}
	if current != "" {
		snapshot := snap(t, current)
		p.file = &snapshot
		p.running = loaded(loads[current])
	}
	return p
}

func (p *pool) publisher() *Publisher {
	publisher, err := New(p, p, p, Timing{Settle: time.Second, Timeout: 10 * time.Second, Interval: 100 * time.Millisecond})
	if err != nil {
		p.t.Fatal(err)
	}
	publisher.now = func() time.Time { return p.now }
	publisher.sleep = func(ctx context.Context, d time.Duration) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		p.now = p.now.Add(d)
		if p.cancel != nil && p.now.Sub(p.started) >= p.cancelAt {
			p.cancel()
		}
		return nil
	}
	return publisher
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
	observation := loaded(digest)
	observation.Settings["dns"] = `"elsewhere"` // 离线加载在另一个环境里
	if strings.Contains(string(snapshot.Content()), "deadline=46") {
		observation.Settings["terminationMaxDeadline"] = `"46s"`
	}
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
	p.puts = append(p.puts, string(snapshot.Content()))
	if err := p.failPut[len(p.puts)]; err != nil {
		return err
	}
	p.file = &snapshot
	at := p.now.Add(p.reloadIn)
	p.reloadAt = &at
	return nil
}

// ReadBack
func (p *pool) Observe(ctx context.Context) (domain.Observation, error) {
	if err := ctx.Err(); err != nil {
		return domain.Observation{}, err
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
	if p.unreadable != nil && p.unreadable(p.now) {
		return domain.Observation{}, errors.New("connection refused")
	}
	return p.running, nil
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
