package application

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"go.idp.xyz/idp-gateway/internal/gatewayconfig/ports"
)

// 这里的快照：内容里写着 deadline=46 的，启动设置与池里在跑的（45 秒）不同，要重启才到位。
var restartSnapshots = map[string]string{
	"one": "digest-one", "two": "digest-two",
	"one deadline=46": "digest-one", "two deadline=46": "digest-two",
}

const setting = "terminationMaxDeadline"

func restart(t *testing.T, p *pool, content string) Result {
	t.Helper()
	result, err := p.publisher().Restart(context.Background(), snap(t, content))
	if err != nil {
		t.Fatalf("Restart: %v", err)
	}
	if p.held {
		t.Error("重启返回之后还占着这个池")
	}
	return result
}

func TestRestartReplacesTheFileThenRestartsTheGateway(t *testing.T) {
	p := newPool(t, "one", restartSnapshots)
	result := restart(t, p, "two deadline=46")

	if result.Outcome != OutcomeActive || !result.Replaced || !result.Restarted || result.Reason != "" || !reflect.DeepEqual(result.Restart, []string{setting}) {
		t.Fatalf("%+v", result)
	}
	// 先核对容器，再记下上一份，换文件，等网关加载得了它，然后才重启；确认之后记下新的。
	if want := []string{"verify", "confirm one", "put two deadline=46", "restart", "confirm two deadline=46"}; !reflect.DeepEqual(p.events, want) {
		t.Fatalf("做过的事是 %v", p.events)
	}
	if p.running.Settings[setting] != `"46s"` || result.Observed.Digest != "digest-two" || p.recorded() != "two deadline=46" ||
		p.record.Adopted || len(p.record.PendingRestart(p.running)) != 0 {
		t.Fatalf("网关的设置 %v，最后读到 %+v，记录 %+v", p.running.Settings, result.Observed, p.record)
	}
	// 记下的是重启之后的那一套设置：拿重启之前的去对，差的正是改的那一项。
	if before := startedWith("one", "digest-two"); !reflect.DeepEqual(p.record.PendingRestart(before), []string{setting}) {
		t.Fatalf("记录 %+v", p.record)
	}
	// 换文件之后等 1 秒，重启之后再等 1 秒。
	if p.elapsed() != 2*time.Second {
		t.Fatalf("等了 %s", p.elapsed())
	}
}

func TestRestartRefusesWhatDoesNotNeedIt(t *testing.T) {
	// 启动设置没有变：用不着重启。
	p := newPool(t, "one", restartSnapshots)
	result := restart(t, p, "two")
	if result.Outcome != OutcomeRefused || !strings.Contains(result.Reason, "nothing to restart") || !strings.Contains(result.Reason, "publish it instead") || len(p.events) != 0 {
		t.Fatalf("%+v，做过的事是 %v", result, p.events)
	}
	// 已经放在那里、已经在跑的这一份也一样；这时连发布都不用。
	if result := restart(t, p, "one"); result.Outcome != OutcomeRefused || strings.Contains(result.Reason, "publish it instead") || len(p.events) != 0 {
		t.Fatalf("%+v，做过的事是 %v", result, p.events)
	}

	// 池里跑的是另一个构建：重启换不了镜像。
	p = newPool(t, "one", restartSnapshots)
	p.running.Revision = "0000000"
	result = restart(t, p, "two deadline=46")
	if result.Outcome != OutcomeRefused || !strings.Contains(result.Reason, "0000000") || !strings.Contains(result.Reason, "does not change the image") || len(p.events) != 0 {
		t.Fatalf("%+v，做过的事是 %v", result, p.events)
	}

	// 发布时挡下的，这里一样挡下：网关加载不了的；带环境变量的（这一种不用离线加载就挡下）。
	p = newPool(t, "one", restartSnapshots)
	if result := restart(t, p, "broken"); result.Outcome != OutcomeRefused || p.staged != 1 || len(p.events) != 0 {
		t.Fatalf("%+v，离线加载 %d 次，做过的事是 %v", result, p.staged, p.events)
	}
	const fromEnvironment = "tenant-$HOME deadline=46"
	p = newPool(t, "one", map[string]string{"one": "digest-one", fromEnvironment: "digest-two"})
	if result := restart(t, p, fromEnvironment); result.Outcome != OutcomeRefused || !strings.Contains(result.Reason, "($HOME)") || p.staged != 0 || len(p.events) != 0 {
		t.Fatalf("%+v，离线加载 %d 次，做过的事是 %v", result, p.staged, p.events)
	}
	p = newPool(t, "one", restartSnapshots)
	p.running.Synchronized = false
	if result := restart(t, p, "two deadline=46"); result.Outcome != OutcomePoolNotReady || len(p.events) != 0 {
		t.Fatalf("%+v，做过的事是 %v", result, p.events)
	}
	// 放在那里的不是记录的那一份：先对账。正要发布的就是放在那里的那一份也一样，
	// 带重启的发布做到一半留下的，不由下一次重启顺手认下。
	p = newPool(t, "two", restartSnapshots).confirmed("one")
	if result := restart(t, p, "two deadline=46"); result.Outcome != OutcomePoolNotReady || !strings.Contains(result.Reason, "reconcile") || len(p.events) != 0 {
		t.Fatalf("%+v，做过的事是 %v", result, p.events)
	}
	p = newPool(t, "two deadline=46", restartSnapshots).confirmed("one")
	p.running.Settings[setting] = `"45s"`
	if result := restart(t, p, "two deadline=46"); result.Outcome != OutcomePoolNotReady || !strings.Contains(result.Reason, "reconcile") || len(p.events) != 0 {
		t.Fatalf("%+v，做过的事是 %v", result, p.events)
	}
	p = newPool(t, "", restartSnapshots)
	p.running = loaded("digest-zero")
	if result := restart(t, p, "two deadline=46"); result.Outcome != OutcomePoolNotReady || len(p.events) != 0 {
		t.Fatalf("%+v，做过的事是 %v", result, p.events)
	}
}

// 池里的网关加载不了这份快照：在重启之前就发现了，放回上一份，不重启。
func TestASnapshotThePoolCannotLoadIsTakenBackWithoutRestarting(t *testing.T) {
	p := newPool(t, "one", restartSnapshots)
	p.onlyOffline["two deadline=46"] = true
	result := restart(t, p, "two deadline=46")
	if result.Outcome != OutcomeRestored || !result.Replaced || result.Restarted || p.restarts != 0 || !strings.Contains(result.Reason, "cannot load") {
		t.Fatalf("%+v，重启了 %d 次", result, p.restarts)
	}
	if !reflect.DeepEqual(p.puts, []string{"two deadline=46", "one"}) || p.recorded() != "one" {
		t.Fatalf("写了 %v，记录是 %q", p.puts, p.recorded())
	}

	// 写不上去也一样。
	p = newPool(t, "one", restartSnapshots)
	p.failPut[1] = errors.New("short write")
	result = restart(t, p, "two deadline=46")
	if result.Outcome != OutcomeRestored || result.Restarted || p.restarts != 0 || !strings.Contains(result.Reason, "short write") {
		t.Fatalf("%+v，重启了 %d 次", result, p.restarts)
	}
}

// 重启之后网关没有起来：把上一份放回去，再重启一次。
func TestAGatewayThatDoesNotComeBackIsRestartedWithThePreviousSnapshot(t *testing.T) {
	p := newPool(t, "one", restartSnapshots)
	p.cannotStart["two deadline=46"] = true
	result := restart(t, p, "two deadline=46")
	if result.Outcome != OutcomeRestored || !result.Restarted || !strings.Contains(result.Reason, "connection refused") || !strings.Contains(result.Reason, "waited 10s") {
		t.Fatalf("%+v", result)
	}
	if want := []string{"verify", "confirm one", "put two deadline=46", "restart", "put one", "restart"}; !reflect.DeepEqual(p.events, want) {
		t.Fatalf("做过的事是 %v", p.events)
	}
	if p.down || p.running.Settings[setting] != `"45s"` || result.Observed.Digest != "digest-one" || p.recorded() != "one" {
		t.Fatalf("down=%t，设置 %v，最后读到 %+v，记录 %q", p.down, p.running.Settings, result.Observed, p.recorded())
	}

	// 重启的命令本身失败了：一样放回去再重启。
	p = newPool(t, "one", restartSnapshots)
	p.failRestart[1] = errors.New("docker: daemon is not running")
	result = restart(t, p, "two deadline=46")
	if result.Outcome != OutcomeRestored || !strings.Contains(result.Reason, "restarting the gateway: docker: daemon is not running") || p.restarts != 2 {
		t.Fatalf("%+v，重启了 %d 次", result, p.restarts)
	}

	// 放回去之后的那次重启也失败：结局未知。
	p = newPool(t, "one", restartSnapshots)
	p.failRestart[1], p.failRestart[2] = errors.New("first"), errors.New("second")
	result = restart(t, p, "two deadline=46")
	if result.Outcome != OutcomeUnknown || !strings.Contains(result.Reason, "restarting the gateway with it failed: second") || string(p.file.Content()) != "one" {
		t.Fatalf("%+v，目录里是 %s", result, p.file.Content())
	}

	// 起来了，记录却写不下来：不算数，放回去再重启。
	p = newPool(t, "one", restartSnapshots).confirmed("one")
	p.failConfirm[1] = errors.New("no space left on device")
	result = restart(t, p, "two deadline=46")
	if result.Outcome != OutcomeRestored || !strings.Contains(result.Reason, "could not be recorded") || p.restarts != 2 || p.running.Settings[setting] != `"45s"` {
		t.Fatalf("%+v，重启了 %d 次，设置 %v", result, p.restarts, p.running.Settings)
	}
}

// 目录里已经是这一份，网关也在跑它，只是启动设置还是旧的（对账留下的 RESTART_PENDING）：只重启，不换文件。
func TestRestartWithTheSnapshotAlreadyInPlaceOnlyRestarts(t *testing.T) {
	p := newPool(t, "one deadline=46", restartSnapshots).confirmed("one deadline=46")
	p.running.Settings[setting] = `"45s"` // 网关是带着旧设置起来的
	result := restart(t, p, "one deadline=46")
	if result.Outcome != OutcomeActive || result.Replaced || !result.Restarted || !reflect.DeepEqual(p.events, []string{"verify", "restart", "confirm one deadline=46"}) {
		t.Fatalf("%+v，做过的事是 %v", result, p.events)
	}
	if p.running.Settings[setting] != `"46s"` {
		t.Fatalf("设置 %v", p.running.Settings)
	}

	// 这时重启之后起不来：没有"上一份"可放，结局未知。
	p = newPool(t, "one deadline=46", restartSnapshots).confirmed("one deadline=46")
	p.running.Settings[setting] = `"45s"`
	p.cannotStart["one deadline=46"] = true
	result = restart(t, p, "one deadline=46")
	if result.Outcome != OutcomeUnknown || !strings.Contains(result.Reason, "nothing to put back") || len(p.puts) != 0 || p.restarts != 1 {
		t.Fatalf("%+v，写了 %v，重启了 %d 次", result, p.puts, p.restarts)
	}
}

// 目录里已经是这一份，网关在跑的却不是它（它没有看到文件变了）：重启之前先让它加载一遍。
// 池里的网关加载不了的文件，不拿去重启。
func TestRestartLoadsTheFileFirstWhenTheGatewayIsNotRunningIt(t *testing.T) {
	p := newPool(t, "two deadline=46", restartSnapshots).confirmed("two deadline=46")
	p.running = loaded("digest-one") // 在跑的还是之前的那一份，启动设置也是旧的
	result := restart(t, p, "two deadline=46")
	if result.Outcome != OutcomeActive || !result.Replaced || !result.Restarted ||
		!reflect.DeepEqual(p.events, []string{"verify", "put two deadline=46", "restart", "confirm two deadline=46"}) {
		t.Fatalf("%+v，做过的事是 %v", result, p.events)
	}

	// 它加载不了：不重启。放回去的还是这一份，所以确认不了。
	p = newPool(t, "two deadline=46", restartSnapshots).confirmed("two deadline=46")
	p.running = loaded("digest-one")
	p.onlyOffline["two deadline=46"] = true
	result = restart(t, p, "two deadline=46")
	if result.Outcome != OutcomeUnknown || result.Restarted || p.restarts != 0 || !strings.Contains(result.Reason, "cannot load") {
		t.Fatalf("%+v，重启了 %d 次", result, p.restarts)
	}
}

// 重启的命令返回了，答话的却还是旧的进程：它已经加载了新文件，摘要对得上，启动设置还是旧的。
// 这不算到位，要等到带着新设置起来的那个进程答话。
func TestRestartWaitsForTheProcessThatStartedWithTheNewSettings(t *testing.T) {
	p := newPool(t, "one", restartSnapshots)
	p.lingering[1] = 3 * time.Second
	result := restart(t, p, "two deadline=46")
	if result.Outcome != OutcomeActive || p.restarts != 1 || result.Observed.Settings[setting] != `"46s"` {
		t.Fatalf("%+v，重启了 %d 次", result, p.restarts)
	}
	// 换文件之后等 1 秒；重启之后旧的进程又答了 3 秒话。记下的是新的那一套设置。
	if p.elapsed() != 4*time.Second || len(p.record.PendingRestart(p.running)) != 0 {
		t.Fatalf("等了 %s，记录 %+v", p.elapsed(), p.record)
	}

	// 新的进程一直没有来：不算到位。放回上一份，再重启一次。
	p = newPool(t, "one", restartSnapshots)
	p.lingering[1] = time.Hour
	result = restart(t, p, "two deadline=46")
	if result.Outcome != OutcomeRestored || !strings.Contains(result.Reason, "other startup settings than expected: "+setting) || !strings.Contains(result.Reason, "waited 10s") {
		t.Fatalf("%+v", result)
	}
	if p.restarts != 2 || p.recorded() != "one" || p.running.Settings[setting] != `"45s"` || string(p.file.Content()) != "one" {
		t.Fatalf("重启了 %d 次，记录 %q，设置 %v，目录里是 %s", p.restarts, p.recorded(), p.running.Settings, p.file.Content())
	}

	// 放回去之后的那次重启也是这样，答话的一直是带着新设置的那个进程：上一份的文件回去了，
	// 启动设置没有回去。结局未知，不报成已经放回去。
	p = newPool(t, "one", restartSnapshots).confirmed("one")
	p.failConfirm[1] = errors.New("no space left on device")
	p.lingering[2] = time.Hour
	result = restart(t, p, "two deadline=46")
	if result.Outcome != OutcomeUnknown || !strings.Contains(result.Reason, "put back but not confirmed") ||
		!strings.Contains(result.Reason, "other startup settings than expected: "+setting) || result.Observed.Digest != "digest-one" || string(p.file.Content()) != "one" {
		t.Fatalf("%+v，目录里是 %s", result, p.file.Content())
	}
}

func TestRestartFailsBeforeTouchingThePool(t *testing.T) {
	// 那个容器不是这个池的网关。
	p := newPool(t, "one", restartSnapshots)
	p.verifyErr = errors.New("it is not the gateway of this pool")
	if _, err := p.publisher().Restart(context.Background(), snap(t, "two deadline=46")); err == nil || !strings.Contains(err.Error(), "process: it is not the gateway") {
		t.Fatalf("得到 %v", err)
	}
	if len(p.puts) != 0 || p.restarts != 0 || len(p.confirms) != 0 || p.held {
		t.Fatalf("写了 %v，重启了 %d 次，记了 %v，held=%t", p.puts, p.restarts, p.confirms, p.held)
	}

	// 没有告诉它怎么重启。
	publisher, err := New(p, p, p, DefaultTiming())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := publisher.Restart(context.Background(), snap(t, "two deadline=46")); err == nil || p.staged != 1 {
		t.Fatalf("得到 %v（离线加载 %d 次）", err, p.staged)
	}
}

func TestCancellationDuringARestart(t *testing.T) {
	// 还没重启就被叫停：放回上一份，不重启。
	p := newPool(t, "one", restartSnapshots)
	ctx, cancel := context.WithCancel(context.Background())
	p.cancel, p.cancelAt = cancel, 500*time.Millisecond
	result, err := p.publisher().Restart(ctx, snap(t, "two deadline=46"))
	cancel()
	if err != nil || result.Outcome != OutcomeRestored || result.Restarted || p.restarts != 0 || !strings.Contains(result.Reason, "interrupted") {
		t.Fatalf("%+v（%v），重启了 %d 次", result, err, p.restarts)
	}

	// 网关刚报告它加载得了新文件，还没重启就被叫停：这是最后一个不必中断这个池的地方，放回去，不重启。
	p = newPool(t, "one", restartSnapshots)
	ctx, cancel = context.WithCancel(context.Background())
	p.afterObserve = func(elapsed time.Duration) {
		if elapsed >= time.Second {
			cancel()
		}
	}
	result, err = p.publisher().Restart(ctx, snap(t, "two deadline=46"))
	cancel()
	if err != nil || result.Outcome != OutcomeRestored || result.Restarted || p.restarts != 0 || !strings.Contains(result.Reason, "interrupted before the gateway was restarted") {
		t.Fatalf("%+v（%v），重启了 %d 次", result, err, p.restarts)
	}
	if !reflect.DeepEqual(p.puts, []string{"two deadline=46", "one"}) || p.recorded() != "one" {
		t.Fatalf("写了 %v，记录是 %q", p.puts, p.recorded())
	}

	// 文件用不着换、只差重启时被叫停：池没有被碰过，报错。
	p = newPool(t, "one deadline=46", restartSnapshots).confirmed("one deadline=46")
	p.running.Settings[setting] = `"45s"`
	ctx, cancel = context.WithCancel(context.Background())
	p.afterObserve = func(time.Duration) { cancel() }
	_, err = p.publisher().Restart(ctx, snap(t, "one deadline=46"))
	cancel()
	if err == nil || !strings.Contains(err.Error(), "interrupted before the gateway was restarted") || p.restarts != 0 || len(p.puts) != 0 || p.held {
		t.Fatalf("得到 %v，重启了 %d 次，写了 %v", err, p.restarts, p.puts)
	}

	// 重启之后被叫停：做完。
	p = newPool(t, "one", restartSnapshots)
	ctx, cancel = context.WithCancel(context.Background())
	p.cancel, p.cancelAt = cancel, 1500*time.Millisecond
	result, err = p.publisher().Restart(ctx, snap(t, "two deadline=46"))
	cancel()
	if err != nil || result.Outcome != OutcomeActive || p.restarts != 1 || p.recorded() != "two deadline=46" {
		t.Fatalf("%+v（%v），重启了 %d 次，记录是 %q", result, err, p.restarts, p.recorded())
	}
}

// 不指定快照：用这个池上最后一次得到确认的那一份。对账留下 RESTART_PENDING 之后做的就是这个。
func TestRestartConfirmedUsesTheRecordedSnapshot(t *testing.T) {
	p := newPool(t, "one deadline=46", restartSnapshots).confirmed("one deadline=46")
	p.running.Settings[setting] = `"45s"` // 有人带着别的文件重启过网关，文件已经由对账放回去了
	result, err := p.publisher().RestartConfirmed(context.Background())
	if err != nil || result.Outcome != OutcomeActive || result.Replaced || !result.Restarted || result.Snapshot != snap(t, "one deadline=46").ID() ||
		!reflect.DeepEqual(result.Restart, []string{setting}) {
		t.Fatalf("%+v（%v）", result, err)
	}
	if !reflect.DeepEqual(p.events, []string{"verify", "restart", "confirm one deadline=46"}) || p.running.Settings[setting] != `"46s"` || p.held {
		t.Fatalf("做过的事是 %v，设置 %v", p.events, p.running.Settings)
	}
	// 再来一次：已经到位，用不着重启。
	result, err = p.publisher().RestartConfirmed(context.Background())
	if err != nil || result.Outcome != OutcomeRefused || !strings.Contains(result.Reason, "nothing to restart") || strings.Contains(result.Reason, "publish it instead") || p.restarts != 1 {
		t.Fatalf("%+v（%v），重启了 %d 次", result, err, p.restarts)
	}

	// 接手来的记录也用得上：那一份是什么设置，离线加载一遍就知道。
	p = newPool(t, "one deadline=46", restartSnapshots).adopted("one deadline=46")
	p.running.Settings[setting] = `"45s"`
	if result, err := p.publisher().RestartConfirmed(context.Background()); err != nil || result.Outcome != OutcomeActive || p.record.Adopted {
		t.Fatalf("%+v（%v），记录 %+v", result, err, p.record)
	}

	// 放在那里的不是记录的那一份：先对账。
	p = newPool(t, "two", restartSnapshots).confirmed("one deadline=46")
	if result, err := p.publisher().RestartConfirmed(context.Background()); err != nil || result.Outcome != OutcomePoolNotReady || len(p.events) != 0 {
		t.Fatalf("%+v（%v），做过的事是 %v", result, err, p.events)
	}

	// 接手来的那一份带着环境变量：发布时会挡下的，这里一样挡下。
	const fromEnvironment = "tenant-$HOME deadline=46"
	p = newPool(t, fromEnvironment, map[string]string{fromEnvironment: "digest-one"}).adopted(fromEnvironment)
	p.running.Settings[setting] = `"45s"`
	if result, err := p.publisher().RestartConfirmed(context.Background()); err != nil || result.Outcome != OutcomeRefused || p.staged != 0 || len(p.events) != 0 || p.held {
		t.Fatalf("%+v（%v），离线加载 %d 次，做过的事是 %v", result, err, p.staged, p.events)
	}
}

func TestRestartConfirmedFailsBeforeTouchingThePool(t *testing.T) {
	// 还没有确认过任何发布：不知道用哪一份。
	p := newPool(t, "one", restartSnapshots)
	if _, err := p.publisher().RestartConfirmed(context.Background()); !errors.Is(err, ErrNothingConfirmed) || p.staged != 0 || len(p.events) != 0 || p.held {
		t.Fatalf("得到 %v，离线加载 %d 次，做过的事是 %v", err, p.staged, p.events)
	}
	// 记录读不成样子。
	p.recordErr = errors.New("the record is damaged")
	if _, err := p.publisher().RestartConfirmed(context.Background()); err == nil || !strings.Contains(err.Error(), "damaged") || p.staged != 0 || p.held {
		t.Fatalf("得到 %v", err)
	}
	// 另一次发布占着这个池：不读记录，读到的可以是它正要换掉的那一份。
	p = newPool(t, "one deadline=46", restartSnapshots).confirmed("one deadline=46")
	p.held = true
	if _, err := p.publisher().RestartConfirmed(context.Background()); !errors.Is(err, ports.ErrBusy) || p.staged != 0 {
		t.Fatalf("得到 %v", err)
	}
}
