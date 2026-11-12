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

func (p *pool) reconciler() *Reconciler {
	reconciler, err := NewReconciler(p, p, Timing{Settle: time.Second, Timeout: 10 * time.Second, Interval: 100 * time.Millisecond})
	if err != nil {
		p.t.Fatal(err)
	}
	p.clock(&reconciler.watch)
	return reconciler
}

func reconcile(t *testing.T, p *pool) Result {
	t.Helper()
	result, err := p.reconciler().Reconcile(context.Background())
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if p.held {
		t.Error("对账返回之后还占着这个池")
	}
	if p.staged != 0 || p.restarts != 0 || len(p.confirms) != 0 {
		t.Errorf("对账不做离线加载、不重启、不改记录：离线加载 %d 次，重启 %d 次，记了 %v", p.staged, p.restarts, p.confirms)
	}
	return result
}

var threeSnapshots = map[string]string{"one": "digest-one", "two": "digest-two", "one deadline=46": "digest-one"}

func TestAPoolThatIsWhatTheRecordSaysIsLeftAlone(t *testing.T) {
	p := newPool(t, "one", threeSnapshots).confirmed("one")
	result := reconcile(t, p)
	if result.Outcome != OutcomeInSync || result.Replaced || result.Reason != "" || len(p.puts) != 0 || p.elapsed() != 0 {
		t.Fatalf("%+v，写了 %v，等了 %s", result, p.puts, p.elapsed())
	}
	if result.Snapshot != snap(t, "one").ID() || result.Previous != snap(t, "one").ID() || result.Expected != "digest-one" || result.Observed.Digest != "digest-one" {
		t.Fatalf("%+v", result)
	}
}

func TestWithoutARecordThereIsNothingToReconcileAgainst(t *testing.T) {
	p := newPool(t, "one", threeSnapshots)
	result := reconcile(t, p)
	if result.Outcome != OutcomeUnconfirmed || result.Replaced || len(p.puts) != 0 || result.Snapshot != "" || result.Expected != "" {
		t.Fatalf("%+v，写了 %v", result, p.puts)
	}
	// 池现在的样子照样报告出来。
	if result.Previous != snap(t, "one").ID() || result.Observed.Digest != "digest-one" || result.Reason == "" {
		t.Fatalf("%+v", result)
	}
}

// 发布器把文件换上去之后死了：放在那里的是没有人确认过的一份。网关加载得了它也一样收回去。
func TestAPublicationThatWasCutShortIsTakenBack(t *testing.T) {
	p := newPool(t, "two", threeSnapshots).confirmed("one")
	result := reconcile(t, p)
	if result.Outcome != OutcomeRestored || !result.Replaced || !strings.Contains(result.Reason, "was not the snapshot last confirmed") {
		t.Fatalf("%+v", result)
	}
	if !reflect.DeepEqual(p.puts, []string{"one"}) || string(p.file.Content()) != "one" || result.Observed.Digest != "digest-one" || !result.Observed.Synchronized {
		t.Fatalf("写了 %v，目录里是 %s，最后读到 %+v", p.puts, p.file.Content(), result.Observed)
	}
	if result.Previous != snap(t, "two").ID() || result.Snapshot != snap(t, "one").ID() || p.elapsed() != time.Second {
		t.Fatalf("%+v，等了 %s", result, p.elapsed())
	}
	// 再对一次：已经对上了。
	if again := reconcile(t, p); again.Outcome != OutcomeInSync || len(p.puts) != 1 {
		t.Fatalf("%+v，写了 %v", again, p.puts)
	}
}

func TestWhateverIsOffTheConfirmedSnapshotIsPutBack(t *testing.T) {
	for name, c := range map[string]struct {
		spoil func(*pool)
		says  string
	}{
		"有人放了一份网关加载不了的文件": {func(p *pool) {
			broken := snap(p.t, "broken")
			p.file = &broken
			p.running.Synchronized, p.running.LastError = false, "cannot load broken"
		}, "the gateway reported that its last load failed: cannot load broken"},
		"文件不见了": {func(p *pool) { p.file = nil }, "there was no configuration file in place"},
		"文件是对的，网关在跑的却是别的（它没有看到文件变了）": {func(p *pool) { p.running.Digest = "digest-two" },
			"the gateway reported digest digest-two"},
		"文件是对的，网关报告上一次加载失败": {func(p *pool) { p.running.Synchronized, p.running.LastError = false, "earlier failure" },
			"earlier failure"},
		"存储不是只读": {func(p *pool) {
			p.running.StorageMode = "file"
			p.afterReload = func() { p.running.StorageMode = "readOnly" }
		}, `storage mode "file"`},
	} {
		p := newPool(t, "one", threeSnapshots).confirmed("one")
		c.spoil(p)
		result := reconcile(t, p)
		if result.Outcome != OutcomeRestored || !result.Replaced || !strings.Contains(result.Reason, c.says) {
			t.Errorf("%s：%+v", name, result)
		}
		if !reflect.DeepEqual(p.puts, []string{"one"}) || string(p.file.Content()) != "one" || !p.record.Holds(result.Observed) {
			t.Errorf("%s：写了 %v，最后读到 %+v", name, p.puts, result.Observed)
		}
	}
}

// 放回去之后，网关过了观察期还在报告之前那份坏文件的加载失败：它只是还没重载，接着等。
func TestWhileReconcilingAReportedFailureIsNotFinal(t *testing.T) {
	p := newPool(t, "broken", threeSnapshots).confirmed("one")
	p.running = loaded("digest-one")
	p.running.Synchronized, p.running.LastError = false, "cannot load broken"
	p.reloadIn = 1500 * time.Millisecond
	result := reconcile(t, p)
	if result.Outcome != OutcomeRestored || !result.Observed.Synchronized || p.elapsed() != 1500*time.Millisecond {
		t.Fatalf("%+v，等了 %s", result, p.elapsed())
	}
}

// 网关读不到（多半是它拿着一份坏文件起不来）：文件照样放回去，这正是它起得来的前提；但确认不了。
func TestWhenTheGatewayCannotBeReadTheFileIsStillPutBack(t *testing.T) {
	p := newPool(t, "broken", threeSnapshots).confirmed("one")
	p.down = true
	result := reconcile(t, p)
	if result.Outcome != OutcomeUnknown || !result.Replaced || !strings.Contains(result.Reason, "the gateway could not be read: connection refused") ||
		!strings.Contains(result.Reason, "put back but not confirmed") || !strings.Contains(result.Reason, "waited 10s") {
		t.Fatalf("%+v", result)
	}
	if !reflect.DeepEqual(p.puts, []string{"one"}) || string(p.file.Content()) != "one" || p.elapsed() != 10*time.Second {
		t.Fatalf("写了 %v，目录里是 %s，等了 %s", p.puts, p.file.Content(), p.elapsed())
	}
	// 网关起来之后（这里由测试替运维重启它）再对一次：对上了，不用再写。
	if err := p.Restart(context.Background()); err != nil {
		t.Fatal(err)
	}
	p.restarts = 0
	if again := reconcile(t, p); again.Outcome != OutcomeInSync || len(p.puts) != 1 {
		t.Fatalf("%+v，写了 %v", again, p.puts)
	}
}

// 文件是对的，只是读不到网关（它正在重启，或者回读口一时够不着）：再写一遍同样的文件帮不上忙。等它，不写。
func TestWhenTheFileIsRightAnUnreadableGatewayIsWaitedFor(t *testing.T) {
	// 一直读不到：结局未知，什么都没有写。
	p := newPool(t, "one", threeSnapshots).confirmed("one")
	p.down = true
	result := reconcile(t, p)
	if result.Outcome != OutcomeUnknown || result.Replaced || len(p.puts) != 0 || p.elapsed() != 10*time.Second {
		t.Fatalf("%+v，写了 %v，等了 %s", result, p.puts, p.elapsed())
	}
	if !strings.Contains(result.Reason, "the confirmed snapshot is in place") || !strings.Contains(result.Reason, "connection refused") || !strings.Contains(result.Reason, "waited 10s") ||
		result.Previous != snap(t, "one").ID() || result.Snapshot != snap(t, "one").ID() {
		t.Fatalf("%+v", result)
	}

	// 过了 2 秒读得到了，在跑的就是那一份：对得上，什么都没有写。
	p = newPool(t, "one", threeSnapshots).confirmed("one")
	since := p.now
	p.unreadable = func(now time.Time) bool { return now.Before(since.Add(2 * time.Second)) }
	result = reconcile(t, p)
	if result.Outcome != OutcomeInSync || result.Replaced || len(p.puts) != 0 || p.elapsed() != 2*time.Second || result.Observed.Digest != "digest-one" {
		t.Fatalf("%+v，写了 %v，等了 %s", result, p.puts, p.elapsed())
	}

	// 读得到了，在跑的却不是那一份：这时才放回去。
	p = newPool(t, "one", threeSnapshots).confirmed("one")
	p.running.Digest = "digest-two"
	since = p.now
	p.unreadable = func(now time.Time) bool { return now.Before(since.Add(2 * time.Second)) }
	result = reconcile(t, p)
	if result.Outcome != OutcomeRestored || !result.Replaced || !reflect.DeepEqual(p.puts, []string{"one"}) || !strings.Contains(result.Reason, "the gateway reported digest digest-two") {
		t.Fatalf("%+v，写了 %v", result, p.puts)
	}

	// 读得到了，网关是带着别的启动设置起来的：照样不写，只报告要重启。
	p = newPool(t, "one", threeSnapshots).confirmed("one")
	p.running.Settings["terminationMaxDeadline"] = `"46s"`
	since = p.now
	p.unreadable = func(now time.Time) bool { return now.Before(since.Add(2 * time.Second)) }
	if result := reconcile(t, p); result.Outcome != OutcomeRestartPending || result.Replaced || len(p.puts) != 0 {
		t.Fatalf("%+v，写了 %v", result, p.puts)
	}

	// 等的时候被叫停：什么都没做，报错。
	p = newPool(t, "one", threeSnapshots).confirmed("one")
	p.down = true
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p.cancel, p.cancelAt = cancel, 500*time.Millisecond
	if _, err := p.reconciler().Reconcile(ctx); err == nil || !strings.Contains(err.Error(), "interrupted") || len(p.puts) != 0 || p.held {
		t.Fatalf("得到 %v，写了 %v", err, p.puts)
	}
}

func TestWhenTheConfirmedSnapshotCannotBePutBackTheOutcomeIsUnknown(t *testing.T) {
	p := newPool(t, "two", threeSnapshots).confirmed("one")
	p.failPut[1] = errors.New("disk full")
	result := reconcile(t, p)
	if result.Outcome != OutcomeUnknown || !strings.Contains(result.Reason, "putting the confirmed snapshot back failed: disk full") || string(p.file.Content()) != "two" {
		t.Fatalf("%+v，目录里是 %s", result, p.file.Content())
	}
}

// 网关换过构建：摘要里有版本，记录里的摘要没法拿来比。
func TestARecordMadeOnAnotherBuildCannotBeCompared(t *testing.T) {
	// 文件是对的，网关报告加载成功：不动它，等再发布一次来确认。
	p := newPool(t, "one", threeSnapshots).confirmed("one")
	p.running.Version, p.running.Digest = "1.8.0", "digest-one-on-1.8.0"
	result := reconcile(t, p)
	if result.Outcome != OutcomeUnconfirmed || result.Replaced || len(p.puts) != 0 || !strings.Contains(result.Reason, "1.8.0") || !strings.Contains(result.Reason, "publish the snapshot again") {
		t.Fatalf("%+v，写了 %v", result, p.puts)
	}

	// 文件也不对：文件放回去，但确认不了。原因里说了两遍换过构建：动手之前看到一次，放回去之后又看到一次。
	p = newPool(t, "two", threeSnapshots).confirmed("one")
	p.running.Version = "1.8.0"
	result = reconcile(t, p)
	if result.Outcome != OutcomeUnknown || !reflect.DeepEqual(p.puts, []string{"one"}) || strings.Count(result.Reason, "the gateway is agentgateway 1.8.0") != 2 {
		t.Fatalf("%+v，写了 %v", result, p.puts)
	}
}

// 文件和运行配置都对得上，启动设置却不是确认时的那一套：有人带着别的设置重启过网关。对账不重启它。
func TestStartupSettingsThatDifferFromTheRecordNeedARestart(t *testing.T) {
	p := newPool(t, "one", threeSnapshots).confirmed("one")
	p.running.Settings["terminationMaxDeadline"] = `"46s"`
	p.running.Settings["dns"] = `"moved"` // 随环境变的不算
	result := reconcile(t, p)
	if result.Outcome != OutcomeRestartPending || result.Replaced || len(p.puts) != 0 || !reflect.DeepEqual(result.Restart, []string{"terminationMaxDeadline"}) {
		t.Fatalf("%+v，写了 %v", result, p.puts)
	}
	if !strings.Contains(result.Reason, "terminationMaxDeadline") {
		t.Fatalf("%+v", result)
	}

	// 接手来的记录没有记启动设置：它说不出"要重启"。
	p = newPool(t, "one", threeSnapshots).adopted("one")
	p.running.Settings["terminationMaxDeadline"] = `"46s"`
	if result := reconcile(t, p); result.Outcome != OutcomeInSync || len(result.Restart) != 0 || len(p.puts) != 0 {
		t.Fatalf("%+v，写了 %v", result, p.puts)
	}

	// 带重启的发布做到一半死了：文件是新的，网关已经带着新设置起来。文件放回去，设置还差一次重启。
	p = newPool(t, "one deadline=46", threeSnapshots).confirmed("one")
	result = reconcile(t, p)
	if result.Outcome != OutcomeRestartPending || !result.Replaced || !reflect.DeepEqual(p.puts, []string{"one"}) || !reflect.DeepEqual(result.Restart, []string{"terminationMaxDeadline"}) {
		t.Fatalf("%+v，写了 %v", result, p.puts)
	}
	if !strings.Contains(result.Reason, "was not the snapshot last confirmed") || !strings.Contains(result.Reason, "restarting it") {
		t.Fatalf("%+v", result)
	}
}

// 开始往回放之后被叫停：做完再返回。
func TestCancellationDoesNotStopReconcilingHalfway(t *testing.T) {
	p := newPool(t, "two", threeSnapshots).confirmed("one")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p.cancel, p.cancelAt = cancel, 500*time.Millisecond
	result, err := p.reconciler().Reconcile(ctx)
	if err != nil || result.Outcome != OutcomeRestored || string(p.file.Content()) != "one" {
		t.Fatalf("%+v（%v），目录里是 %s", result, err, p.file.Content())
	}

	// 还没开始放就被叫停：不开始。
	p = newPool(t, "two", threeSnapshots).confirmed("one")
	p.afterObserve = func(time.Duration) { cancel() }
	if _, err := p.reconciler().Reconcile(ctx); err == nil || !strings.Contains(err.Error(), "interrupted before") || len(p.puts) != 0 || string(p.file.Content()) != "two" || p.held {
		t.Fatalf("得到 %v，写了 %v", err, p.puts)
	}
}

func TestReconcileFailsWithoutTouchingThePool(t *testing.T) {
	p := newPool(t, "two", threeSnapshots).confirmed("one")
	p.held = true
	if _, err := p.reconciler().Reconcile(context.Background()); !errors.Is(err, ports.ErrBusy) {
		t.Fatalf("得到 %v", err)
	}
	p.held = false
	p.recordErr = errors.New("the record is damaged")
	if _, err := p.reconciler().Reconcile(context.Background()); err == nil || !strings.Contains(err.Error(), "damaged") {
		t.Fatalf("得到 %v", err)
	}
	if len(p.puts) != 0 || p.held {
		t.Fatalf("写了 %v，held=%t", p.puts, p.held)
	}
}

func TestNewReconcilerRefusesUnusableArguments(t *testing.T) {
	p := newPool(t, "one", threeSnapshots)
	if _, err := NewReconciler(p, p, DefaultTiming()); err != nil {
		t.Fatal(err)
	}
	if _, err := NewReconciler(nil, p, DefaultTiming()); err == nil {
		t.Error("没有下发：被接受了")
	}
	if _, err := NewReconciler(p, nil, DefaultTiming()); err == nil {
		t.Error("没有回读：被接受了")
	}
	if _, err := NewReconciler(p, p, Timing{Settle: time.Minute, Timeout: time.Second, Interval: time.Second}); err == nil {
		t.Error("时限比观察期还短：被接受了")
	}
}
