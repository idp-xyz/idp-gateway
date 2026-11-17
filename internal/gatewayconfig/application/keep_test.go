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

var background = context.Background()

// fleet 模拟单机上一个池的三个常驻容器和启动它们的那条命令。它接在 pool 这个假的池上：
// 网关容器没在跑、或者接着的命名空间不在了，回读口就读不到。
type fleet struct {
	*pool
	members domain.Members
	stamps  int
	// calls 按先后记下对容器做过的事："stop"、"start"。startedAt 是每一次启动命令开始的时刻（从测试开始算起）。
	calls     []string
	startedAt []time.Duration
	// looks 是看过几眼。onLook 在每一眼之前调用：模拟这时发生的事。
	looks  int
	onLook func(look int)
	// lookErr：第几眼（从 1 数）返回什么错误。
	lookErr map[int]error
	// broken：启动命令起不来的那个容器（"gateway" 或 "front"）；空表示都起得来。
	broken  string
	stopErr error
	// during 在停、起的中途调用。
	during func(step string)
}

// newFleet 布置一个三个容器都在跑的池。confirmed 为假时这个池还没有记录。
func newFleet(t *testing.T, current string, confirmed bool) *fleet {
	t.Helper()
	p := newPool(t, current, threeSnapshots)
	if confirmed {
		p.confirmed(current)
	}
	f := &fleet{pool: p, lookErr: map[int]error{}}
	f.members = domain.Members{Holder: f.up(), Gateway: f.up(), Front: f.up()}
	p.unreadable = func(time.Time) bool {
		return !f.members.Holder.Running || f.members.Gateway.Started.Before(f.members.Holder.Started)
	}
	return f
}

// up 是一个刚启动的容器。先后启动的两个，启动时刻不同。
func (f *fleet) up() domain.Member {
	f.stamps++
	return domain.Member{Running: true, Started: f.now.Add(time.Duration(f.stamps)), State: "running"}
}

func (f *fleet) member(name string) *domain.Member {
	switch name {
	case "holder":
		return &f.members.Holder
	case "gateway":
		return &f.members.Gateway
	case "front":
		return &f.members.Front
	}
	f.t.Fatalf("没有叫 %s 的容器", name)
	return nil
}

// kill 让容器死掉。
func (f *fleet) kill(names ...string) {
	for _, name := range names {
		member := f.member(name)
		member.Running, member.State = false, "exited (137)"
		if name == "gateway" {
			f.down = true
		}
	}
}

func (f *fleet) condition() domain.Condition {
	condition, _ := f.members.Condition()
	return condition
}

// Pool
func (f *fleet) Members(ctx context.Context) (domain.Members, error) {
	f.looks++
	if f.onLook != nil {
		f.onLook(f.looks)
	}
	if err := ctx.Err(); err != nil {
		return domain.Members{}, err
	}
	if err := f.lookErr[f.looks]; err != nil {
		return domain.Members{}, err
	}
	return f.members, nil
}

// Start 是启动这个池的命令，和真的一样：在跑的不动，没在跑的按先后起起来；网关启动之前把记录的那一份
// 放到位，对账没有通过就不开前置代理。
func (f *fleet) Start(ctx context.Context) error {
	f.calls = append(f.calls, "start")
	f.startedAt = append(f.startedAt, f.elapsed())
	if f.held {
		f.t.Error("跑启动命令时还占着这个池：命令里的那两步自己要占它")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if f.during != nil {
		f.during("start")
	}
	if !f.members.Holder.Running {
		f.members.Holder = f.up()
	}
	if f.record != nil && (f.file == nil || string(f.file.Content()) != f.recorded()) {
		recorded := f.record.Snapshot
		f.file, f.currentErr = &recorded, nil
	}
	if !f.members.Gateway.Running {
		if f.broken == "gateway" {
			f.members.Gateway.State = "exited (1)"
			return errors.New(`service "confirm" didn't complete successfully: exit 5`)
		}
		f.members.Gateway = f.up()
		f.comeUp()
	}
	if f.record == nil {
		return errors.New(`service "confirm" didn't complete successfully: exit 3`)
	}
	if f.unreadable(f.now) {
		return errors.New(`service "confirm" didn't complete successfully: exit 5`)
	}
	if !f.members.Front.Running {
		if f.broken == "front" {
			f.members.Front.State = "exited (1)"
			return nil // 命令把它启动了就算数；它随后自己退出了
		}
		f.members.Front = f.up()
	}
	return nil
}

func (f *fleet) StopDependents(ctx context.Context) error {
	f.calls = append(f.calls, "stop")
	if f.held {
		f.t.Error("停容器时还占着这个池")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if f.during != nil {
		f.during("stop")
	}
	if f.stopErr != nil {
		return f.stopErr
	}
	for _, name := range []string{"front", "gateway"} {
		if member := f.member(name); member.Running {
			member.Running, member.State = false, "exited (0)"
		}
	}
	f.down = true
	return nil
}

var pace = Pace{Interval: 5 * time.Second, Reconcile: time.Minute, MaxBackoff: 5 * time.Minute}

func (f *fleet) keeper() *Keeper { return f.keeperOver(f) }

func (f *fleet) keeperOver(delivery ports.Delivery) *Keeper {
	f.t.Helper()
	keeper, err := NewKeeper(f, delivery, f, Timing{Settle: time.Second, Timeout: 10 * time.Second, Interval: 100 * time.Millisecond}, pace)
	if err != nil {
		f.t.Fatal(err)
	}
	f.clock(&keeper.reconciler.watch)
	keeper.now, keeper.sleep = keeper.reconciler.now, keeper.reconciler.sleep
	return keeper
}

// keep 让看守守 d 这么久（假的时间），返回它报告过的。
func (f *fleet) keep(keeper *Keeper, d time.Duration) []Tending {
	f.t.Helper()
	ctx, cancel := context.WithCancel(background)
	defer cancel()
	f.cancel, f.cancelAt = cancel, f.elapsed()+d
	var reported []Tending
	keeper.Run(ctx, func(t Tending) { reported = append(reported, t) })
	f.cancel = nil
	if f.held {
		f.t.Error("看守返回之后还占着这个池")
	}
	return reported
}

func seconds(durations []time.Duration) []int {
	whole := make([]int, len(durations))
	for i, d := range durations {
		whole[i] = int(d / time.Second)
	}
	return whole
}

func outcomes(reported []Tending) []Outcome {
	var all []Outcome
	for _, t := range reported {
		if t.Reconciled != nil {
			all = append(all, t.Reconciled.Outcome)
		} else {
			all = append(all, "")
		}
	}
	return all
}

func TestAWholePoolIsOnlyReconciled(t *testing.T) {
	f := newFleet(t, "one", true)
	keeper := f.keeper()

	tending := keeper.tend(background, true, time.Time{})
	if tending.Condition != domain.ConditionWhole || tending.Why != "" || tending.Acted() || tending.Busy || tending.Err != nil {
		t.Fatalf("%+v", tending)
	}
	if tending.Reconciled == nil || tending.Reconciled.Outcome != OutcomeInSync || tending.After != nil {
		t.Fatalf("%+v", tending)
	}
	// 还没到对账的时候：只看一眼。
	observed := 0
	f.afterObserve = func(time.Duration) { observed++ }
	tending = keeper.tend(background, false, time.Time{})
	if tending.Condition != domain.ConditionWhole || tending.Reconciled != nil || observed != 0 {
		t.Fatalf("%+v，读了 %d 次回读口", tending, observed)
	}
	if len(f.calls) != 0 || len(f.puts) != 0 || f.held {
		t.Fatalf("动过容器 %v，写过 %v", f.calls, f.puts)
	}
}

func TestADeadContainerIsBroughtBackByTheStartCommand(t *testing.T) {
	for _, dead := range [][]string{{"gateway"}, {"front"}, {"gateway", "front"}, {"holder", "gateway", "front"}} {
		f := newFleet(t, "one", true)
		before := f.members
		f.kill(dead...)

		tending := f.keeper().tend(background, false, time.Time{})
		if tending.Condition != domain.ConditionDown || !tending.Started || tending.Stopped || tending.StartErr != "" || tending.Err != nil {
			t.Fatalf("%v 死了：%+v", dead, tending)
		}
		if !reflect.DeepEqual(f.calls, []string{"start"}) || !tending.Repaired() || f.condition() != domain.ConditionWhole {
			t.Fatalf("%v 死了：做了 %v，之后是 %+v", dead, f.calls, tending.After)
		}
		// 没到对账的时候也对一次：启动命令成没成，看的是它。
		if tending.Reconciled == nil || tending.Reconciled.Outcome != OutcomeInSync {
			t.Fatalf("%v 死了：%+v", dead, tending.Reconciled)
		}
		// 动手之前的样子留在报告里；活着的容器没有被动过。
		if tending.Members == *tending.After {
			t.Fatalf("%v 死了：报告里动手前后是一个样子", dead)
		}
		for _, name := range []string{"holder", "gateway", "front"} {
			if !strings.Contains(strings.Join(dead, " "), name) {
				switch name {
				case "holder":
					if f.members.Holder != before.Holder {
						t.Errorf("%v 死了：占着命名空间的那个被动过", dead)
					}
				case "gateway":
					if f.members.Gateway != before.Gateway {
						t.Errorf("%v 死了：网关被动过", dead)
					}
				case "front":
					if f.members.Front != before.Front {
						t.Errorf("%v 死了：前置代理被动过", dead)
					}
				}
			}
		}
	}
}

// 网关死的时候目录里放着一份没人确认过的文件：它经启动命令起来，带着的是记录的那一份。
func TestTheGatewayComesBackWithTheConfirmedSnapshot(t *testing.T) {
	f := newFleet(t, "one", true)
	two := snap(t, "two")
	f.file = &two
	f.kill("gateway")

	tending := f.keeper().tend(background, false, time.Time{})
	if !tending.Repaired() || string(f.file.Content()) != "one" || f.running.Digest != "digest-one" {
		t.Fatalf("%+v，目录里是 %s，网关在跑 %s", tending, f.file.Content(), f.running.Digest)
	}
	// 放回去的是启动命令里的那一步，不是看守自己：看守没有在网关起来之前写过文件。
	if len(f.puts) != 0 || tending.Reconciled == nil || tending.Reconciled.Outcome != OutcomeInSync {
		t.Fatalf("看守写过 %v，对账是 %+v", f.puts, tending.Reconciled)
	}
}

func TestContainersAttachedToANamespaceThatIsGoneAreStoppedFirst(t *testing.T) {
	for name, spoil := range map[string]func(*fleet){
		"占着命名空间的那个死了":                func(f *fleet) { f.kill("holder") },
		"占着命名空间的那个重新启动过":             func(f *fleet) { f.members.Holder = f.up() },
		"占着命名空间的那个重新启动过，网关也死了":       func(f *fleet) { f.members.Holder = f.up(); f.kill("gateway") },
		"占着命名空间的那个死了，前置代理也死了，只剩网关在跑": func(f *fleet) { f.kill("holder", "front") },
	} {
		f := newFleet(t, "one", true)
		spoil(f)

		tending := f.keeper().tend(background, false, time.Time{})
		if tending.Condition != domain.ConditionOrphaned || !tending.Stopped || !tending.Started || tending.Err != nil || tending.StartErr != "" {
			t.Fatalf("%s：%+v", name, tending)
		}
		if !reflect.DeepEqual(f.calls, []string{"stop", "start"}) || !tending.Repaired() || f.condition() != domain.ConditionWhole {
			t.Fatalf("%s：做了 %v，之后是 %+v", name, f.calls, tending.After)
		}
		if tending.Reconciled == nil || tending.Reconciled.Outcome != OutcomeInSync {
			t.Fatalf("%s：%+v", name, tending.Reconciled)
		}
	}
}

// 这个假的启动命令和真的一样，修不好接错了的。不然上面那个用例说明不了"先停"是必要的。
func TestTheStartCommandAloneDoesNotRepairAnOrphan(t *testing.T) {
	f := newFleet(t, "one", true)
	f.kill("holder")
	if err := f.Start(background); err == nil || f.condition() != domain.ConditionOrphaned {
		t.Fatalf("启动命令返回 %v，之后是 %s", err, f.condition())
	}
}

func TestThePoolIsLeftAloneWhileAPublicationHoldsIt(t *testing.T) {
	for dead, condition := range map[string]domain.Condition{"gateway": domain.ConditionDown, "holder": domain.ConditionOrphaned} {
		f := newFleet(t, "one", true)
		f.kill(dead)
		keeper := f.keeper()
		release, err := f.Hold(background) // 一次带重启的发布正占着这个池：网关是它停的
		if err != nil {
			t.Fatal(err)
		}

		tending := keeper.tend(background, true, time.Time{})
		if tending.Condition != condition || !tending.Busy || tending.Acted() || tending.Reconciled != nil || tending.Err != nil {
			t.Fatalf("%s 死了：%+v", dead, tending)
		}
		if len(f.calls) != 0 {
			t.Fatalf("%s 死了：动过容器 %v", dead, f.calls)
		}

		// 那次发布做完了，池还是坏的：这时才动手。
		release()
		tending = keeper.tend(background, true, time.Time{})
		if tending.Busy || !tending.Acted() || !tending.Repaired() {
			t.Fatalf("%s 死了：%+v", dead, tending)
		}
	}
}

func TestReconcilingWaitsItsTurn(t *testing.T) {
	f := newFleet(t, "one", true)
	two := snap(t, "two")
	f.file = &two // 一次发布刚把文件换上去，还占着这个池
	release, err := f.Hold(background)
	if err != nil {
		t.Fatal(err)
	}
	keeper := f.keeper()

	tending := keeper.tend(background, true, time.Time{})
	if !tending.Busy || tending.Reconciled != nil || tending.Err != nil || len(f.puts) != 0 {
		t.Fatalf("%+v，写过 %v", tending, f.puts)
	}
	// 那次发布死在了这里，池被放开了：下一眼对账，把它留下的收回去。
	release()
	tending = keeper.tend(background, true, time.Time{})
	if tending.Busy || tending.Reconciled == nil || tending.Reconciled.Outcome != OutcomeRestored || string(f.file.Content()) != "one" {
		t.Fatalf("%+v", tending)
	}
}

func TestALockThatCannotBeTakenKeepsTheKeeperFromActing(t *testing.T) {
	f := newFleet(t, "one", true)
	f.kill("gateway")
	keeper := f.keeperOver(lockedOut{f.pool, errors.New("directory: open .config.yaml.lock: permission denied")})

	tending := keeper.tend(background, true, time.Time{})
	if tending.Err == nil || !strings.Contains(tending.Err.Error(), "delivery: directory: open .config.yaml.lock: permission denied") {
		t.Fatalf("%+v", tending)
	}
	if tending.Acted() || tending.Busy || len(f.calls) != 0 {
		t.Fatalf("%+v，动过容器 %v", tending, f.calls)
	}
}

// lockedOut 是一个占不了的池：不是别人占着，是这个进程没有权限。
type lockedOut struct {
	*pool
	err error
}

func (l lockedOut) Hold(context.Context) (func(), error) { return nil, l.err }

func TestALookThatFailsChangesNothing(t *testing.T) {
	f := newFleet(t, "one", true)
	f.kill("gateway")
	for look := 1; look <= 4; look++ {
		f.lookErr[look] = errors.New("Cannot connect to the Docker daemon")
	}

	reported := f.keep(f.keeper(), 30*time.Second)
	// 看不成的那四眼只报告一次，什么都不做；第五眼看成了，网关起回来。
	if len(reported) != 2 || reported[0].Err == nil || reported[0].Condition != "" || reported[0].Acted() ||
		!strings.Contains(reported[0].Err.Error(), "pool: Cannot connect to the Docker daemon") {
		t.Fatalf("%+v", reported)
	}
	if !reported[1].Repaired() || !reflect.DeepEqual(seconds(f.startedAt), []int{20}) {
		t.Fatalf("%+v，启动命令在第 %v 秒", reported[1], seconds(f.startedAt))
	}
}

// 启动命令跑完之后没看成：不知道修没修好，按没修好算。
func TestNotSeeingThePoolAfterAStartCountsAsNotRepaired(t *testing.T) {
	f := newFleet(t, "one", true)
	f.kill("gateway")
	f.lookErr[2] = errors.New("Cannot connect to the Docker daemon")

	reported := f.keep(f.keeper(), 15*time.Second)
	if len(reported) != 2 || !reported[0].Started || reported[0].After != nil || reported[0].Repaired() || reported[0].Reconciled != nil ||
		reported[0].Err == nil || reported[0].RetryIn != 10*time.Second {
		t.Fatalf("%+v", reported)
	}
	// 下一眼看到它其实好了：不用再动手，也不接着等。
	if reported[1].Condition != domain.ConditionWhole || reported[1].Acted() || reported[1].RetryIn != 0 || !reflect.DeepEqual(f.calls, []string{"start"}) {
		t.Fatalf("%+v，做了 %v", reported[1], f.calls)
	}
}

// 记录读不成样子：对不了账。只报告，不动池，下一眼再试。
func TestARecordThatCannotBeReadIsReportedAndNothingIsTouched(t *testing.T) {
	f := newFleet(t, "one", true)
	f.recordErr = errors.New("directory: the record of the last confirmed snapshot is damaged")
	var observedAt []time.Duration
	f.afterObserve = func(elapsed time.Duration) { observedAt = append(observedAt, elapsed) }
	f.onLook = func(look int) {
		if look == 4 { // 有人把记录收拾好了
			f.recordErr = nil
		}
	}

	reported := f.keep(f.keeper(), time.Minute)
	if len(reported) != 2 || reported[0].Condition != domain.ConditionWhole || reported[0].Reconciled != nil || reported[0].Acted() {
		t.Fatalf("%+v", reported)
	}
	if reported[0].Err == nil || !strings.Contains(reported[0].Err.Error(), "delivery: directory: the record of the last confirmed snapshot is damaged") {
		t.Fatalf("%+v", reported[0])
	}
	// 前三眼各试了一次，只报告了一次。收拾好之后的那一眼（第 15 秒）就对上了，不等到一分钟之后。
	if reported[1].Err != nil || reported[1].Reconciled == nil || reported[1].Reconciled.Outcome != OutcomeInSync ||
		!reflect.DeepEqual(seconds(observedAt), []int{15}) {
		t.Fatalf("%+v，读回读口是在第 %v 秒", reported[1], seconds(observedAt))
	}
	if len(f.puts) != 0 || len(f.calls) != 0 {
		t.Fatalf("写过 %v，动过容器 %v", f.puts, f.calls)
	}
}

func TestAStopThatFailsIsNotFollowedByAStart(t *testing.T) {
	f := newFleet(t, "one", true)
	f.kill("holder")
	f.stopErr = errors.New("container: docker compose stop front agentgateway: exit status 1")

	tending := f.keeper().tend(background, false, time.Time{})
	if !tending.Stopped || tending.Started || tending.Repaired() || tending.After != nil || !reflect.DeepEqual(f.calls, []string{"stop"}) {
		t.Fatalf("%+v，做了 %v", tending, f.calls)
	}
	if tending.Err == nil || !strings.Contains(tending.Err.Error(), "pool: container: docker compose stop") {
		t.Fatalf("%+v", tending)
	}
}

func TestAQuietPoolIsReportedOnceAndReconciledAtItsPace(t *testing.T) {
	f := newFleet(t, "one", true)
	observed := 0
	f.afterObserve = func(time.Duration) { observed++ }

	reported := f.keep(f.keeper(), 10*time.Minute)
	if len(reported) != 1 || reported[0].Condition != domain.ConditionWhole || !reflect.DeepEqual(outcomes(reported), []Outcome{OutcomeInSync}) {
		t.Fatalf("%+v", reported)
	}
	// 5 秒看一眼，一分钟对一次账：十分钟里 120 眼，对了 10 次。
	if f.looks != 120 || observed != 10 || len(f.calls) != 0 || len(f.puts) != 0 {
		t.Fatalf("看了 %d 眼，对了 %d 次账，动过容器 %v，写过 %v", f.looks, observed, f.calls, f.puts)
	}
}

func TestWhatAReconcilePutsBackIsReportedEachTime(t *testing.T) {
	f := newFleet(t, "one", true)
	f.onLook = func(look int) {
		if look == 20 || look == 60 { // 有人绕过发布器写了这个文件
			two := snap(t, "two")
			f.file = &two
			f.running.Digest = "digest-two"
		}
	}

	reported := f.keep(f.keeper(), 10*time.Minute)
	if !reflect.DeepEqual(outcomes(reported), []Outcome{OutcomeInSync, OutcomeRestored, OutcomeInSync, OutcomeRestored, OutcomeInSync}) {
		t.Fatalf("%v", outcomes(reported))
	}
	if !reflect.DeepEqual(f.puts, []string{"one", "one"}) || len(f.calls) != 0 || string(f.file.Content()) != "one" {
		t.Fatalf("写过 %v，动过容器 %v", f.puts, f.calls)
	}
	for _, tending := range reported {
		if tending.Condition != domain.ConditionWhole || tending.Acted() {
			t.Fatalf("%+v", tending)
		}
	}
}

func TestAStartThatDoesNotRepairIsRetriedLessAndLessOften(t *testing.T) {
	f := newFleet(t, "one", true)
	f.kill("gateway")
	f.broken = "gateway"
	observed := 0
	f.afterObserve = func(time.Duration) { observed++ }

	reported := f.keep(f.keeper(), 30*time.Minute)
	// 第一次立刻；之后隔 10、20、40、80、160 秒，再往后每 5 分钟一次。
	if want := []int{0, 10, 30, 70, 150, 310, 610, 910, 1210, 1510}; !reflect.DeepEqual(seconds(f.startedAt), want) {
		t.Fatalf("启动命令在第 %v 秒，要的是 %v", seconds(f.startedAt), want)
	}
	// 每动一次手报告一次，带着离下一次还有多久；中间那些眼看到的还是老样子，不出声。
	var retries []time.Duration
	for _, tending := range reported {
		if !tending.Started || tending.Repaired() || !strings.Contains(tending.StartErr, "exit 5") || tending.Reconciled != nil {
			t.Fatalf("%+v", tending)
		}
		retries = append(retries, tending.RetryIn)
	}
	if want := []int{10, 20, 40, 80, 160, 300, 300, 300, 300, 300}; !reflect.DeepEqual(seconds(retries), want) {
		t.Fatalf("各次报告的等待是 %v 秒，要的是 %v", seconds(retries), want)
	}
	// 网关没在跑：没有账可对，不去读回读口。半小时里按间隔看了 360 眼，十次动手之后各多看一眼。
	if observed != 0 || len(f.puts) != 0 || f.looks != 370 {
		t.Fatalf("读了 %d 次回读口，写过 %v，看了 %d 眼", observed, f.puts, f.looks)
	}
}

func TestBackoffStartsOverAfterARepair(t *testing.T) {
	f := newFleet(t, "one", true)
	f.kill("gateway")
	f.broken = "gateway"
	f.onLook = func(look int) {
		switch f.elapsed() {
		case 35 * time.Second: // 有人把毛病修好了：下一次启动命令成得了
			f.broken = ""
		case 100 * time.Second: // 后来它又死了，又起不来
			f.kill("gateway")
			f.broken = "gateway"
		}
	}

	reported := f.keep(f.keeper(), 135*time.Second)
	// 0、10、30 秒三次没成；70 秒那次成了。100 秒再出事：立刻动手，下一次只隔 10 秒，不接着上一回的 80 秒。
	if want := []int{0, 10, 30, 70, 100, 110, 130}; !reflect.DeepEqual(seconds(f.startedAt), want) {
		t.Fatalf("启动命令在第 %v 秒，要的是 %v", seconds(f.startedAt), want)
	}
	var repaired []bool
	for _, tending := range reported {
		repaired = append(repaired, tending.Repaired())
	}
	if !reflect.DeepEqual(repaired, []bool{false, false, false, true, false, false, false}) || reported[3].RetryIn != 0 {
		t.Fatalf("各次是不是修好了：%v；修好的那次：%+v", repaired, reported[3])
	}
}

func TestBackoffIsForgottenOnceThePoolIsWholeAgain(t *testing.T) {
	f := newFleet(t, "one", true)
	f.kill("gateway")
	f.broken = "gateway"
	f.onLook = func(look int) {
		switch f.elapsed() {
		case 15 * time.Second: // 有人自己把它起起来了
			f.broken = ""
			f.members.Gateway = f.up()
			f.comeUp()
			f.broken = "gateway"
		case 40 * time.Second:
			f.kill("gateway")
		}
	}

	reported := f.keep(f.keeper(), 55*time.Second)
	// 0、10 秒两次没成，本来要等到 30 秒。15 秒时池已经好了；40 秒再出事，隔 10 秒再试，不是隔 40 秒。
	if want := []int{0, 10, 40, 50}; !reflect.DeepEqual(seconds(f.startedAt), want) {
		t.Fatalf("启动命令在第 %v 秒，要的是 %v", seconds(f.startedAt), want)
	}
	// 别人修好的那一眼也报告：看到的样子变了。
	var conditions []domain.Condition
	for _, tending := range reported {
		conditions = append(conditions, tending.Condition)
	}
	if want := []domain.Condition{domain.ConditionDown, domain.ConditionDown, domain.ConditionWhole, domain.ConditionDown, domain.ConditionDown}; !reflect.DeepEqual(conditions, want) {
		t.Fatalf("%v", conditions)
	}
}

// 还没有记录的池：启动命令每次都卡在对账那一步，前置代理不开。看守照样按间隔对账，照样越试越稀。
func TestAPoolWithoutARecordStaysClosedAndKeepsBeingReconciled(t *testing.T) {
	f := newFleet(t, "one", false)
	f.members.Front = domain.Member{State: "created"}
	observed := 0
	f.afterObserve = func(time.Duration) { observed++ }

	reported := f.keep(f.keeper(), 10*time.Minute)
	if want := []int{0, 10, 30, 70, 150, 310}; !reflect.DeepEqual(seconds(f.startedAt), want) {
		t.Fatalf("启动命令在第 %v 秒，要的是 %v", seconds(f.startedAt), want)
	}
	if len(reported) != len(f.startedAt) || f.members.Front.Running || len(f.puts) != 0 {
		t.Fatalf("报告了 %d 次，前置代理 %+v，写过 %v", len(reported), f.members.Front, f.puts)
	}
	for _, tending := range reported {
		if tending.Repaired() || !strings.Contains(tending.StartErr, "exit 3") || tending.Reconciled == nil || tending.Reconciled.Outcome != OutcomeUnconfirmed {
			t.Fatalf("%+v", tending)
		}
	}
	// 每次启动之后对一次，其间至少一分钟一次。
	if observed < 10 {
		t.Fatalf("十分钟里只对了 %d 次账", observed)
	}

	// 发布了第一份之后，下一次启动命令就开得了前置代理。
	f.confirmed("one")
	reported = f.keep(f.keeper(), time.Minute)
	if len(reported) != 1 || !reported[0].Repaired() || !f.members.Front.Running || reported[0].Reconciled.Outcome != OutcomeInSync {
		t.Fatalf("%+v", reported)
	}
}

// 门没开、还在等下一次动手的时候，第一份发布做完了：账一对上，下一眼就再试，不等到时候。
func TestTheDoorIsTriedAgainAsSoonAsTheAccountAgrees(t *testing.T) {
	f := newFleet(t, "one", false)
	f.members.Front = domain.Member{State: "created"}
	f.onLook = func(int) {
		if f.elapsed() == 200*time.Second && f.record == nil {
			f.confirmed("one") // 发布器把第一份记下来了
		}
	}

	reported := f.keep(f.keeper(), 4*time.Minute)
	// 0、10、30、70、150 秒五次没成，下一次本来在 310 秒。200 秒时有了记录；210 秒那次对账对上了，215 秒那一眼就动手。
	if want := []int{0, 10, 30, 70, 150, 215}; !reflect.DeepEqual(seconds(f.startedAt), want) {
		t.Fatalf("启动命令在第 %v 秒，要的是 %v", seconds(f.startedAt), want)
	}
	if len(reported) != 7 {
		t.Fatalf("报告了 %d 次：%v", len(reported), outcomes(reported))
	}
	// 对上的那一眼自己也报告：对账的结局变了，也不用再等了。
	agreed, opened := reported[5], reported[6]
	if agreed.Acted() || agreed.Condition != domain.ConditionDown || agreed.Reconciled.Outcome != OutcomeInSync || agreed.RetryIn != 0 {
		t.Fatalf("%+v", agreed)
	}
	if !opened.Repaired() || !f.members.Front.Running || opened.RetryIn != 0 || opened.StartErr != "" {
		t.Fatalf("%+v", opened)
	}
}

// 账对上了才提前的那一次还是没成（前置代理自己起不来）：接着原来的等，不从头来；账一直对得上，也不再提前。
func TestARetryOnAgreementThatFailsKeepsTheBackoff(t *testing.T) {
	f := newFleet(t, "one", false)
	f.members.Front = domain.Member{State: "created"}
	f.broken = "front"
	f.onLook = func(int) {
		if f.elapsed() == 200*time.Second && f.record == nil {
			f.confirmed("one")
		}
	}

	reported := f.keep(f.keeper(), 12*time.Minute)
	if want := []int{0, 10, 30, 70, 150, 215, 515}; !reflect.DeepEqual(seconds(f.startedAt), want) {
		t.Fatalf("启动命令在第 %v 秒，要的是 %v", seconds(f.startedAt), want)
	}
	var waits []time.Duration
	for _, tending := range reported {
		if tending.Acted() {
			waits = append(waits, tending.RetryIn)
		}
	}
	// 第六次（215 秒，账对上才提前的那一次）没成：等的是最长的那一档，不是从 10 秒重新数起。
	if want := []int{10, 20, 40, 80, 160, 300, 300}; !reflect.DeepEqual(seconds(waits), want) || f.members.Front.Running {
		t.Fatalf("各次之后的等待是 %v 秒，要的是 %v", seconds(waits), want)
	}
}

// 前置代理起来就退出：网关的账照样对。
func TestTheGatewayKeepsBeingReconciledWhileTheFrontCannotStart(t *testing.T) {
	f := newFleet(t, "one", true)
	f.kill("front")
	f.broken = "front"
	f.onLook = func(look int) {
		if f.elapsed() == 100*time.Second {
			two := snap(t, "two")
			f.file = &two
			f.running.Digest = "digest-two"
		}
	}

	reported := f.keep(f.keeper(), 140*time.Second)
	// 70 秒那次之后，下一次动手在 150 秒。
	if want := []int{0, 10, 30, 70}; !reflect.DeepEqual(seconds(f.startedAt), want) {
		t.Fatalf("启动命令在第 %v 秒，要的是 %v", seconds(f.startedAt), want)
	}
	// 100 秒时文件被人换了。130 秒那一眼还在等下一次动手，账照样对了：看守自己把它放回去。
	if !reflect.DeepEqual(f.puts, []string{"one"}) || string(f.file.Content()) != "one" {
		t.Fatalf("写过 %v", f.puts)
	}
	restored := 0
	for _, tending := range reported {
		if tending.Reconciled != nil && tending.Reconciled.Outcome == OutcomeRestored {
			restored++
			if tending.Acted() || tending.RetryIn != 20*time.Second {
				t.Fatalf("%+v", tending)
			}
		}
	}
	if restored != 1 {
		t.Fatalf("%v", outcomes(reported))
	}
}

func TestBeingToldToStopHalfwayDoesNotLeaveThePoolStopped(t *testing.T) {
	f := newFleet(t, "one", true)
	f.kill("holder")
	ctx, cancel := context.WithCancel(background)
	defer cancel()
	f.during = func(step string) {
		if step == "stop" {
			cancel()
		}
	}

	var reported []Tending
	f.keeper().Run(ctx, func(t Tending) { reported = append(reported, t) })
	// 停下之后被叫停：启动命令照样跑完，然后才返回。
	if !reflect.DeepEqual(f.calls, []string{"stop", "start"}) || f.condition() != domain.ConditionWhole {
		t.Fatalf("做了 %v，之后是 %s", f.calls, f.condition())
	}
	// 动过的手照样报告。之后那次对账被叫停打断了：不算出错。
	if len(reported) != 1 || !reported[0].Repaired() || reported[0].Reconciled != nil || reported[0].Err != nil || f.held {
		t.Fatalf("%+v", reported)
	}
}

func TestBeingToldToStopWhileIdleIsNotReportedAsTrouble(t *testing.T) {
	// 还没开始就被叫停：一眼都不看。
	f := newFleet(t, "one", true)
	ctx, cancel := context.WithCancel(background)
	cancel()
	reports := 0
	f.keeper().Run(ctx, func(Tending) { reports++ })
	if reports != 0 || f.looks != 0 {
		t.Fatalf("报告了 %d 次，看了 %d 眼", reports, f.looks)
	}

	// 看到一半被叫停：那一眼没看成，不报告成池出了事，也不动手。
	f = newFleet(t, "one", true)
	f.kill("gateway")
	ctx, cancel = context.WithCancel(background)
	defer cancel()
	f.onLook = func(int) { cancel() }
	f.keeper().Run(ctx, func(Tending) { reports++ })
	if reports != 0 || f.looks != 1 || len(f.calls) != 0 {
		t.Fatalf("报告了 %d 次，看了 %d 眼，做了 %v", reports, f.looks, f.calls)
	}

	// 对账对到一半被叫停（文件是对的，在等读得到网关）：同样不报告。
	f = newFleet(t, "one", true)
	f.unreadable = func(time.Time) bool { return true }
	ctx, cancel = context.WithCancel(background)
	defer cancel()
	f.cancel, f.cancelAt = cancel, 3*time.Second
	f.keeper().Run(ctx, func(Tending) { reports++ })
	if reports != 0 || f.held || len(f.puts) != 0 {
		t.Fatalf("报告了 %d 次，写过 %v", reports, f.puts)
	}
}

func TestNewKeeperRefusesUnusableArguments(t *testing.T) {
	f := newFleet(t, "one", true)
	timing := DefaultTiming()
	if _, err := NewKeeper(f, f, f, timing, DefaultPace()); err != nil {
		t.Fatal(err)
	}
	if got := DefaultPace(); got.Interval != 5*time.Second || got.Reconcile != time.Minute || got.MaxBackoff != 5*time.Minute {
		t.Fatalf("%+v", got)
	}
	if _, err := NewKeeper(nil, f, f, timing, pace); err == nil {
		t.Error("没有容器也被接受了")
	}
	if _, err := NewKeeper(f, nil, f, timing, pace); err == nil {
		t.Error("没有下发也被接受了")
	}
	if _, err := NewKeeper(f, f, nil, timing, pace); err == nil {
		t.Error("没有回读也被接受了")
	}
	if _, err := NewKeeper(f, f, f, Timing{}, pace); err == nil {
		t.Error("不能用的时限被接受了")
	}
	for name, bad := range map[string]Pace{
		"不看":         {Interval: 0, Reconcile: time.Minute, MaxBackoff: time.Minute},
		"不对账":        {Interval: time.Second, Reconcile: 0, MaxBackoff: time.Minute},
		"最长的等待比间隔还短": {Interval: time.Minute, Reconcile: time.Minute, MaxBackoff: time.Second},
	} {
		if _, err := NewKeeper(f, f, f, timing, bad); err == nil {
			t.Errorf("%s：被接受了", name)
		}
	}
}
