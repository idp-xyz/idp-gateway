package application

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"go.idp.xyz/idp-gateway/internal/gatewayconfig/domain"
)

// neighbours 模拟池里另外照看的服务（ADR-0024）：叠加文件里的 gateway-authz（两个副本，网关经出口规则按名字连它）
// 和 authz-state（一个）。它接在 fleet 上：fleet 的启动命令也把这里没在跑的容器起起来，和真的 docker compose up -d 一样；
// 在跑着的不动。
type neighbours struct {
	f        *fleet
	services []domain.Service
	// was 是每个容器停下之前的地址：没在跑的容器没有地址，起来时还是它（docker 多半给回同一个）。
	was map[string][]string
	// next：起来时换一个地址的容器。
	next map[string]string
	// looks 是看过几眼；lookErr 是第几眼（从 1 数）返回什么错误。
	looks   int
	lookErr map[int]error
	// broken 是启动命令起不来的服务；forgetErr 是 forget 返回的错误。
	broken    string
	forgetErr error
	forgets   int
}

func newNeighbours(f *fleet) *neighbours {
	n := &neighbours{f: f, was: map[string][]string{}, next: map[string]string{}, lookErr: map[int]error{}}
	n.services = []domain.Service{
		{Name: "gateway-authz", Replicas: []domain.Replica{
			{Name: "pool-gateway-authz-1", Running: true, State: "running", Addresses: []string{"172.30.0.5"}},
			{Name: "pool-gateway-authz-2", Running: true, State: "running", Addresses: []string{"172.30.0.6"}},
		}},
		{Name: "authz-state", Replicas: []domain.Replica{
			{Name: "pool-authz-state-1", Running: true, State: "running", Addresses: []string{"172.30.0.4"}},
		}},
	}
	f.during = func(step string) {
		if step == "start" {
			n.start()
		}
	}
	return n
}

// keeper 是照看这两个服务的看守：gateway-authz 是钉住的。
func (n *neighbours) keeper() *Keeper {
	n.f.t.Helper()
	keeper := n.f.keeper()
	if err := keeper.Tend(n, []string{"gateway-authz", "authz-state"}, []string{"gateway-authz"}); err != nil {
		n.f.t.Fatal(err)
	}
	return keeper
}

func (n *neighbours) replica(name string) *domain.Replica {
	for i := range n.services {
		for j := range n.services[i].Replicas {
			if n.services[i].Replicas[j].Name == name {
				return &n.services[i].Replicas[j]
			}
		}
	}
	n.f.t.Fatalf("没有叫 %s 的容器", name)
	return nil
}

// kill 让一个容器死掉：它的地址跟着没了。
func (n *neighbours) kill(name string) {
	r := n.replica(name)
	n.was[name] = r.Addresses
	r.Running, r.State, r.Addresses = false, "exited (137)", nil
}

// move 让一个在跑的容器换了地址（像 docker network disconnect、connect 之后那样），容器一直在跑。
func (n *neighbours) move(name, address string) { n.replica(name).Addresses = []string{address} }

// start 是启动命令在这些服务上做的：没在跑的起起来，在跑的不动。
func (n *neighbours) start() {
	for i := range n.services {
		if n.services[i].Name == n.broken {
			continue
		}
		for j := range n.services[i].Replicas {
			r := &n.services[i].Replicas[j]
			if r.Running {
				continue
			}
			r.Running, r.State, r.Addresses = true, "running", n.was[r.Name]
			if address, ok := n.next[r.Name]; ok {
				r.Addresses = []string{address}
			}
		}
	}
}

// Others
func (n *neighbours) Services(ctx context.Context, names []string) ([]domain.Service, error) {
	n.looks++
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := n.lookErr[n.looks]; err != nil {
		return nil, err
	}
	var seen []domain.Service
	for _, name := range names {
		service := domain.Service{Name: name}
		for _, s := range n.services {
			if s.Name != name {
				continue
			}
			for _, r := range s.Replicas {
				r.Addresses = append([]string(nil), r.Addresses...)
				service.Replicas = append(service.Replicas, r)
			}
		}
		seen = append(seen, service)
	}
	return seen, nil
}

func (n *neighbours) Forget(ctx context.Context) error {
	n.f.calls = append(n.f.calls, "forget")
	n.forgets++
	if n.f.held {
		n.f.t.Error("forget 时还占着这个池")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return n.forgetErr
}

func allRunning(services []domain.Service) bool {
	return len(services) > 0 && domain.Down(services) == ""
}

func TestATendedServiceThatDiedIsBroughtBackByTheStartCommand(t *testing.T) {
	for _, dead := range [][]string{{"pool-gateway-authz-2"}, {"pool-authz-state-1"}, {"pool-gateway-authz-1", "pool-gateway-authz-2", "pool-authz-state-1"}} {
		f := newFleet(t, "one", true)
		n := newNeighbours(f)
		keeper := n.keeper()
		before := f.members
		if first := keeper.tend(background, false, time.Time{}); first.Acted() || !allRunning(first.Services) || len(first.Moved) != 0 {
			t.Fatalf("%v：头一眼 %+v", dead, first)
		}
		for _, name := range dead {
			n.kill(name)
		}

		tending := keeper.tend(background, false, time.Time{})
		// 三个常驻的都在跑；另外照看的里有没在跑的：跑的是同一条启动命令，不停任何容器。
		if tending.Condition != domain.ConditionWhole || !tending.Started || tending.Stopped || tending.Forgot || tending.Err != nil || tending.StartErr != "" {
			t.Fatalf("%v 死了：%+v", dead, tending)
		}
		for _, name := range dead {
			if !strings.Contains(domain.Down(tending.Services), name+" is not running (exited (137))") {
				t.Fatalf("%v 死了：看到的是 %q", dead, domain.Down(tending.Services))
			}
		}
		if !reflect.DeepEqual(f.calls, []string{"start"}) || !tending.Repaired() || !allRunning(tending.ServicesAfter) {
			t.Fatalf("%v 死了：做了 %v，之后是 %+v", dead, f.calls, tending.ServicesAfter)
		}
		// 三个常驻的没有被动过；地址没变的，不用让网关跟上。
		if f.members != before || tending.Reconciled == nil || tending.Reconciled.Outcome != OutcomeInSync {
			t.Fatalf("%v 死了：常驻的 %+v，对账 %+v", dead, f.members, tending.Reconciled)
		}
		if next := keeper.tend(background, false, time.Time{}); next.Acted() || !next.settled() || n.forgets != 0 {
			t.Fatalf("%v 死了：下一眼 %+v", dead, next)
		}
	}
}

func TestATendedServiceWithoutAnyContainerIsStartedToo(t *testing.T) {
	f := newFleet(t, "one", true)
	n := newNeighbours(f)
	n.services[1].Replicas = nil // authz-state 还没有容器（比如叠加文件是后来加的）
	n.f.during = func(step string) {
		if step == "start" {
			n.services[1].Replicas = []domain.Replica{{Name: "pool-authz-state-1", Running: true, State: "running", Addresses: []string{"172.30.0.4"}}}
		}
	}
	tending := n.keeper().tend(background, false, time.Time{})
	if !tending.Started || domain.Down(tending.Services) != "authz-state has no container" || !tending.Repaired() {
		t.Fatalf("%+v", tending)
	}
}

func TestATendedServiceIsLeftAloneWhileAPublicationHoldsThePool(t *testing.T) {
	f := newFleet(t, "one", true)
	n := newNeighbours(f)
	keeper := n.keeper()
	n.kill("pool-authz-state-1")
	release, err := f.Hold(background)
	if err != nil {
		t.Fatal(err)
	}
	tending := keeper.tend(background, true, time.Time{})
	if !tending.Busy || tending.Acted() || len(f.calls) != 0 || tending.Reconciled != nil {
		t.Fatalf("%+v，做了 %v", tending, f.calls)
	}
	release()
	tending = keeper.tend(background, true, time.Time{})
	if tending.Busy || !tending.Started || !tending.Repaired() || !reflect.DeepEqual(f.calls, []string{"start"}) {
		t.Fatalf("%+v，做了 %v", tending, f.calls)
	}
}

// 网关经出口规则按名字连 gateway-authz。一个副本在跑着的时候换了地址：出口规则不认新地址，网关还连旧的，
// 去那里的请求已经在失败（关闭）。看守先 forget，再停下前置代理和网关、跑启动命令。
func TestANewAddressOfAPinnedServiceIsFollowed(t *testing.T) {
	f := newFleet(t, "one", true)
	n := newNeighbours(f)
	keeper := n.keeper()
	// 头一眼只记下：看守启动之前出口规则钉的是哪些，它不知道。
	first := keeper.tend(background, false, time.Time{})
	if first.Acted() || len(first.Moved) != 0 || !first.settled() {
		t.Fatalf("头一眼：%+v", first)
	}
	before := f.members
	n.move("pool-gateway-authz-1", "172.30.0.9")

	tending := keeper.tend(background, false, time.Time{})
	if !reflect.DeepEqual(tending.Moved, []string{"gateway-authz 172.30.0.9"}) || tending.Condition != domain.ConditionWhole {
		t.Fatalf("%+v", tending)
	}
	if !tending.Forgot || !tending.Stopped || !tending.Started || tending.Err != nil || tending.StartErr != "" || !tending.Repaired() {
		t.Fatalf("%+v", tending)
	}
	// 先让出口规则重新解析，再停前置代理和网关，再跑启动命令（place、egress、网关、confirm，对上了才开 front）。
	if !reflect.DeepEqual(f.calls, []string{"forget", "stop", "start"}) {
		t.Fatalf("做了 %v", f.calls)
	}
	// 网关和前置代理是新起的，占着命名空间的那个没动；gateway-authz 的两个副本一直在跑，没有被重启。
	if f.members.Holder != before.Holder || f.members.Gateway == before.Gateway || f.members.Front == before.Front {
		t.Fatalf("之前 %+v，之后 %+v", before, f.members)
	}
	for _, r := range tending.ServicesAfter[0].Replicas {
		if !r.Running {
			t.Fatalf("%+v", tending.ServicesAfter)
		}
	}
	if tending.Reconciled == nil || tending.Reconciled.Outcome != OutcomeInSync {
		t.Fatalf("%+v", tending.Reconciled)
	}
	// 记下的是新的那一组：下一眼不再动手。
	if next := keeper.tend(background, false, time.Time{}); next.Acted() || len(next.Moved) != 0 || !next.settled() {
		t.Fatalf("下一眼：%+v", next)
	}
	// 后来它又回到原来的地址：forget 丢掉了原来的钉，这又是一个新地址。
	n.move("pool-gateway-authz-1", "172.30.0.5")
	if again := keeper.tend(background, false, time.Time{}); !reflect.DeepEqual(again.Moved, []string{"gateway-authz 172.30.0.5"}) || !again.Forgot {
		t.Fatalf("又换回去：%+v", again)
	}
}

// 看守启动时地址就已经和出口规则钉的不同：它不知道，头一眼只记下，什么都不做。之后一直安稳，就一直不出声。
func TestTheFirstLookOnlyRecordsTheAddresses(t *testing.T) {
	f := newFleet(t, "one", true)
	n := newNeighbours(f)
	reported := f.keep(n.keeper(), 10*time.Minute)
	if len(reported) != 1 || reported[0].Acted() || len(reported[0].Moved) != 0 || !allRunning(reported[0].Services) {
		t.Fatalf("%+v", reported)
	}
	if len(f.calls) != 0 || n.forgets != 0 || n.looks != 120 {
		t.Fatalf("做了 %v，forget %d 次，看了 %d 眼", f.calls, n.forgets, n.looks)
	}
	if !reported[0].Services[0].Pinned || reported[0].Services[1].Pinned {
		t.Fatalf("%+v", reported[0].Services)
	}
}

// 少了一个副本（缩容）：少了的地址不算。之后再多出一个：用的是记着的那个地址就不算，用的是新地址才算。
func TestAnAddressThatGoesAwayIsNotFollowed(t *testing.T) {
	f := newFleet(t, "one", true)
	n := newNeighbours(f)
	keeper := n.keeper()
	keeper.tend(background, false, time.Time{})
	n.services[0].Replicas = n.services[0].Replicas[:1]
	if tending := keeper.tend(background, false, time.Time{}); tending.Acted() || len(tending.Moved) != 0 || !tending.settled() {
		t.Fatalf("缩容：%+v", tending)
	}
	n.services[0].Replicas = append(n.services[0].Replicas, domain.Replica{Name: "pool-gateway-authz-2", Running: true, State: "running", Addresses: []string{"172.30.0.6"}})
	if tending := keeper.tend(background, false, time.Time{}); tending.Acted() || len(tending.Moved) != 0 {
		t.Fatalf("回到原来的地址：%+v", tending)
	}
	n.services[0].Replicas = append(n.services[0].Replicas, domain.Replica{Name: "pool-gateway-authz-3", Running: true, State: "running", Addresses: []string{"172.30.0.7"}})
	if tending := keeper.tend(background, false, time.Time{}); !reflect.DeepEqual(tending.Moved, []string{"gateway-authz 172.30.0.7"}) || !tending.Forgot {
		t.Fatalf("扩容到新地址：%+v", tending)
	}
	if len(f.calls) != 3 || n.forgets != 1 {
		t.Fatalf("做了 %v", f.calls)
	}
}

// authz-state 网关不连（连它的是 gateway-authz，没有出口规则）：它换了地址不用谁跟上。
func TestANewAddressOfAServiceThatIsNotPinnedChangesNothing(t *testing.T) {
	f := newFleet(t, "one", true)
	n := newNeighbours(f)
	keeper := n.keeper()
	keeper.tend(background, false, time.Time{})
	n.move("pool-authz-state-1", "172.30.0.20")
	reported := f.keep(keeper, time.Minute)
	if len(reported) != 1 || reported[0].Acted() || len(reported[0].Moved) != 0 || len(f.calls) != 0 || n.forgets != 0 {
		t.Fatalf("%+v，做了 %v", reported, f.calls)
	}
}

// 一次发布正占着池：新地址照样看到、照样报告，这一眼不动手；放开之后的那一眼才动手。
func TestANewAddressIsFollowedOnlyOnceThePoolIsFree(t *testing.T) {
	f := newFleet(t, "one", true)
	n := newNeighbours(f)
	keeper := n.keeper()
	keeper.tend(background, false, time.Time{})
	n.move("pool-gateway-authz-2", "172.30.0.8")
	release, err := f.Hold(background)
	if err != nil {
		t.Fatal(err)
	}
	busy := keeper.tend(background, false, time.Time{})
	if !busy.Busy || busy.Acted() || !reflect.DeepEqual(busy.Moved, []string{"gateway-authz 172.30.0.8"}) || len(f.calls) != 0 {
		t.Fatalf("%+v，做了 %v", busy, f.calls)
	}
	release()
	// 占着的时候没有记下：放开之后的这一眼还看得到它。
	done := keeper.tend(background, false, time.Time{})
	if done.Busy || !done.Forgot || !done.Repaired() || !reflect.DeepEqual(f.calls, []string{"forget", "stop", "start"}) {
		t.Fatalf("%+v，做了 %v", done, f.calls)
	}
}

// forget 没成：不停网关（停了也连不上新地址），不记下，越隔越久再试；成了之后从头算。
func TestAForgetThatFailsIsRetriedLessAndLessOften(t *testing.T) {
	f := newFleet(t, "one", true)
	n := newNeighbours(f)
	n.forgetErr = errors.New(`container: docker compose run --rm --no-deps egress forget: exit status 1: pin-egress: cannot read /work/config/config.yaml`)
	keeper := n.keeper()
	var forgotAt []time.Duration
	f.onLook = func(look int) {
		switch f.elapsed() {
		case 5 * time.Second:
			n.move("pool-gateway-authz-1", "172.30.0.9")
		case 100 * time.Second: // 有人把毛病修好了
			n.forgetErr = nil
		}
	}
	keeper.Watch(func(tending Tending) {
		if tending.Forgot {
			forgotAt = append(forgotAt, f.elapsed())
		}
	})
	reported := f.keep(keeper, 3*time.Minute)
	// 第 5 秒那一眼看到新地址就动手；之后隔 10、20、40、80 秒。第 100 秒毛病没了，第 155 秒那次成了。
	if want := []int{5, 15, 35, 75, 155}; !reflect.DeepEqual(seconds(forgotAt), want) {
		t.Fatalf("forget 在第 %v 秒，要的是 %v", seconds(forgotAt), want)
	}
	var failed int
	for _, tending := range reported {
		if !tending.Forgot {
			continue
		}
		if tending.Err != nil {
			failed++
			if tending.Stopped || tending.Started || tending.Repaired() || !strings.Contains(tending.Err.Error(), "pool: container: docker compose run --rm --no-deps egress forget") {
				t.Fatalf("%+v", tending)
			}
		} else if !tending.Stopped || !tending.Started || !tending.Repaired() {
			t.Fatalf("%+v", tending)
		}
	}
	if failed != 4 || !reflect.DeepEqual(f.calls, []string{"forget", "forget", "forget", "forget", "forget", "stop", "start"}) {
		t.Fatalf("没成 %d 次，做了 %v", failed, f.calls)
	}
}

// 有副本没在跑、钉住的另一个也换了地址：先把没在跑的起起来；都在跑了，下一眼再让网关跟上。
func TestANewAddressWaitsUntilEverythingRuns(t *testing.T) {
	f := newFleet(t, "one", true)
	n := newNeighbours(f)
	keeper := n.keeper()
	keeper.tend(background, false, time.Time{})
	n.kill("pool-gateway-authz-2")
	n.next["pool-gateway-authz-2"] = "172.30.0.9" // 起来时换了地址
	started := keeper.tend(background, false, time.Time{})
	if !started.Started || started.Forgot || started.Stopped || len(started.Moved) != 0 || !started.Repaired() {
		t.Fatalf("%+v", started)
	}
	followed := keeper.tend(background, false, time.Time{})
	if !reflect.DeepEqual(followed.Moved, []string{"gateway-authz 172.30.0.9"}) || !followed.Forgot || !followed.Repaired() {
		t.Fatalf("%+v", followed)
	}
	if !reflect.DeepEqual(f.calls, []string{"start", "forget", "stop", "start"}) {
		t.Fatalf("做了 %v", f.calls)
	}
}

// 起不来的副本：同一套越试越稀，不因为三个常驻的都在跑就每一眼再试一次。
func TestATendedServiceThatCannotStartIsRetriedLessAndLessOften(t *testing.T) {
	f := newFleet(t, "one", true)
	n := newNeighbours(f)
	n.kill("pool-authz-state-1")
	n.broken = "authz-state"
	reported := f.keep(n.keeper(), 10*time.Minute)
	if want := []int{0, 10, 30, 70, 150, 310}; !reflect.DeepEqual(seconds(f.startedAt), want) {
		t.Fatalf("启动命令在第 %v 秒，要的是 %v", seconds(f.startedAt), want)
	}
	for _, tending := range reported {
		if !tending.Started || tending.Repaired() || !strings.Contains(domain.Down(tending.ServicesAfter), "pool-authz-state-1 is not running") {
			t.Fatalf("%+v", tending)
		}
	}
	// 三个常驻的一直在跑，账照样按时对。
	if f.condition() != domain.ConditionWhole || len(f.puts) != 0 {
		t.Fatalf("%s，写过 %v", f.condition(), f.puts)
	}
}

func TestALookAtTheTendedServicesThatFailsChangesNothing(t *testing.T) {
	f := newFleet(t, "one", true)
	n := newNeighbours(f)
	n.kill("pool-authz-state-1")
	for look := 1; look <= 3; look++ {
		n.lookErr[look] = errors.New("container: docker network ls: exit status 1: Cannot connect to the Docker daemon")
	}
	reported := f.keep(n.keeper(), 20*time.Second)
	if len(reported) != 2 || reported[0].Err == nil || reported[0].Acted() || !strings.Contains(reported[0].Err.Error(), "pool: container: docker network ls") {
		t.Fatalf("%+v", reported)
	}
	// 第四眼看成了：头一眼只记下地址，没在跑的照样起起来。
	if !reported[1].Started || !reported[1].Repaired() || !reflect.DeepEqual(seconds(f.startedAt), []int{15}) {
		t.Fatalf("%+v，启动命令在第 %v 秒", reported[1], seconds(f.startedAt))
	}
}

// 动过手之后另外照看的服务没看成：不知道修没修好，按没修好算。
func TestNotSeeingTheTendedServicesAfterAStartCountsAsNotRepaired(t *testing.T) {
	f := newFleet(t, "one", true)
	n := newNeighbours(f)
	keeper := n.keeper()
	keeper.tend(background, false, time.Time{})
	n.kill("pool-authz-state-1")
	n.lookErr[3] = errors.New("container: docker inspect: exit status 1")
	tending := keeper.tend(background, false, time.Time{})
	if !tending.Started || tending.After != nil || tending.Repaired() || tending.Err == nil {
		t.Fatalf("%+v", tending)
	}
}

func TestWithoutTendTheKeeperLooksOnlyAtTheThree(t *testing.T) {
	f := newFleet(t, "one", true)
	n := newNeighbours(f)
	n.kill("pool-authz-state-1")
	n.move("pool-gateway-authz-1", "172.30.0.9")
	reported := f.keep(f.keeper(), time.Minute)
	if len(reported) != 1 || reported[0].Services != nil || reported[0].Moved != nil || reported[0].Acted() || n.looks != 0 || len(f.calls) != 0 {
		t.Fatalf("%+v，看了 %d 眼，做了 %v", reported, n.looks, f.calls)
	}
}

func TestTendRefusesUnusableArguments(t *testing.T) {
	f := newFleet(t, "one", true)
	n := newNeighbours(f)
	for name, c := range map[string]struct {
		others           *neighbours
		services, pinned []string
		says             string
	}{
		"没有看它们的办法":   {nil, []string{"gateway-authz"}, nil, "need a way to see them"},
		"一个服务都没有":    {n, nil, nil, "no service to tend"},
		"名字是空的":      {n, []string{""}, nil, "empty or given twice"},
		"给了两次":       {n, []string{"authz-state", "authz-state"}, nil, "empty or given twice"},
		"钉住的不在照看的里面": {n, []string{"authz-state"}, []string{"gateway-authz"}, "not one of the services to tend"},
	} {
		keeper := f.keeper()
		var err error
		if c.others == nil {
			err = keeper.Tend(nil, c.services, c.pinned)
		} else {
			err = keeper.Tend(c.others, c.services, c.pinned)
		}
		if err == nil || !strings.Contains(err.Error(), c.says) || keeper.others != nil {
			t.Errorf("%s：%v", name, err)
		}
	}
}
