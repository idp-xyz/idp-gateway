package application

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"go.idp.xyz/idp-gateway/internal/gatewayconfig/domain"
	"go.idp.xyz/idp-gateway/internal/gatewayconfig/ports"
)

// Pace 是守着一个池的几个间隔。
type Pace struct {
	// Interval：隔多久看一眼池里常驻的容器。
	Interval time.Duration
	// Reconcile：网关在跑时，隔多久对一次账。
	Reconcile time.Duration
	// MaxBackoff：动了手却没修好时，下一次动手之前等多久：从 Interval 的两倍起，每次加倍，最多到这么久。
	MaxBackoff time.Duration
}

// DefaultPace：容器死了，5 秒之内看得到；一分钟对一次账。
func DefaultPace() Pace {
	return Pace{Interval: 5 * time.Second, Reconcile: time.Minute, MaxBackoff: 5 * time.Minute}
}

func (p Pace) check() error {
	if p.Interval <= 0 || p.Reconcile <= 0 || p.MaxBackoff < p.Interval {
		return fmt.Errorf("gatewayconfig: unusable pace %+v", p)
	}
	return nil
}

// Keeper 守着单机上的一个池（ADR-0010 第 10 条）。常驻的容器有没在跑的，它跑启动这个池的那条命令，
// 让它们按部署规定的先后起回来：网关启动之前先把确认过的那份配置放到位，回读对上了才开前置代理。
// 网关在跑时，它隔一阵对一次账：发布器死在半路留下的文件、有人绕过发布器写的文件，到这时被收回去。
//
// 它自己不直接启动哪个容器，也不重启在跑着的容器。只有一种情况它会停容器：前置代理或网关接着的
// 是一个已经不在了的网络命名空间，这时它们本来就谁也连不到。给了 Tend 时多一种（ADR-0024）：网关经出口规则
// 按名字连的服务有了它没有记下的地址，这时去那个地址的请求已经在失败（关闭）。
//
// 另一次发布正占着这个池时它不动手：带重启的发布会让网关停一下，那不是它死了。
type Keeper struct {
	pool       ports.Pool
	delivery   ports.Delivery
	reconciler *Reconciler
	pace       Pace
	now        func() time.Time
	sleep      func(context.Context, time.Duration) error
	watch      func(Tending)
	// 另外照看的服务（Tend）。others 为 nil 时只看三个常驻的。
	others ports.Others
	tended []string
	pinned map[string]bool
	// pins 是记下的、钉住的各个服务的地址：看成的头一眼时的，或者上一次让出口规则重新解析时的。还没看成过一眼时为 nil。
	pins map[string]map[string]bool
}

// Tend 让看守另外照看几个服务（docs/adr/ADR-0024.md）。每一眼也看它们的每一个容器；有没在跑的、或者一个容器
// 都没有的，跑的是同一条启动命令，同样等占着池的发布放开、同样越试越稀。pinned 是其中网关经出口规则按名字
// 连的那几个，要在 services 里：它们有了没有记下的地址、而池里照看的容器都在跑时，看守先让出口规则重新解析
// （Others.Forget），再停下前置代理和网关、跑启动命令，网关起来时按新的解析连。看成的头一眼只记下地址：
// 看守启动之前出口规则钉的是哪些，它不知道。地址少了不算。要在 Run 之前设；不设就只看三个常驻的。
func (k *Keeper) Tend(others ports.Others, services, pinned []string) error {
	if others == nil {
		return errors.New("gatewayconfig: the services to tend need a way to see them")
	}
	if len(services) == 0 {
		return errors.New("gatewayconfig: no service to tend was given")
	}
	named := map[string]bool{}
	for _, name := range services {
		if name == "" || named[name] {
			return fmt.Errorf("gatewayconfig: the service %q to tend is empty or given twice", name)
		}
		named[name] = true
	}
	k.pinned = map[string]bool{}
	for _, name := range pinned {
		if !named[name] {
			return fmt.Errorf("gatewayconfig: the pinned service %q is not one of the services to tend", name)
		}
		k.pinned[name] = true
	}
	k.others, k.tended = others, append([]string(nil), services...)
	return nil
}

// Watch 让 f 在每看完一眼之后被叫一次，不管这一眼有没有事。Run 的 report 只在有事时才叫：一个安稳的池上
// 它一直不出声，从它那里看不出看守还在不在看。要在 Run 之前设。
func (k *Keeper) Watch(f func(Tending)) { k.watch = f }

// WithHistory 让看守每一次对账都给发布历史里停在半路的发布补结局（ADR-0013 第 4 条）。要在 Run 之前设。
func (k *Keeper) WithHistory(history ports.History) *Keeper {
	k.reconciler.WithHistory(history)
	return k
}

// NewKeeper 构造一个池的看守。对账用的是 Reconciler 的那一套，时限由 timing 给。
func NewKeeper(pool ports.Pool, delivery ports.Delivery, readBack ports.ReadBack, timing Timing, pace Pace) (*Keeper, error) {
	if pool == nil {
		return nil, errors.New("gatewayconfig: the pool's containers are required")
	}
	if err := pace.check(); err != nil {
		return nil, err
	}
	reconciler, err := NewReconciler(delivery, readBack, timing)
	if err != nil {
		return nil, err
	}
	return &Keeper{pool: pool, delivery: delivery, reconciler: reconciler, pace: pace, now: time.Now, sleep: sleep}, nil
}

// Tending 是看了一眼池之后看到了什么、做了什么。
type Tending struct {
	// Members 是动手之前三个容器的样子；Condition 和 Why 是据此得出的。没看成时 Condition 为空。
	Members   domain.Members
	Condition domain.Condition
	Why       string
	// Busy：另一次发布正占着这个池，该做的这一次没有做。
	Busy bool
	// RetryIn：动了手却没修好，离下一次动手还有这么久。
	RetryIn time.Duration
	// Failures：到这一眼为止，接连几次动了手却没修好。修好了，或者看到用不着动手（三个都在跑，另外照看的也是），
	// 从头算。由 Run 填。
	Failures int
	// Stopped：停过前置代理和网关（接在旧命名空间里的，或者为了让网关重新解析）。Started：跑过启动命令；
	// StartErr 是它没有成功时说的。
	Stopped, Started bool
	StartErr         string
	// Services 是另外照看的服务（Tend）动手之前的样子；没有另外照看的服务时为空。
	Services []domain.Service
	// Moved 是钉住的服务有了的、没有记下的地址，"服务 地址"。
	Moved []string
	// Forgot：为 Moved 让出口规则重新解析过（Others.Forget）。没成时 Err 说原因，后面的停、起没有做。
	Forgot bool
	// After 是动过手之后三个容器的样子，ServicesAfter 是另外照看的服务的；没有动手、或者之后没看成时为 nil。
	After         *domain.Members
	ServicesAfter []domain.Service
	// Reconciled 是这一次对账的结果；没有对账时为 nil。
	Reconciled *Result
	// Err：这一次没看成，或者有一步没做成。
	Err error
}

// Acted 报告这一次有没有动过池里的容器，或者让出口规则重新解析过。
func (t Tending) Acted() bool { return t.Stopped || t.Started || t.Forgot }

// Repaired 报告动过手之后三个容器、另外照看的服务是不是都好了。
func (t Tending) Repaired() bool {
	if t.After == nil {
		return false
	}
	condition, _ := t.After.Condition()
	return condition == domain.ConditionWhole && domain.Down(t.ServicesAfter) == ""
}

// settled 报告这一眼看到的用不着动手：三个常驻的、另外照看的都在跑，钉住的地址也没有多出来。
func (t Tending) settled() bool {
	return t.Condition == domain.ConditionWhole && domain.Down(t.Services) == "" && len(t.Moved) == 0
}

// repin 报告该让网关跟上钉住的服务的新地址了：别的都好，只是地址多出来了。
func (t Tending) repin() bool {
	return t.Condition == domain.ConditionWhole && domain.Down(t.Services) == "" && len(t.Moved) > 0
}

func signature(condition domain.Condition, why, others string, busy bool, err error) string {
	return fmt.Sprintf("%s|%s|%s|%t|%v", condition, why, others, busy, err)
}

// seen 是这一眼看到的样子：与上一次报告留下的一样，就不用再报告。
func (t Tending) seen() string {
	return signature(t.Condition, t.Why, domain.Down(t.Services)+"|"+strings.Join(t.Moved, ","), t.Busy, t.Err)
}

// left 是这一次报告留下的样子：动过手的，是动手之后的。地址动手之后已经记下了。
func (t Tending) left() string {
	if t.After == nil {
		return t.seen()
	}
	condition, why := t.After.Condition()
	return signature(condition, why, domain.Down(t.ServicesAfter)+"|", false, t.Err)
}

// reconciled 是对账的结局：与上一次报告的一样，也不用再报告。
func (t Tending) reconciled() string {
	return string(t.Reconciled.Outcome) + "|" + t.Reconciled.Reason
}

// agrees 报告这一次对账之后账是不是对上了：本来就对（IN_SYNC），或者放回去之后对上了（RESTORED）。
// 这之后再跑启动命令，它里面的那一步对账过得去，前置代理开得了门。
func (r Result) agrees() bool {
	return r.Outcome == OutcomeInSync || r.Outcome == OutcomeRestored
}

// Run 一直守着，直到 ctx 被取消。有事才叫 report：动过手的，往回放过文件的，以及看到的样子或对账的结局
// 与上一次报告时不同的。一个安安稳稳的池，开头报告一次，之后不出声。
//
// 已经开始的一步做完才返回。
func (k *Keeper) Run(ctx context.Context, report func(Tending)) {
	var (
		reconciledAt time.Time // 上一次对账的时刻
		failures     int       // 接连几次动了手却没修好
		notBefore    time.Time // 这个时刻之前不再动手
		agreed       bool      // 上一次对账时账是对上的
		seen         string    // 上一次报告留下的样子
		reconciled   string    // 上一次报告的对账结局
	)
	for ctx.Err() == nil {
		due := reconciledAt.IsZero() || !k.now().Before(reconciledAt.Add(k.pace.Reconcile))
		tending := k.tend(ctx, due, notBefore)
		if ctx.Err() != nil && !tending.Acted() {
			return // 被叫停了：这一眼没看完，不是池出了事
		}
		now := k.now()
		switch {
		case tending.Acted() && !tending.Repaired():
			failures++
			tending.RetryIn = k.backoff(failures)
			notBefore = now.Add(tending.RetryIn)
		case tending.Acted(), tending.settled():
			// 修好了，或者别人修好了：下一次出事不接着上一回的等。
			failures, notBefore = 0, time.Time{}
		case tending.Reconciled != nil && tending.Reconciled.agrees() && !agreed:
			// 还在等下一次动手，账这时却对上了：第一份发布做完了，或者网关这才读得到。上一回没成的原因
			// 多半已经不在，下一眼就再试，不等到时候。这一次还不成的话接着原来的等：failures 不清零。
			notBefore, tending.RetryIn = time.Time{}, 0
		}
		tending.Failures = failures
		switch {
		case tending.Reconciled != nil:
			agreed = tending.Reconciled.agrees()
		case tending.Stopped || tending.Started:
			agreed = false // 动过手之后没有对成账：网关没在跑，或者池被占着。只 forget 没成的，网关没有被碰过
		}
		if k.watch != nil {
			k.watch(tending)
		}
		worth := tending.Acted() || tending.seen() != seen
		if tending.Reconciled != nil {
			reconciledAt = now
			worth = worth || tending.Reconciled.Replaced || tending.reconciled() != reconciled
		}
		if worth {
			seen = tending.left()
			if tending.Reconciled != nil {
				reconciled = tending.reconciled()
			}
			report(tending)
		}
		if k.sleep(ctx, k.pace.Interval) != nil {
			return
		}
	}
}

// backoff 是接连 failures 次没修好之后，下一次动手之前等多久。一个起不来的网关、一个还没有记录的池，
// 启动命令每次都要失败；不等的话就是每隔 Interval 把这条命令再跑一遍。
//
// 有一种情况不等到时候：等着的时候对账的结局变成了对得上（见 Run）。
func (k *Keeper) backoff(failures int) time.Duration {
	delay := k.pace.Interval
	for i := 0; i < failures; i++ {
		if delay > k.pace.MaxBackoff/2 {
			return k.pace.MaxBackoff
		}
		delay *= 2
	}
	return delay
}

// tend 看一眼，该动手就动手。due 表示该对账了；notBefore 之前不动容器。
func (k *Keeper) tend(ctx context.Context, due bool, notBefore time.Time) Tending {
	var t Tending
	members, err := k.pool.Members(ctx)
	if err != nil {
		t.Err = fmt.Errorf("pool: %w", err)
		return t
	}
	t.Members = members
	t.Condition, t.Why = members.Condition()
	if k.others != nil {
		services, err := k.others.Services(ctx, k.tended)
		if err != nil {
			t.Err = fmt.Errorf("pool: %w", err)
			return t
		}
		t.Services = k.mark(services)
		t.Moved = k.moved(t.Services)
	}
	if wait := notBefore.Sub(k.now()); t.settled() || wait > 0 {
		if !t.settled() {
			t.RetryIn = wait
		}
		// 前置代理没有开的时候（比如这个池还没有记录），账照样要对。
		if due && gatewayUp(members) {
			k.reconcile(ctx, &t)
		}
		return t
	}
	// 另一次发布正占着这个池时不插手。这里只是看一眼就放开：启动命令里的那两步自己要占它。
	release, err := k.delivery.Hold(ctx)
	if errors.Is(err, ports.ErrBusy) {
		t.Busy = true
		return t
	}
	if err != nil {
		t.Err = fmt.Errorf("delivery: %w", err)
		return t
	}
	release()

	// 开始动手之后不随 ctx 取消：停下了的就要接着起起来。
	steady := context.WithoutCancel(ctx)
	switch {
	case t.Condition == domain.ConditionOrphaned:
		t.Stopped = true
		if err := k.pool.StopDependents(steady); err != nil {
			t.Err = fmt.Errorf("pool: %w", err)
			return t
		}
	case t.repin():
		// 只让出口规则重新解析不够：在跑着的网关还连它记着的地址（tests/integration/coordinators 的 CO-07）。
		t.Forgot = true
		if err := k.others.Forget(steady); err != nil {
			t.Err = fmt.Errorf("pool: %w", err)
			return t
		}
		t.Stopped = true
		if err := k.pool.StopDependents(steady); err != nil {
			t.Err = fmt.Errorf("pool: %w", err)
			return t
		}
		// 规则已经按这一眼的解析钉好，网关停下了，起来时也按它连：从这时起记的是这一眼的地址。
		k.remember(t.Services)
	}
	t.Started = true
	if err := k.pool.Start(steady); err != nil {
		t.StartErr = err.Error()
	}
	after, err := k.pool.Members(steady)
	if err != nil {
		t.Err = fmt.Errorf("pool: %w", err)
		return t
	}
	if k.others != nil {
		services, err := k.others.Services(steady, k.tended)
		if err != nil {
			t.Err = fmt.Errorf("pool: %w", err)
			return t
		}
		t.ServicesAfter = k.mark(services)
	}
	t.After = &after
	// 启动命令里已经对过一次账。这里再对一次，为的是它的结局：启动命令没有成功时，它只说得出是哪一步。
	if gatewayUp(after) {
		k.reconcile(ctx, &t)
	}
	return t
}

// mark 标出其中网关经出口规则按名字连的那几个。
func (k *Keeper) mark(services []domain.Service) []domain.Service {
	for i := range services {
		services[i].Pinned = k.pinned[services[i].Name]
	}
	return services
}

// moved 是钉住的服务有了的、没有记下的地址。看成的头一眼只记下，不算。
func (k *Keeper) moved(services []domain.Service) []string {
	if k.pins == nil {
		k.remember(services)
		return nil
	}
	var moved []string
	for _, service := range services {
		if !service.Pinned {
			continue
		}
		for _, address := range service.Addresses() {
			if !k.pins[service.Name][address] {
				moved = append(moved, service.Name+" "+address)
			}
		}
	}
	return moved
}

// remember 记下钉住的服务现在的地址，换掉原来记着的。
func (k *Keeper) remember(services []domain.Service) {
	k.pins = map[string]map[string]bool{}
	for _, service := range services {
		if !service.Pinned {
			continue
		}
		k.pins[service.Name] = map[string]bool{}
		for _, address := range service.Addresses() {
			k.pins[service.Name][address] = true
		}
	}
}

// gatewayUp 报告网关是不是在跑，并且接在一个还在的命名空间里：这时才有账可对。
func gatewayUp(members domain.Members) bool {
	return members.Holder.Running && members.Gateway.Running && !members.Gateway.Started.Before(members.Holder.Started)
}

func (k *Keeper) reconcile(ctx context.Context, t *Tending) {
	result, err := k.reconciler.Reconcile(ctx)
	switch {
	case errors.Is(err, ports.ErrBusy):
		t.Busy = true
	case err != nil && ctx.Err() != nil:
		// 被叫停了，没有对完：不是出了错。
	case err != nil:
		t.Err = err
	default:
		t.Reconciled = &result
	}
}
