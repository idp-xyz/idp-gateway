// Package application 把往一个池发布一份快照这件事串起来：先离线加载，再换上去，经回读确认；
// 没有生效就把上一份放回去。要重启网关才生效的快照走 Restart；池和记录对不上时由 Reconcile 收拾。
// 它不知道快照是怎么送到网关那里的，也不知道回读走的是什么协议。
//
// 做法和它的依据见 docs/adr/ADR-0010.md 第 6、10 条和 tests/integration/compose/README.md。
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

// Outcome 是一次操作的结局。
type Outcome string

// 发布（Publish）和重启（Restart）的结局。REFUSED、RESTART_REQUIRED、POOL_NOT_READY 时池没有被碰过。
const (
	// OutcomeActive：这份快照正在池里的网关上生效，并且记成了这个池上最后一次得到确认的。
	OutcomeActive Outcome = "ACTIVE"
	// OutcomeRefused：动手之前就被挡下了。快照里有要拿环境变量去换的写法，网关加载不了这份快照，
	// 加载出来不带必须的设置，或者（重启时）这份快照用不着重启。
	OutcomeRefused Outcome = "REFUSED"
	// OutcomeRestartRequired：这份快照要重启网关才能全部生效（启动设置不同，或者网关的构建不同）。
	// 重启会让这个池中断，不在一次发布里自动做。
	OutcomeRestartRequired Outcome = "RESTART_REQUIRED"
	// OutcomePoolNotReady：动手之前池的状态就不对：网关上一次加载失败，存储不是只读，
	// 或者放在那里的不是记录里确认过的那一份（也不是正要发布的、已经在生效的这一份）。要先对账。
	OutcomePoolNotReady Outcome = "POOL_NOT_READY"
	// OutcomeRestored：换上去了，没有生效；上一份已经放回去，网关报告它在跑的又是之前的那一份。
	// 对账时：池和记录对不上，记录的那一份已经放回去并得到确认。
	OutcomeRestored Outcome = "RESTORED"
	// OutcomeUnknown：换上去了，没有生效，也没能确认放回去了。不是成功也不是失败，要对账。
	// 对账时：记录的那一份在不在网关上生效，没能读到。
	OutcomeUnknown Outcome = "UNKNOWN"
)

// 只有对账（Reconcile）才有的结局。
const (
	// OutcomeInSync：放在那里的就是记录里确认过的那一份，网关报告它在跑的也是。什么都没有写。
	OutcomeInSync Outcome = "IN_SYNC"
	// OutcomeUnconfirmed：没有可以拿来对的记录。这个池上还没有确认过任何发布，或者记录是在网关的
	// 另一个构建上做的。再发布一次才有。
	OutcomeUnconfirmed Outcome = "UNCONFIRMED"
	// OutcomeRestartPending：文件和运行配置都对得上，但网关的启动设置不是确认这份快照时的那一套：
	// 它带着别的文件重启过。要再重启一次才回得去。
	OutcomeRestartPending Outcome = "RESTART_PENDING"
)

// Result 是一次操作做了什么、看到了什么。
type Result struct {
	Outcome Outcome
	// Snapshot 是要发布的快照（对账时是记录里确认过的那一份）；Previous 是动手之前放在那里的，
	// 那里什么都没有时为空。
	Snapshot string
	Previous string
	// Replaced 报告这一次有没有往池里写过配置。
	Replaced bool
	// Restarted 报告这一次有没有重启过网关。
	Restarted bool
	// Expected 是期望的运行配置摘要：发布时来自离线加载（没有通过时为空），对账时来自记录。
	Expected string
	// Observed 是最后一次从池里的网关读到的。
	Observed domain.Observation
	// Reason 说明为什么不是 ACTIVE（对账时：为什么不是 IN_SYNC）。
	Reason string
	// Restart 列出不同的启动设置：RESTART_REQUIRED、RESTART_PENDING，以及重启时要改的那几项。
	Restart []string
}

// Timing 是换上文件之后等网关的几个时限。
type Timing struct {
	// Settle：换上文件之后至少过这么久，读到的才算数。网关攒 250 毫秒才重载；新旧两份的运行配置
	// 相同时，更早读到的"已生效"说明不了它已经加载过新文件。
	Settle time.Duration
	// Timeout：最多等这么久。到时还没有生效，就把上一份放回去。
	Timeout time.Duration
	// Interval：隔多久读一次。
	Interval time.Duration
}

// DefaultTiming 按实测取：换文件之后 0.3 秒左右生效（tests/integration/compose/README.md 第 1 点）。
func DefaultTiming() Timing {
	return Timing{Settle: time.Second, Timeout: 10 * time.Second, Interval: 100 * time.Millisecond}
}

func (t Timing) check() error {
	if t.Interval <= 0 || t.Settle < 0 || t.Timeout < t.Settle {
		return fmt.Errorf("gatewayconfig: unusable timing %+v", t)
	}
	return nil
}

// watch 经回读口等网关变成某个样子。
type watch struct {
	readBack ports.ReadBack
	timing   Timing
	now      func() time.Time
	sleep    func(context.Context, time.Duration) error
}

func newWatch(readBack ports.ReadBack, timing Timing) watch {
	return watch{readBack: readBack, timing: timing, now: time.Now, sleep: sleep}
}

func sleep(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// condition 判断一次观察是不是等的那个样子；不是时说出差在哪里。
type condition func(domain.Observation) (met bool, why string)

// running 等的是：网关报告 want 所代表的那份配置在生效。
func running(want domain.Observation) condition {
	return func(seen domain.Observation) (bool, string) {
		if seen.Confirms(want) {
			return true, ""
		}
		return false, fmt.Sprintf("the gateway reports digest %s and storage mode %q; expected digest %s", seen.Digest, seen.StorageMode, want.Digest)
	}
}

// started 等的是：网关是带着 want 的启动设置起来的，并且在跑 want 所代表的那份配置。
func started(want domain.Observation) condition {
	return func(seen domain.Observation) (bool, string) {
		if met, why := running(want)(seen); !met {
			return false, why
		}
		if differing := want.Settings.Differing(seen.Settings); len(differing) > 0 {
			return false, "the gateway runs with other startup settings than expected: " + strings.Join(differing, ", ")
		}
		return true, ""
	}
}

// await 等网关符合 wanted。failFast 为真时，网关一报告加载失败就不再等。
// 返回最后一次读到的（一次都没读到时为 nil）、是否等到、没等到的原因。
func (w watch) await(ctx context.Context, wanted condition, failFast bool) (*domain.Observation, bool, string) {
	started := w.now()
	var last *domain.Observation
	why := "the gateway could not be read"
	for {
		if err := w.sleep(ctx, w.timing.Interval); err != nil {
			return last, false, "interrupted while waiting for the gateway: " + err.Error()
		}
		elapsed := w.now().Sub(started)
		observed, err := w.readBack.Observe(ctx)
		switch {
		case err != nil:
			why = "read-back: " + err.Error()
		case elapsed < w.timing.Settle:
			last, why = &observed, "the gateway was only read before the settling period was over"
		default:
			met, difference := wanted(observed)
			if met {
				return &observed, true, ""
			}
			last, why = &observed, difference
			if !observed.Synchronized {
				why = "the gateway could not load it: " + observed.LastError
				if failFast {
					return last, false, why
				}
			}
		}
		if elapsed >= w.timing.Timeout {
			return last, false, fmt.Sprintf("%s (waited %s)", why, w.timing.Timeout)
		}
	}
}

// Publisher 往一个池发布快照。
type Publisher struct {
	watch
	staging  ports.Staging
	delivery ports.Delivery
	process  ports.Process
}

// New 构造一个池的发布器。
func New(staging ports.Staging, delivery ports.Delivery, readBack ports.ReadBack, timing Timing) (*Publisher, error) {
	if staging == nil || delivery == nil || readBack == nil {
		return nil, errors.New("gatewayconfig: staging, delivery and read-back are all required")
	}
	if err := timing.check(); err != nil {
		return nil, err
	}
	return &Publisher{watch: newWatch(readBack, timing), staging: staging, delivery: delivery}, nil
}

// WithProcess 告诉发布器怎么重启这个池的网关。只有 Restart 用得着它。
func (p *Publisher) WithProcess(process ports.Process) *Publisher {
	p.process = process
	return p
}

// survey 是动池之前看清的东西。
type survey struct {
	// staged 是离线加载这份快照得到的；before 是池里的网关此刻的样子。
	staged, before domain.Observation
	// previous 是放在那里的；那里什么都没有时 hadPrevious 为假。
	previous    domain.Snapshot
	hadPrevious bool
	// record 是这个池上最后一次得到确认的发布；还没有过时 recorded 为假。
	record   domain.Confirmation
	recorded bool
	// offRecord 为真表示有记录，而放在那里的不是记录的那一份：上一次发布没有做完，或者有别人
	// 写过这个文件。这时"上一份"是什么已经说不清。
	offRecord bool
	// differing 是这份快照的启动设置里与网关启动时不同的项。
	differing []string
}

// refusal 说明为什么不在一个对不上记录的池上动手。
func (s survey) refusal() string {
	return "what is in place is not the snapshot last confirmed on this pool (" + s.record.Snapshot.ShortID() +
		"): an earlier publication was cut short, or something else wrote the file; reconcile the pool first"
}

// admit 挡下不必看池就知道不能发布的快照。返回 false 表示结局已经写在 result 里。
func admit(snapshot domain.Snapshot, result *Result) (bool, error) {
	if snapshot.IsZero() {
		return false, errors.New("gatewayconfig: nothing to publish")
	}
	// 快照必须自己说得清它是什么。带环境变量的，离线加载和池里加载出来的可以不是同一份配置。
	if references := snapshot.EnvironmentReferences(); len(references) > 0 {
		result.Outcome = OutcomeRefused
		result.Reason = "the snapshot refers to the environment of the process that loads it (" + strings.Join(references, ", ") +
			"): the gateway replaces these before it parses the file; a literal $ is written $$"
		return false, nil
	}
	return true, nil
}

// look 离线加载这份快照，再看池现在的样子。调用的人占着这个池。
// ok 为假而 err 为空表示到此为止，结局已经写在 result 里；池没有被碰过。
func (p *Publisher) look(ctx context.Context, snapshot domain.Snapshot, result *Result) (seen survey, ok bool, err error) {
	// 一、离线加载：同一个镜像另起一个网关。加载不了的快照到此为止。
	staged, err := p.staging.Load(ctx, snapshot)
	var rejected *ports.RejectedError
	switch {
	case errors.As(err, &rejected):
		result.Outcome, result.Reason = OutcomeRefused, rejected.Reason
		return seen, false, nil
	case err != nil:
		return seen, false, fmt.Errorf("staging: %w", err)
	case !staged.Confirms(staged):
		result.Outcome = OutcomeRefused
		result.Reason = fmt.Sprintf("loaded offline, the snapshot gives synchronized=%t and storage mode %q; it must be synchronized with storage mode %q",
			staged.Synchronized, staged.StorageMode, domain.StorageReadOnly)
		return seen, false, nil
	}
	seen.staged, result.Expected = staged, staged.Digest

	// 二、池里的网关现在的样子。
	before, err := p.readBack.Observe(ctx)
	if err != nil {
		return seen, false, fmt.Errorf("read-back before publishing: %w", err)
	}
	seen.before, result.Observed = before, before
	switch {
	case !before.Synchronized:
		result.Outcome, result.Reason = OutcomePoolNotReady, "the gateway reports that its last load failed: "+before.LastError
		return seen, false, nil
	case before.StorageMode != domain.StorageReadOnly:
		result.Outcome, result.Reason = OutcomePoolNotReady, fmt.Sprintf("the gateway reports storage mode %q, not %q", before.StorageMode, domain.StorageReadOnly)
		return seen, false, nil
	case !before.SameBuild(staged):
		result.Outcome = OutcomeRestartRequired
		result.Reason = fmt.Sprintf("the pool runs agentgateway %s (%s), the offline load used %s (%s)", before.Version, before.Revision, staged.Version, staged.Revision)
		return seen, false, nil
	}
	seen.differing = staged.Settings.Differing(before.Settings)

	// 三、放在那里的是不是记录里确认过的那一份。
	seen.previous, seen.hadPrevious, err = p.delivery.Current(ctx)
	if err != nil {
		return seen, false, fmt.Errorf("delivery: %w", err)
	}
	if seen.hadPrevious {
		result.Previous = seen.previous.ID()
	}
	seen.record, seen.recorded, err = p.delivery.Confirmed(ctx)
	if err != nil {
		return seen, false, fmt.Errorf("delivery: %w", err)
	}
	seen.offRecord = seen.recorded && (!seen.hadPrevious || seen.previous.ID() != seen.record.Snapshot.ID())
	return seen, true, nil
}

// adopt 在第一次动一个池之前，把当时放在那里的和网关当时报告的记成第一条记录：从这以后，
// 发布器中途死了也知道该放回哪一份。
func (p *Publisher) adopt(ctx context.Context, seen survey) error {
	if seen.recorded || !seen.hadPrevious {
		return nil
	}
	found, err := domain.FoundInPlace(seen.previous, seen.before)
	if err != nil {
		return err
	}
	if err := p.delivery.Confirm(ctx, found); err != nil {
		return fmt.Errorf("delivery: %w", err)
	}
	return nil
}

// Publish 把快照发布到这个池。
//
// 放在那里的不是记录里确认过的那一份时，它不发布（POOL_NOT_READY），只有一种情况例外：放在那里的
// 正是要发布的这一份，网关也报告它在生效。那是上一次发布它时没来得及记下来，这里补记，不再写配置。
//
// 返回错误表示还没有动过池就做不下去了。动过之后不再返回错误：结局写在 Result 里，要么是
// ACTIVE，要么说明上一份有没有放回去。ctx 在动过池之后被取消时，仍会把上一份放回去再返回。
func (p *Publisher) Publish(ctx context.Context, snapshot domain.Snapshot) (Result, error) {
	result := Result{Snapshot: snapshot.ID()}
	if ok, err := admit(snapshot, &result); !ok {
		return result, err
	}
	release, err := p.delivery.Hold(ctx)
	if err != nil {
		return result, err
	}
	defer release()

	seen, ok, err := p.look(ctx, snapshot, &result)
	if !ok {
		return result, err
	}
	inPlace := seen.hadPrevious && seen.previous.ID() == snapshot.ID()
	switch {
	case seen.offRecord && (!inPlace || len(seen.differing) > 0):
		result.Outcome, result.Reason = OutcomePoolNotReady, seen.refusal()
		return result, nil
	case len(seen.differing) > 0:
		result.Outcome, result.Restart = OutcomeRestartRequired, seen.differing
		result.Reason = "startup settings differ from the ones the gateway started with: " + strings.Join(seen.differing, ", ")
		return result, nil
	case seen.offRecord:
		return p.complete(ctx, snapshot, seen, result)
	case inPlace && seen.before.Confirms(seen.staged):
		// 已经是这一份了，不用再写配置。记录里没有它，记的是接手时的样子，或者记的是网关另一个
		// 构建上的样子时，补上。
		fresh, err := domain.ConfirmedBy(snapshot, seen.before)
		if err != nil {
			return result, err
		}
		if !seen.recorded || !seen.record.Equal(fresh) {
			if err := p.delivery.Confirm(ctx, fresh); err != nil {
				return result, fmt.Errorf("delivery: %w", err)
			}
		}
		result.Outcome = OutcomeActive
		return result, nil
	}
	if err := p.adopt(ctx, seen); err != nil {
		return result, err
	}

	// 四、换上去，等网关报告。
	result.Replaced = true
	why := ""
	if err := p.delivery.Put(ctx, snapshot); err != nil {
		why = "delivery: " + err.Error()
	} else {
		observed, confirmed, reason := p.await(ctx, running(seen.staged), true)
		if observed != nil {
			result.Observed = *observed
		}
		why = reason
		if confirmed {
			if why = p.record(ctx, snapshot, *observed); why == "" {
				result.Outcome = OutcomeActive
				return result, nil
			}
		}
	}
	// 五、没有生效：把上一份放回去。
	return p.putBack(ctx, result, seen, why, false), nil
}

// complete 补完一次没做完的发布：放在那里的不是记录的那一份，却正是要发布的这一份。上一次发布它时
// 文件换上去了，没来得及记下来。网关确认它在生效就记下来，不必先收回去再发一遍。这里什么配置都不写；
// 等网关的时限与刚换上去时相同，因为那个文件可能是刚刚才换上去的。
func (p *Publisher) complete(ctx context.Context, snapshot domain.Snapshot, seen survey, result Result) (Result, error) {
	observed, confirmed, reason := p.await(ctx, running(seen.staged), true)
	if observed != nil {
		result.Observed = *observed
	}
	switch {
	case confirmed:
		if why := p.record(ctx, snapshot, *observed); why != "" {
			return result, errors.New("gatewayconfig: " + why)
		}
		result.Outcome = OutcomeActive
	case ctx.Err() != nil:
		return result, errors.New("gatewayconfig: " + reason)
	default:
		result.Outcome = OutcomePoolNotReady
		result.Reason = "this snapshot is in place without having been confirmed, and the gateway does not report it running: " +
			reason + "; reconcile the pool first"
	}
	return result, nil
}

// record 记下这份快照得到了确认。记不下来时返回原因：没有记下来的不算数，否则下一次对账会把它当成
// 没做完的发布收回去。这一步不随 ctx 取消。
func (p *Publisher) record(ctx context.Context, snapshot domain.Snapshot, observed domain.Observation) string {
	confirmation, err := domain.ConfirmedBy(snapshot, observed)
	if err == nil {
		err = p.delivery.Confirm(context.WithoutCancel(ctx), confirmation)
	}
	if err != nil {
		return "the snapshot took effect, but that could not be recorded: " + err.Error()
	}
	return ""
}

// putBack 把上一份放回去；restart 为真时再重启一次网关，让它带着上一份的启动设置起来。
// 网关加载不了的文件留在那里，它下次重启就起不来，所以这一步不随 ctx 取消：做到一半停下，
// 留下的正是要避免的状态。
func (p *Publisher) putBack(ctx context.Context, result Result, seen survey, why string, restart bool) Result {
	if !seen.hadPrevious {
		result.Outcome = OutcomeUnknown
		result.Reason = why + "; there was nothing in place before, so nothing was put back"
		return result
	}
	steady := context.WithoutCancel(ctx)
	if err := p.delivery.Put(steady, seen.previous); err != nil {
		result.Outcome = OutcomeUnknown
		result.Reason = why + "; putting the previous snapshot back failed: " + err.Error()
		return result
	}
	wanted := running(seen.before)
	if restart {
		if err := p.process.Restart(steady); err != nil {
			result.Outcome = OutcomeUnknown
			result.Reason = why + "; the previous snapshot was put back, but restarting the gateway with it failed: " + err.Error()
			return result
		}
		wanted = started(seen.before)
	}
	restoring, cancel := context.WithTimeout(steady, p.timing.Timeout+10*time.Second)
	defer cancel()
	observed, confirmed, reason := p.await(restoring, wanted, false)
	if observed != nil {
		result.Observed = *observed
	}
	if confirmed {
		result.Outcome, result.Reason = OutcomeRestored, why
	} else {
		result.Outcome = OutcomeUnknown
		result.Reason = why + "; the previous snapshot was put back but not confirmed: " + reason
	}
	return result
}
