// Package application 把往一个池发布一份快照这件事串起来：先离线加载，再换上去，经回读确认；
// 没有生效就把上一份放回去。它不知道快照是怎么送到网关那里的，也不知道回读走的是什么协议。
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

// Outcome 是一次发布的结局。前四种里只有 ACTIVE 可能动过池；后两种都动过。
type Outcome string

const (
	// OutcomeActive：这份快照正在池里的网关上生效。
	OutcomeActive Outcome = "ACTIVE"
	// OutcomeRefused：发布之前就被挡下了。快照里有要拿环境变量去换的写法，网关加载不了这份快照，
	// 或者加载出来不带必须的设置。池没有被碰过。
	OutcomeRefused Outcome = "REFUSED"
	// OutcomeRestartRequired：这份快照要重启网关才能全部生效（启动设置不同，或者网关的构建不同）。
	// 重启会让这个池中断，不在一次发布里自动做。池没有被碰过。
	OutcomeRestartRequired Outcome = "RESTART_REQUIRED"
	// OutcomePoolNotReady：发布之前池的状态就不对（网关上一次加载失败，或存储不是只读）。要先对账。池没有被碰过。
	OutcomePoolNotReady Outcome = "POOL_NOT_READY"
	// OutcomeRestored：换上去了，没有生效；上一份已经放回去，网关报告它在跑的又是发布之前的那一份。
	OutcomeRestored Outcome = "RESTORED"
	// OutcomeUnknown：换上去了，没有生效，也没能确认放回去了。不是成功也不是失败，要对账。
	OutcomeUnknown Outcome = "UNKNOWN"
)

// Result 是一次发布做了什么、看到了什么。
type Result struct {
	Outcome Outcome
	// Snapshot 是要发布的快照；Previous 是发布之前放在那里的，那里什么都没有时为空。
	Snapshot string
	Previous string
	// Replaced 报告这次发布有没有往池里写过。
	Replaced bool
	// Expected 是期望的运行配置摘要，来自离线加载；离线加载没有通过时为空。
	Expected string
	// Observed 是最后一次从池里的网关读到的。
	Observed domain.Observation
	// Reason 说明为什么不是 ACTIVE。
	Reason string
	// Restart 在 RESTART_REQUIRED 时列出不同的启动设置。
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

// Publisher 往一个池发布快照。
type Publisher struct {
	staging  ports.Staging
	delivery ports.Delivery
	readBack ports.ReadBack
	timing   Timing
	now      func() time.Time
	sleep    func(context.Context, time.Duration) error
}

// New 构造一个池的发布器。
func New(staging ports.Staging, delivery ports.Delivery, readBack ports.ReadBack, timing Timing) (*Publisher, error) {
	if staging == nil || delivery == nil || readBack == nil {
		return nil, errors.New("gatewayconfig: staging, delivery and read-back are all required")
	}
	if timing.Interval <= 0 || timing.Settle < 0 || timing.Timeout < timing.Settle {
		return nil, fmt.Errorf("gatewayconfig: unusable timing %+v", timing)
	}
	return &Publisher{staging: staging, delivery: delivery, readBack: readBack, timing: timing, now: time.Now, sleep: sleep}, nil
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

// Publish 把快照发布到这个池。
//
// 返回错误表示还没有动过池就做不下去了。动过之后不再返回错误：结局写在 Result 里，要么是
// ACTIVE，要么说明上一份有没有放回去。ctx 在动过池之后被取消时，仍会把上一份放回去再返回。
func (p *Publisher) Publish(ctx context.Context, snapshot domain.Snapshot) (Result, error) {
	result := Result{Snapshot: snapshot.ID()}
	if snapshot.IsZero() {
		return result, errors.New("gatewayconfig: nothing to publish")
	}
	// 快照必须自己说得清它是什么。带环境变量的，离线加载和池里加载出来的可以不是同一份配置。
	if references := snapshot.EnvironmentReferences(); len(references) > 0 {
		result.Outcome = OutcomeRefused
		result.Reason = "the snapshot refers to the environment of the process that loads it (" + strings.Join(references, ", ") +
			"): the gateway replaces these before it parses the file; a literal $ is written $$"
		return result, nil
	}
	release, err := p.delivery.Hold(ctx)
	if err != nil {
		return result, err
	}
	defer release()

	// 一、离线加载：同一个镜像另起一个网关。加载不了的快照到此为止。
	staged, err := p.staging.Load(ctx, snapshot)
	var rejected *ports.RejectedError
	switch {
	case errors.As(err, &rejected):
		result.Outcome, result.Reason = OutcomeRefused, rejected.Reason
		return result, nil
	case err != nil:
		return result, fmt.Errorf("staging: %w", err)
	case !staged.Confirms(staged):
		result.Outcome = OutcomeRefused
		result.Reason = fmt.Sprintf("loaded offline, the snapshot gives synchronized=%t and storage mode %q; it must be synchronized with storage mode %q",
			staged.Synchronized, staged.StorageMode, domain.StorageReadOnly)
		return result, nil
	}
	result.Expected = staged.Digest

	// 二、池里的网关现在的样子。
	before, err := p.readBack.Observe(ctx)
	if err != nil {
		return result, fmt.Errorf("read-back before publishing: %w", err)
	}
	result.Observed = before
	switch {
	case !before.Synchronized:
		result.Outcome, result.Reason = OutcomePoolNotReady, "the gateway reports that its last load failed: "+before.LastError
		return result, nil
	case before.StorageMode != domain.StorageReadOnly:
		result.Outcome, result.Reason = OutcomePoolNotReady, fmt.Sprintf("the gateway reports storage mode %q, not %q", before.StorageMode, domain.StorageReadOnly)
		return result, nil
	case !before.SameBuild(staged):
		result.Outcome = OutcomeRestartRequired
		result.Reason = fmt.Sprintf("the pool runs agentgateway %s (%s), the offline load used %s (%s)", before.Version, before.Revision, staged.Version, staged.Revision)
		return result, nil
	}
	if differing := staged.Settings.Differing(before.Settings); len(differing) > 0 {
		result.Outcome, result.Restart = OutcomeRestartRequired, differing
		result.Reason = "startup settings differ from the ones the gateway started with: " + strings.Join(differing, ", ")
		return result, nil
	}
	previous, hadPrevious, err := p.delivery.Current(ctx)
	if err != nil {
		return result, fmt.Errorf("delivery: %w", err)
	}
	if hadPrevious {
		result.Previous = previous.ID()
		if previous.ID() == snapshot.ID() && before.Confirms(staged) {
			result.Outcome = OutcomeActive // 已经是这一份了，不用再写
			return result, nil
		}
	}

	// 三、换上去，等网关报告。
	result.Replaced = true
	why := ""
	if err := p.delivery.Put(ctx, snapshot); err != nil {
		why = "delivery: " + err.Error()
	} else {
		observed, confirmed, reason := p.await(ctx, staged, true)
		if observed != nil {
			result.Observed = *observed
		}
		if confirmed {
			result.Outcome = OutcomeActive
			return result, nil
		}
		why = reason
	}

	// 四、没有生效：把上一份放回去。网关加载不了的文件留在那里，它下次重启就起不来。
	// 这一步不随 ctx 取消：做到一半停下，留下的正是要避免的状态。
	if !hadPrevious {
		result.Outcome = OutcomeUnknown
		result.Reason = why + "; there was nothing in place before, so nothing was put back"
		return result, nil
	}
	restoring, cancel := context.WithTimeout(context.WithoutCancel(ctx), p.timing.Timeout+10*time.Second)
	defer cancel()
	if err := p.delivery.Put(restoring, previous); err != nil {
		result.Outcome = OutcomeUnknown
		result.Reason = why + "; putting the previous snapshot back failed: " + err.Error()
		return result, nil
	}
	observed, confirmed, reason := p.await(restoring, before, false)
	if observed != nil {
		result.Observed = *observed
	}
	if confirmed {
		result.Outcome, result.Reason = OutcomeRestored, why
	} else {
		result.Outcome = OutcomeUnknown
		result.Reason = why + "; the previous snapshot was put back but not confirmed: " + reason
	}
	return result, nil
}

// await 等网关报告 want 所代表的那份配置在生效。failFast 为真时，网关一报告加载失败就不再等。
// 返回最后一次读到的（一次都没读到时为 nil）、是否确认、没确认的原因。
func (p *Publisher) await(ctx context.Context, want domain.Observation, failFast bool) (*domain.Observation, bool, string) {
	started := p.now()
	var last *domain.Observation
	why := "the gateway could not be read"
	for {
		if err := p.sleep(ctx, p.timing.Interval); err != nil {
			return last, false, "interrupted while waiting for the gateway: " + err.Error()
		}
		elapsed := p.now().Sub(started)
		observed, err := p.readBack.Observe(ctx)
		switch {
		case err != nil:
			why = "read-back: " + err.Error()
		case elapsed < p.timing.Settle:
			last, why = &observed, "the gateway was only read before the settling period was over"
		case observed.Confirms(want):
			return &observed, true, ""
		case !observed.Synchronized:
			last, why = &observed, "the gateway could not load it: "+observed.LastError
			if failFast {
				return last, false, why
			}
		default:
			last = &observed
			why = fmt.Sprintf("the gateway reports digest %s and storage mode %q; expected digest %s", observed.Digest, observed.StorageMode, want.Digest)
		}
		if elapsed >= p.timing.Timeout {
			return last, false, fmt.Sprintf("%s (waited %s)", why, p.timing.Timeout)
		}
	}
}
