package application

import (
	"context"
	"errors"
	"fmt"

	"go.idp.xyz/idp-gateway/internal/gatewayconfig/domain"
)

// ErrNothingConfirmed 表示这个池上还没有确认过任何发布。
var ErrNothingConfirmed = errors.New("gatewayconfig: no publication has been confirmed on this pool yet")

// Restart 发布一份要重启网关才能全部生效的快照：启动设置与网关启动时不同的那种
// （ADR-0010 第 10 条"要重启网关的变更"）。重启会让这个池中断，所以它是单独的一个操作，
// Publish 遇到这种快照只报告 RESTART_REQUIRED。
//
// 顺序是：先把文件换上去，等池里的网关报告它加载得了（这一步网关不重启，启动设置之外的部分
// 已经生效）；再重启网关，等它报告启动设置也到位。先换文件是为了不拿一份池里加载不了的文件去重启：
// 那样网关起不来。
//
// 返回错误表示还没有动过池。还没重启就做不下去的（包括被叫停），把上一份放回去，不重启；
// 重启之后没有到位的，把上一份放回去再重启一次。重启一旦开始，后面的步骤不随 ctx 取消。
func (p *Publisher) Restart(ctx context.Context, snapshot domain.Snapshot) (Result, error) {
	return p.restart(ctx, &snapshot)
}

// RestartConfirmed 重启网关，让它带着这个池上最后一次得到确认的那份快照的启动设置起来。
// 对账报告 RESTART_PENDING 之后要做的就是这个：文件已经是那一份，只差重启。
// 还没有确认过任何发布时返回 ErrNothingConfirmed。其余与 Restart 相同。
func (p *Publisher) RestartConfirmed(ctx context.Context) (Result, error) {
	return p.restart(ctx, nil)
}

// restart 是 Restart 和 RestartConfirmed 共用的。given 为 nil 表示用记录里的那一份。
func (p *Publisher) restart(ctx context.Context, given *domain.Snapshot) (Result, error) {
	var result Result
	if p.process == nil {
		return result, errors.New("gatewayconfig: no way to restart the gateway of this pool was given")
	}
	if given != nil {
		result.Snapshot = given.ID()
		if ok, err := admit(*given, &result); !ok {
			return result, err
		}
	}
	release, err := p.delivery.Hold(ctx)
	if err != nil {
		return result, err
	}
	defer release()

	var snapshot domain.Snapshot
	if given != nil {
		snapshot = *given
	} else {
		// 占着池再读记录：先读再占的话，读到的可以是另一次发布正要换掉的那一份。
		record, recorded, err := p.delivery.Confirmed(ctx)
		switch {
		case err != nil:
			return result, fmt.Errorf("delivery: %w", err)
		case !recorded:
			return result, ErrNothingConfirmed
		}
		snapshot, result.Snapshot = record.Snapshot, record.Snapshot.ID()
		// 接手来的那一份没有经过发布时的检查，这里补上。
		if ok, err := admit(snapshot, &result); !ok {
			return result, err
		}
	}

	seen, ok, err := p.look(ctx, snapshot, &result)
	if !ok {
		if result.Outcome == OutcomeRestartRequired {
			// 池里跑的是另一个构建：重启换不了镜像。
			result.Outcome = OutcomeRefused
			result.Reason += "; restarting the gateway does not change the image it runs"
		}
		return result, err
	}
	switch {
	case !seen.hadPrevious:
		result.Outcome, result.Reason = OutcomePoolNotReady, "there is no configuration file in place"
		return result, nil
	case seen.offRecord:
		result.Outcome, result.Reason = OutcomePoolNotReady, seen.refusal()
		return result, nil
	case len(seen.differing) == 0:
		result.Outcome = OutcomeRefused
		result.Reason = "the gateway already runs with the startup settings of this snapshot: there is nothing to restart it for"
		if seen.previous.ID() != snapshot.ID() {
			result.Reason += "; publish it instead"
		}
		return result, nil
	}
	result.Restart = seen.differing
	if err := p.process.Verify(ctx); err != nil {
		return result, fmt.Errorf("process: %w", err)
	}
	if err := p.adopt(ctx, seen); err != nil {
		return result, err
	}

	// 换上去，等网关报告它加载得了。目录里已经是这一份、网关也在跑它时不用换：只差重启。
	if seen.previous.ID() != snapshot.ID() || !seen.before.Confirms(seen.staged) {
		result.Replaced = true
		why := ""
		if err := p.delivery.Put(ctx, snapshot); err != nil {
			why = "delivery: " + err.Error()
		} else {
			observed, confirmed, reason := p.await(ctx, running(seen.staged), true)
			if observed != nil {
				result.Observed = *observed
			}
			if !confirmed {
				why = reason
			}
		}
		if why != "" {
			return p.putBack(ctx, result, seen, why, false), nil
		}
	}

	// 重启之前再看一眼有没有被叫停：这是最后一个不必中断这个池就能退回去的地方。
	if err := ctx.Err(); err != nil {
		if !result.Replaced {
			return result, fmt.Errorf("gatewayconfig: interrupted before the gateway was restarted: %w", err)
		}
		return p.putBack(ctx, result, seen, "interrupted before the gateway was restarted: "+err.Error(), false), nil
	}

	// 重启。从这里起不随 ctx 取消：网关停到一半没人管，或者带着新设置起来了却没人确认，
	// 都比多等几秒糟。
	steady := context.WithoutCancel(ctx)
	result.Restarted = true
	why := ""
	if err := p.process.Restart(steady); err != nil {
		why = "restarting the gateway: " + err.Error()
	} else {
		observed, confirmed, reason := p.await(steady, started(seen.staged), false)
		if observed != nil {
			result.Observed = *observed
		}
		why = reason
		if confirmed {
			if why = p.record(steady, snapshot, *observed); why == "" {
				result.Outcome = OutcomeActive
				return result, nil
			}
		}
	}
	if !result.Replaced {
		// 文件没有换过，没有"上一份"可放：再重启一次也还是这份文件。
		result.Outcome = OutcomeUnknown
		result.Reason = why + "; the snapshot was already in place, so there is nothing to put back"
		return result, nil
	}
	return p.putBack(steady, result, seen, why, true), nil
}
