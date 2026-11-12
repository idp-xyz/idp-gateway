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

// Reconciler 拿一个池上最后一次得到确认的发布，去对这个池现在的样子。
type Reconciler struct {
	watch
	delivery ports.Delivery
}

// NewReconciler 构造一个池的对账器。它不做离线加载：依据是记录，不是重新算出来的期望值。
func NewReconciler(delivery ports.Delivery, readBack ports.ReadBack, timing Timing) (*Reconciler, error) {
	if delivery == nil || readBack == nil {
		return nil, errors.New("gatewayconfig: delivery and read-back are both required")
	}
	if err := timing.check(); err != nil {
		return nil, err
	}
	return &Reconciler{watch: newWatch(readBack, timing), delivery: delivery}, nil
}

// Reconcile 对账（ADR-0010 第 10 条）：放在那里的是不是记录里确认过的那一份，网关报告它在跑的
// 是不是那一份。都是，什么也不写（IN_SYNC）。有一样不是，就把记录的那一份放回去，等网关确认
// （RESTORED；确认不了是 UNKNOWN）。发布器换上文件之后死了、有人绕过发布器写了这个文件、
// 文件不见了，都是这样收拾。
//
// 文件是对的、只是读不到网关时它不写，只等：等不到是 UNKNOWN。
//
// 它不重启网关。文件和运行配置都对上了，启动设置却不是确认时的那一套，结局是 RESTART_PENDING。
// 没有记录可对时（UNCONFIRMED）它什么都不做。
//
// 返回错误表示什么都没做。开始往回放之后不随 ctx 取消。
func (r *Reconciler) Reconcile(ctx context.Context) (Result, error) {
	var result Result
	release, err := r.delivery.Hold(ctx)
	if err != nil {
		return result, err
	}
	defer release()

	record, recorded, err := r.delivery.Confirmed(ctx)
	if err != nil {
		return result, fmt.Errorf("delivery: %w", err)
	}
	current, hasCurrent, err := r.delivery.Current(ctx)
	if err != nil {
		return result, fmt.Errorf("delivery: %w", err)
	}
	if hasCurrent {
		result.Previous = current.ID()
	}
	observed, readErr := r.readBack.Observe(ctx)
	if readErr == nil {
		result.Observed = observed
	}
	if !recorded {
		result.Outcome = OutcomeUnconfirmed
		result.Reason = "no publication has been confirmed on this pool yet, so there is nothing to reconcile it against; the first publication records one"
		return result, nil
	}
	result.Snapshot, result.Expected = record.Snapshot.ID(), record.Digest

	// 一、放在那里的是不是记录的那一份。
	var off []string
	switch {
	case !hasCurrent:
		off = append(off, "there was no configuration file in place")
	case current.ID() != record.Snapshot.ID():
		off = append(off, "what was in place ("+current.ShortID()+") was not the snapshot last confirmed on this pool")
	}
	inPlace := len(off) == 0

	// 二、网关在跑的是不是那一份。文件是对的、只是读不到网关时，再写一遍同样的文件帮不上忙：等它读得到。
	if inPlace && readErr != nil {
		readable := func(domain.Observation) (bool, string) { return true, "" }
		seen, answered, reason := r.await(ctx, readable, false)
		if !answered {
			if ctx.Err() != nil {
				return result, errors.New("gatewayconfig: " + reason)
			}
			result.Outcome = OutcomeUnknown
			result.Reason = "the confirmed snapshot is in place, but what the gateway runs could not be read: " + reason
			return result, nil
		}
		observed, readErr, result.Observed = *seen, nil, *seen
	}
	switch {
	case readErr != nil:
		off = append(off, "the gateway could not be read: "+readErr.Error())
	case !observed.Synchronized:
		off = append(off, "the gateway reported that its last load failed: "+observed.LastError)
	case !record.SameBuild(observed):
		if inPlace {
			// 文件是对的，网关也说加载成功，只是换过构建：摘要里有版本，新旧没法比。放回去也改变不了什么。
			result.Outcome = OutcomeUnconfirmed
			result.Reason = fmt.Sprintf("the confirmed snapshot is in place and the gateway reports a successful load, but it is agentgateway %s (%s) "+
				"and the confirmation was made on %s (%s): publish the snapshot again to confirm it on this build",
				observed.Version, observed.Revision, record.Version, record.Revision)
			return result, nil
		}
		off = append(off, otherBuild(observed, record))
	case !record.Holds(observed):
		off = append(off, fmt.Sprintf("the gateway reported digest %s and storage mode %q, the confirmation says digest %s",
			observed.Digest, observed.StorageMode, record.Digest))
	}
	if len(off) == 0 {
		return settled(result, record, observed, OutcomeInSync, ""), nil
	}
	why := strings.Join(off, "; ")
	if err := ctx.Err(); err != nil {
		return result, fmt.Errorf("gatewayconfig: interrupted before the confirmed snapshot was put back (%s): %w", why, err)
	}

	// 把记录的那一份放回去。文件本来就对、网关却没在跑它时也再放一次：换文件会让网关重新加载。
	steady, cancel := context.WithTimeout(context.WithoutCancel(ctx), r.timing.Timeout+10*time.Second)
	defer cancel()
	result.Replaced = true
	if err := r.delivery.Put(steady, record.Snapshot); err != nil {
		result.Outcome = OutcomeUnknown
		result.Reason = why + "; putting the confirmed snapshot back failed: " + err.Error()
		return result, nil
	}
	holds := func(seen domain.Observation) (bool, string) {
		switch {
		case !record.SameBuild(seen):
			return false, otherBuild(seen, record)
		case !record.Holds(seen):
			return false, fmt.Sprintf("the gateway reports digest %s and storage mode %q; expected digest %s", seen.Digest, seen.StorageMode, record.Digest)
		}
		return true, ""
	}
	back, confirmed, reason := r.await(steady, holds, false)
	if back != nil {
		result.Observed = *back
	}
	if !confirmed {
		result.Outcome = OutcomeUnknown
		result.Reason = why + "; the confirmed snapshot was put back but not confirmed: " + reason
		return result, nil
	}
	return settled(result, record, *back, OutcomeRestored, why), nil
}

func otherBuild(seen domain.Observation, record domain.Confirmation) string {
	return fmt.Sprintf("the gateway is agentgateway %s (%s), the confirmation was made on %s (%s)",
		seen.Version, seen.Revision, record.Version, record.Revision)
}

// settled 在文件和运行配置都对上之后，再看启动设置：不是确认时的那一套，就是 RESTART_PENDING。
func settled(result Result, record domain.Confirmation, observed domain.Observation, outcome Outcome, why string) Result {
	result.Outcome, result.Reason = outcome, why
	if pending := record.PendingRestart(observed); len(pending) > 0 {
		result.Outcome, result.Restart = OutcomeRestartPending, pending
		restart := "the gateway started with other startup settings than it had when this snapshot was confirmed (" + strings.Join(pending, ", ") +
			"); restarting it with that snapshot brings them back"
		if why != "" {
			restart = why + "; " + restart
		}
		result.Reason = restart
	}
	return result
}
