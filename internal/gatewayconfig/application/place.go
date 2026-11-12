package application

import (
	"context"
	"errors"
	"fmt"

	"go.idp.xyz/idp-gateway/internal/gatewayconfig/ports"
)

// 只有就位（Place）才有的结局。两个都表示网关可以启动了。
const (
	// OutcomeInPlace：放在那里的是记录里确认过的那一份。本来就是，或者这一次放回去的（Replaced 为真）。
	OutcomeInPlace Outcome = "IN_PLACE"
	// OutcomeNoRecord：这个池上还没有确认过任何发布，没有哪一份可放，什么都没有写。网关启动时读到的
	// 是当时放在那里的文件；之后的对账不认它（UNCONFIRMED），要发布一次才有记录。
	OutcomeNoRecord Outcome = "NO_RECORD"
)

// Place 在网关启动之前把配置放到位（ADR-0010 第 10 条）：放在那里的不是记录里确认过的那一份，
// 就把那一份放回去。没做完的发布留下的文件、有人绕过发布器写的文件、读不成一份配置的文件、
// 文件不见了，都是这样收拾。这样网关启动时读到的总是确认过的那一份；不然它拿到的可能是一份
// 没人确认过的文件，也可能是一份它加载不了的文件，那样它起不来。
//
// 它不读网关：这时网关还没有起来。所以它说明不了网关在跑什么，那是网关起来之后对账的事。
// 网关在跑的时候叫它，它也只是把文件放回去。
//
// 没有记录时（NO_RECORD）它什么都不做。记录的那一份放不回去时结局是 UNKNOWN：
// 这时不该启动网关。
//
// 返回错误表示什么都没做。开始往回放之后不随 ctx 取消。
func Place(ctx context.Context, delivery ports.Delivery) (Result, error) {
	var result Result
	if delivery == nil {
		return result, errors.New("gatewayconfig: delivery is required")
	}
	release, err := delivery.Hold(ctx)
	if err != nil {
		return result, err
	}
	defer release()

	record, recorded, err := delivery.Confirmed(ctx)
	if err != nil {
		return result, fmt.Errorf("delivery: %w", err)
	}
	current, hasCurrent, unreadable := delivery.Current(ctx)
	if unreadable == nil && hasCurrent {
		result.Previous = current.ID()
	}
	if !recorded {
		if unreadable != nil {
			// 没有可放回去的，放在那里的又读不出来：不能说网关可以启动。
			return result, fmt.Errorf("delivery: %w", unreadable)
		}
		result.Outcome = OutcomeNoRecord
		result.Reason = "no publication has been confirmed on this pool yet, so there is nothing to put in place: " +
			"the gateway starts from whatever file is there, and reconcile will not confirm it until a snapshot is published"
		return result, nil
	}
	result.Snapshot, result.Expected = record.Snapshot.ID(), record.Digest

	var why string
	switch {
	case unreadable != nil:
		// 有记录时，放在那里的读不出来（空文件、读不了）也一样：该放着的是哪一份是知道的。
		why = "what was in place could not be read as a configuration (" + unreadable.Error() + ")"
	case !hasCurrent:
		why = "there was no configuration file in place"
	case current.ID() != record.Snapshot.ID():
		why = "what was in place (" + current.ShortID() + ") was not the snapshot last confirmed on this pool"
	default:
		result.Outcome = OutcomeInPlace
		return result, nil
	}
	if err := ctx.Err(); err != nil {
		return result, fmt.Errorf("gatewayconfig: interrupted before the confirmed snapshot was put in place (%s): %w", why, err)
	}
	result.Replaced = true
	if err := delivery.Put(context.WithoutCancel(ctx), record.Snapshot); err != nil {
		result.Outcome = OutcomeUnknown
		result.Reason = why + "; putting the confirmed snapshot back failed: " + err.Error()
		return result, nil
	}
	result.Outcome, result.Reason = OutcomeInPlace, why
	return result, nil
}
