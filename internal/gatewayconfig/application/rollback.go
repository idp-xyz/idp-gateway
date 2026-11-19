package application

import (
	"context"
	"errors"
	"fmt"

	"go.idp.xyz/idp-gateway/internal/gatewayconfig/ports"
)

// CommandRollback 是发起回滚的命令在历史里的名字。
const CommandRollback = "rollback"

// Rollback 回到历史里第 number 条发布放上去的那份快照（docs/adr/ADR-0013.md 第 6 条）。
// 它是一次新的发布：走的是 Publish（withRestart 为真时是 Restart）的全套检查和确认，记成新的一条，
// 那一条指向被取出的编号；历史里已有的各条一个字都不改。
//
// 只能回到到过 ACTIVE 的那几条；编号不存在、那一条没有到过 ACTIVE，结局是 REFUSED，池没有被碰过。
// 目标就是现在放着的那一份时也是 REFUSED（Restart 不在此列：它自己判断有没有重启的必要）。
// 取出的快照要重启才生效时，Publish 的结局是 RESTART_REQUIRED；要 Restart 才会重启。
// 老快照用现在的镜像加载不了，是 REFUSED：这是全套检查要的，不绕过。
//
// 读不到历史、存下的快照与它的 SHA-256 对不上，返回错误，池没有被碰过。要先给 WithHistory。
func (p *Publisher) Rollback(ctx context.Context, number uint64, withRestart bool) (Result, error) {
	var result Result
	if p.history == nil {
		return result, errors.New("gatewayconfig: a rollback needs the release history")
	}
	target, err := p.history.Get(ctx, number)
	switch {
	case errors.Is(err, ports.ErrReleaseNotFound):
		result.Outcome = OutcomeRefused
		result.Reason = fmt.Sprintf("there is no release %d in the history of this pool", number)
		return result, nil
	case err != nil:
		return result, fmt.Errorf("the release history could not be read, so nothing was done to the pool: %w", err)
	}
	result.Snapshot = target.Snapshot
	if !target.ReachedActive() {
		result.Outcome = OutcomeRefused
		result.Reason = fmt.Sprintf("release %d never reached ACTIVE (it ended %s): only a release that was ACTIVE can be rolled back to", number, target.State())
		return result, nil
	}
	snapshot, err := p.history.Snapshot(ctx, target.Snapshot)
	if err != nil {
		return result, fmt.Errorf("the snapshot of release %d could not be read from the history, so nothing was done to the pool: %w", number, err)
	}
	opts := releaseOptions{rollbackTo: number, command: CommandRollback}
	if withRestart {
		return p.restart(ctx, &snapshot, opts)
	}
	opts.refuseInPlace = true
	return p.publish(ctx, snapshot, opts)
}
