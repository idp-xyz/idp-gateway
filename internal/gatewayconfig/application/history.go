package application

import (
	"context"
	"fmt"
	"strings"
	"time"

	"go.idp.xyz/idp-gateway/internal/gatewayconfig/domain"
	"go.idp.xyz/idp-gateway/internal/gatewayconfig/ports"
)

// 发布历史接在发布、重启和对账上（docs/adr/ADR-0013.md 第 2、4 条）。没有给历史时（Publisher.history 为 nil）
// 这里的每一步都什么都不做：命令与没有历史时完全一样。

// OutcomeActiveNotRecorded：这份快照在池里的网关上生效了，池的记录也记下了，只是历史里的 ACTIVE 那一行
// 没有写进去。池没有问题；历史停在最后写成的那一步，由下一次对账补上，或者再发布一次同一份快照。
const OutcomeActiveNotRecorded Outcome = "ACTIVE_NOT_RECORDED"

// ReleaseMeta 是发起一次发布的人和命令：历史里每一条记录开头要有的那几样。
type ReleaseMeta struct {
	// Command 是哪个命令发起的：publish、restart 或 rollback。
	Command string
	By      domain.Initiator
	// Note 是操作员的备注，未经核实。
	Note string
}

// WithHistory 让发布器把每一次发布记进历史。不调用它，就没有历史。
func (p *Publisher) WithHistory(history ports.History, meta ReleaseMeta) *Publisher {
	p.history, p.meta = history, meta
	return p
}

// releaseOptions 是一次发布里与历史有关的、和命令有关的几样。
type releaseOptions struct {
	// rollbackTo 不为 0 表示这是回滚，回到的是这一条。
	rollbackTo uint64
	// refuseInPlace 为真时，目标就是现在放着的那一份，不发布（回滚：没有什么可回的）。
	refuseInPlace bool
	command       string // 不为空时盖过 meta.Command
}

// ledger 是一次发布在历史里的那一条。nil 表示没有历史：它的每个方法都不做事。
type ledger struct {
	history ports.History
	number  uint64
	now     func() time.Time
	// last 说明最后一行写成的是哪一步，ACTIVE_NOT_RECORDED 的说明里要用。
	last    string
	command string
}

func describeStep(state domain.ReleaseState, name string) string {
	if name == "" {
		return string(state)
	}
	return string(state) + " (" + name + ")"
}

// begin 开始这一次发布的记录，写 STAGED。返回错误时池没有被碰过，也没有什么被开始。
func (p *Publisher) begin(ctx context.Context, snapshot domain.Snapshot, seen survey, result *Result, opts releaseOptions) (*ledger, error) {
	if p.history == nil {
		return nil, nil
	}
	command := p.meta.Command
	if opts.command != "" {
		command = opts.command
	}
	start := domain.ReleaseStart{
		Snapshot: snapshot, Expected: seen.staged.Digest, Command: command, By: p.meta.By, Note: p.meta.Note,
		RolledBackTo: opts.rollbackTo, At: p.now(),
	}
	if seen.hadPrevious {
		start.Previous = seen.previous
	}
	number, err := p.history.Begin(ctx, start)
	if err != nil {
		return nil, fmt.Errorf("the release history could not be written, so nothing was done to the pool: %w", err)
	}
	result.Release = number
	return &ledger{history: p.history, number: number, now: p.now, last: string(domain.StateStaged), command: command}, nil
}

func (l *ledger) write(ctx context.Context, step domain.ReleaseStep) error {
	step.At = l.now()
	if err := l.history.Advance(ctx, l.number, step); err != nil {
		return err
	}
	l.last = describeStep(step.State, step.Name)
	return nil
}

// applying 在一步动手之前写 APPLYING。写不进去时返回错误：这一步不做，池没有被这一步碰过。
func (l *ledger) applying(ctx context.Context, name string) error {
	if l == nil {
		return nil
	}
	if err := l.write(ctx, domain.ReleaseStep{State: domain.StateApplying, Name: name}); err != nil {
		return fmt.Errorf("the release history could not be written, so the step %q was not taken: %w", name, err)
	}
	return nil
}

// observing 在等网关报告之前写 OBSERVING。这不是动手之前的一步：写不进去不拦发布，只在警告里说一句。
func (l *ledger) observing(ctx context.Context, result *Result) {
	if l == nil {
		return
	}
	if err := l.write(context.WithoutCancel(ctx), domain.ReleaseStep{State: domain.StateObserving}); err != nil {
		result.Warnings = append(result.Warnings, fmt.Sprintf("release %d: the OBSERVING step could not be written to the history (%v); "+
			"the publication goes on, and the history stays at %s until the outcome is written or the next reconcile", l.number, err, l.last))
	}
}

// finish 把结局写进历史。结局写不进去时：池确实是 ACTIVE 的，结局改成 ACTIVE_NOT_RECORDED；
// 别的结局（RESTORED、UNKNOWN 本来就是非零）不变，警告里说一句。这一步不随 ctx 取消。
func (l *ledger) finish(ctx context.Context, result *Result) {
	if l == nil {
		return
	}
	result.Release = l.number
	var state domain.ReleaseState
	switch result.Outcome {
	case OutcomeActive:
		state = domain.StateActive
	case OutcomeRestored, OutcomePoolNotReady:
		// POOL_NOT_READY 只会在补完上一次没做完的那一支里到这里：对不上一个状态，原因里写清楚
		state = domain.StateFailed
	case OutcomeUnknown:
		state = domain.StateUnknown
	default:
		return
	}
	err := l.write(context.WithoutCancel(ctx), domain.ReleaseStep{State: state, Reason: result.Reason, Facts: facts(*result)})
	switch {
	case err == nil:
	case state == domain.StateActive:
		result.Outcome = OutcomeActiveNotRecorded
		result.Reason = notRecorded(l.number, result.Snapshot, l.last, err, l.command)
	default:
		result.Warnings = append(result.Warnings, fmt.Sprintf("release %d: the outcome %s could not be written to the history (%v); "+
			"the history stays at %s until the next reconcile", l.number, result.Outcome, err, l.last))
	}
}

func notRecorded(number uint64, snapshot, last string, cause error, command string) string {
	again := "Running the same command again is safe: it finds the directory already holding this snapshot and completes the history."
	if command != "publish" {
		again = "Running " + command + " again would not complete it (there is nothing left for it to do); " +
			"completing the history is what a reconcile does (the keeper runs one every minute), or publishing the same snapshot again."
	}
	return fmt.Sprintf("the pool already runs snapshot %s and its record says so, but the history could not be written (%v): "+
		"release %d stops at %s. The pool is fine. %s", domain.ShortSnapshot(snapshot), cause, number, last, again)
}

func facts(result Result) *domain.StepFacts {
	if result.Observed.Digest == "" && len(result.Restart) == 0 {
		return nil
	}
	return &domain.StepFacts{
		Digest: result.Observed.Digest, Version: result.Observed.Version, Revision: result.Observed.Revision,
		Restart: result.Restart,
	}
}

// verdict 是给停在半路的记录补结局时的依据：池的记录，和这一次看到的池。
type verdict struct {
	record   domain.Confirmation
	observed domain.Observation
	// restart 是 RESTART_PENDING 时不同的启动设置。
	restart []string
	// why 是对账时的说明（比如把记录的那一份放回去了）。
	why string
	// step 是写在补上的那一行上的步骤名。
	step string
	// onlyActive 为真时，只在最新的那一条正是这份快照、记录也确认了它时补 ACTIVE，别的都不动。
	// 再发布一次同一份快照时用它。
	onlyActive bool
}

// settleOpen 给这个池上没有结局的记录补结局（ADR-0013 第 4 条，和实现时定下的规则）。调用的人占着池。
//
// 只有这个池最新的那一条能得到"事实上怎么样了"的结局：记录确认的就是它的快照（而且那一次确认不早于它
// 开始的时刻），补 ACTIVE；记录确认的是别的快照，它没有生效，补 FAILED。它之前没有结局的，都已经被后来
// 的发布越过：补 OVERTAKEN，结局不明，不借用 FAILED。最新的一条已经有结局，或者记录确认的是它的快照
// 却早于它开始（同一份快照先后发布了两次，第二次中途被杀），就不动它。
// 返回补上的各条的编号和要说的话。
func settleOpen(ctx context.Context, history ports.History, now time.Time, v verdict) (settled []uint64, notes []string, err error) {
	releases, err := history.List(ctx)
	if err != nil || len(releases) == 0 {
		return nil, nil, err
	}
	latest := releases[len(releases)-1]
	if !v.onlyActive {
		for _, release := range releases[:len(releases)-1] {
			if release.Settled() {
				continue
			}
			reason := fmt.Sprintf("a later release (%d) was started while this one had no outcome: "+
				"whether it ever took effect is not known", latest.Number)
			if err := history.Advance(ctx, release.Number, domain.ReleaseStep{State: domain.StateOvertaken, Name: v.step, Reason: reason, At: now}); err != nil {
				return settled, notes, err
			}
			settled = append(settled, release.Number)
		}
	}
	if latest.Settled() {
		return settled, notes, nil
	}
	step := domain.ReleaseStep{Name: v.step, At: now, Facts: &domain.StepFacts{
		Digest: v.observed.Digest, Version: v.observed.Version, Revision: v.observed.Revision, Restart: v.restart,
	}}
	switch {
	case v.record.Snapshot.ID() == latest.Snapshot:
		if v.record.At.IsZero() || v.record.At.Before(latest.StartedAt().Truncate(time.Second)) {
			notes = append(notes, fmt.Sprintf("release %d has no outcome yet: the pool's record confirms its snapshot, but that confirmation (%s) is not "+
				"after the release started (%s), so it cannot be told to be this release's", latest.Number,
				v.record.At.UTC().Format(time.RFC3339), latest.StartedAt().UTC().Format(time.RFC3339)))
			return settled, notes, nil
		}
		step.State = domain.StateActive
		step.Reason = "the pool's record confirms this snapshot, made after this release started; the outcome was written afterwards (" + v.step + ")"
	case v.onlyActive:
		return settled, notes, nil
	default:
		step.State = domain.StateFailed
		step.Reason = fmt.Sprintf("the pool's record confirms snapshot %s, not this release's (%s): it did not take effect", v.record.Snapshot.ShortID(),
			domain.ShortSnapshot(latest.Snapshot))
		if v.why != "" {
			step.Reason += "; " + v.why
		}
	}
	if err := history.Advance(ctx, latest.Number, step); err != nil {
		return settled, notes, err
	}
	return append(settled, latest.Number), notes, nil
}

// settleOutcomes 是对账的哪几种结局说明得了池的状态：池的记录，和网关此刻的样子，是对得上的（或者已经放回去了）。
// UNKNOWN、UNCONFIRMED 说明不了：读不到网关，或者没有可以拿来对的记录，这时不补。
func settleOutcomes(outcome Outcome) bool {
	return outcome == OutcomeInSync || outcome == OutcomeRestored || outcome == OutcomeRestartPending
}

// WithHistory 让对账给停在半路的发布记录补结局。不调用它，对账与没有历史时完全一样。
func (r *Reconciler) WithHistory(history ports.History) *Reconciler {
	r.history = history
	return r
}

// settleAfter 在对账做完之后，调用的人仍占着池，给历史补结局。补不成不改变对账的结局：只在警告里说一句。
func (r *Reconciler) settleAfter(ctx context.Context, result *Result, record domain.Confirmation, recorded bool) {
	if r.history == nil || !recorded || !settleOutcomes(result.Outcome) {
		return
	}
	settled, notes, err := settleOpen(context.WithoutCancel(ctx), r.history, r.now(), verdict{
		record: record, observed: result.Observed, restart: result.Restart, why: strings.TrimSpace(result.Reason), step: domain.StepReconcile,
	})
	result.Warnings = append(result.Warnings, notes...)
	if err != nil {
		result.Warnings = append(result.Warnings, "the release history could not be brought up to date: "+err.Error())
	}
	result.Settled = settled
}
