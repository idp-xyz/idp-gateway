package domain

// ReleaseState 是契约 ReleaseState 的一个词。对外只使用这 16 个词。
type ReleaseState string

const (
	StateDraft             ReleaseState = "DRAFT"
	StateValidated         ReleaseState = "VALIDATED"
	StateApproved          ReleaseState = "APPROVED"
	StateStaged            ReleaseState = "STAGED"
	StateApplying          ReleaseState = "APPLYING"
	StateObserving         ReleaseState = "OBSERVING"
	StateActive            ReleaseState = "ACTIVE"
	StateRejected          ReleaseState = "REJECTED"
	StateCanceled          ReleaseState = "CANCELED"
	StateFailed            ReleaseState = "FAILED"
	StatePartial           ReleaseState = "PARTIAL"
	StateUnknown           ReleaseState = "UNKNOWN"
	StateSuperseded        ReleaseState = "SUPERSEDED"
	StateWithdrawRequested ReleaseState = "WITHDRAW_REQUESTED"
	StateRevoking          ReleaseState = "REVOKING"
	StateRevoked           ReleaseState = "REVOKED"
)

// Valid 报告 s 是不是契约里的 16 个词之一。
func (s ReleaseState) Valid() bool {
	switch s {
	case StateDraft, StateValidated, StateApproved, StateStaged, StateApplying, StateObserving,
		StateActive, StateRejected, StateCanceled, StateFailed, StatePartial, StateUnknown,
		StateSuperseded, StateWithdrawRequested, StateRevoking, StateRevoked:
		return true
	default:
		return false
	}
}

// Terminal 报告这条发布已经有结局，不会再往前走。
// UNKNOWN 和 PARTIAL 不是：它们还等对账。进行中的词也不是。
func (s ReleaseState) Terminal() bool {
	switch s {
	case StateActive, StateRejected, StateCanceled, StateFailed, StateSuperseded, StateRevoked:
		return true
	default:
		return false
	}
}

// BlocksNewPublish 报告这个状态会挡住同一池上的另一次发布（HTTP 409）。
// 已经结束的、以及交给对账的 UNKNOWN / PARTIAL，不挡。
func (s ReleaseState) BlocksNewPublish() bool {
	switch s {
	case StateDraft, StateValidated, StateApproved, StateStaged, StateApplying, StateObserving,
		StateWithdrawRequested, StateRevoking:
		return true
	default:
		return false
	}
}
