package domain

import "testing"

func TestReleaseStateVocabulary(t *testing.T) {
	canonical := []ReleaseState{
		StateDraft, StateValidated, StateApproved, StateStaged, StateApplying, StateObserving,
		StateActive, StateRejected, StateCanceled, StateFailed, StatePartial, StateUnknown,
		StateSuperseded, StateWithdrawRequested, StateRevoking, StateRevoked,
	}
	if len(canonical) != 16 {
		t.Fatalf("规范词 %d 个", len(canonical))
	}
	seen := map[ReleaseState]struct{}{}
	for _, state := range canonical {
		if !state.Valid() {
			t.Errorf("%s 应该有效", state)
		}
		seen[state] = struct{}{}
	}
	if len(seen) != 16 {
		t.Fatal("规范词有重复")
	}
	if ReleaseState("OVERTAKEN").Valid() || ReleaseState("RECEIVED").Valid() || ReleaseState("REVIEW").Valid() {
		t.Fatal("契约之外的词被当成了有效状态")
	}
	for _, state := range []ReleaseState{StateActive, StateRejected, StateCanceled, StateFailed, StateSuperseded, StateRevoked} {
		if !state.Terminal() || state.BlocksNewPublish() {
			t.Errorf("%s 应该是结局且不挡新发布", state)
		}
	}
	for _, state := range []ReleaseState{StateUnknown, StatePartial} {
		if state.Terminal() || state.BlocksNewPublish() {
			t.Errorf("%s 应该留给对账，既不是结局也不挡新发布", state)
		}
	}
	for _, state := range []ReleaseState{StateDraft, StateValidated, StateApproved, StateStaged, StateApplying, StateObserving, StateWithdrawRequested, StateRevoking} {
		if state.Terminal() || !state.BlocksNewPublish() {
			t.Errorf("%s 应该挡新发布", state)
		}
	}
}
