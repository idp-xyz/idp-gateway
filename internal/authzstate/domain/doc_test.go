package domain

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestAccountAndOperationIDsKeepTheFilestoreShape(t *testing.T) {
	now := time.Date(2026, 11, 24, 1, 2, 3, 0, time.UTC)
	revoke := Mutation{Action: ActionRevoke, AccountID: "account-blue", By: "spiffe://idp.test/revoker", Reason: "key leaked"}
	ban := Mutation{Action: ActionBan, OperationID: "tracking.get", By: "spiffe://idp.test/revoker", Reason: "abuse"}
	other := Mutation{Action: ActionBan, OperationID: "orders.create", By: "spiffe://idp.test/revoker", Reason: "abuse"}
	for _, m := range []Mutation{revoke, ban, other} {
		if err := ValidateMutation(m); err != nil {
			t.Fatalf("%+v: %v", m, err)
		}
		_, changed, err := Apply(Snapshot{}, m, now)
		if err != nil || !changed {
			t.Fatalf("%+v apply: changed=%v err=%v", m, changed, err)
		}
	}
	if err := ValidateMutation(Mutation{Action: ActionRevoke, By: "spiffe://idp.test/revoker", Reason: "x"}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("empty account: %v", err)
	}
	if err := ValidateMutation(Mutation{Action: ActionBan, By: "spiffe://idp.test/revoker", Reason: "x"}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("empty operation: %v", err)
	}
	longReason := strings.Repeat("因", MaxReasonRunes)
	if err := ValidateMutation(Mutation{Action: ActionRevoke, AccountID: "account-blue", By: "spiffe://idp.test/revoker", Reason: longReason}); err != nil {
		t.Fatal(err)
	}
	if err := ValidateMutation(Mutation{Action: ActionRevoke, AccountID: "account-blue", By: "spiffe://idp.test/revoker", Reason: longReason + "又"}); !errors.Is(err, ErrInvalid) {
		t.Fatal(err)
	}
	by := strings.Repeat("a", MaxByRunes)
	if err := ValidateMutation(Mutation{Action: ActionRevoke, AccountID: "account-blue", By: by, Reason: "x"}); err != nil {
		t.Fatal(err)
	}
	if err := ValidateMutation(Mutation{Action: ActionRevoke, AccountID: "account-blue", By: by + "b", Reason: "x"}); !errors.Is(err, ErrInvalid) {
		t.Fatal(err)
	}
	if err := ValidateMutation(Mutation{Action: ActionRevoke, AccountID: "account-blue", By: "has space", Reason: "x"}); !errors.Is(err, ErrInvalid) {
		t.Fatal(err)
	}
}

func TestEpochAdvancesOnlyWhenTheSetChanges(t *testing.T) {
	now := time.Date(2026, 11, 24, 1, 2, 3, 999, time.UTC)
	m := Mutation{Action: ActionRevoke, AccountID: "account-blue", By: "spiffe://idp.test/revoker", Reason: "key leaked"}
	next, changed, err := Apply(Snapshot{}, m, now)
	if err != nil || !changed || next.Epoch != 1 {
		t.Fatalf("%+v %v %v", next, changed, err)
	}
	if next.Accounts["account-blue"].At != now.Truncate(time.Second) {
		t.Fatal(next.Accounts["account-blue"].At)
	}
	again, changed, err := Apply(next, m, now.Add(time.Hour))
	if err != nil || changed || again.Epoch != 1 {
		t.Fatalf("repeat %+v %v %v", again, changed, err)
	}
	restored, changed, err := Apply(again, Mutation{Action: ActionRestore, AccountID: "account-blue"}, now)
	if err != nil || !changed || restored.Epoch != 2 {
		t.Fatalf("restore %+v %v %v", restored, changed, err)
	}
	if _, ok := restored.Accounts["account-blue"]; ok {
		t.Fatal("restore left the account")
	}
}

func TestRetryAfterUsesIntegerWindowMath(t *testing.T) {
	if got := RetryAfterSeconds(0, 1, 3600, 0); got != 3600 {
		t.Fatalf("long window: %d", got)
	}
	if got := RetryAfterSeconds(0, 3, 10, 0); got != 4 {
		t.Fatalf("ceil 10/3: %d", got)
	}
	if got := RetryAfterSeconds(1, 1, 3600, 0); got != 1 {
		t.Fatalf("already a token: %d", got)
	}
	windowNS := int64(10) * int64(time.Second)
	half := windowNS / 2
	if got := RetryAfterSeconds(0, 3, 10, half); got != 2 {
		t.Fatalf("half progress: %d", got)
	}
	tokens, residue := Advance(0, 0, 10*time.Second, 3, 10, 2)
	if tokens != 2 || residue != 0 {
		t.Fatalf("refill to capacity: %d %d", tokens, residue)
	}
}
