package application

import (
	"errors"
	"sync"
	"testing"
	"time"

	"go.idp.xyz/idp-gateway/internal/authzstate/domain"
)

type memStore struct {
	mu   sync.Mutex
	snap domain.Snapshot
	fail bool
}

func (s *memStore) Load() (domain.Snapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.snap.Accounts == nil {
		s.snap.Accounts = map[string]domain.Entry{}
	}
	if s.snap.Bans == nil {
		s.snap.Bans = map[string]domain.Entry{}
	}
	return s.snap.Clone(), nil
}

func (s *memStore) Save(next domain.Snapshot) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fail {
		return errors.New("disk")
	}
	s.snap = next.Clone()
	return nil
}

func TestTwoCallersShareOneRevoke(t *testing.T) {
	store := &memStore{}
	coord, err := New(store, func() time.Time { return time.Date(2026, 11, 24, 3, 4, 5, 0, time.UTC) })
	if err != nil {
		t.Fatal(err)
	}
	if _, err := coord.Mutate(domain.Mutation{Action: domain.ActionRevoke, AccountID: "account-blue", By: "spiffe://idp.test/revoker", Reason: "key leaked"}); err != nil {
		t.Fatal(err)
	}
	snap := coord.Snapshot()
	entry, ok := snap.Accounts["account-blue"]
	if !ok || snap.Epoch != 1 || entry.Reason != "key leaked" {
		t.Fatalf("second snapshot: %+v ok=%v", snap, ok)
	}
	again, err := coord.Mutate(domain.Mutation{Action: domain.ActionRevoke, AccountID: "account-blue", By: "spiffe://idp.test/other", Reason: "again"})
	if err != nil || again.Changed || again.Epoch != 1 || entry.By == "spiffe://idp.test/other" {
		t.Fatalf("repeat: %+v %v", again, err)
	}
	if snap := coord.Snapshot(); snap.Accounts["account-blue"].By != "spiffe://idp.test/revoker" {
		t.Fatal(snap.Accounts["account-blue"])
	}
}

func TestRestoreDoesNotApplyWhenSaveFails(t *testing.T) {
	store := &memStore{}
	coord, err := New(store, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := coord.Mutate(domain.Mutation{Action: domain.ActionRevoke, AccountID: "account-blue", By: "spiffe://idp.test/revoker", Reason: "key leaked"}); err != nil {
		t.Fatal(err)
	}
	store.fail = true
	result, err := coord.Mutate(domain.Mutation{Action: domain.ActionRestore, AccountID: "account-blue"})
	if !errors.Is(err, ErrStoreUnavailable) || result.Changed {
		t.Fatalf("restore: %+v %v", result, err)
	}
	snap := coord.Snapshot()
	if _, ok := snap.Accounts["account-blue"]; !ok || snap.Epoch != 1 {
		t.Fatalf("save failure loosened the snapshot: %+v", snap)
	}
	store.fail = false
	revoked, err := coord.Mutate(domain.Mutation{Action: domain.ActionRevoke, AccountID: "account-green", By: "spiffe://idp.test/revoker", Reason: "x"})
	if err == nil {
		store.fail = true
		if _, err := coord.Mutate(domain.Mutation{Action: domain.ActionRevoke, AccountID: "account-red", By: "spiffe://idp.test/revoker", Reason: "nope"}); !errors.Is(err, ErrStoreUnavailable) {
			t.Fatal(err)
		}
		snap = coord.Snapshot()
		if _, ok := snap.Accounts["account-red"]; ok || snap.Epoch != revoked.Epoch {
			t.Fatalf("failed revoke was published: %+v", snap)
		}
	} else {
		t.Fatal(err)
	}
}

func TestTwoQuotaCallersAllowExactlyOne(t *testing.T) {
	coord, err := New(&memStore{}, func() time.Time { return time.Unix(1_700_000_000, 0) })
	if err != nil {
		t.Fatal(err)
	}
	charge := domain.Charge{Key: strings64('a'), MaxRequests: 1, WindowSeconds: 3600, Capacity: 1}
	var allowed int
	for range 2 {
		ok, retry, err := coord.Quota([]domain.Charge{charge})
		if err != nil {
			t.Fatal(err)
		}
		if ok {
			allowed++
			if retry != 0 {
				t.Fatal(retry)
			}
		} else if retry != 3600 {
			t.Fatalf("retry %d", retry)
		}
	}
	if allowed != 1 {
		t.Fatalf("allowed %d", allowed)
	}
}

func TestQuotaIsAllOrNothing(t *testing.T) {
	coord, err := New(&memStore{}, func() time.Time { return time.Unix(1_700_000_000, 0) })
	if err != nil {
		t.Fatal(err)
	}
	keyA := strings64('a')
	keyB := strings64('b')
	one := func(key string) domain.Charge {
		return domain.Charge{Key: key, MaxRequests: 1, WindowSeconds: 3600, Capacity: 1}
	}
	if ok, _, err := coord.Quota([]domain.Charge{one(keyA)}); err != nil || !ok {
		t.Fatalf("prime A: %v %v", ok, err)
	}
	ok, retry, err := coord.Quota([]domain.Charge{one(keyA), one(keyB)})
	if err != nil || ok || retry < 1 {
		t.Fatalf("pair: ok=%v retry=%d err=%v", ok, retry, err)
	}
	if ok, _, err := coord.Quota([]domain.Charge{one(keyB)}); err != nil || !ok {
		t.Fatalf("B was charged on the denied request: %v %v", ok, err)
	}
}

func TestParameterMismatchDoesNotLoosen(t *testing.T) {
	coord, err := New(&memStore{}, func() time.Time { return time.Unix(1_700_000_000, 0) })
	if err != nil {
		t.Fatal(err)
	}
	key := strings64('c')
	tight := domain.Charge{Key: key, MaxRequests: 1, WindowSeconds: 3600, Capacity: 1}
	loose := domain.Charge{Key: key, MaxRequests: 5, WindowSeconds: 3600, Capacity: 5}
	if ok, _, err := coord.Quota([]domain.Charge{tight}); err != nil || !ok {
		t.Fatal(err)
	}
	ok, _, err := coord.Quota([]domain.Charge{loose})
	if !errors.Is(err, ErrParameterMismatch) || ok {
		t.Fatalf("mismatch: ok=%v err=%v", ok, err)
	}
	ok, retry, err := coord.Quota([]domain.Charge{tight})
	if err != nil || ok || retry < 1 {
		t.Fatalf("original bucket was replaced: ok=%v retry=%d err=%v", ok, retry, err)
	}
}

func strings64(fill byte) string {
	return string(repeat(fill))
}

func repeat(fill byte) []byte {
	b := make([]byte, 64)
	for i := range b {
		b[i] = fill
	}
	return b
}
