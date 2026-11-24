package application

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"go.idp.xyz/idp-gateway/internal/sflease/domain"
)

const (
	testKey   = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	testToken = "shared-access-token"
)

type memStore struct {
	mu    sync.Mutex
	fail  bool
	saved map[string]domain.LeaseRecord
	loads int
}

func (s *memStore) Load() (map[string]domain.LeaseRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.loads++
	out := map[string]domain.LeaseRecord{}
	for k, v := range s.saved {
		out[k] = v
	}
	return out, nil
}

func (s *memStore) Save(records map[string]domain.LeaseRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fail {
		return errors.New("disk")
	}
	out := map[string]domain.LeaseRecord{}
	for k, v := range records {
		out[k] = v
	}
	s.saved = out
	return nil
}

func (s *memStore) token() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.saved[testKey]
	if !ok {
		return ""
	}
	return rec.Token.Reveal()
}

type manualClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *manualClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *manualClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func newCoord(t *testing.T, store *memStore, now func() time.Time) *Coordinator {
	t.Helper()
	c, err := New(store, now)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func acquire(holder string, wait time.Duration) AcquireReq {
	return AcquireReq{LeaseKey: testKey, HolderID: holder, RefreshLead: 0, LockTTL: 2 * time.Second, Wait: wait}
}

func TestTenHoldersOneFetchThenTheSameValidToken(t *testing.T) {
	coord := newCoord(t, &memStore{}, time.Now)
	ctx := context.Background()
	type fetched struct {
		holder string
		fence  uint64
	}
	fetchCh := make(chan fetched, 10)
	var mu sync.Mutex
	var valids []AcquireResp
	var errs []error
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := range 10 {
		wg.Add(1)
		go func(holder string) {
			defer wg.Done()
			<-start
			resp, err := coord.Acquire(ctx, acquire(holder, 500*time.Millisecond))
			if err != nil {
				mu.Lock()
				errs = append(errs, err)
				mu.Unlock()
				return
			}
			if resp.State == StateFetch {
				fetchCh <- fetched{holder, resp.FenceToken}
				return
			}
			mu.Lock()
			valids = append(valids, resp)
			mu.Unlock()
		}(fmt.Sprintf("holder-%02d", i))
	}
	close(start)
	var winner fetched
	select {
	case winner = <-fetchCh:
	case <-time.After(2 * time.Second):
		t.Fatal("no holder received FETCH")
	}
	begun := time.Now()
	expires := time.Now().Add(time.Hour)
	if err := coord.Commit(ctx, CommitReq{
		LeaseKey: testKey, HolderID: winner.holder, FenceToken: winner.fence,
		Token: testToken, Lifetime: time.Hour, ExpiresAt: expires,
	}); err != nil {
		t.Fatal(err)
	}
	wg.Wait()
	if elapsed := time.Since(begun); elapsed > 2*time.Second {
		t.Fatalf("waiters took %s after commit; the wake should beat the 500ms wait", elapsed)
	}
	select {
	case extra := <-fetchCh:
		t.Fatalf("second FETCH for %s fence %d", extra.holder, extra.fence)
	default:
	}
	if len(errs) != 0 || len(valids) != 9 {
		t.Fatalf("valids %d errs %v", len(valids), errs)
	}
	for _, resp := range valids {
		if resp.State != StateValid || resp.Token.Reveal() != testToken || resp.FenceToken != 0 {
			t.Fatalf("valid %+v token %q", resp.State, resp.Token.Reveal())
		}
	}
	if strings.Contains(fmt.Sprintf("%v", valids[0].Token), testToken) {
		t.Fatal("token leaked through formatting")
	}
}

func TestStaleFenceAndWrongHolderAreRejected(t *testing.T) {
	coord := newCoord(t, &memStore{}, time.Now)
	ctx := context.Background()
	resp, err := coord.Acquire(ctx, acquire("holder-a", 0))
	if err != nil || resp.State != StateFetch {
		t.Fatal(resp, err)
	}
	err = coord.Commit(ctx, CommitReq{
		LeaseKey: testKey, HolderID: "holder-b", FenceToken: resp.FenceToken,
		Token: testToken, Lifetime: time.Hour, ExpiresAt: time.Now().Add(time.Hour),
	})
	if !errors.Is(err, ErrStaleFence) {
		t.Fatalf("wrong holder: %v", err)
	}
	err = coord.Commit(ctx, CommitReq{
		LeaseKey: testKey, HolderID: "holder-a", FenceToken: resp.FenceToken + 9,
		Token: testToken, Lifetime: time.Hour, ExpiresAt: time.Now().Add(time.Hour),
	})
	if !errors.Is(err, ErrStaleFence) {
		t.Fatalf("wrong fence: %v", err)
	}
	bad := "token with secret " + testToken
	err = coord.Commit(ctx, CommitReq{
		LeaseKey: testKey, HolderID: "holder-a", FenceToken: resp.FenceToken,
		Token: "has space", Lifetime: time.Hour, ExpiresAt: time.Now().Add(time.Hour),
	})
	if !errors.Is(err, ErrInvalid) || strings.Contains(err.Error(), "has space") || strings.Contains(err.Error(), testToken) {
		t.Fatalf("invalid token error: %v", err)
	}
	_ = bad
	if err := coord.Commit(ctx, CommitReq{
		LeaseKey: testKey, HolderID: "holder-a", FenceToken: resp.FenceToken,
		Token: testToken, Lifetime: time.Hour, ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
}

func TestExpiredLockIsTakenOverAndTheOldCommitIsRejected(t *testing.T) {
	clk := &manualClock{t: time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)}
	coord := newCoord(t, &memStore{}, clk.Now)
	ctx := context.Background()
	first, err := coord.Acquire(ctx, AcquireReq{LeaseKey: testKey, HolderID: "old", RefreshLead: 0, LockTTL: 200 * time.Millisecond})
	if err != nil || first.State != StateFetch {
		t.Fatal(first, err)
	}
	clk.Advance(200 * time.Millisecond)
	second, err := coord.Acquire(ctx, AcquireReq{LeaseKey: testKey, HolderID: "new", RefreshLead: 0, LockTTL: 200 * time.Millisecond})
	if err != nil || second.State != StateFetch || second.FenceToken == first.FenceToken {
		t.Fatalf("takeover %+v %v", second, err)
	}
	err = coord.Commit(ctx, CommitReq{
		LeaseKey: testKey, HolderID: "old", FenceToken: first.FenceToken,
		Token: testToken, Lifetime: time.Hour, ExpiresAt: clk.Now().Add(time.Hour),
	})
	if !errors.Is(err, ErrStaleFence) {
		t.Fatalf("old commit: %v", err)
	}
	if err := coord.Commit(ctx, CommitReq{
		LeaseKey: testKey, HolderID: "new", FenceToken: second.FenceToken,
		Token: testToken, Lifetime: time.Hour, ExpiresAt: clk.Now().Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	again, err := coord.Acquire(ctx, acquire("someone", 0))
	if err != nil || again.State != StateValid || again.Token.Reveal() != testToken {
		t.Fatalf("%+v %v", again, err)
	}
}

func TestReleaseWakesTheWaiter(t *testing.T) {
	coord := newCoord(t, &memStore{}, time.Now)
	ctx := context.Background()
	holder, err := coord.Acquire(ctx, acquire("holder-a", 0))
	if err != nil || holder.State != StateFetch {
		t.Fatal(holder, err)
	}
	done := make(chan AcquireResp, 1)
	go func() {
		resp, err := coord.Acquire(ctx, acquire("holder-b", 500*time.Millisecond))
		if err != nil {
			t.Errorf("waiter: %v", err)
		}
		done <- resp
	}()
	time.Sleep(30 * time.Millisecond)
	begun := time.Now()
	if err := coord.Release(ctx, ReleaseReq{LeaseKey: testKey, HolderID: "holder-a", FenceToken: holder.FenceToken}); err != nil {
		t.Fatal(err)
	}
	select {
	case resp := <-done:
		if time.Since(begun) > 2*time.Second {
			t.Fatalf("release did not wake the waiter promptly: %s", time.Since(begun))
		}
		if resp.State != StateFetch {
			t.Fatalf("waiter state %s", resp.State)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("waiter did not return")
	}
	if err := coord.Release(ctx, ReleaseReq{LeaseKey: testKey, HolderID: "holder-a", FenceToken: holder.FenceToken}); !errors.Is(err, ErrStaleFence) {
		t.Fatalf("second release: %v", err)
	}
}

func TestStoreFailureDoesNotPublishTheLeaseAndWakesWaiters(t *testing.T) {
	store := &memStore{fail: true}
	coord := newCoord(t, store, time.Now)
	ctx := context.Background()
	holder, err := coord.Acquire(ctx, acquire("holder-a", 0))
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan AcquireResp, 1)
	go func() {
		resp, err := coord.Acquire(ctx, acquire("holder-b", 500*time.Millisecond))
		if err != nil {
			t.Errorf("waiter: %v", err)
		}
		done <- resp
	}()
	time.Sleep(30 * time.Millisecond)
	err = coord.Commit(ctx, CommitReq{
		LeaseKey: testKey, HolderID: "holder-a", FenceToken: holder.FenceToken,
		Token: testToken, Lifetime: time.Hour, ExpiresAt: time.Now().Add(time.Hour),
	})
	if !errors.Is(err, ErrStoreUnavailable) || strings.Contains(err.Error(), testToken) {
		t.Fatalf("store error: %v", err)
	}
	if store.token() != "" {
		t.Fatal("failed save updated the store")
	}
	select {
	case resp := <-done:
		if resp.State != StateFetch {
			t.Fatalf("waiter after failed commit: %s", resp.State)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("waiter was not woken")
	}
	reloaded := newCoord(t, store, time.Now)
	resp, err := reloaded.Acquire(ctx, acquire("holder-d", 0))
	if err != nil || resp.State != StateFetch {
		t.Fatalf("memory/store published a lease anyway: %+v %v", resp, err)
	}
}

func TestReloadKeepsACommittedLease(t *testing.T) {
	store := &memStore{}
	coord := newCoord(t, store, time.Now)
	ctx := context.Background()
	resp, err := coord.Acquire(ctx, acquire("holder-a", 0))
	if err != nil {
		t.Fatal(err)
	}
	expires := time.Now().Add(2 * time.Hour)
	if err := coord.Commit(ctx, CommitReq{
		LeaseKey: testKey, HolderID: "holder-a", FenceToken: resp.FenceToken,
		Token: testToken, Lifetime: 2 * time.Hour, ExpiresAt: expires,
	}); err != nil {
		t.Fatal(err)
	}
	again := newCoord(t, store, time.Now)
	got, err := again.Acquire(ctx, AcquireReq{LeaseKey: testKey, HolderID: "holder-z", RefreshLead: 10 * time.Minute, Wait: 0})
	if err != nil || got.State != StateValid || got.Token.Reveal() != testToken {
		t.Fatalf("%+v %v", got, err)
	}
}
