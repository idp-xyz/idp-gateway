// Package application 是顺丰访问令牌的租约协调：一把指纹键同一时刻只有一个持有者去承运商取票，
// 取到的令牌先落盘，再交给所有在等的副本。协调器不持有 app_secret 和 encoding_aes_key。
package application

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"go.idp.xyz/idp-gateway/internal/sflease/domain"
	"go.idp.xyz/idp-gateway/internal/sflease/ports"
)

const (
	// StateValid 表示内存里已有还能用的令牌，调用方不要再去承运商取。
	StateValid = "VALID"
	// StateFetch 表示这一次由该持有者去承运商取，取完必须带着同一个 fence 提交。
	StateFetch = "FETCH"
	// StateWait 表示别的持有者正拿着锁，调用方应过 RetryAfterMs 再问。
	StateWait = "WAIT"

	defaultLockTTL = 2 * time.Second
	minLockTTL     = 200 * time.Millisecond
	maxLockTTL     = 10 * time.Second
	maxRefreshLead = time.Hour
	maxWait        = 500 * time.Millisecond
	retryAfterMs   = 50
)

// 对外的错误。HTTP 层把它们译成状态码；句子里没有令牌。
var (
	// ErrInvalid 是参数不合格。
	ErrInvalid = errors.New("sflease: invalid")
	// ErrStaleFence 是锁已经不是这一对持有者和 fence。HTTP 409。
	ErrStaleFence = errors.New("sflease: stale fence")
	// ErrStoreUnavailable 是落盘失败。内存里的租约没有被这次提交改掉。HTTP 503。
	ErrStoreUnavailable = errors.New("sflease: store unavailable")
)

// AcquireReq 是一次询问。LockTTL 为 0 时用 2 秒。
type AcquireReq struct {
	LeaseKey    string
	HolderID    string
	RefreshLead time.Duration
	LockTTL     time.Duration
	Wait        time.Duration
}

// AcquireResp 是询问的结果。Token 只在 StateValid 时有值；FenceToken 只在 StateFetch 时有值。
type AcquireResp struct {
	State        string
	Token        domain.Secret
	ExpiresAt    time.Time
	Lifetime     time.Duration
	FenceToken   uint64
	RetryAfterMs int
}

// CommitReq 把刚取到的令牌交回来。先落盘，成功之后才放进内存并唤醒等待者。
type CommitReq struct {
	LeaseKey   string
	HolderID   string
	FenceToken uint64
	Token      string
	Lifetime   time.Duration
	ExpiresAt  time.Time
}

// ReleaseReq 放弃一把还没提交的锁，让等待的副本立刻再问。
type ReleaseReq struct {
	LeaseKey   string
	HolderID   string
	FenceToken uint64
}

// refreshLock 是一次取票的独占权。过期之后别人可以接管，旧 fence 再提交会被拒绝。
type refreshLock struct {
	holder    string
	fence     uint64
	expiresAt time.Time
}

// Coordinator 在一个进程里串起同一把租约键上的取票。
type Coordinator struct {
	store ports.Store
	now   func() time.Time

	mu        sync.Mutex
	leases    map[string]domain.LeaseRecord
	locks     map[string]*refreshLock
	nextFence uint64
	waiters   map[string]chan struct{}
}

// New 读出已经落盘的租约。now 为 nil 时用 time.Now。store 的错误原样返回（不得含令牌）。
func New(store ports.Store, now func() time.Time) (*Coordinator, error) {
	if store == nil {
		return nil, errors.New("sflease: store is required")
	}
	loaded, err := store.Load()
	if err != nil {
		return nil, err
	}
	if now == nil {
		now = time.Now
	}
	leases := make(map[string]domain.LeaseRecord, len(loaded))
	for key, rec := range loaded {
		leases[key] = rec
	}
	return &Coordinator{
		store:   store,
		now:     now,
		leases:  leases,
		locks:   map[string]*refreshLock{},
		waiters: map[string]chan struct{}{},
	}, nil
}

// Acquire 在 wait 截止前反复看：能用就直接给令牌；没人取就发一把锁；别人正取就等他提交后的唤醒。
func (c *Coordinator) Acquire(ctx context.Context, req AcquireReq) (AcquireResp, error) {
	if req.LockTTL == 0 {
		req.LockTTL = defaultLockTTL
	}
	if err := validateAcquire(req); err != nil {
		return AcquireResp{}, err
	}
	// 等待预算用墙钟。租约和锁的过期用 c.now，测试才能拨时钟。
	deadline := time.Now().Add(req.Wait)
	for {
		if err := ctx.Err(); err != nil {
			return AcquireResp{}, err
		}
		now := c.now()
		c.mu.Lock()
		if rec, ok := c.leases[req.LeaseKey]; ok && rec.Usable(now, req.RefreshLead) {
			resp := AcquireResp{State: StateValid, Token: rec.Token, ExpiresAt: rec.ExpiresAt, Lifetime: rec.Lifetime}
			c.mu.Unlock()
			return resp, nil
		}
		lock := c.locks[req.LeaseKey]
		if lock == nil || !lock.expiresAt.After(now) {
			c.nextFence++
			fence := c.nextFence
			c.locks[req.LeaseKey] = &refreshLock{holder: req.HolderID, fence: fence, expiresAt: now.Add(req.LockTTL)}
			c.mu.Unlock()
			return AcquireResp{State: StateFetch, FenceToken: fence}, nil
		}
		if lock.holder == req.HolderID && lock.fence != 0 {
			fence := lock.fence
			c.mu.Unlock()
			return AcquireResp{State: StateFetch, FenceToken: fence}, nil
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			c.mu.Unlock()
			return AcquireResp{State: StateWait, RetryAfterMs: retryAfterMs}, nil
		}
		ch := c.waiterLocked(req.LeaseKey)
		c.mu.Unlock()

		timer := time.NewTimer(remaining)
		select {
		case <-ch:
			timer.Stop()
			continue
		case <-timer.C:
			return AcquireResp{State: StateWait, RetryAfterMs: retryAfterMs}, nil
		case <-ctx.Done():
			timer.Stop()
			return AcquireResp{}, ctx.Err()
		}
	}
}

// Commit 核对锁仍是这个持有者的这把 fence，先把租约写进 Store，写完才更新内存、放开锁并唤醒。
// 落盘失败时内存租约不动，锁仍然放开，等待者可以另取。
func (c *Coordinator) Commit(ctx context.Context, req CommitReq) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := validateCommit(req); err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	lock := c.locks[req.LeaseKey]
	if lock == nil || !lock.expiresAt.After(now) || lock.holder != req.HolderID || lock.fence != req.FenceToken {
		return ErrStaleFence
	}
	if !req.ExpiresAt.After(now) {
		return fmt.Errorf("%w: expires_at", ErrInvalid)
	}
	next := make(map[string]domain.LeaseRecord, len(c.leases)+1)
	for key, rec := range c.leases {
		if rec.ExpiresAt.After(now) {
			next[key] = rec
		}
	}
	next[req.LeaseKey] = domain.LeaseRecord{
		LeaseKey: req.LeaseKey, Token: domain.NewSecret(req.Token),
		ExpiresAt: req.ExpiresAt, Lifetime: req.Lifetime,
	}
	if err := c.store.Save(next); err != nil {
		// 不把存储错误的文字带出去：实现若哪天把路径以外的东西写进错误，这里也不会跟着出去。
		delete(c.locks, req.LeaseKey)
		c.wakeLocked(req.LeaseKey)
		return fmt.Errorf("%w", ErrStoreUnavailable)
	}
	c.leases = next
	delete(c.locks, req.LeaseKey)
	c.wakeLocked(req.LeaseKey)
	return nil
}

// Release 在锁仍属于这对持有者和 fence 时把它丢掉，并立刻唤醒等着的副本。对不上是 ErrStaleFence。
func (c *Coordinator) Release(ctx context.Context, req ReleaseReq) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := validateRelease(req); err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	lock := c.locks[req.LeaseKey]
	if lock == nil || !lock.expiresAt.After(now) || lock.holder != req.HolderID || lock.fence != req.FenceToken {
		return ErrStaleFence
	}
	delete(c.locks, req.LeaseKey)
	c.wakeLocked(req.LeaseKey)
	return nil
}

func (c *Coordinator) waiterLocked(key string) chan struct{} {
	ch, ok := c.waiters[key]
	if !ok {
		ch = make(chan struct{})
		c.waiters[key] = ch
	}
	return ch
}

// wakeLocked 关掉当前的 channel 并换上一根新的，选在这根旧 channel 上的等待者全部返回。
func (c *Coordinator) wakeLocked(key string) {
	if ch, ok := c.waiters[key]; ok {
		close(ch)
	}
	c.waiters[key] = make(chan struct{})
}

func validateAcquire(req AcquireReq) error {
	if err := domain.ValidateLeaseKey(req.LeaseKey); err != nil {
		return fmt.Errorf("%w: lease_key", ErrInvalid)
	}
	if err := domain.ValidateHolderID(req.HolderID); err != nil {
		return fmt.Errorf("%w: holder_id", ErrInvalid)
	}
	if req.RefreshLead < 0 || req.RefreshLead > maxRefreshLead {
		return fmt.Errorf("%w: refresh_lead", ErrInvalid)
	}
	if req.LockTTL < minLockTTL || req.LockTTL > maxLockTTL {
		return fmt.Errorf("%w: lock_ttl", ErrInvalid)
	}
	if req.Wait < 0 || req.Wait > maxWait {
		return fmt.Errorf("%w: wait", ErrInvalid)
	}
	return nil
}

func validateCommit(req CommitReq) error {
	if err := domain.ValidateLeaseKey(req.LeaseKey); err != nil {
		return fmt.Errorf("%w: lease_key", ErrInvalid)
	}
	if err := domain.ValidateHolderID(req.HolderID); err != nil {
		return fmt.Errorf("%w: holder_id", ErrInvalid)
	}
	if err := domain.ValidateToken(req.Token); err != nil {
		return fmt.Errorf("%w: token", ErrInvalid)
	}
	if req.Lifetime <= 0 {
		return fmt.Errorf("%w: lifetime", ErrInvalid)
	}
	if req.FenceToken == 0 {
		return fmt.Errorf("%w: fence_token", ErrInvalid)
	}
	if req.ExpiresAt.IsZero() {
		return fmt.Errorf("%w: expires_at", ErrInvalid)
	}
	return nil
}

func validateRelease(req ReleaseReq) error {
	if err := domain.ValidateLeaseKey(req.LeaseKey); err != nil {
		return fmt.Errorf("%w: lease_key", ErrInvalid)
	}
	if err := domain.ValidateHolderID(req.HolderID); err != nil {
		return fmt.Errorf("%w: holder_id", ErrInvalid)
	}
	if req.FenceToken == 0 {
		return fmt.Errorf("%w: fence_token", ErrInvalid)
	}
	return nil
}
