package sfopenapi

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"time"

	"go.idp.xyz/idp-gateway/internal/egressauthz/ports"
)

const (
	// 等协调器唤醒的上限。提交之后等待者会立刻被叫醒，不必把整段等待一次用完。
	leaseAcquireWaitCap = 400 * time.Millisecond
	// 提交用独立的短超时，不占用取票那一次的预算。
	leaseCommitTimeout = 500 * time.Millisecond
	// 取票失败时放开锁，好让别的副本马上再问。
	leaseReleaseTimeout = 200 * time.Millisecond

	resultLeaseUnavailable = "lease_unavailable"
)

// LeaseState 是协调器对一次询问的回答。
type LeaseState string

const (
	// LeaseValid 表示协调器已经有还能用的令牌，不必再向承运商取。
	LeaseValid LeaseState = "VALID"
	// LeaseFetch 表示这一次由本进程去承运商取，取完要提交。
	LeaseFetch LeaseState = "FETCH"
	// LeaseWait 表示别人正拿着锁，过 RetryAfter 再问。
	LeaseWait LeaseState = "WAIT"
)

// AcquireRequest 是向协调器问一把租约。
type AcquireRequest struct {
	LeaseKey    string
	HolderID    string
	RefreshLead time.Duration
	LockTTL     time.Duration
	Wait        time.Duration
}

// AcquireResult 是询问的结果。Token 只在 LeaseValid 时有值。
type AcquireResult struct {
	State        LeaseState
	Token        ports.Secret
	ExpiresAt    time.Time
	Lifetime     time.Duration
	FenceToken   uint64
	RetryAfterMs int
}

// CommitRequest 把刚取到的令牌交给协调器。提交成功之前，调用方不得把它放进本地缓存。
type CommitRequest struct {
	LeaseKey   string
	HolderID   string
	FenceToken uint64
	Token      ports.Secret
	Lifetime   time.Duration
	ExpiresAt  time.Time
}

// ReleaseRequest 放弃一把还没提交的锁。
type ReleaseRequest struct {
	LeaseKey   string
	HolderID   string
	FenceToken uint64
}

// LeaseCoordinator 是跨实例的租约协调。实现不得在日志和错误里写下令牌。
type LeaseCoordinator interface {
	Acquire(ctx context.Context, req AcquireRequest) (AcquireResult, error)
	Commit(ctx context.Context, req CommitRequest) error
	Release(ctx context.Context, req ReleaseRequest) error
}

// leaseKey 是协调器使用的指纹：句柄、令牌端点、appKey、密钥版本、应用密钥摘要，各自带长度前缀后取 SHA-256。
// 协调器因此拿不到 app_secret，也拿不到 encoding_aes_key（它根本不进这个输入）。
func leaseKey(k cacheKey) string {
	var buf []byte
	write := func(b []byte) {
		var n [4]byte
		binary.BigEndian.PutUint32(n[:], uint32(len(b)))
		buf = append(buf, n[:]...)
		buf = append(buf, b...)
	}
	write([]byte(k.handle))
	write([]byte(k.tokenEndpoint))
	write([]byte(k.appKey))
	write([]byte(k.keyVersion))
	write(k.secretDigest[:])
	sum := sha256.Sum256(buf)
	return hex.EncodeToString(sum[:])
}

func newHolderID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw[:]), nil
}

func validHolderID(id string) bool {
	if len(id) < 1 || len(id) > 128 {
		return false
	}
	for i := 0; i < len(id); i++ {
		if id[i] < 0x21 || id[i] > 0x7e {
			return false
		}
	}
	return true
}

// fetchCoordinated 在本地缓存失效时走协调器。协调器不可达、拒绝或答错时失败关闭，不调用 c.request。
func (c *Client) fetchCoordinated(e *entry, started time.Time, prevLifetime time.Duration) (token ports.Secret, lifetime time.Duration, expires time.Time, result, cause string, err error) {
	key := leaseKey(e.key())
	lead := MaxRefreshLead
	if prevLifetime > 0 {
		lead = RefreshLead(prevLifetime)
	}
	lockTTL := 2 * time.Second
	if need := c.timeout + leaseCommitTimeout; need > lockTTL {
		lockTTL = need
	}
	if lockTTL > 10*time.Second {
		lockTTL = 10 * time.Second
	}
	deadline := time.Now().Add(c.timeout)
	for {
		if time.Now().After(deadline) {
			return c.leaseUnavailable(e, "timeout")
		}
		remaining := time.Until(deadline)
		wait := min(remaining, leaseAcquireWaitCap)
		ctx, cancel := context.WithTimeout(context.Background(), wait+300*time.Millisecond)
		resp, callErr := c.lease.Acquire(ctx, AcquireRequest{
			LeaseKey: key, HolderID: c.holderID, RefreshLead: lead, LockTTL: lockTTL, Wait: wait,
		})
		cancel()
		if callErr != nil {
			return c.leaseUnavailable(e, leaseCause(callErr))
		}
		switch resp.State {
		case LeaseValid:
			if resp.Token.IsZero() || resp.Lifetime <= 0 || resp.ExpiresAt.IsZero() {
				return c.leaseUnavailable(e, "bad_answer")
			}
			return resp.Token, resp.Lifetime, resp.ExpiresAt, resultOK, "", nil
		case LeaseWait:
			delay := time.Duration(resp.RetryAfterMs) * time.Millisecond
			if delay < 0 || time.Now().Add(delay).After(deadline) {
				return c.leaseUnavailable(e, "timeout")
			}
			if delay == 0 {
				delay = time.Millisecond
			}
			timer := time.NewTimer(delay)
			<-timer.C
			continue
		case LeaseFetch:
			return c.fetchAndCommit(e, key, resp.FenceToken, started)
		default:
			return c.leaseUnavailable(e, "bad_answer")
		}
	}
}

// fetchAndCommit 向承运商取一次。提交成功才把令牌交回去；取票失败或提交失败都放开锁。
// 提交失败时不把这枚令牌放进本地缓存，免得和别的副本分叉。
func (c *Client) fetchAndCommit(e *entry, key string, fence uint64, started time.Time) (token ports.Secret, lifetime time.Duration, expires time.Time, result, cause string, err error) {
	token, expiresIn, result, cause, err := c.request(e)
	if err != nil {
		c.releaseLease(key, fence)
		return ports.Secret{}, 0, time.Time{}, result, cause, err
	}
	lifetime = time.Duration(min(expiresIn, maxExpiresIn)) * time.Second
	expires = started.Add(lifetime)
	ctx, cancel := context.WithTimeout(context.Background(), leaseCommitTimeout)
	commitErr := c.lease.Commit(ctx, CommitRequest{
		LeaseKey: key, HolderID: c.holderID, FenceToken: fence,
		Token: token, Lifetime: lifetime, ExpiresAt: expires,
	})
	cancel()
	if commitErr != nil {
		c.releaseLease(key, fence)
		return c.leaseUnavailable(e, "commit_failed")
	}
	return token, lifetime, expires, resultOK, "", nil
}

func (c *Client) releaseLease(key string, fence uint64) {
	ctx, cancel := context.WithTimeout(context.Background(), leaseReleaseTimeout)
	defer cancel()
	_ = c.lease.Release(ctx, ReleaseRequest{LeaseKey: key, HolderID: c.holderID, FenceToken: fence})
}

// leaseUnavailable 是协调器不可用时的失败关闭。
// 这里不调用 c.request：退回去各取各的令牌，会把别的副本手里那一枚作废。
func (c *Client) leaseUnavailable(e *entry, cause string) (ports.Secret, time.Duration, time.Time, string, string, error) {
	return ports.Secret{}, 0, time.Time{}, resultLeaseUnavailable, cause, failure(e.handle, resultLeaseUnavailable)
}

func leaseCause(err error) string {
	var kind *leaseCallError
	if errors.As(err, &kind) && kind.cause != "" {
		return kind.cause
	}
	return "unreachable"
}
