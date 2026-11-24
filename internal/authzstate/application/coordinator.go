// Package application 把撤销/封禁先落盘再发布，并把配额桶留在内存里。
// 落盘失败不改已经发布的快照，也不放宽。配额不写文件：进程重启之后每个键都是满桶。
package application

import (
	"errors"
	"sort"
	"sync"
	"time"

	"go.idp.xyz/idp-gateway/internal/authzstate/domain"
	"go.idp.xyz/idp-gateway/internal/authzstate/ports"
)

const idleWindows = 2

// 对外的错误。HTTP 层把它们译成状态码。句子里没有请求正文，也没有配额键的原像。
var (
	// ErrInvalid 是参数不合格。
	ErrInvalid = domain.ErrInvalid
	// ErrStoreUnavailable 是落盘失败。内存里的快照没有被这次调用改掉。HTTP 503。
	ErrStoreUnavailable = errors.New("authzstate: store unavailable")
	// ErrParameterMismatch 是同一把配额键后来带了不同的上限、窗口或容量。HTTP 409。
	// 调用方必须失败关闭，不能改用更松的那一组参数。
	ErrParameterMismatch = errors.New("authzstate: parameter mismatch")
)

// MutationResult 是一次改动之后已发布的情况。Revoked 只在账户动作时有意义，Banned 只在操作动作时有意义。
type MutationResult struct {
	Changed bool
	Epoch   uint64
	Revoked bool
	Banned  bool
}

// Coordinator 在一个进程里保存已发布的撤销表，以及只存在于内存的配额桶。
type Coordinator struct {
	store ports.Store
	now   func() time.Time

	mu   sync.Mutex
	snap domain.Snapshot

	quotaMu   sync.Mutex
	buckets   map[string]*quotaBucket
	maxWindow int
}

type quotaBucket struct {
	tokens        int
	residue       int64
	updated       time.Time
	lastUsed      time.Time
	maxRequests   int
	windowSeconds int
	capacity      int
}

// New 读出已经落盘的快照。now 为 nil 时用 time.Now。store 的错误原样返回。
func New(store ports.Store, now func() time.Time) (*Coordinator, error) {
	if store == nil {
		return nil, errors.New("authzstate: store is required")
	}
	loaded, err := store.Load()
	if err != nil {
		return nil, err
	}
	if now == nil {
		now = time.Now
	}
	if loaded.Accounts == nil {
		loaded.Accounts = map[string]domain.Entry{}
	}
	if loaded.Bans == nil {
		loaded.Bans = map[string]domain.Entry{}
	}
	return &Coordinator{
		store:   store,
		now:     now,
		snap:    loaded,
		buckets: map[string]*quotaBucket{},
	}, nil
}

// Snapshot 返回已发布快照的副本。
func (c *Coordinator) Snapshot() domain.Snapshot {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.snap.Clone()
}

// Mutate 先写盘，写成功才换掉内存。写失败时已发布的快照不动：收紧没有对外可见，放宽也不会发生。
// 集合没有变化时不写盘，代次也不增加。
func (c *Coordinator) Mutate(m domain.Mutation) (MutationResult, error) {
	now := c.now()
	c.mu.Lock()
	defer c.mu.Unlock()
	next, changed, err := domain.Apply(c.snap, m, now)
	if err != nil {
		return MutationResult{}, err
	}
	if changed {
		if err := c.store.Save(next); err != nil {
			return MutationResult{}, ErrStoreUnavailable
		}
		c.snap = next
	}
	return resultOf(c.snap, m, changed), nil
}

func resultOf(snap domain.Snapshot, m domain.Mutation, changed bool) MutationResult {
	out := MutationResult{Changed: changed, Epoch: snap.Epoch}
	switch m.Action {
	case domain.ActionRevoke, domain.ActionRestore:
		_, out.Revoked = snap.Accounts[m.AccountID]
	case domain.ActionBan, domain.ActionLift:
		_, out.Banned = snap.Bans[m.OperationID]
	}
	return out
}

// Quota 按服务器时钟对这一组扣费做全有或全无。拒绝时一张桶都不扣，retryAfter 至少为 1。
// 一把键第一次出现时锁住 max_requests、window 和 capacity。之后参数不同是 ErrParameterMismatch，桶保持原样。
// 空列表直接放行。键只按指纹保存，这里没有原像。
func (c *Coordinator) Quota(charges []domain.Charge) (allowed bool, retryAfter int, err error) {
	grouped, order, err := groupCharges(charges)
	if err != nil {
		return false, 0, err
	}
	if len(order) == 0 {
		return true, 0, nil
	}
	now := c.now()
	c.quotaMu.Lock()
	defer c.quotaMu.Unlock()
	c.sweep(now)
	for _, key := range order {
		g := grouped[key]
		if bucket := c.buckets[key]; bucket != nil && !sameParams(bucket, g.charge) {
			return false, 0, ErrParameterMismatch
		}
	}
	denied := false
	retry := 0
	touched := make([]*quotaBucket, 0, len(order))
	for _, key := range order {
		g := grouped[key]
		bucket := c.buckets[key]
		if bucket == nil {
			bucket = &quotaBucket{
				tokens:        g.charge.Capacity,
				updated:       now,
				lastUsed:      now,
				maxRequests:   g.charge.MaxRequests,
				windowSeconds: g.charge.WindowSeconds,
				capacity:      g.charge.Capacity,
			}
			c.buckets[key] = bucket
			if g.charge.WindowSeconds > c.maxWindow {
				c.maxWindow = g.charge.WindowSeconds
			}
		}
		bucket.tokens, bucket.residue = domain.Advance(bucket.tokens, bucket.residue, now.Sub(bucket.updated), bucket.maxRequests, bucket.windowSeconds, bucket.capacity)
		bucket.updated = now
		bucket.lastUsed = now
		touched = append(touched, bucket)
		if bucket.tokens < g.count {
			denied = true
			wait := domain.RetryAfterSeconds(bucket.tokens, bucket.maxRequests, bucket.windowSeconds, bucket.residue)
			if wait > retry {
				retry = wait
			}
		}
	}
	if denied {
		if retry < 1 {
			retry = 1
		}
		return false, retry, nil
	}
	for i, key := range order {
		touched[i].tokens -= grouped[key].count
		if touched[i].tokens < 0 {
			touched[i].tokens = 0
		}
	}
	return true, 0, nil
}

type chargeGroup struct {
	charge domain.Charge
	count  int
}

func groupCharges(charges []domain.Charge) (map[string]*chargeGroup, []string, error) {
	grouped := make(map[string]*chargeGroup, len(charges))
	order := make([]string, 0, len(charges))
	for _, charge := range charges {
		if err := domain.ValidateCharge(charge); err != nil {
			return nil, nil, err
		}
		if existing, ok := grouped[charge.Key]; ok {
			if !sameCharge(existing.charge, charge) {
				return nil, nil, ErrInvalid
			}
			existing.count++
			continue
		}
		grouped[charge.Key] = &chargeGroup{charge: charge, count: 1}
		order = append(order, charge.Key)
	}
	return grouped, order, nil
}

func sameParams(bucket *quotaBucket, charge domain.Charge) bool {
	return bucket.maxRequests == charge.MaxRequests && bucket.windowSeconds == charge.WindowSeconds && bucket.capacity == charge.Capacity
}

func sameCharge(a, b domain.Charge) bool {
	return a.MaxRequests == b.MaxRequests && a.WindowSeconds == b.WindowSeconds && a.Capacity == b.Capacity
}

// sweep 在键的数量超过上限时回收。先丢闲置超过两个最长窗口的，还多就丢最久没用的。
func (c *Coordinator) sweep(now time.Time) {
	if len(c.buckets) <= domain.QuotaKeyCap {
		return
	}
	window := c.maxWindow
	if window < 1 {
		window = 1
	}
	cutoff := now.Add(-time.Duration(window) * time.Second * idleWindows)
	for key, bucket := range c.buckets {
		if !bucket.lastUsed.After(cutoff) {
			delete(c.buckets, key)
		}
	}
	if len(c.buckets) <= domain.QuotaKeyCap {
		return
	}
	type aged struct {
		key  string
		when time.Time
	}
	order := make([]aged, 0, len(c.buckets))
	for key, bucket := range c.buckets {
		order = append(order, aged{key: key, when: bucket.lastUsed})
	}
	sort.Slice(order, func(i, j int) bool {
		if order[i].when.Equal(order[j].when) {
			return order[i].key < order[j].key
		}
		return order[i].when.Before(order[j].when)
	})
	extra := len(c.buckets) - domain.QuotaKeyCap
	for i := 0; i < extra; i++ {
		delete(c.buckets, order[i].key)
	}
}
