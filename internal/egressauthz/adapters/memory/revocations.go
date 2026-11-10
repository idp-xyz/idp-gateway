// Package memory 把撤销状态放在进程内存里。
//
// 这是第一版的占位：进程重启后状态清空，多个副本之间也不同步。产品二进制里目前没有
// 任何东西会调用 Revoke，撤销从哪里来还没有定（见 ADR-0009"没有定的"）。
package memory

import (
	"context"
	"sync"
)

// Revocations 实现 ports.Revocations。零值可用。
type Revocations struct {
	mu      sync.RWMutex
	revoked map[string]struct{}
	epoch   uint64
}

// State 返回账户是否已撤销及当前代次。两者在同一把锁下读出，彼此一致。
func (r *Revocations) State(_ context.Context, accountID string) (bool, uint64, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, revoked := r.revoked[accountID]
	return revoked, r.epoch, nil
}

// Epoch 返回当前代次。
func (r *Revocations) Epoch(context.Context) (uint64, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.epoch, nil
}

// Revoke 撤销一个账户。状态确有变化时代次加一。
func (r *Revocations) Revoke(accountID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, already := r.revoked[accountID]; already {
		return
	}
	if r.revoked == nil {
		r.revoked = make(map[string]struct{})
	}
	r.revoked[accountID] = struct{}{}
	r.epoch++
}

// Restore 取消对一个账户的撤销。状态确有变化时代次加一。
func (r *Revocations) Restore(accountID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, revoked := r.revoked[accountID]; !revoked {
		return
	}
	delete(r.revoked, accountID)
	r.epoch++
}

// RestoreAll 取消全部撤销。原本有撤销时代次加一。
func (r *Revocations) RestoreAll() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.revoked) == 0 {
		return
	}
	r.revoked = nil
	r.epoch++
}

// Revoked 返回当前被撤销的账户，顺序不定。
func (r *Revocations) Revoked() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	accounts := make([]string, 0, len(r.revoked))
	for account := range r.revoked {
		accounts = append(accounts, account)
	}
	return accounts
}
