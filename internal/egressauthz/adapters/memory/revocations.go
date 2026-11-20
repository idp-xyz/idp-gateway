// Package memory 把撤销状态放在进程内存里。
//
// 进程重启后状态清空，多个副本之间也不同步。产品二进制只在没有给撤销文件时用它，那时
// 没有任何东西会调用 Revoke，表永远是空的；给了撤销文件，用的是 filestore 里落盘的那一张
// （docs/adr/ADR-0012.md）。验收构建的控制接口在没有撤销文件时改的是这一张。
package memory

import (
	"context"
	"sync"
)

// Revocations 实现 ports.Revocations。零值可用。
//
// 产品构建在没有撤销文件时用它，那时没有写入口，封禁一直是空的。Ban 和 Lift 与 Revoke 一样，
// 留给测试；验收控制接口只调用账户的那一侧。
type Revocations struct {
	mu      sync.RWMutex
	revoked map[string]struct{}
	banned  map[string]struct{}
	epoch   uint64
}

// State 返回账户是否已撤销及当前代次。两者在同一把锁下读出，彼此一致。
func (r *Revocations) State(_ context.Context, accountID string) (bool, uint64, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, revoked := r.revoked[accountID]
	return revoked, r.epoch, nil
}

// View 同时读出账户是否被撤销、操作是否被封禁，以及代次。
func (r *Revocations) View(_ context.Context, accountID, operationID string) (bool, bool, uint64, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, revoked := r.revoked[accountID]
	_, banned := r.banned[operationID]
	return revoked, banned, r.epoch, nil
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

// Ban 封禁一个操作。状态确有变化时代次加一。与账户撤销共用代次。
func (r *Revocations) Ban(operationID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, already := r.banned[operationID]; already {
		return
	}
	if r.banned == nil {
		r.banned = make(map[string]struct{})
	}
	r.banned[operationID] = struct{}{}
	r.epoch++
}

// Lift 解除对一个操作的封禁。状态确有变化时代次加一。
func (r *Revocations) Lift(operationID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, banned := r.banned[operationID]; !banned {
		return
	}
	delete(r.banned, operationID)
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
