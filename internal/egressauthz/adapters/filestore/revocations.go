package filestore

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"go.idp.xyz/idp-gateway/internal/egressauthz/ports"
)

// Revocations 是落在文件里的撤销表：哪些账户被撤销了，各是什么时候、谁撤的、为什么，外加
// 撤销代次（docs/adr/ADR-0012.md）。它实现 ports.RevocationLedger。
//
// 文件在启动时读一次，之后不再读：这个进程是唯一往里写的。要手工改它，先停进程。判定读的
// 是内存里的表，不碰磁盘。
//
// 改动只往收紧的方向偏。撤销先在内存里生效，再写文件；写不成时撤销仍然有效，返回的错误
// 包装了 ports.ErrRevocationNotWritten，下一次改动会把它一并写下去。恢复先写文件，写不成就
// 不恢复。
type Revocations struct {
	path string
	now  func() time.Time

	// writing 让改动一个一个来。写文件在它下面做，不占着 mu，判定不用等磁盘。
	writing sync.Mutex

	mu    sync.RWMutex
	epoch uint64
	// revoked 只会被整张换掉，不会被就地改：拿到它的人可以在锁外面读。
	revoked map[string]revocation
	// unwritten 为 true 表示内存里的表比文件里的紧：有撤销生效了，却没有写成。
	unwritten bool
}

type revocation struct {
	at     time.Time
	by     string
	reason string
}

// revocationsDocument 是文件的样子。两个字段都必须写出来：没有撤销时写一张空表。
type revocationsDocument struct {
	Epoch    *uint64                       `json:"epoch"`
	Accounts map[string]revocationDocument `json:"revoked_accounts"`
}

type revocationDocument struct {
	At     *string `json:"at"`
	By     string  `json:"by"`
	Reason string  `json:"reason"`
}

// LoadRevocations 读撤销文件：{"epoch": 代次, "revoked_accounts": {账户: {"at", "by", "reason"}}}。
//
// 读不成就返回错误，调用方应当不启动：文件不存在、对属主以外可读、不是这个样子、有不认识的
// 字段、后面还有内容。"没有撤销"是一份写着空表的文件，不是没有文件：文件丢了不能等于全部恢复。
func LoadRevocations(path string) (*Revocations, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("revocations: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("revocations: %w", err)
	}
	if mode := info.Mode().Perm(); mode&0o077 != 0 {
		return nil, fmt.Errorf("revocations %s: mode %04o is readable by others; want 0600 or stricter", path, mode)
	}
	raw, err := io.ReadAll(file)
	if err != nil {
		return nil, fmt.Errorf("revocations: %w", err)
	}
	epoch, revoked, err := parseRevocations(raw)
	if err != nil {
		return nil, fmt.Errorf("revocations %s: %w", path, err)
	}
	return &Revocations{path: path, now: time.Now, epoch: epoch, revoked: revoked}, nil
}

func parseRevocations(raw []byte) (uint64, map[string]revocation, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var doc revocationsDocument
	if err := decoder.Decode(&doc); err != nil {
		return 0, nil, errors.New(`not a JSON object of "epoch" and "revoked_accounts"`)
	}
	if _, err := decoder.Token(); err != io.EOF {
		return 0, nil, errors.New("unexpected data after the object")
	}
	if doc.Epoch == nil || doc.Accounts == nil {
		return 0, nil, errors.New(`"epoch" and "revoked_accounts" are both required; with nothing revoked, "revoked_accounts" is {}`)
	}
	revoked := make(map[string]revocation, len(doc.Accounts))
	for account, entry := range doc.Accounts {
		if account == "" {
			return 0, nil, errors.New("an entry has an empty account")
		}
		if entry.At == nil {
			return 0, nil, fmt.Errorf(`entry %q: "at" is required`, account)
		}
		at, err := time.Parse(time.RFC3339, *entry.At)
		if err != nil {
			return 0, nil, fmt.Errorf(`entry %q: "at" is not an RFC 3339 time`, account)
		}
		revoked[account] = revocation{at: at.UTC(), by: entry.By, reason: entry.Reason}
	}
	return *doc.Epoch, revoked, nil
}

// State 实现 ports.Revocations。两个值在同一把锁下读出，彼此一致。
func (r *Revocations) State(_ context.Context, accountID string) (bool, uint64, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, revoked := r.revoked[accountID]
	return revoked, r.epoch, nil
}

// Epoch 实现 ports.Revocations。
func (r *Revocations) Epoch(context.Context) (uint64, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.epoch, nil
}

// Revoke 实现 ports.RevocationLedger：先生效，再写文件。
//
// 账户已经被撤销时什么都不改；但上一次没有写成的话，这一次再写一遍，所以重发同一个撤销
// 是把它写下去的办法。
func (r *Revocations) Revoke(_ context.Context, accountID, by, reason string) (ports.RevocationChange, error) {
	if accountID == "" {
		return ports.RevocationChange{}, errors.New("revocations: no account given")
	}
	r.writing.Lock()
	defer r.writing.Unlock()

	r.mu.Lock()
	_, already := r.revoked[accountID]
	if !already {
		next := maps.Clone(r.revoked)
		next[accountID] = revocation{at: r.now().UTC().Truncate(time.Second), by: by, reason: reason}
		r.revoked, r.unwritten = next, true
		r.epoch++
	}
	epoch, revoked, unwritten := r.epoch, r.revoked, r.unwritten
	r.mu.Unlock()

	change := ports.RevocationChange{Changed: !already, Revoked: true, Epoch: epoch}
	if !unwritten {
		return change, nil
	}
	if err := r.write(epoch, revoked); err != nil {
		return change, fmt.Errorf("%w: %w", ports.ErrRevocationNotWritten, err)
	}
	r.mu.Lock()
	r.unwritten = false
	r.mu.Unlock()
	return change, nil
}

// Restore 实现 ports.RevocationLedger：先写文件，写成了才恢复。
func (r *Revocations) Restore(_ context.Context, accountID string) (ports.RevocationChange, error) {
	r.writing.Lock()
	defer r.writing.Unlock()

	r.mu.RLock()
	_, revoked := r.revoked[accountID]
	epoch, current := r.epoch, r.revoked
	r.mu.RUnlock()
	if !revoked {
		return ports.RevocationChange{Epoch: epoch}, nil
	}
	next := maps.Clone(current)
	delete(next, accountID)
	if err := r.write(epoch+1, next); err != nil {
		return ports.RevocationChange{Revoked: true, Epoch: epoch}, fmt.Errorf("revocations: restore not applied: %w", err)
	}
	r.mu.Lock()
	// 写下去的是整张表，之前没写成的撤销也在里面了。
	r.revoked, r.epoch, r.unwritten = next, epoch+1, false
	r.mu.Unlock()
	return ports.RevocationChange{Changed: true, Epoch: epoch + 1}, nil
}

// Revoked 实现 ports.RevocationLedger。
func (r *Revocations) Revoked(context.Context) ([]ports.RevokedAccount, uint64, error) {
	r.mu.RLock()
	epoch, revoked := r.epoch, r.revoked
	r.mu.RUnlock()
	accounts := make([]ports.RevokedAccount, 0, len(revoked))
	for _, account := range slices.Sorted(maps.Keys(revoked)) {
		entry := revoked[account]
		accounts = append(accounts, ports.RevokedAccount{AccountID: account, At: entry.at, By: entry.by, Reason: entry.reason})
	}
	return accounts, epoch, nil
}

// write 把一张表换到文件上：写临时文件，刷盘，改名，再刷目录。中途失败时原来的文件不动。
func (r *Revocations) write(epoch uint64, revoked map[string]revocation) error {
	doc := revocationsDocument{Epoch: &epoch, Accounts: make(map[string]revocationDocument, len(revoked))}
	for account, entry := range revoked {
		at := entry.at.UTC().Format(time.RFC3339)
		doc.Accounts[account] = revocationDocument{At: &at, By: entry.by, Reason: entry.reason}
	}
	encoded, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	next := r.path + ".next"
	file, err := os.OpenFile(next, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	// 上一次留下的临时文件可能是别的权限：O_TRUNC 不改权限。
	err = file.Chmod(0o600)
	if err == nil {
		_, err = file.Write(append(encoded, '\n'))
	}
	if err == nil {
		err = file.Sync()
	}
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err == nil {
		err = os.Rename(next, r.path)
	}
	if err != nil {
		_ = os.Remove(next)
		return err
	}
	// 改名之后刷目录：不然断电时可能回到改名之前。
	directory, err := os.Open(filepath.Dir(r.path))
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
