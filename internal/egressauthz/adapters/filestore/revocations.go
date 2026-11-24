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
	"syscall"
	"time"

	"go.idp.xyz/idp-gateway/internal/egressauthz/ports"
)

// Revocations 是落在文件里的撤销表：哪些账户被撤销了，哪些操作被封禁了，各是什么时候、谁做的、
// 为什么，外加一个代次（docs/adr/ADR-0012.md）。账户和操作共用这一份文件、这一个代次。
// 它实现 ports.RevocationLedger。
//
// 启动时读一次，读不成就不往下走。之后 State、View、Epoch、Revoked、Banned 发现文件被换掉就整份重读：
// 改名换成另一个文件，或者大小、修改时间、权限变了。身份、修改时间、大小和权限都没变时不读内容。
// 几个进程可以打开同一份，它们不互相调用。写之前先占住旁边的锁文件，把磁盘上已经有的表并进来，
// 再写整份：后写的进程不会把先写的撤销或封禁盖掉。
// 内存里还有没写下去的撤销或封禁时，重读不拿文件盖掉内存；写的时候只往这份内存里补磁盘上多出来的条目。
// 重读失败（读不懂、别人能读、文件不在了）时留下原来的表，这一次读返回错误：判定因此是
// REVOCATION_STATE_UNAVAILABLE，读表因此是 revocations_unavailable。封禁不是路由发布，也不改
// agentgateway 的配置。
//
// 改动只往收紧的方向偏。撤销和封禁先在内存里生效，再写文件；写不成时收紧仍然有效，返回的错误
// 包装了 ports.ErrRevocationNotWritten，下一次改动会把它一并写下去。恢复和解除先写文件，写不成就
// 不放宽。
type Revocations struct {
	path string
	now  func() time.Time

	// writing 让改动一个一个来。写文件在它下面做，不占着 mu。
	// 文件变了要重读时也取这把锁，重读才不会盖住写到一半的内存。文件没变时不取。
	writing sync.Mutex

	mu    sync.RWMutex
	epoch uint64
	// revoked 和 banned 只会被整张换掉，不会被就地改：拿到它们的人可以在锁外面读。
	revoked map[string]revocation
	banned  map[string]revocation
	// unwritten 为 true 表示内存里的表比文件里的紧：有撤销或封禁生效了，却没有写成。
	unwritten bool
	// seen 是最近一次对照过的文件。reloadErr 非空表示这份文件没有读成，内存里仍是上一份读成的。
	seen      os.FileInfo
	reloadErr error
}

type revocation struct {
	at     time.Time
	by     string
	reason string
}

// revocationsDocument 是文件的样子。epoch 和 revoked_accounts 读的时候必须有。
// banned_operations 可以不写，表示没有封禁；这个进程写文件时两张表都写，没有封禁时是 {}。
type revocationsDocument struct {
	Epoch    *uint64                       `json:"epoch"`
	Accounts map[string]revocationDocument `json:"revoked_accounts"`
	Banned   map[string]revocationDocument `json:"banned_operations"`
}

type revocationDocument struct {
	At     *string `json:"at"`
	By     string  `json:"by"`
	Reason string  `json:"reason"`
}

// LoadRevocations 读撤销文件：{"epoch": 代次, "revoked_accounts": {账户: {"at", "by", "reason"}}}，
// 可以再有 "banned_operations": {operation_id: {"at", "by", "reason"}}。没有 banned_operations
// 表示一个操作都没有被封禁。
//
// 读不成就返回错误，调用方应当不启动：文件不存在、对属主以外可读、不是这个样子、有不认识的
// 字段、后面还有内容。"没有撤销"是一份写着空表的文件，不是没有文件：文件丢了不能等于全部恢复。
func LoadRevocations(path string) (*Revocations, error) {
	epoch, revoked, banned, info, err := readRevocations(path)
	if err != nil {
		return nil, err
	}
	return &Revocations{path: path, now: time.Now, epoch: epoch, revoked: revoked, banned: banned, seen: info}, nil
}

// readRevocations 读路径上现在的那一份。info 是实际打开的那个文件；打开失败时 info 为 nil。
// 调用方在重读失败时用它记住是哪一份，免得同一份坏文件每次判定都再读一遍。
func readRevocations(path string) (uint64, map[string]revocation, map[string]revocation, os.FileInfo, error) {
	file, err := os.Open(path)
	if err != nil {
		return 0, nil, nil, nil, fmt.Errorf("revocations: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return 0, nil, nil, nil, fmt.Errorf("revocations: %w", err)
	}
	if mode := info.Mode().Perm(); mode&0o077 != 0 {
		return 0, nil, nil, info, fmt.Errorf("revocations %s: mode %04o is readable by others; want 0600 or stricter", path, mode)
	}
	raw, err := io.ReadAll(file)
	if err != nil {
		return 0, nil, nil, info, fmt.Errorf("revocations: %w", err)
	}
	epoch, revoked, banned, err := parseRevocations(raw)
	if err != nil {
		return 0, nil, nil, info, fmt.Errorf("revocations %s: %w", path, err)
	}
	return epoch, revoked, banned, info, nil
}

// settled 报告这一次读能不能直接用内存。文件没变时不再读内容。
// 内存里有没写下去的收紧时也不读。文件不在了：表不动，返回错误。
func (r *Revocations) settled() (error, bool) {
	r.mu.RLock()
	unwritten := r.unwritten
	seen := r.seen
	reloadErr := r.reloadErr
	r.mu.RUnlock()
	if unwritten {
		return nil, true
	}
	info, err := os.Stat(r.path)
	if err != nil {
		return fmt.Errorf("revocations: %w", err), true
	}
	if seen != nil && sameFile(seen, info) && seen.Mode().Perm() == info.Mode().Perm() {
		return reloadErr, true
	}
	return nil, false
}

// refresh 在文件被换掉时用文件里的表换掉内存。写到一半的收紧不换。读不成不把表清掉。
func (r *Revocations) refresh() error {
	if err, done := r.settled(); done {
		return err
	}
	// 和改动串行：否则可能把刚刚收紧、还没记到 seen 上的内存，盖成打开时的旧文件。
	r.writing.Lock()
	defer r.writing.Unlock()
	if err, done := r.settled(); done {
		return err
	}
	info, statErr := os.Stat(r.path)
	epoch, revoked, banned, readInfo, err := readRevocations(r.path)
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.unwritten {
		return nil
	}
	if err != nil {
		switch {
		case readInfo != nil:
			r.seen = readInfo
		case statErr == nil:
			r.seen = info
		}
		r.reloadErr = err
		return err
	}
	r.epoch = epoch
	r.revoked = revoked
	r.banned = banned
	r.seen = readInfo
	r.reloadErr = nil
	return nil
}

func parseRevocations(raw []byte) (uint64, map[string]revocation, map[string]revocation, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var doc revocationsDocument
	if err := decoder.Decode(&doc); err != nil {
		return 0, nil, nil, errors.New(`not a JSON object of "epoch" and "revoked_accounts"`)
	}
	if _, err := decoder.Token(); err != io.EOF {
		return 0, nil, nil, errors.New("unexpected data after the object")
	}
	if doc.Epoch == nil || doc.Accounts == nil {
		return 0, nil, nil, errors.New(`"epoch" and "revoked_accounts" are both required; with nothing revoked, "revoked_accounts" is {}`)
	}
	revoked, err := parseEntries(doc.Accounts, "account")
	if err != nil {
		return 0, nil, nil, err
	}
	// 没有这个字段，或者写成 null，都是一张空的封禁表。已有的撤销文件因此照旧能读。
	banned, err := parseEntries(doc.Banned, "operation")
	if err != nil {
		return 0, nil, nil, err
	}
	return *doc.Epoch, revoked, banned, nil
}

func parseEntries(entries map[string]revocationDocument, kind string) (map[string]revocation, error) {
	parsed := make(map[string]revocation, len(entries))
	for name, entry := range entries {
		if name == "" {
			return nil, errors.New("an entry has an empty " + kind)
		}
		if entry.At == nil {
			return nil, fmt.Errorf(`entry %q: "at" is required`, name)
		}
		at, err := time.Parse(time.RFC3339, *entry.At)
		if err != nil {
			return nil, fmt.Errorf(`entry %q: "at" is not an RFC 3339 time`, name)
		}
		parsed[name] = revocation{at: at.UTC(), by: entry.By, reason: entry.Reason}
	}
	return parsed, nil
}

// State 实现 ports.Revocations。两个值在同一把锁下读出，彼此一致。
func (r *Revocations) State(_ context.Context, accountID string) (bool, uint64, error) {
	if err := r.refresh(); err != nil {
		return false, 0, err
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, revoked := r.revoked[accountID]
	return revoked, r.epoch, nil
}

// View 实现 ports.Revocations。账户、操作和代次在同一把锁下读出。
func (r *Revocations) View(_ context.Context, accountID, operationID string) (bool, bool, uint64, error) {
	if err := r.refresh(); err != nil {
		return false, false, 0, err
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, revoked := r.revoked[accountID]
	_, banned := r.banned[operationID]
	return revoked, banned, r.epoch, nil
}

// Epoch 实现 ports.Revocations。
func (r *Revocations) Epoch(context.Context) (uint64, error) {
	if err := r.refresh(); err != nil {
		return 0, err
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.epoch, nil
}

// Revoke 实现 ports.RevocationLedger：先生效，再写文件。
//
// 账户已经被撤销时什么都不改；但上一次没有写成的话，这一次再写一遍，所以重发同一个撤销
// 是把它写下去的办法。写之前把磁盘上其他进程已经写下的表并进来。
func (r *Revocations) Revoke(_ context.Context, accountID, by, reason string) (ports.RevocationChange, error) {
	if accountID == "" {
		return ports.RevocationChange{}, errors.New("revocations: no account given")
	}
	snap, release, err := r.exclusive()
	defer release()

	_, already := snap.revoked[accountID]
	if !already {
		next := maps.Clone(snap.revoked)
		if next == nil {
			next = map[string]revocation{}
		}
		next[accountID] = revocation{at: r.now().UTC().Truncate(time.Second), by: by, reason: reason}
		snap.revoked = next
		snap.epoch++
		snap.unwritten = true
	}
	change := ports.RevocationChange{Changed: !already, Revoked: true, Epoch: snap.epoch}
	if err != nil {
		if !already {
			r.publish(snap, false)
		}
		return change, fmt.Errorf("%w: %w", ports.ErrRevocationNotWritten, err)
	}
	if !snap.unwritten {
		r.publish(snap, true)
		return change, nil
	}
	if err := r.write(snap.epoch, snap.revoked, snap.banned); err != nil {
		r.publish(snap, false)
		return change, fmt.Errorf("%w: %w", ports.ErrRevocationNotWritten, err)
	}
	r.publish(snap, true)
	return change, nil
}

// Restore 实现 ports.RevocationLedger：先写文件，写成了才恢复。
// 磁盘上其他进程写下的撤销留在表里，只拿掉这一个账户。
func (r *Revocations) Restore(_ context.Context, accountID string) (ports.RevocationChange, error) {
	snap, release, err := r.exclusive()
	defer release()
	if err != nil {
		revoked, epoch := r.accountRevoked(accountID)
		return ports.RevocationChange{Revoked: revoked, Epoch: epoch}, fmt.Errorf("revocations: restore not applied: %w", err)
	}
	if _, revoked := snap.revoked[accountID]; !revoked {
		r.publish(snap, !snap.unwritten)
		return ports.RevocationChange{Epoch: snap.epoch}, nil
	}
	next := maps.Clone(snap.revoked)
	delete(next, accountID)
	if err := r.write(snap.epoch+1, next, snap.banned); err != nil {
		return ports.RevocationChange{Revoked: true, Epoch: snap.epoch}, fmt.Errorf("revocations: restore not applied: %w", err)
	}
	snap.revoked, snap.epoch = next, snap.epoch+1
	r.publish(snap, true)
	return ports.RevocationChange{Changed: true, Epoch: snap.epoch}, nil
}

// Ban 实现 ports.RevocationLedger：先生效，再写文件。重复封禁不是错误，也不增加代次。
//
// 操作已经被封禁时什么都不改；但上一次没有写成的话，这一次再写一遍。写之前把磁盘上其他进程已经写下的表并进来。
func (r *Revocations) Ban(_ context.Context, operationID, by, reason string) (ports.BanChange, error) {
	if operationID == "" {
		return ports.BanChange{}, errors.New("revocations: no operation given")
	}
	snap, release, err := r.exclusive()
	defer release()

	_, already := snap.banned[operationID]
	if !already {
		next := maps.Clone(snap.banned)
		if next == nil {
			next = map[string]revocation{}
		}
		next[operationID] = revocation{at: r.now().UTC().Truncate(time.Second), by: by, reason: reason}
		snap.banned = next
		snap.epoch++
		snap.unwritten = true
	}
	change := ports.BanChange{Changed: !already, Banned: true, Epoch: snap.epoch}
	if err != nil {
		if !already {
			r.publish(snap, false)
		}
		return change, fmt.Errorf("%w: %w", ports.ErrRevocationNotWritten, err)
	}
	if !snap.unwritten {
		r.publish(snap, true)
		return change, nil
	}
	if err := r.write(snap.epoch, snap.revoked, snap.banned); err != nil {
		r.publish(snap, false)
		return change, fmt.Errorf("%w: %w", ports.ErrRevocationNotWritten, err)
	}
	r.publish(snap, true)
	return change, nil
}

// Lift 实现 ports.RevocationLedger：先写文件，写成了才解除。重复解除不是错误，也不增加代次。
// 磁盘上其他进程写下的封禁留在表里，只拿掉这一个操作。
func (r *Revocations) Lift(_ context.Context, operationID string) (ports.BanChange, error) {
	snap, release, err := r.exclusive()
	defer release()
	if err != nil {
		banned, epoch := r.operationBanned(operationID)
		return ports.BanChange{Banned: banned, Epoch: epoch}, fmt.Errorf("revocations: lift not applied: %w", err)
	}
	if _, banned := snap.banned[operationID]; !banned {
		r.publish(snap, !snap.unwritten)
		return ports.BanChange{Epoch: snap.epoch}, nil
	}
	next := maps.Clone(snap.banned)
	delete(next, operationID)
	if err := r.write(snap.epoch+1, snap.revoked, next); err != nil {
		return ports.BanChange{Banned: true, Epoch: snap.epoch}, fmt.Errorf("revocations: lift not applied: %w", err)
	}
	snap.banned, snap.epoch = next, snap.epoch+1
	r.publish(snap, true)
	return ports.BanChange{Changed: true, Epoch: snap.epoch}, nil
}

// Banned 实现 ports.RevocationLedger。
func (r *Revocations) Banned(context.Context) ([]ports.BannedOperation, uint64, error) {
	if err := r.refresh(); err != nil {
		return nil, 0, err
	}
	r.mu.RLock()
	epoch, banned := r.epoch, r.banned
	r.mu.RUnlock()
	operations := make([]ports.BannedOperation, 0, len(banned))
	for _, operation := range slices.Sorted(maps.Keys(banned)) {
		entry := banned[operation]
		operations = append(operations, ports.BannedOperation{OperationID: operation, At: entry.at, By: entry.by, Reason: entry.reason})
	}
	return operations, epoch, nil
}

// Adopt 用协调器的快照整份换掉内存和文件。它在与 Revoke 同一把写锁下写完再发布。
// 代次不在这里递增：写下去的就是调用方给的那一个。本地代次不同时，调用方给的这一份留下。
// 写文件失败时内存保持原样。Load、Revoke、Restore、Ban、Lift、View 的行为不因这个方法改变。
func (r *Revocations) Adopt(epoch uint64, accounts []ports.RevokedAccount, bans []ports.BannedOperation) error {
	revoked, err := revocationEntries(accounts)
	if err != nil {
		return err
	}
	banned, err := banEntries(bans)
	if err != nil {
		return err
	}
	r.writing.Lock()
	defer r.writing.Unlock()
	unlock, err := r.hold()
	if err != nil {
		return err
	}
	defer unlock()
	if err := r.write(epoch, revoked, banned); err != nil {
		return err
	}
	r.publish(snapshot{epoch: epoch, revoked: revoked, banned: banned}, true)
	return nil
}

func revocationEntries(accounts []ports.RevokedAccount) (map[string]revocation, error) {
	revoked := make(map[string]revocation, len(accounts))
	for _, account := range accounts {
		if account.AccountID == "" {
			return nil, errors.New("revocations: no account given")
		}
		if _, ok := revoked[account.AccountID]; ok {
			return nil, fmt.Errorf("revocations: account %q is duplicated", account.AccountID)
		}
		revoked[account.AccountID] = revocation{at: account.At.UTC(), by: account.By, reason: account.Reason}
	}
	return revoked, nil
}

func banEntries(bans []ports.BannedOperation) (map[string]revocation, error) {
	banned := make(map[string]revocation, len(bans))
	for _, ban := range bans {
		if ban.OperationID == "" {
			return nil, errors.New("revocations: no operation given")
		}
		if _, ok := banned[ban.OperationID]; ok {
			return nil, fmt.Errorf("revocations: operation %q is duplicated", ban.OperationID)
		}
		banned[ban.OperationID] = revocation{at: ban.At.UTC(), by: ban.By, reason: ban.Reason}
	}
	return banned, nil
}

// Revoked 实现 ports.RevocationLedger。
func (r *Revocations) Revoked(context.Context) ([]ports.RevokedAccount, uint64, error) {
	if err := r.refresh(); err != nil {
		return nil, 0, err
	}
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

// snapshot 是一次改动要写下去的那张表。revoked 和 banned 不会和正在被读的那两张是同一个 map。
type snapshot struct {
	epoch           uint64
	revoked, banned map[string]revocation
	unwritten       bool
}

// exclusive 占住本进程的写锁和旁边的锁文件，再读磁盘。
// 内存里有没写下去的收紧时，把磁盘上多出来的条目补进来，不丢掉内存里的。
// 没有这种收紧时，磁盘是这份表的来源。锁文件建不出来或磁盘读不成时，返回改动前的内存，并带上错误。
// release 总会解开这两把锁。
func (r *Revocations) exclusive() (snapshot, func(), error) {
	r.writing.Lock()
	unlock, err := r.hold()
	if err != nil {
		return r.memorySnapshot(), func() { r.writing.Unlock() }, err
	}
	release := func() {
		unlock()
		r.writing.Unlock()
	}
	diskEpoch, diskRevoked, diskBanned, _, readErr := readRevocations(r.path)
	snap := r.memorySnapshot()
	if readErr != nil {
		return snap, release, readErr
	}
	if snap.unwritten {
		snap.revoked = unionRevocations(snap.revoked, diskRevoked)
		snap.banned = unionRevocations(snap.banned, diskBanned)
		if diskEpoch > snap.epoch {
			snap.epoch = diskEpoch
		}
		return snap, release, nil
	}
	snap.epoch, snap.revoked, snap.banned = diskEpoch, diskRevoked, diskBanned
	return snap, release, nil
}

func (r *Revocations) memorySnapshot() snapshot {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return snapshot{epoch: r.epoch, revoked: r.revoked, banned: r.banned, unwritten: r.unwritten}
}

func (r *Revocations) accountRevoked(accountID string) (bool, uint64) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, revoked := r.revoked[accountID]
	return revoked, r.epoch
}

func (r *Revocations) operationBanned(operationID string) (bool, uint64) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, banned := r.banned[operationID]
	return banned, r.epoch
}

// publish 把表换成这次改动之后的。synced 表示它和锁还占着的那份文件是同一张。
func (r *Revocations) publish(snap snapshot, synced bool) {
	var info os.FileInfo
	var err error
	if synced {
		info, err = os.Stat(r.path)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.epoch, r.revoked, r.banned = snap.epoch, snap.revoked, snap.banned
	r.unwritten = !synced
	if synced && err == nil {
		r.seen = info
		r.reloadErr = nil
	}
}

// hold 占住路径旁边的锁文件。数据文件每次写都会改名，锁要落在不会被换掉的那个文件上。
// 占着的进程退出时内核放开。锁文件留着，权限是 0600。
func (r *Revocations) hold() (func(), error) {
	file, err := os.OpenFile(r.path+".lock", os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return nil, err
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX); err != nil {
		_ = file.Close()
		return nil, err
	}
	return func() {
		_ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
		_ = file.Close()
	}, nil
}

// unionRevocations 保留 local 里已有的条目，再补上 disk 里多出来的。
func unionRevocations(local, disk map[string]revocation) map[string]revocation {
	merged := maps.Clone(local)
	if merged == nil {
		merged = map[string]revocation{}
	}
	for name, entry := range disk {
		if _, ok := merged[name]; !ok {
			merged[name] = entry
		}
	}
	return merged
}

// write 把账户表和封禁表一起换到文件上：写临时文件，刷盘，改名，再刷目录。中途失败时原来的文件不动。
// 两张表都写；没有条目时写 {}，不写 null。
func (r *Revocations) write(epoch uint64, revoked, banned map[string]revocation) error {
	if banned == nil {
		banned = map[string]revocation{}
	}
	doc := revocationsDocument{
		Epoch:    &epoch,
		Accounts: make(map[string]revocationDocument, len(revoked)),
		Banned:   make(map[string]revocationDocument, len(banned)),
	}
	for account, entry := range revoked {
		at := entry.at.UTC().Format(time.RFC3339)
		doc.Accounts[account] = revocationDocument{At: &at, By: entry.by, Reason: entry.reason}
	}
	for operation, entry := range banned {
		at := entry.at.UTC().Format(time.RFC3339)
		doc.Banned[operation] = revocationDocument{At: &at, By: entry.by, Reason: entry.reason}
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
