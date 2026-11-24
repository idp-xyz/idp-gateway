// Package domain 是撤销、封禁和配额键的规则。它不做 I/O，不导入 net、os 或 log/slog。
package domain

import (
	"errors"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	// ActionRevoke 把一个账户放进撤销表。
	ActionRevoke = "revoke"
	// ActionRestore 把一个账户从撤销表里拿掉。
	ActionRestore = "restore"
	// ActionBan 封禁一个操作。
	ActionBan = "ban"
	// ActionLift 解除对一个操作的封禁。
	ActionLift = "lift"

	// MaxByRunes 是 by 的长度上限。by 必须是可见 ASCII。
	MaxByRunes = 256
	// MaxReasonRunes 是原因的长度上限。filestore 不限制长度；协调器在入口加上这一档。
	MaxReasonRunes = 512
	// MaxIDBytes 与 gateway-authz 已有的账户名上限相同。account-blue、tracking.get 都在这一档里。
	MaxIDBytes = 256
)

// ErrInvalid 是参数不合格。错误文字里没有请求正文。
var ErrInvalid = errors.New("authzstate: invalid")

// Entry 是撤销表或封禁表里的一行。
type Entry struct {
	At     time.Time
	By     string
	Reason string
}

// Snapshot 是一份撤销/封禁文档：代次、被撤销的账户、被封禁的操作。
type Snapshot struct {
	Epoch    uint64
	Accounts map[string]Entry
	Bans     map[string]Entry
}

// Clone 返回一份不和原来共用 map 的快照。
func (s Snapshot) Clone() Snapshot {
	return Snapshot{Epoch: s.Epoch, Accounts: cloneEntries(s.Accounts), Bans: cloneEntries(s.Bans)}
}

func cloneEntries(in map[string]Entry) map[string]Entry {
	if len(in) == 0 {
		return map[string]Entry{}
	}
	out := make(map[string]Entry, len(in))
	for key, entry := range in {
		out[key] = entry
	}
	return out
}

// Mutation 是一次收紧或放宽。revoke/restore 只用 AccountID，ban/lift 只用 OperationID。
type Mutation struct {
	Action      string
	AccountID   string
	OperationID string
	By          string
	Reason      string
}

// ValidateMutation 拒绝空的账户或操作、过长的 by/reason，以及不认识的动作。
// 账户和操作只拒绝空串和控制字符，不另加格式：account-blue、tracking.get 都合法。
func ValidateMutation(m Mutation) error {
	switch m.Action {
	case ActionRevoke, ActionRestore:
		if m.OperationID != "" || !plainID(m.AccountID) {
			return ErrInvalid
		}
	case ActionBan, ActionLift:
		if m.AccountID != "" || !plainID(m.OperationID) {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	if m.Action == ActionRevoke || m.Action == ActionBan {
		if !visibleASCII(m.By, MaxByRunes) {
			return ErrInvalid
		}
	} else if m.By != "" && !visibleASCII(m.By, MaxByRunes) {
		return ErrInvalid
	}
	if !plainReason(m.Reason) {
		return ErrInvalid
	}
	return nil
}

// Apply 返回应用 m 之后的快照，以及集合是否真的变了。代次只在集合变化时加一。
// 它不写盘。调用方必须先把返回值落盘，成功之后才能把它当成已发布的状态。
func Apply(current Snapshot, m Mutation, now time.Time) (Snapshot, bool, error) {
	if err := ValidateMutation(m); err != nil {
		return Snapshot{}, false, err
	}
	next := current.Clone()
	if next.Accounts == nil {
		next.Accounts = map[string]Entry{}
	}
	if next.Bans == nil {
		next.Bans = map[string]Entry{}
	}
	switch m.Action {
	case ActionRevoke:
		if _, ok := next.Accounts[m.AccountID]; ok {
			return current.Clone(), false, nil
		}
		next.Accounts[m.AccountID] = Entry{At: now.UTC().Truncate(time.Second), By: m.By, Reason: m.Reason}
		next.Epoch++
		return next, true, nil
	case ActionRestore:
		if _, ok := next.Accounts[m.AccountID]; !ok {
			return current.Clone(), false, nil
		}
		delete(next.Accounts, m.AccountID)
		next.Epoch++
		return next, true, nil
	case ActionBan:
		if _, ok := next.Bans[m.OperationID]; ok {
			return current.Clone(), false, nil
		}
		next.Bans[m.OperationID] = Entry{At: now.UTC().Truncate(time.Second), By: m.By, Reason: m.Reason}
		next.Epoch++
		return next, true, nil
	case ActionLift:
		if _, ok := next.Bans[m.OperationID]; !ok {
			return current.Clone(), false, nil
		}
		delete(next.Bans, m.OperationID)
		next.Epoch++
		return next, true, nil
	default:
		return Snapshot{}, false, ErrInvalid
	}
}

func plainID(s string) bool {
	if s == "" || len(s) > MaxIDBytes || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if r == 0 || unicode.IsControl(r) {
			return false
		}
	}
	return true
}

func plainReason(s string) bool {
	if !utf8.ValidString(s) || utf8.RuneCountInString(s) > MaxReasonRunes {
		return false
	}
	for _, r := range s {
		if r == 0 || unicode.IsControl(r) {
			return false
		}
	}
	return true
}

// visibleASCII 报告 s 是 1 到 maxRunes 个可见 ASCII（0x21–0x7e）。
func visibleASCII(s string, maxRunes int) bool {
	if s == "" || utf8.RuneCountInString(s) > maxRunes || len(s) != utf8.RuneCountInString(s) {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x21 || s[i] > 0x7e {
			return false
		}
	}
	return true
}
