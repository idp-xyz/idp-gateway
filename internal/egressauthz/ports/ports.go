// Package ports 是出站判定对外部依赖的要求：凭证从哪里取，撤销状态从哪里读，
// 账户的使用授权向谁问。
package ports

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"go.idp.xyz/idp-gateway/internal/egressauthz/domain"
)

// ErrCredentialNotHeld 表示凭证来源里没有这个账户的凭证。
var ErrCredentialNotHeld = errors.New("egressauthz: credential not held")

// CredentialSource 给出以某个账户调用 Provider 时使用的凭证。
type CredentialSource interface {
	// AuthorizationHeader 返回写入上游请求 Authorization 头的完整值。
	// 没有这个账户的凭证时返回包装了 ErrCredentialNotHeld 的错误。
	AuthorizationHeader(ctx context.Context, bindingRef, accountID string) (Secret, error)
}

// Revocations 给出账户的撤销状态，以及操作是否被封禁。每次判定都要读，不允许用路由发布时的旧值。
type Revocations interface {
	// State 返回账户此刻是否已被撤销，以及读到这个结果时的撤销代次。
	State(ctx context.Context, accountID string) (revoked bool, epoch uint64, err error)
	// View 同时读出账户是否被撤销、操作是否被封禁，以及这一刻的代次。三个值同一次读出，彼此一致。
	View(ctx context.Context, accountID, operationID string) (accountRevoked, operationBanned bool, epoch uint64, err error)
	// Epoch 返回当前的撤销代次。账户撤销和操作封禁共用这一个代次。
	Epoch(ctx context.Context) (uint64, error)
}

// ErrRevocationNotWritten 表示一次撤销已经在内存里生效，却没有写到保存它的地方：现在的
// 请求会被拒绝，重启之后这次撤销就没有了。
var ErrRevocationNotWritten = errors.New("egressauthz: revocation in effect but not written")

// RevokedAccount 是撤销表里的一行。
type RevokedAccount struct {
	AccountID string
	At        time.Time
	// By 是做这次撤销的工作负载身份。
	By     string
	Reason string
}

// RevocationChange 是一次撤销或恢复之后的情况。
type RevocationChange struct {
	// Changed 为 false 表示这次调用之前就已经是这个状态。
	Changed bool
	// Revoked 是这次调用之后账户是否处于被撤销的状态。
	Revoked bool
	// Epoch 是这次调用之后的撤销代次。
	Epoch uint64
}

// BannedOperation 是封禁表里的一行：这个 operation_id 对每个账户都不放行。
type BannedOperation struct {
	OperationID string
	At          time.Time
	// By 是做这次封禁的工作负载身份。
	By     string
	Reason string
}

// BanChange 是一次封禁或解除之后的情况。
type BanChange struct {
	// Changed 为 false 表示这次调用之前就已经是这个状态。
	Changed bool
	// Banned 是这次调用之后该操作是否处于被封禁的状态。
	Banned bool
	// Epoch 是这次调用之后的代次。与账户撤销共用。
	Epoch uint64
}

// RevocationLedger 是撤销状态可以改的那一侧（docs/adr/ADR-0012.md）。读的一侧仍是 Revocations。
// 账户撤销和操作封禁在同一份状态、同一个代次里。
//
// 改动只往收紧的方向偏：Revoke 和 Ban 先生效再保存，保存不成时返回包装了 ErrRevocationNotWritten
// 的错误，收紧仍然有效；Restore 和 Lift 先保存，保存不成就不放宽。
type RevocationLedger interface {
	Revocations
	// Revoke 撤销一个账户。by 是做这件事的工作负载身份。
	Revoke(ctx context.Context, accountID, by, reason string) (RevocationChange, error)
	// Restore 取消对一个账户的撤销。
	Restore(ctx context.Context, accountID string) (RevocationChange, error)
	// Revoked 返回整张表（按账户排序）和当前代次。
	Revoked(ctx context.Context) ([]RevokedAccount, uint64, error)
	// Ban 封禁一个操作：从下一次判定起，每个账户做这个操作都不放行。by 是做这件事的工作负载身份。
	Ban(ctx context.Context, operationID, by, reason string) (BanChange, error)
	// Lift 解除对一个操作的封禁。
	Lift(ctx context.Context, operationID string) (BanChange, error)
	// Banned 返回被封禁的操作（按 operation_id 排序）和当前代次。
	Banned(ctx context.Context) ([]BannedOperation, uint64, error)
}

// RateLimiter 按 Provider 账户做进程内配额。allowed 为 false 时 retryAfterSeconds 至少为 1。
// err 非 nil 表示这一跳的结果不可用：调用方必须失败关闭，既不能放行，也不能把它当成策略拒绝。
type RateLimiter interface {
	Allow(ctx context.Context, subject domain.RateLimitSubject) (allowed bool, retryAfterSeconds int, err error)
}

// Grants 回答某个调用方此刻有没有被授予某个 Provider 账户的使用权。授权数据不在本服务里。
type Grants interface {
	// MayUse 报告租户 tenantID 名下的调用方 subject 能否使用 accountID。
	// 问不出结果时返回错误：调用方不得把错误当成"没有授权"，更不得当成"有授权"。
	MayUse(ctx context.Context, subject, tenantID, accountID string) (bool, error)
}

// Handle 是凭证句柄：凭证绑定加账户。它出现在只返回判定的接口里，本身不是凭证。
func Handle(bindingRef, accountID string) string {
	return bindingRef + "/" + accountID
}

// Secret 包住一个不该出现在日志、错误信息或 JSON 里的值。要用它只能显式调用 Reveal，
// 其余常见的输出途径得到的都是占位符。
type Secret struct{ value string }

const redacted = "[REDACTED]"

// NewSecret 包住一个值。
func NewSecret(value string) Secret { return Secret{value: value} }

// Reveal 返回原值。只在把它写到该去的地方时调用。
func (s Secret) Reveal() string { return s.value }

// IsZero 报告里面是否没有值。
func (s Secret) IsZero() bool { return s.value == "" }

func (Secret) String() string               { return redacted }
func (Secret) GoString() string             { return redacted }
func (Secret) LogValue() slog.Value         { return slog.StringValue(redacted) }
func (Secret) MarshalText() ([]byte, error) { return []byte(redacted), nil }
