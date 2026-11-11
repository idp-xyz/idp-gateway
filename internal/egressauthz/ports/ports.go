// Package ports 是出站判定对外部依赖的要求：凭证从哪里取，撤销状态从哪里读，
// 账户的使用授权向谁问。
package ports

import (
	"context"
	"errors"
	"log/slog"
)

// ErrCredentialNotHeld 表示凭证来源里没有这个账户的凭证。
var ErrCredentialNotHeld = errors.New("egressauthz: credential not held")

// CredentialSource 给出以某个账户调用 Provider 时使用的凭证。
type CredentialSource interface {
	// AuthorizationHeader 返回写入上游请求 Authorization 头的完整值。
	// 没有这个账户的凭证时返回包装了 ErrCredentialNotHeld 的错误。
	AuthorizationHeader(ctx context.Context, bindingRef, accountID string) (Secret, error)
}

// Revocations 给出账户的撤销状态。每次判定都要读，不允许用路由发布时的旧值。
type Revocations interface {
	// State 返回账户此刻是否已被撤销，以及读到这个结果时的撤销代次。
	State(ctx context.Context, accountID string) (revoked bool, epoch uint64, err error)
	// Epoch 返回当前的撤销代次。
	Epoch(ctx context.Context) (uint64, error)
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
