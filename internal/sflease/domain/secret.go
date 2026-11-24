package domain

import "fmt"

// redacted 是秘密值出现在日志、错误、JSON 里时的占位符。
const redacted = "[REDACTED]"

// Secret 包住一个不该出现在日志、错误信息或 JSON 里的值（访问令牌）。要用它只能显式调用 Reveal。
// 形状与 egressauthz/ports.Secret、providersigner/ports.Secret 相同，但本包是 domain：
// 不能导入 log/slog（internal/architecture 禁止 domain 写日志），所以没有 LogValue。
// 值放在未导出字段里；slog 的反射不会把它打出来。String、GoString、Format、MarshalText、
// MarshalJSON 覆盖 fmt 和 encoding/json 的出口。
type Secret struct{ value string }

// NewSecret 包住一个值。
func NewSecret(value string) Secret { return Secret{value: value} }

// Reveal 返回原值。只在把它写进租约文件或协调器应答时调用。
func (s Secret) Reveal() string { return s.value }

// IsZero 报告里面是否没有值。
func (s Secret) IsZero() bool { return s.value == "" }

func (Secret) String() string               { return redacted }
func (Secret) GoString() string             { return redacted }
func (Secret) MarshalText() ([]byte, error) { return []byte(redacted), nil }
func (Secret) MarshalJSON() ([]byte, error) { return []byte(`"` + redacted + `"`), nil }

// Format 管住所有的动词：%d、%x 之类对结构体会展开未导出的字段，只靠 String 管不到。
func (Secret) Format(f fmt.State, _ rune) { _, _ = f.Write([]byte(redacted)) }
