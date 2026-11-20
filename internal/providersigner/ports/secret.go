package ports

import (
	"fmt"
	"log/slog"
)

const redacted = "[REDACTED]"

// Secret 包住一个不该出现在日志、错误信息或 JSON 里的值（appKey、访问令牌）。要用它只能显式调用
// Reveal，其余常见的输出途径得到的都是占位符。这是 egressauthz 的 ports.Secret 的一份最小等价物：
// 两个上下文不能互相导入。
type Secret struct{ value string }

// NewSecret 包住一个值。
func NewSecret(value string) Secret { return Secret{value: value} }

// Reveal 返回原值。只在把它写到该去的地方（发给承运商的请求头）时调用。
func (s Secret) Reveal() string { return s.value }

func (Secret) String() string               { return redacted }
func (Secret) GoString() string             { return redacted }
func (Secret) LogValue() slog.Value         { return slog.StringValue(redacted) }
func (Secret) MarshalText() ([]byte, error) { return []byte(redacted), nil }
func (Secret) MarshalJSON() ([]byte, error) { return []byte(`"` + redacted + `"`), nil }

// Format 管住所有的动词：%d、%x 之类对结构体会展开未导出的字段，只靠 String 管不到。
func (Secret) Format(f fmt.State, _ rune) { _, _ = f.Write([]byte(redacted)) }
