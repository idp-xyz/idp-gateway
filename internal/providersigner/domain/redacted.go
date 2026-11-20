package domain

import "fmt"

const placeholder = "[REDACTED]"

// redacted 嵌入在装着秘密的类型里：格式化、文本编码和 JSON 编码得到的都是占位符，
// 与秘密里是什么无关。domain 不许导入 log/slog，所以这里没有 LogValue；slog 对没有 LogValue 的
// 值会走 MarshalText 或 MarshalJSON，两者都是占位符。ports.Secret 是带 LogValue 的那一份。
type redacted struct{}

func (redacted) String() string               { return placeholder }
func (redacted) GoString() string             { return placeholder }
func (redacted) MarshalText() ([]byte, error) { return []byte(placeholder), nil }
func (redacted) MarshalJSON() ([]byte, error) { return []byte(`"` + placeholder + `"`), nil }

// Format 管住所有的动词：%d、%x 之类对结构体会展开未导出的字段，只靠 String 管不到。
func (redacted) Format(f fmt.State, _ rune) { _, _ = f.Write([]byte(placeholder)) }
