// Package ports 是 JWKS 同步对外部的要求：从哪里取文档，取到之后写到哪里。
// 取和写都在适配器里；这里只有这两件事的形状。
package ports

import "context"

// Fetcher 取回身份提供者当前给出的 JWKS 正文。失败时不要返回正文：
// 调用方只在 err 为 nil 时才把字节当作密钥集来解析。
type Fetcher interface {
	Fetch(ctx context.Context) ([]byte, error)
}

// Store 是本机的那一份 JWKS 文件。Read 在文件还不存在时返回 false，这不是错误。
// Write 必须整份替换：先写临时文件，再改名，读者不会看到写了一半的内容。
type Store interface {
	Read() (data []byte, exists bool, err error)
	Write(data []byte) error
}
