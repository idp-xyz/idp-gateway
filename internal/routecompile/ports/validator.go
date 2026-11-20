// Package ports 是 routecompile 对外的端口。校验器跑的是锁定的 agentgateway，不在 domain 里。
package ports

import (
	"context"
	"errors"
)

// ErrRefused 表示原生校验拒绝了这份配置。调用方不得把文件写出去。
var ErrRefused = errors.New("native validation refused")

// Validator 用 agentgateway --validate-only 检查一份已经编译好的配置。
// tlsDir 和 jwksFile 为空时，实现自己准备临时的证书和 JWKS，不监听端口。
type Validator interface {
	Validate(ctx context.Context, yamlBytes []byte, tlsDir string, jwksFile string) error
}
