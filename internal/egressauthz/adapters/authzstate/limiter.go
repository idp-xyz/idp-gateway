package authzstate

import (
	"context"
	"log/slog"

	"go.idp.xyz/idp-gateway/internal/egressauthz/adapters/filestore"
	"go.idp.xyz/idp-gateway/internal/egressauthz/domain"
)

// Limiter 把配额扣费交给协调器。规则仍从本地文件读，本地桶不扣。
// 没有命中的规则时不发请求，直接放行。协调器答错、超时或参数冲突都是错误，不得放行。
type Limiter struct {
	client *Client
	limits *filestore.RateLimits
	log    *slog.Logger
}

// NewLimiter 在同时配置了协调器和 --rate-limits 时使用。
func NewLimiter(client *Client, limits *filestore.RateLimits, logger *slog.Logger) *Limiter {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	return &Limiter{client: client, limits: limits, log: logger}
}

// Allow 实现 ports.RateLimiter。Charges 不改本地桶。空清单零次 RPC。
func (l *Limiter) Allow(ctx context.Context, subject domain.RateLimitSubject) (bool, int, error) {
	if err := ctx.Err(); err != nil {
		return false, 0, err
	}
	charges := l.limits.Charges(subject)
	if len(charges) == 0 {
		return true, 0, nil
	}
	allowed, retry, err := l.client.Quota(ctx, charges)
	if err != nil {
		l.log.Warn("authz state quota failed", "cause", err.Error())
		return false, 0, err
	}
	if !allowed && retry < 1 {
		err := &callError{cause: "bad_answer"}
		l.log.Warn("authz state quota failed", "cause", err.Error())
		return false, 0, err
	}
	return allowed, retry, nil
}
