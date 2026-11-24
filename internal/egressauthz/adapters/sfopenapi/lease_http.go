package sfopenapi

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"go.idp.xyz/idp-gateway/internal/egressauthz/ports"
)

// leaseCallError 的文字是固定的类别。它不包装 *url.Error，免得把地址和查询串带出去。
type leaseCallError struct{ cause string }

func (e *leaseCallError) Error() string { return "lease coordinator " + e.cause }

// HTTPLeaseClient 用双向 TLS 调用 sf-token-coordinator 的三个接口。
// 日志和错误里没有令牌、URL 查询串或密钥。
type HTTPLeaseClient struct {
	base   string
	http   *http.Client
	logger *slog.Logger
}

// NewHTTPLeaseClient 要求 baseURL 是没有用户信息、查询串和片段的 https 地址。
// tlsConfig 由调用方配好（含热重载的客户端证书）；这里禁止代理、不跟随重定向。
func NewHTTPLeaseClient(baseURL string, tlsConfig *tls.Config, logger *slog.Logger) (*HTTPLeaseClient, error) {
	if tlsConfig == nil {
		return nil, errors.New("sf openapi lease: tls config is required")
	}
	parsed, err := url.Parse(baseURL)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, errors.New("sf openapi lease: url must be https without user information, a query string, or a fragment")
	}
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	return &HTTPLeaseClient{
		base:   parsed.String(),
		logger: logger,
		http: &http.Client{
			Transport: &http.Transport{
				Proxy: nil, // 环境变量里的代理不能插到租约这一跳上
				DialContext: (&net.Dialer{
					Timeout:   2 * time.Second,
					KeepAlive: 30 * time.Second,
				}).DialContext,
				TLSClientConfig:       tlsConfig,
				ForceAttemptHTTP2:     true,
				MaxIdleConns:          8,
				IdleConnTimeout:       60 * time.Second,
				TLSHandshakeTimeout:   2 * time.Second,
				ResponseHeaderTimeout: 2 * time.Second,
				ExpectContinueTimeout: time.Second,
			},
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}, nil
}

// Acquire 询问协调器。非 200、读不懂的正文都是错误，错误里没有应答正文。
func (c *HTTPLeaseClient) Acquire(ctx context.Context, req AcquireRequest) (AcquireResult, error) {
	payload := map[string]any{
		"lease_key":       req.LeaseKey,
		"holder_id":       req.HolderID,
		"refresh_lead_ms": req.RefreshLead.Milliseconds(),
		"lock_ttl_ms":     req.LockTTL.Milliseconds(),
		"wait_ms":         req.Wait.Milliseconds(),
	}
	var decoded struct {
		State        string `json:"state"`
		Token        string `json:"token"`
		ExpiresAt    string `json:"expires_at"`
		LifetimeMs   int64  `json:"lifetime_ms"`
		FenceToken   string `json:"fence_token"`
		RetryAfterMs int    `json:"retry_after_ms"`
	}
	if err := c.post(ctx, "/v1/sf-leases/acquire", payload, &decoded); err != nil {
		return AcquireResult{}, err
	}
	switch LeaseState(decoded.State) {
	case LeaseValid:
		expires, err := time.Parse(time.RFC3339Nano, decoded.ExpiresAt)
		if err != nil || decoded.Token == "" || decoded.LifetimeMs <= 0 || !visibleASCII(decoded.Token) || containsSemicolon(decoded.Token) {
			return AcquireResult{}, c.bad("bad_answer")
		}
		return AcquireResult{
			State: LeaseValid, Token: ports.NewSecret(decoded.Token),
			ExpiresAt: expires, Lifetime: time.Duration(decoded.LifetimeMs) * time.Millisecond,
		}, nil
	case LeaseFetch:
		fence, err := strconv.ParseUint(decoded.FenceToken, 10, 64)
		if err != nil || fence == 0 {
			return AcquireResult{}, c.bad("bad_answer")
		}
		return AcquireResult{State: LeaseFetch, FenceToken: fence}, nil
	case LeaseWait:
		if decoded.RetryAfterMs < 0 {
			return AcquireResult{}, c.bad("bad_answer")
		}
		return AcquireResult{State: LeaseWait, RetryAfterMs: decoded.RetryAfterMs}, nil
	default:
		return AcquireResult{}, c.bad("bad_answer")
	}
}

// Commit 提交令牌。只有 200 且 ok 为真才算成功。
func (c *HTTPLeaseClient) Commit(ctx context.Context, req CommitRequest) error {
	payload := map[string]any{
		"lease_key":   req.LeaseKey,
		"holder_id":   req.HolderID,
		"fence_token": strconv.FormatUint(req.FenceToken, 10),
		"token":       req.Token.Reveal(),
		"lifetime_ms": req.Lifetime.Milliseconds(),
		"expires_at":  req.ExpiresAt.UTC().Format(time.RFC3339Nano),
	}
	var decoded struct {
		OK bool `json:"ok"`
	}
	if err := c.post(ctx, "/v1/sf-leases/commit", payload, &decoded); err != nil {
		return err
	}
	if !decoded.OK {
		return c.bad("bad_answer")
	}
	return nil
}

// Release 放开锁。协调器已经不认这把锁时也只是返回错误，调用方可以忽略。
func (c *HTTPLeaseClient) Release(ctx context.Context, req ReleaseRequest) error {
	payload := map[string]any{
		"lease_key":   req.LeaseKey,
		"holder_id":   req.HolderID,
		"fence_token": strconv.FormatUint(req.FenceToken, 10),
	}
	var decoded struct {
		OK bool `json:"ok"`
	}
	if err := c.post(ctx, "/v1/sf-leases/release", payload, &decoded); err != nil {
		return err
	}
	if !decoded.OK {
		return c.bad("bad_answer")
	}
	return nil
}

func (c *HTTPLeaseClient) post(ctx context.Context, path string, payload any, dst any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		// 编码错误可能夹着令牌。不把 err 传出去。
		return c.bad("bad_answer")
	}
	endpoint, err := c.endpoint(path)
	if err != nil {
		return c.bad("unreachable")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return c.bad("unreachable")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return c.transport(err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		return c.transport(err)
	}
	if len(raw) > maxBody {
		return c.bad("bad_answer")
	}
	if resp.StatusCode != http.StatusOK {
		return c.bad(statusCause(resp.StatusCode))
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return c.bad("bad_answer")
	}
	if _, err := dec.Token(); err != io.EOF {
		return c.bad("bad_answer")
	}
	return nil
}

func (c *HTTPLeaseClient) endpoint(path string) (string, error) {
	base, err := url.Parse(c.base)
	if err != nil {
		return "", err
	}
	ref, err := url.Parse(path)
	if err != nil {
		return "", err
	}
	resolved := base.ResolveReference(ref)
	if resolved.RawQuery != "" || resolved.Fragment != "" || resolved.User != nil {
		return "", errors.New("query")
	}
	return resolved.String(), nil
}

func (c *HTTPLeaseClient) bad(cause string) error {
	c.logger.Warn("sf openapi lease call failed", "cause", cause)
	return &leaseCallError{cause: cause}
}

func (c *HTTPLeaseClient) transport(err error) error {
	cause := "unreachable"
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		cause = "timeout"
	} else {
		var urlErr *url.Error
		if errors.As(err, &urlErr) && urlErr.Timeout() {
			cause = "timeout"
		}
	}
	return c.bad(cause)
}

func statusCause(status int) string {
	switch status {
	case http.StatusUnauthorized:
		return "unauthorized"
	case http.StatusConflict:
		return "stale_fence"
	default:
		if status >= 500 {
			return "unavailable"
		}
		return "bad_answer"
	}
}

func containsSemicolon(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == ';' {
			return true
		}
	}
	return false
}
