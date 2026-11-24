// Package authzstate 是 gateway-authz 到撤销协调器的客户端。
// 五个 --authz-state-* 都给出时，撤销表的读和写、以及配额扣费走这里。
// 它不导入 sflease。日志和错误里没有请求正文，也没有配额键的原像。
package authzstate

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
	"time"

	"go.idp.xyz/idp-gateway/internal/egressauthz/domain"
	"go.idp.xyz/idp-gateway/internal/egressauthz/ports"
)

const (
	pathMutate   = "/v1/authz-state/mutate"
	pathSnapshot = "/v1/authz-state/snapshot"
	pathQuota    = "/v1/authz-state/quota"
	maxBody      = 64 << 10
)

// callError 的文字是固定的类别。它不包装 *url.Error，免得把地址带出去。
type callError struct{ cause string }

func (e *callError) Error() string { return "authz state " + e.cause }

// Client 用双向 TLS 调用 authz-state。
type Client struct {
	base   string
	http   *http.Client
	logger *slog.Logger
}

// New 要求 baseURL 是没有用户信息、查询串和片段的 https 地址。
// tlsConfig 由调用方配好（含热重载的客户端证书）；这里禁止代理、不跟随重定向。
func New(baseURL string, tlsConfig *tls.Config, logger *slog.Logger) (*Client, error) {
	if tlsConfig == nil {
		return nil, errors.New("authz state: tls config is required")
	}
	parsed, err := url.Parse(baseURL)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, errors.New("authz state: url must be https without user information, a query string, or a fragment")
	}
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	return &Client{
		base:   parsed.String(),
		logger: logger,
		http: &http.Client{
			Transport: &http.Transport{
				Proxy: nil,
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

type mutation struct {
	Action      string
	AccountID   string
	OperationID string
	By          string
	Reason      string
}

type mutationResult struct {
	Changed bool
	Epoch   uint64
	Revoked bool
	Banned  bool
	account bool
}

type snapshot struct {
	epoch    uint64
	accounts []ports.RevokedAccount
	bans     []ports.BannedOperation
}

// Snapshot 取一份新的快照。连不上、超时、401、5xx 或正文读不懂都是错误。
func (c *Client) Snapshot(ctx context.Context) (snapshot, error) {
	var doc struct {
		Epoch    *uint64                  `json:"epoch"`
		Accounts map[string]snapshotEntry `json:"revoked_accounts"`
		Banned   map[string]snapshotEntry `json:"banned_operations"`
	}
	if err := c.call(ctx, http.MethodGet, pathSnapshot, nil, &doc); err != nil {
		return snapshot{}, err
	}
	if doc.Epoch == nil || doc.Accounts == nil {
		return snapshot{}, c.bad("bad_answer")
	}
	accounts, err := entriesToAccounts(doc.Accounts)
	if err != nil {
		return snapshot{}, c.bad("bad_answer")
	}
	bans, err := entriesToBans(doc.Banned)
	if err != nil {
		return snapshot{}, c.bad("bad_answer")
	}
	return snapshot{epoch: *doc.Epoch, accounts: accounts, bans: bans}, nil
}

type snapshotEntry struct {
	At     *string `json:"at"`
	By     string  `json:"by"`
	Reason string  `json:"reason"`
}

func entriesToAccounts(raw map[string]snapshotEntry) ([]ports.RevokedAccount, error) {
	out := make([]ports.RevokedAccount, 0, len(raw))
	for id, row := range raw {
		at, err := parseAt(id, row)
		if err != nil {
			return nil, err
		}
		out = append(out, ports.RevokedAccount{AccountID: id, At: at, By: row.By, Reason: row.Reason})
	}
	sortAccounts(out)
	return out, nil
}

func entriesToBans(raw map[string]snapshotEntry) ([]ports.BannedOperation, error) {
	out := make([]ports.BannedOperation, 0, len(raw))
	for id, row := range raw {
		at, err := parseAt(id, row)
		if err != nil {
			return nil, err
		}
		out = append(out, ports.BannedOperation{OperationID: id, At: at, By: row.By, Reason: row.Reason})
	}
	sortBans(out)
	return out, nil
}

func parseAt(id string, row snapshotEntry) (time.Time, error) {
	if id == "" || row.At == nil {
		return time.Time{}, errors.New("missing")
	}
	at, err := time.Parse(time.RFC3339, *row.At)
	if err != nil {
		return time.Time{}, err
	}
	return at.UTC(), nil
}

func (c *Client) mutate(ctx context.Context, m mutation) (mutationResult, error) {
	payload := map[string]string{
		"action": m.Action, "account_id": m.AccountID, "operation_id": m.OperationID, "by": m.By, "reason": m.Reason,
	}
	var decoded struct {
		Changed bool   `json:"changed"`
		Epoch   uint64 `json:"epoch"`
		Revoked *bool  `json:"revoked"`
		Banned  *bool  `json:"banned"`
	}
	if err := c.call(ctx, http.MethodPost, pathMutate, payload, &decoded); err != nil {
		return mutationResult{}, err
	}
	account := m.Action == "revoke" || m.Action == "restore"
	if account && decoded.Revoked == nil || !account && decoded.Banned == nil {
		return mutationResult{}, c.bad("bad_answer")
	}
	out := mutationResult{Changed: decoded.Changed, Epoch: decoded.Epoch, account: account}
	if decoded.Revoked != nil {
		out.Revoked = *decoded.Revoked
	}
	if decoded.Banned != nil {
		out.Banned = *decoded.Banned
	}
	return out, nil
}

// Quota 把一组扣费交给协调器。409 是参数和已锁住的桶不一致，返回错误，不把它当成放行。
func (c *Client) Quota(ctx context.Context, charges []domain.QuotaCharge) (bool, int, error) {
	body := make([]map[string]any, 0, len(charges))
	for _, charge := range charges {
		if !hexKey(charge.Key) {
			return false, 0, c.bad("bad_answer")
		}
		body = append(body, map[string]any{
			"key": charge.Key, "max_requests": charge.MaxRequests, "window_seconds": charge.WindowSeconds, "capacity": charge.Capacity,
		})
	}
	var decoded struct {
		Allowed    bool `json:"allowed"`
		RetryAfter int  `json:"retry_after"`
	}
	if err := c.call(ctx, http.MethodPost, pathQuota, map[string]any{"charges": body}, &decoded); err != nil {
		return false, 0, err
	}
	if !decoded.Allowed && decoded.RetryAfter < 1 {
		return false, 0, c.bad("bad_answer")
	}
	return decoded.Allowed, decoded.RetryAfter, nil
}

func hexKey(key string) bool {
	if len(key) != 64 {
		return false
	}
	for i := 0; i < len(key); i++ {
		c := key[i]
		if c < '0' || (c > '9' && c < 'a') || c > 'f' {
			return false
		}
	}
	return true
}

func (c *Client) call(ctx context.Context, method, path string, payload any, dst any) error {
	var reader io.Reader
	if payload != nil {
		encoded, err := json.Marshal(payload)
		if err != nil || bytes.Contains(encoded, []byte{0}) {
			return c.bad("bad_answer")
		}
		reader = bytes.NewReader(encoded)
	}
	endpoint, err := c.endpoint(path)
	if err != nil {
		return c.bad("unreachable")
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, reader)
	if err != nil {
		return c.bad("unreachable")
	}
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
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

func (c *Client) endpoint(path string) (string, error) {
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

func (c *Client) bad(cause string) error {
	c.logger.Warn("authz state call failed", "cause", cause)
	return &callError{cause: cause}
}

func (c *Client) transport(err error) error {
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
		return "parameter_mismatch"
	default:
		if status >= 500 {
			return "unavailable"
		}
		return "bad_answer"
	}
}
