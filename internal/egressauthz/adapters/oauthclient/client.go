// Package oauthclient 是 ports.CredentialSource 的一种实现：OAuth2 客户端凭证（RFC 6749 第 4.4 节）。
// 向 Provider 的令牌端点取访问令牌，按账户隔离着缓存，过期之前换新，同一个缓存键同时来的
// 请求只向令牌端点发一次（docs/adr/ADR-0011.md 第 4 条）。
//
// 取不到（连不上、超时、状态不是 200、答错），这次请求拿不到凭证：不用过期的令牌，也不用上一枚
// 顶上。返回的错误里没有客户端密钥、访问令牌，也没有令牌端点应答的正文。
//
// 客户端密钥来自一个文件，规矩与 filestore 里的两种凭证文件相同：权限 0600 或更严；启动时读不成
// 就不启动；修改时间变了就整份重读；新文件读不成或校验不过，继续用上一份，并记一条不含秘密的
// 错误。换文件要写临时文件再改名。
package oauthclient

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"go.idp.xyz/idp-gateway/internal/egressauthz/ports"
)

const (
	// DefaultTimeout 是向令牌端点取一次令牌的超时。评审过的网关配置里 ExtAuthZ 等 PDP 最多 1 秒，
	// 取令牌要留在它之内。
	DefaultTimeout = 800 * time.Millisecond

	// MaxRefreshLead 是提前换新的上限：令牌剩下的寿命不超过这个值，就不再交出它。
	MaxRefreshLead = 30 * time.Second

	// maxBody 是令牌端点的应答正文最多读多少字节。超过就算答错。
	maxBody = 64 << 10

	// maxExpiresIn 是 expires_in 取用的上限（秒）。更大的值照样接受，只是按这个值算，免得乘出溢出。
	maxExpiresIn = 10 * 365 * 24 * 3600
)

// RefreshLead 返回寿命为 lifetime 的令牌在它到期前多久起不再交出：30 秒和总寿命的十分之一，取较小的。
//
// 这是实现取的值，不是业务要求（ADR-0011 V1.2）：ADR 只说"过期之前换新，提前多少在实现时取一个值"。
func RefreshLead(lifetime time.Duration) time.Duration {
	return min(MaxRefreshLead, lifetime/10)
}

// 取一次令牌的结果的类别。它们写进日志，也是错误信息里唯一说得出的事。
const (
	resultOK          = "ok"
	resultTimeout     = "timeout"
	resultUnreachable = "unreachable"
	resultBadAnswer   = "bad_answer"
	// 状态不是 200 时，类别是 "status N"。
)

// Config 是 Load 的参数。
type Config struct {
	// Path 是客户端凭证文件。
	Path string
	// Timeout 是取一次令牌的超时；零值用 DefaultTimeout。
	Timeout time.Duration
	// Reserved 不为 nil 时，它说已经被别的凭证来源占着的句柄：文件里有这样的句柄就整份拒绝。
	Reserved func(handle string) bool
	// Logger 为 nil 时不记日志。
	Logger *slog.Logger
	// Now 是时钟；零值用 time.Now。测试用它，不靠真的等。
	Now func() time.Time
}

// Client 实现 ports.CredentialSource。
type Client struct {
	path     string
	timeout  time.Duration
	reserved func(handle string) bool
	logger   *slog.Logger
	now      func() time.Time
	http     *http.Client

	// mu 管文件的重读。
	mu      sync.Mutex
	seen    os.FileInfo // 上一次看到的文件，读成没读成都记；nil 表示上一次看时它不在。
	entries map[string]*entry
	// held 是 entries 的另一份指针：Holds 读它，不拿 mu，理由同 filestore.DeveloperTokens。
	held atomic.Pointer[map[string]*entry]

	// cmu 管缓存。它只在改缓存的几行里拿着，不会拿着它去发请求或读文件。
	cmu   sync.Mutex
	slots map[cacheKey]*slot
}

// slot 是一个缓存键下的状态：手里有的令牌，和正在进行的那一次获取。
type slot struct {
	token    ports.Secret
	lifetime time.Duration
	expires  time.Time
	flight   *flight
}

// flight 是一次向令牌端点的获取。同一个键同时来的请求等它。
type flight struct {
	done  chan struct{}
	token ports.Secret
	err   error
}

// Load 读客户端凭证文件。文件的格式见 docs/adr/ADR-0011.md 的 V1.2 一节。启动时读不成返回错误。
func Load(cfg Config) (*Client, error) {
	c := &Client{path: cfg.Path, timeout: cfg.Timeout, reserved: cfg.Reserved, logger: cfg.Logger, now: cfg.Now,
		slots: map[cacheKey]*slot{}}
	if c.timeout <= 0 {
		c.timeout = DefaultTimeout
	}
	if c.logger == nil {
		c.logger = slog.New(slog.DiscardHandler)
	}
	if c.now == nil {
		c.now = time.Now
	}
	c.http = &http.Client{
		Transport: &http.Transport{
			Proxy:               nil, // 环境变量里的代理不能插到客户端密钥的路上
			TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
			ForceAttemptHTTP2:   true,
			MaxIdleConns:        16,
			IdleConnTimeout:     60 * time.Second,
			TLSHandshakeTimeout: c.timeout,
		},
		// 不跟随重定向：3xx 算状态不是 200，客户端密钥不会被带到别处去。
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Timeout:       c.timeout,
	}
	entries, info, err := c.read()
	if err != nil {
		return nil, err
	}
	c.entries, c.seen = entries, info
	c.held.Store(&entries)
	return c, nil
}

// Len 返回此刻持有的凭证数量，供启动日志使用。
func (c *Client) Len() int { return len(c.current()) }

// Holds 报告这个凭证句柄是不是在最近一次读成的那份文件里。它不看文件有没有变，也不重读：
// 别的凭证来源用它来拒绝重复的句柄。
func (c *Client) Holds(handle string) bool {
	table := c.held.Load()
	if table == nil {
		return false
	}
	_, ok := (*table)[handle]
	return ok
}

// AuthorizationHeader 实现 ports.CredentialSource。返回的值是 "Bearer " 加访问令牌。
func (c *Client) AuthorizationHeader(ctx context.Context, bindingRef, accountID string) (ports.Secret, error) {
	handle := ports.Handle(bindingRef, accountID)
	e, ok := c.current()[handle]
	if !ok {
		return ports.Secret{}, fmt.Errorf("%w: %s", ports.ErrCredentialNotHeld, handle)
	}
	key := e.key()

	c.cmu.Lock()
	s := c.slots[key]
	if s == nil {
		s = &slot{}
		c.slots[key] = s
	}
	if !s.token.IsZero() && c.usable(s) {
		token := s.token
		c.cmu.Unlock()
		return token, nil
	}
	// 手里的令牌过期了，或到了该换新的时候：不再交出它。
	f := s.flight
	if f == nil {
		f = &flight{done: make(chan struct{})}
		s.flight = f
		go c.fetch(e, s, f)
	}
	c.cmu.Unlock()

	select {
	case <-f.done:
		return f.token, f.err
	case <-ctx.Done():
		return ports.Secret{}, fmt.Errorf("oauth token for %s: %w", handle, ctx.Err())
	}
}

// usable 报告缓存里的令牌此刻能不能交出：剩下的寿命要多于 RefreshLead。调用时要拿着 cmu。
func (c *Client) usable(s *slot) bool {
	return s.expires.Sub(c.now()) > RefreshLead(s.lifetime)
}

// fetch 向令牌端点取一次令牌，把结果交给等着的各路请求。它不受发起它的那个请求的 ctx 管：
// 那个请求走了，别的等着的请求仍然要结果。它受超时管。
func (c *Client) fetch(e *entry, s *slot, f *flight) {
	started := c.now()
	begun := time.Now()
	token, expiresIn, result, err := c.request(e)
	elapsed := time.Since(begun)

	attrs := []any{"handle", e.handle, "result", result, "elapsed_ms", elapsed.Milliseconds()}
	if err == nil {
		c.logger.Info("oauth token fetched", append(attrs, "expires_in", expiresIn)...)
	} else {
		c.logger.Warn("oauth token not fetched", attrs...)
	}

	c.cmu.Lock()
	s.flight = nil
	if err == nil {
		lifetime := time.Duration(min(expiresIn, maxExpiresIn)) * time.Second
		// 寿命从请求发出的时刻算起：令牌端点在收到请求之后才签发，所以这样算只会偏早，不会偏晚。
		s.token, s.lifetime, s.expires = token, lifetime, started.Add(lifetime)
	} else {
		// 取不到时手里没有可用的令牌：就算上一枚还没到期，也不拿它顶上。
		s.token, s.lifetime, s.expires = ports.Secret{}, 0, time.Time{}
	}
	f.token, f.err = token, err
	c.cmu.Unlock()
	close(f.done)
}

// request 发一次 client_credentials 请求。返回的 result 是类别，错误里只有类别。
func (c *Client) request(e *entry) (token ports.Secret, expiresIn int64, result string, err error) {
	form := url.Values{"grant_type": {"client_credentials"}}
	if e.scope != "" {
		form.Set("scope", e.scope)
	}
	if e.audience != "" {
		form.Set("audience", e.audience)
	}
	ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.tokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return ports.Secret{}, 0, resultUnreachable, failure(e.handle, resultUnreachable)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	// client_secret_basic（RFC 6749 第 2.3.1 节）：客户端标识和密钥先按 application/x-www-form-urlencoded
	// 编码，再做 Basic。只有可见 ASCII 的字符里字母、数字和 -._* 不变。
	req.SetBasicAuth(url.QueryEscape(e.clientID), url.QueryEscape(e.clientSecret.Reveal()))

	resp, err := c.http.Do(req)
	if err != nil {
		// net/http 的错误里有请求的地址。地址本身没有秘密，但这里只留类别：错误信息的形状不依赖它。
		var timeout interface{ Timeout() bool }
		if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &timeout) && timeout.Timeout()) {
			return ports.Secret{}, 0, resultTimeout, failure(e.handle, resultTimeout)
		}
		return ports.Secret{}, 0, resultUnreachable, failure(e.handle, resultUnreachable)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		result = "status " + strconv.Itoa(resp.StatusCode)
		return ports.Secret{}, 0, result, failure(e.handle, result)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return ports.Secret{}, 0, resultTimeout, failure(e.handle, resultTimeout)
		}
		return ports.Secret{}, 0, resultUnreachable, failure(e.handle, resultUnreachable)
	}
	if len(body) > maxBody {
		return ports.Secret{}, 0, resultBadAnswer, failure(e.handle, resultBadAnswer)
	}
	token, expiresIn, ok := parseAnswer(body)
	if !ok {
		return ports.Secret{}, 0, resultBadAnswer, failure(e.handle, resultBadAnswer)
	}
	return token, expiresIn, resultOK, nil
}

func failure(handle, result string) error {
	return fmt.Errorf("oauth token for %s not obtained: %s", handle, result)
}

// parseAnswer 查令牌端点的应答：一个 JSON 对象；access_token 非空、可见 ASCII、不含空白；token_type 不分
// 大小写等于 Bearer；expires_in 是正整数。别的一律算答错。
func parseAnswer(body []byte) (token ports.Secret, expiresIn int64, ok bool) {
	var answer struct {
		AccessToken *string         `json:"access_token"`
		TokenType   *string         `json:"token_type"`
		ExpiresIn   json.RawMessage `json:"expires_in"`
	}
	decoder := json.NewDecoder(strings.NewReader(string(body)))
	if err := decoder.Decode(&answer); err != nil {
		return ports.Secret{}, 0, false
	}
	if _, err := decoder.Token(); err != io.EOF {
		return ports.Secret{}, 0, false
	}
	if answer.AccessToken == nil || answer.TokenType == nil || len(answer.ExpiresIn) == 0 {
		return ports.Secret{}, 0, false
	}
	if !visibleASCII(*answer.AccessToken) || !strings.EqualFold(*answer.TokenType, "Bearer") {
		return ports.Secret{}, 0, false
	}
	seconds, err := strconv.ParseInt(string(answer.ExpiresIn), 10, 64) // 带引号的字符串、小数、指数写法都解不成整数
	if err != nil || seconds <= 0 {
		return ports.Secret{}, 0, false
	}
	return ports.NewSecret("Bearer " + *answer.AccessToken), seconds, true
}

// current 返回此刻该用的那张表：文件变了就先重读，并把缓存里不再对得上的条目丢掉。
func (c *Client) current() map[string]*entry {
	c.mu.Lock()
	defer c.mu.Unlock()

	info, err := os.Stat(c.path)
	if err != nil {
		if c.seen != nil {
			c.seen = nil
			c.logger.Error("oauth clients file cannot be seen; still using the last one that loaded",
				"path", c.path, "error", err.Error(), "entries", len(c.entries))
		}
		return c.entries
	}
	if c.seen != nil && sameFile(c.seen, info) {
		return c.entries
	}
	entries, read, err := c.read()
	if err != nil {
		// 记下看到的是哪一份：它再被换掉之前不重读，也不再记。
		c.seen = info
		c.logger.Error("oauth clients file did not load; still using the last one that loaded",
			"path", c.path, "error", err.Error(), "entries", len(c.entries))
		return c.entries
	}
	c.entries, c.seen = entries, read
	c.held.Store(&entries)
	c.prune(entries)
	c.logger.Info("oauth clients file loaded again", "path", c.path, "entries", len(entries))
	return c.entries
}

// prune 丢掉键不在新表里的缓存条目：不再出现的句柄，和句柄的端点、客户端、scope、audience、密钥版本
// 有任何一个变了的。正在进行的获取不被打断，它的结果落在已经被丢掉的条目上，不会被别的请求用到。
func (c *Client) prune(entries map[string]*entry) {
	live := make(map[cacheKey]bool, len(entries))
	for _, e := range entries {
		live[e.key()] = true
	}
	c.cmu.Lock()
	defer c.cmu.Unlock()
	for key := range c.slots {
		if !live[key] {
			delete(c.slots, key)
		}
	}
}

// sameFile 报告两次看到的是不是同一份没有动过的文件。
func sameFile(a, b os.FileInfo) bool {
	return os.SameFile(a, b) && a.ModTime().Equal(b.ModTime()) && a.Size() == b.Size()
}
