// Package sfopenapi 是 ports.CredentialSource 的一种实现：顺丰国际开放平台（SF International）的应用凭证
// （docs/adr/ADR-0014.md 的"推荐决策"第 2 条）。这家的开放接口每个请求要三样东西：appKey、短命的访问令牌、
// 长期有效的 AES 密钥（encodingAesKey）。本包向承运商的令牌端点取访问令牌，按凭证句柄隔离着缓存，过期之前换新，
// 同一个缓存键同时来的请求只向令牌端点发一次；放行时交出的认证头是
//
//	Sf-OpenApi appKey;访问令牌;AES密钥
//
// 它由另一个进程（受限的签名适配器）拆开，用来加密正文和签名；网关只把这一个响应头抄给上游。
//
// 取不到（连不上、超时、状态不是 200、承运商拒绝、答错），这次请求拿不到凭证：不用过期的令牌，也不用上一枚
// 顶上。承运商写明取了新令牌旧的就失效，所以一个 appKey 只许出现在一个句柄之下，两个缓存条目会互相作废。
//
// 取令牌的请求是 GET，应用密钥在查询串里，而 net/http 的错误（*url.Error）带着完整的地址。所以本包返回的错误
// 和写的日志里没有请求的地址和查询串、应用密钥、访问令牌、AES 密钥，也没有承运商应答的任何内容（包括
// apiErrorMsg）：只有一个类别。
//
// 应用密钥来自一个文件，规矩与 oauthclient 和 filestore 里的凭证文件相同：权限 0600 或更严；启动时读不成
// 就不启动；修改时间变了就整份重读；新文件读不成或校验不过，继续用上一份，并记一条不含秘密的错误。
// 换文件要写临时文件再改名。
package sfopenapi

import (
	"bytes"
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
	// Scheme 是交出的认证头的开头：值是 Scheme、一个空格，然后是 appKey;访问令牌;AES密钥。
	// 后端上"放行却没有凭证就拒绝"的规则按这个前缀认。
	Scheme = "Sf-OpenApi"

	// DefaultTimeout 是向令牌端点取一次令牌的超时。评审过的网关配置里 ExtAuthZ 等 PDP 最多 1 秒，
	// 取令牌要留在它之内。
	DefaultTimeout = 800 * time.Millisecond

	// MaxRefreshLead 是提前换新的上限：承运商建议过期前 5 到 10 分钟换，取上限 10 分钟。
	MaxRefreshLead = 10 * time.Minute

	// maxBody 是令牌端点的应答正文最多读多少字节。超过就算答错。
	maxBody = 64 << 10

	// maxExpiresIn 是 expireIn 取用的上限（秒）。更大的值照样接受，只是按这个值算，免得乘出溢出。
	maxExpiresIn = 10 * 365 * 24 * 3600
)

// RefreshLead 返回寿命为 lifetime 的令牌在它到期前多久起不再交出：10 分钟和总寿命的十分之一，取较小的。
// 寿命 2 小时的令牌提前 10 分钟换。
//
// 这是实现取的值，不是业务要求：ADR-0014 只说"提前多少换新，实现时取值"，承运商建议 5 到 10 分钟。
func RefreshLead(lifetime time.Duration) time.Duration {
	return min(MaxRefreshLead, lifetime/10)
}

// 取一次令牌的结果的类别。它们写进日志，也是错误信息里唯一说得出的事。
const (
	resultOK          = "ok"
	resultTimeout     = "timeout"
	resultUnreachable = "unreachable"
	resultBadAnswer   = "bad_answer"
	// 状态不是 200 时，类别是 "status N"；承运商的信封里 apiResultCode 不是 0 时，类别是 "code N"。
)

// Config 是 Load 的参数。
type Config struct {
	// Path 是应用凭证文件。
	Path string
	// Timeout 是取一次令牌的超时；零值用 DefaultTimeout。
	Timeout time.Duration
	// PlainHTTPHost 不为空时，令牌端点的主机名与它相等（不分大小写）的 http 地址也接受。
	// 给承运商没有 TLS 的沙箱用；空串表示没有这个例外。除此之外 http 只在主机是回环地址字面量时接受。
	PlainHTTPHost string
	// Reserved 不为 nil 时，它说已经被别的凭证来源占着的句柄：文件里有这样的句柄就整份拒绝。
	Reserved func(handle string) bool
	// Logger 为 nil 时不记日志。
	Logger *slog.Logger
	// Now 是时钟；零值用 time.Now。测试用它，不靠真的等。
	Now func() time.Time
}

// Client 实现 ports.CredentialSource。
type Client struct {
	path          string
	timeout       time.Duration
	plainHTTPHost string
	reserved      func(handle string) bool
	logger        *slog.Logger
	now           func() time.Time
	http          *http.Client

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

// slot 是一个缓存键下的状态：手里有的访问令牌，和正在进行的那一次获取。
// 缓存里只有访问令牌；认证头在交出的那一刻由文件里此刻的条目和这枚令牌拼成。
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

// Load 读应用凭证文件。文件的格式见 docs/adr/ADR-0014.md。启动时读不成返回错误。
func Load(cfg Config) (*Client, error) {
	c := &Client{path: cfg.Path, timeout: cfg.Timeout, plainHTTPHost: cfg.PlainHTTPHost, reserved: cfg.Reserved,
		logger: cfg.Logger, now: cfg.Now, slots: map[cacheKey]*slot{}}
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
			Proxy:               nil, // 环境变量里的代理不能插到应用密钥的路上
			TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
			ForceAttemptHTTP2:   true,
			MaxIdleConns:        16,
			IdleConnTimeout:     60 * time.Second,
			TLSHandshakeTimeout: c.timeout,
		},
		// 不跟随重定向：3xx 算状态不是 200，应用密钥不会被带到别处去。
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

// AuthorizationHeader 实现 ports.CredentialSource。返回的值是 "Sf-OpenApi " 加 appKey、分号、访问令牌、
// 分号、AES 密钥。
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
		return header(e, token), nil
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
		if f.err != nil {
			return ports.Secret{}, f.err
		}
		return header(e, f.token), nil
	case <-ctx.Done():
		return ports.Secret{}, fmt.Errorf("sf openapi token for %s: %w", handle, ctx.Err())
	}
}

// header 拼出交给网关的认证头：Scheme、空格、appKey、分号、访问令牌、分号、AES 密钥。
// appKey 和 AES 密钥取自文件里的条目，令牌取自缓存；三样都不含分号和空白（文件和应答的校验保证）。
func header(e *entry, token ports.Secret) ports.Secret {
	return ports.NewSecret(Scheme + " " + e.appKey + ";" + token.Reveal() + ";" + e.aesKey.Reveal())
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
		c.logger.Info("sf openapi token fetched", append(attrs, "expires_in", expiresIn)...)
	} else {
		c.logger.Warn("sf openapi token not fetched", attrs...)
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

// request 向令牌端点发一次 GET。返回的 result 是类别，错误里只有类别。
//
// 请求的地址带着应用密钥（查询串）。http.Client.Do 返回的 *url.Error 带着完整的地址，所以它不往外传：
// 只看它是不是超时，其余一律算连不上。
func (c *Client) request(e *entry) (token ports.Secret, expiresIn int64, result string, err error) {
	query := url.Values{"appKey": {e.appKey}, "appSecret": {e.appSecret.Reveal()}}
	ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, e.tokenEndpoint+"?"+query.Encode(), nil)
	if err != nil {
		return ports.Secret{}, 0, resultUnreachable, failure(e.handle, resultUnreachable)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
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
	token, expiresIn, result, ok := parseAnswer(body)
	if !ok {
		return ports.Secret{}, 0, result, failure(e.handle, result)
	}
	return token, expiresIn, resultOK, nil
}

func failure(handle, result string) error {
	return fmt.Errorf("sf openapi token for %s not obtained: %s", handle, result)
}

// parseAnswer 查令牌端点的应答：一个 JSON 对象，后面没有别的内容；apiResultCode 是整数，不是 0 就是承运商
// 拒绝了（类别 "code N"，apiErrorMsg 是承运商写的文字，不读也不记）；apiResultData 是对象，里面 accessToken 是
// 非空、可见 ASCII、不含分号的字符串，expireIn 是正整数。信封和 apiResultData 里别的成员不管。
// 别的一律算答错。ok 为 false 时 result 是类别。
func parseAnswer(body []byte) (token ports.Secret, expiresIn int64, result string, ok bool) {
	// 解成 map 而不是结构体：成员名要一字不差（encoding/json 解结构体时不分大小写）。
	envelope, ok := decodeObject(body)
	if !ok {
		return ports.Secret{}, 0, resultBadAnswer, false
	}
	rawCode, present := envelope["apiResultCode"]
	if !present {
		return ports.Secret{}, 0, resultBadAnswer, false
	}
	code, err := strconv.ParseInt(string(rawCode), 10, 64) // 带引号的字符串、小数、指数写法都解不成整数
	if err != nil {
		return ports.Secret{}, 0, resultBadAnswer, false
	}
	if code != 0 {
		return ports.Secret{}, 0, "code " + strconv.FormatInt(code, 10), false
	}
	rawData, present := envelope["apiResultData"]
	if !present {
		return ports.Secret{}, 0, resultBadAnswer, false
	}
	data, ok := decodeObject(rawData)
	if !ok {
		return ports.Secret{}, 0, resultBadAnswer, false
	}
	rawToken, present := data["accessToken"]
	rawExpires, expiresPresent := data["expireIn"]
	if !present || !expiresPresent {
		return ports.Secret{}, 0, resultBadAnswer, false
	}
	var accessToken *string
	if err := json.Unmarshal(rawToken, &accessToken); err != nil || accessToken == nil {
		return ports.Secret{}, 0, resultBadAnswer, false
	}
	if !visibleASCII(*accessToken) || strings.Contains(*accessToken, ";") {
		return ports.Secret{}, 0, resultBadAnswer, false
	}
	seconds, err := strconv.ParseInt(string(rawExpires), 10, 64)
	if err != nil || seconds <= 0 {
		return ports.Secret{}, 0, resultBadAnswer, false
	}
	return ports.NewSecret(*accessToken), seconds, resultOK, true
}

// decodeObject 把 raw 解成一个 JSON 对象：它必须是对象（null、数组、字符串都不行），后面不能再有别的内容。
func decodeObject(raw []byte) (map[string]json.RawMessage, bool) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	var object map[string]json.RawMessage
	if err := decoder.Decode(&object); err != nil || object == nil {
		return nil, false
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, false
	}
	return object, true
}

// current 返回此刻该用的那张表：文件变了就先重读，并把缓存里不再对得上的条目丢掉。
func (c *Client) current() map[string]*entry {
	c.mu.Lock()
	defer c.mu.Unlock()

	info, err := os.Stat(c.path)
	if err != nil {
		if c.seen != nil {
			c.seen = nil
			c.logger.Error("sf openapi apps file cannot be seen; still using the last one that loaded",
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
		c.logger.Error("sf openapi apps file did not load; still using the last one that loaded",
			"path", c.path, "error", err.Error(), "entries", len(c.entries))
		return c.entries
	}
	c.entries, c.seen = entries, read
	c.held.Store(&entries)
	c.prune(entries)
	c.logger.Info("sf openapi apps file loaded again", "path", c.path, "entries", len(entries))
	return c.entries
}

// prune 丢掉键不在新表里的缓存条目：不再出现的句柄，和句柄的端点、appKey、密钥版本、应用密钥有任何一个
// 变了的。正在进行的获取不被打断，它的结果落在已经被丢掉的条目上，不会被别的请求用到。
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
