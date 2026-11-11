// Package gatekeeper 向 Gatekeeper 的 PDP 询问 Provider 账户的使用授权。
//
// 它问的是 PDP 的 /authz/check：调用方是不是这个账户的获授调用方，并且属于账户所属的租户。
// 调用方属于哪个租户由本服务从已验签的 Token 得知，随每次询问以上下文关系的形式带过去，
// Gatekeeper 不需要事先存一份。
//
// PDP 没能求出判定时（它背后的查询失败了）仍然答 200 和 decision=false，只是多带一个
// "indeterminate": true。这里把这样的应答读成没有结论，不读成拒绝。这个字段是 Gatekeeper
// 10dc843 加的：更早的 Gatekeeper 查询失败时的应答与拒绝没有区别，在这里会被读成拒绝。
package gatekeeper

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"go.idp.xyz/idp-gateway/internal/egressauthz/ports"
)

const (
	// Action 是询问的动作名。Gatekeeper 的 PDP 把授权模型里的"类型.关系"当作动作。
	Action = "provider_account.use"
	// ResourceType 是账户在授权模型里的类型。
	ResourceType = "provider_account"
	// DefaultTimeout 是一次询问的时限。网关等本服务的时限是秒级的，这里必须明显更短。
	DefaultTimeout = 300 * time.Millisecond

	checkPath        = "/authz/check"
	maxResponseBytes = 16 << 10
	// PDP 的授权模型里没有 Action 这个动作时，它不做查询就答 decision=false，不带 indeterminate，
	// reason 以这段文字开头。那不是对这个调用方的判定，而是模型里还没有 Provider 账户这个类型。
	// Gatekeeper 自己的 SDK 也按这个开头认"动作没有映射"。它改了措辞的话，这种情况会被读成拒绝。
	reasonUnknownAction = "unknown action"
)

// identifier 是可以原样写进授权关系的标识：不含会被授权引擎当作语法的字符
// （类型分隔的冒号、用户集的 #、通配的 *）。
var identifier = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._~-]{0,127}$`)

// Config 是连接 Gatekeeper PDP 所需的配置。
type Config struct {
	// BaseURL 是 PDP 所在服务的地址。必须是 https；只有回环地址允许 http。
	BaseURL string
	// Token 是 PDP 要求的 Bearer 令牌。
	Token ports.Secret
	// Timeout 为 0 时取 DefaultTimeout。
	Timeout time.Duration
}

// Grants 实现 ports.Grants。
type Grants struct {
	endpoint string
	token    ports.Secret
	client   *http.Client
}

// New 校验配置并构造 Grants。它不发起连接：Gatekeeper 一时不可达不妨碍本服务启动，
// 那段时间里的判定都没有结论。
func New(cfg Config) (*Grants, error) {
	base, err := url.Parse(cfg.BaseURL)
	if err != nil || base.Host == "" {
		return nil, errors.New("gatekeeper: the PDP address is not an absolute URL")
	}
	if base.User != nil || base.RawQuery != "" || base.Fragment != "" {
		return nil, errors.New("gatekeeper: the PDP address must not carry credentials, a query or a fragment")
	}
	switch {
	case base.Scheme == "https":
	case base.Scheme == "http" && loopback(base.Hostname()):
	default:
		return nil, errors.New("gatekeeper: the PDP address must be https (plain http is accepted for loopback only)")
	}
	if cfg.Token.IsZero() {
		return nil, errors.New("gatekeeper: no PDP token")
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	transport := &http.Transport{
		// 不读环境里的代理设置：这条连接上走的是授权判定和令牌。
		Proxy:                 nil,
		DialContext:           (&net.Dialer{Timeout: timeout}).DialContext,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout:   timeout,
		ResponseHeaderTimeout: timeout,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          64,
		MaxIdleConnsPerHost:   64,
		IdleConnTimeout:       90 * time.Second,
	}
	return &Grants{
		endpoint: strings.TrimRight(base.String(), "/") + checkPath,
		token:    cfg.Token,
		client: &http.Client{
			Transport: transport,
			Timeout:   timeout,
			// 不跟随重定向：令牌只发给配置的那个地址。
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}, nil
}

// LoadToken 从文件读 PDP 令牌。文件对属主以外可读时拒绝加载。
func LoadToken(path string) (ports.Secret, error) {
	info, err := os.Stat(path)
	if err != nil {
		return ports.Secret{}, fmt.Errorf("gatekeeper token: %w", err)
	}
	if mode := info.Mode().Perm(); mode&0o077 != 0 {
		return ports.Secret{}, fmt.Errorf("gatekeeper token %s: mode %04o is readable by others; want 0600 or stricter", path, mode)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return ports.Secret{}, fmt.Errorf("gatekeeper token: %w", err)
	}
	token := strings.TrimRight(string(raw), "\r\n")
	if token == "" {
		return ports.Secret{}, fmt.Errorf("gatekeeper token %s: empty", path)
	}
	for i := 0; i < len(token); i++ {
		if token[i] <= 0x20 || token[i] >= 0x7f {
			return ports.Secret{}, fmt.Errorf("gatekeeper token %s: contains characters that cannot go into a header", path)
		}
	}
	return ports.NewSecret(token), nil
}

type tuple struct {
	User     string `json:"user"`
	Relation string `json:"relation"`
	Object   string `json:"object"`
}

type checkRequest struct {
	Subject struct {
		ID string `json:"id"`
	} `json:"subject"`
	Action   string `json:"action"`
	Resource struct {
		Type string `json:"type"`
		ID   string `json:"id"`
	} `json:"resource"`
	Context struct {
		TenantID         string  `json:"tenant_id"`
		ContextualTuples []tuple `json:"contextual_tuples"`
	} `json:"context"`
}

type checkResponse struct {
	Decision *bool  `json:"decision"`
	Reason   string `json:"reason"`
	// Indeterminate 为 true 时 PDP 没能求出判定，Decision 里的 false 不是拒绝。
	Indeterminate bool `json:"indeterminate"`
}

// MayUse 实现 ports.Grants。
//
// 三个标识里只要有一个不能原样写进授权关系，就直接答"没有授权"，不去问：这样的标识
// 不可能持有授权，而把它发过去会被授权引擎当作别的东西来解释。
//
// 返回错误表示没有结论：PDP 不可达、答的不是 200、应答读不出判定、应答带着 indeterminate，
// 或者 PDP 的模型里没有这个动作。拒绝只有一种：一份读得出来、不带 indeterminate 的
// decision=false，不看 reason 的措辞。
func (g *Grants) MayUse(ctx context.Context, subject, tenantID, accountID string) (bool, error) {
	for _, id := range []string{subject, tenantID, accountID} {
		if !identifier.MatchString(id) {
			return false, nil
		}
	}
	var ask checkRequest
	ask.Subject.ID = subject
	ask.Action = Action
	ask.Resource.Type, ask.Resource.ID = ResourceType, accountID
	ask.Context.TenantID = tenantID
	ask.Context.ContextualTuples = []tuple{{User: "user:" + subject, Relation: "member", Object: "org:" + tenantID}}
	body, err := json.Marshal(ask)
	if err != nil {
		return false, fmt.Errorf("gatekeeper: %w", err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, g.endpoint, bytes.NewReader(body))
	if err != nil {
		return false, fmt.Errorf("gatekeeper: %w", err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+g.token.Reveal())

	response, err := g.client.Do(request)
	if err != nil {
		return false, fmt.Errorf("gatekeeper: %w", err)
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes))
	if err != nil {
		return false, fmt.Errorf("gatekeeper: %w", err)
	}
	if response.StatusCode != http.StatusOK {
		return false, fmt.Errorf("gatekeeper: the PDP answered %d", response.StatusCode)
	}
	var answer checkResponse
	if err := json.Unmarshal(raw, &answer); err != nil || answer.Decision == nil {
		return false, errors.New("gatekeeper: the PDP's answer cannot be read as a decision")
	}
	switch {
	case answer.Indeterminate:
		// 先看这个标记：带着它的应答不管 decision 写的是什么，都不是判定。
		return false, fmt.Errorf("gatekeeper: the PDP could not evaluate the decision (%.80q)", answer.Reason)
	case *answer.Decision:
		return true, nil
	case strings.HasPrefix(answer.Reason, reasonUnknownAction):
		return false, fmt.Errorf("gatekeeper: the PDP's authorization model has no action %s", Action)
	default:
		return false, nil
	}
}

func loopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
