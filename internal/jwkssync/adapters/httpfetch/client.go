// Package httpfetch 按 ADR-0014 对出站地址的规矩去取一份 JWKS。
//
// 只接受 https。明文 http 只在两种情况下允许：主机是回环地址的字面量（127.0.0.0/8 或 ::1，
// localhost 不算，它要靠解析），或者主机名与调用方显式给出的那一个裸主机名相同（只比整个名字，
// 不分大小写，没有后缀，也没有通配）。地址里不能有用户信息、查询串和片段。
//
// 不走环境变量里的代理，不跟随重定向，应答正文有上限。不是 200 的应答一律是失败，正文不解析：
// 身份提供者前面的网关用 503 带一段 JSON 错误时，不能把那段错误当成密钥集写下去。
package httpfetch

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"time"

	"go.idp.xyz/idp-gateway/internal/jwkssync/ports"
)

// DefaultMaxBodyBytes 是命令行不另外收紧时的应答上限。
const DefaultMaxBodyBytes = 1 << 20

// Config 是一次取回的全部配置。
type Config struct {
	// URL 是 JWKS 文档的地址。
	URL string
	// PlainHTTPHost 是唯一允许明文 http 的裸主机名。空表示没有这个例外。
	PlainHTTPHost string
	// Timeout 是整次交换的时限，必须大于 0。
	Timeout time.Duration
	// MaxBodyBytes 是接受的应答正文的上限，必须大于 0。
	MaxBodyBytes int64
	// TLS 非空时用作传输层配置（信任的 CA、客户端证书）。空则使用默认的系统根，且至少 TLS 1.2。
	TLS *tls.Config
}

// Client 实现 ports.Fetcher。
type Client struct {
	raw  string
	max  int64
	http *http.Client
}

var _ ports.Fetcher = (*Client)(nil)

// New 核对地址和时限。地址不合规矩时返回错误，错误里没有地址本身，因为不合规矩的地址里可能带着用户信息。
func New(config Config) (*Client, error) {
	if _, err := ParseURL(config.URL, config.PlainHTTPHost); err != nil {
		return nil, err
	}
	if config.Timeout <= 0 {
		return nil, errors.New("jwks fetch: timeout must be greater than zero")
	}
	if config.MaxBodyBytes <= 0 {
		return nil, errors.New("jwks fetch: body limit must be greater than zero")
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if config.TLS != nil {
		tlsConfig = config.TLS.Clone()
		if tlsConfig.MinVersion < tls.VersionTLS12 {
			tlsConfig.MinVersion = tls.VersionTLS12
		}
	}
	return &Client{
		raw: config.URL,
		max: config.MaxBodyBytes,
		http: &http.Client{
			Timeout: config.Timeout,
			Transport: &http.Transport{
				Proxy:           nil,
				TLSClientConfig: tlsConfig,
				IdleConnTimeout: 30 * time.Second,
			},
			// 3xx 不跟过去：那一跳本身就是失败，不能改去另一个地址取密钥。
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}, nil
}

// ParseURL 核对 JWKS 地址。plainHTTPHost 非空时必须是裸主机名：可见 ASCII，且没有 / : @ ? #。
func ParseURL(raw, plainHTTPHost string) (*url.URL, error) {
	if plainHTTPHost != "" && !bareHost(plainHTTPHost) {
		return nil, errors.New("plain-http host must be a bare host name: visible ASCII, none of / : @ ? #")
	}
	if !visibleASCII(raw) {
		return nil, errors.New("JWKS URL must be non-empty visible ASCII")
	}
	if strings.ContainsAny(raw, "?#") {
		return nil, errors.New("JWKS URL must not carry a query string or a fragment")
	}
	target, err := url.Parse(raw)
	if err != nil || !target.IsAbs() || target.Hostname() == "" {
		return nil, errors.New("JWKS URL is not an absolute URL with a host")
	}
	if target.User != nil {
		return nil, errors.New("JWKS URL must not carry user information")
	}
	switch target.Scheme {
	case "https":
		return target, nil
	case "http":
		if loopbackLiteral(target.Hostname()) || hostAllowed(target.Hostname(), plainHTTPHost) {
			return target, nil
		}
		return nil, errors.New("JWKS URL must be https: plain http is only for a loopback address literal (127.0.0.0/8 or ::1, not localhost) or the host named by --plain-http-host")
	default:
		return nil, errors.New("JWKS URL scheme must be https or http")
	}
}

func hostAllowed(host, plain string) bool {
	return plain != "" && strings.EqualFold(host, plain)
}

func bareHost(host string) bool {
	return visibleASCII(host) && !strings.ContainsAny(host, "/:@?#")
}

func visibleASCII(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] <= 0x20 || s[i] >= 0x7f {
			return false
		}
	}
	return true
}

// loopbackLiteral 报告 host 是不是回环地址的字面量。localhost 这样的名字不算；
// IPv4 映射进 IPv6 的写法和带区域的写法也不算。
func loopbackLiteral(host string) bool {
	address, err := netip.ParseAddr(host)
	if err != nil || address.Zone() != "" || address.Is4In6() {
		return false
	}
	return address.IsLoopback()
}

// Fetch 取一次。不是 200、正文超过上限、超时或连不上，都返回错误且不带回正文。
func (c *Client) Fetch(ctx context.Context) ([]byte, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, c.raw, nil)
	if err != nil {
		return nil, errors.New("jwks fetch: request was not built")
	}
	request.Header.Set("Accept", "application/json")
	response, err := c.http.Do(request)
	if err != nil {
		return nil, classify(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		return nil, fmt.Errorf("jwks fetch: HTTP %d", response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, c.max+1))
	if err != nil {
		return nil, errors.New("jwks fetch: response was not read")
	}
	if int64(len(body)) > c.max {
		return nil, fmt.Errorf("jwks fetch: response exceeds %d bytes", c.max)
	}
	return body, nil
}

// classify 把传输错误收成固定的句子。*url.Error 带着完整地址，不能原样往外传。
func classify(err error) error {
	if errors.Is(err, context.Canceled) {
		return errors.New("jwks fetch: canceled")
	}
	var network net.Error
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) || (errors.As(err, &network) && network.Timeout()) {
		return errors.New("jwks fetch: timed out")
	}
	return errors.New("jwks fetch: request failed")
}
