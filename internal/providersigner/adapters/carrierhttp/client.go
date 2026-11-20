// Package carrierhttp 是 ports.Carrier 的 HTTP 实现：向承运商的 dispatch 地址发一次 POST。
//
// 发出去的请求只有八个头（appKey、token、timestamp、nonce、signature、msgType、lang、Content-Type）
// 和密文；调用方的任何东西都进不到这里，因为这个包根本拿不到它们。不用环境变量里的代理，不跟随
// 重定向，不重试，整次交换有时限，应答正文有上限。
package carrierhttp

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"go.idp.xyz/idp-gateway/internal/providersigner/domain"
	"go.idp.xyz/idp-gateway/internal/providersigner/ports"
)

// Config 是到承运商的那一跳的全部配置。
type Config struct {
	// URL 是 dispatch 地址，完整的，例如 https://api-ifsp.sf.global/openapi/api/dispatch。
	URL string
	// PlainHTTPHost 是唯一一个允许用明文 http 的主机名（承运商的沙箱没有 TLS）。空表示没有。
	PlainHTTPHost string
	// Timeout 是整次交换的时限，必须大于 0。
	Timeout time.Duration
	// MaxResponseBytes 是接受的应答正文的上限，必须大于 0。
	MaxResponseBytes int64
}

// Client 实现 ports.Carrier。
type Client struct {
	url    string
	target *url.URL
	max    int64
	http   *http.Client
}

var _ ports.Carrier = (*Client)(nil)

// New 核对配置并构造 Client。地址不合规矩时返回错误；错误里没有地址本身，因为不合规矩的地址
// 里可能带着用户信息。
func New(config Config) (*Client, error) {
	target, err := ParseURL(config.URL, config.PlainHTTPHost)
	if err != nil {
		return nil, err
	}
	if config.Timeout <= 0 {
		return nil, errors.New("carrier timeout must be greater than zero")
	}
	if config.MaxResponseBytes <= 0 {
		return nil, errors.New("carrier response size limit must be greater than zero")
	}
	transport := &http.Transport{
		// 不看 HTTP_PROXY 等环境变量：到承运商的连接就是直连。
		Proxy:           nil,
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
		IdleConnTimeout: 30 * time.Second,
	}
	return &Client{
		url:    config.URL,
		target: target,
		max:    config.MaxResponseBytes,
		http: &http.Client{
			Transport: transport,
			Timeout:   config.Timeout,
			// 承运商答 3xx 时不跟过去：答复就是 3xx 本身。
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}, nil
}

// Scheme 是承运商地址的协议，写进启动日志。
func (c *Client) Scheme() string { return c.target.Scheme }

// Host 是承运商地址里的主机（有端口时带端口），写进启动日志。路径不写。
func (c *Client) Host() string { return c.target.Host }

// ParseURL 核对 --carrier-url：绝对地址，有主机；只有可见 ASCII；没有用户信息、查询串和片段；
// 协议是 https，或者是 http 且主机是回环地址的字面量（127.0.0.0/8 或 ::1，localhost 不算），
// 或者主机名与 plainHTTPHost 完全相同（只比较大小写，没有后缀或通配）。
// plainHTTPHost 本身必须是裸主机名：非空时只含可见 ASCII，且没有 / : @ ? #。
func ParseURL(raw, plainHTTPHost string) (*url.URL, error) {
	if plainHTTPHost != "" && (!domain.VisibleASCII(plainHTTPHost) || strings.ContainsAny(plainHTTPHost, "/:@?#")) {
		return nil, errors.New("plain-http host must be a bare host name: visible ASCII without any of / : @ ? #")
	}
	if raw == "" || !domain.VisibleASCII(raw) {
		return nil, errors.New("carrier URL must be non-empty visible ASCII")
	}
	if strings.ContainsAny(raw, "?#") {
		return nil, errors.New("carrier URL must not carry a query string or a fragment")
	}
	target, err := url.Parse(raw)
	if err != nil || !target.IsAbs() || target.Hostname() == "" {
		return nil, errors.New("carrier URL is not an absolute URL with a host")
	}
	if target.User != nil {
		return nil, errors.New("carrier URL must not carry user information")
	}
	switch target.Scheme {
	case "https":
	case "http":
		if !loopbackLiteral(target.Hostname()) && (plainHTTPHost == "" || !strings.EqualFold(target.Hostname(), plainHTTPHost)) {
			return nil, errors.New("carrier URL must be https: plain http is only for a loopback address literal " +
				"or the host named by the plain-http exception")
		}
	default:
		return nil, errors.New("carrier URL scheme must be https")
	}
	return target, nil
}

// loopbackLiteral 报告 host 是不是回环地址的字面量：127.0.0.0/8 里的 IPv4 地址，或者 ::1。
// localhost 这样的名字不算；IPv4 映射的 IPv6 写法和带区域的写法也不算。
func loopbackLiteral(host string) bool {
	address, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	return (address.Is4() && address.IsLoopback()) || address == netip.IPv6Loopback()
}

// Send 发一次请求。状态不是 200 时不读正文；是 200 时最多读 MaxResponseBytes+1 字节。
func (c *Client) Send(ctx context.Context, request ports.CarrierRequest) (ports.CarrierResponse, error) {
	ciphertext := []byte(request.Ciphertext)
	// 请求体用 NopCloser 包着，并显式给长度：这样请求没有 GetBody，Go 的传输层不会在复用的空闲连接上
	// 悄悄重发它。"不重试"在这里是一个字都不重发，哪怕对方一个字节也没收到。
	outgoing, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url, io.NopCloser(bytes.NewReader(ciphertext)))
	if err != nil {
		return ports.CarrierResponse{}, ports.ErrUnreachable
	}
	outgoing.ContentLength = int64(len(ciphertext))
	outgoing.Header.Set("appKey", request.AppKey.Reveal())
	outgoing.Header.Set("token", request.Token.Reveal())
	outgoing.Header.Set("timestamp", request.Timestamp)
	outgoing.Header.Set("nonce", request.Nonce)
	outgoing.Header.Set("signature", request.Signature)
	outgoing.Header.Set("msgType", request.MsgType)
	outgoing.Header.Set("lang", request.Lang)
	outgoing.Header.Set("Content-Type", "application/json")

	response, err := c.http.Do(outgoing)
	if err != nil {
		return ports.CarrierResponse{}, classify(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return ports.CarrierResponse{Status: response.StatusCode}, nil
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, c.max+1))
	if err != nil {
		return ports.CarrierResponse{}, classify(err)
	}
	if int64(len(body)) > c.max {
		return ports.CarrierResponse{}, ports.ErrAnswerTooLarge
	}
	return ports.CarrierResponse{Status: response.StatusCode, Body: body}, nil
}

// classify 把 http.Client.Do 或读正文的错误归成两类。错误本身不往外传：*url.Error 带着完整的地址，
// 底层错误可能带着对端的文字。
func classify(err error) error {
	var network net.Error
	if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &network) && network.Timeout()) {
		return ports.ErrTimeout
	}
	return ports.ErrUnreachable
}
