// Package readback 经网关自己的回读口读它在跑什么（docs/adr/ADR-0010.md 第 5 条）：双向 TLS，
// 出示发布器的证书，只用两个 GET。写法与黑盒套件的 P1-RB-03 相同。
package readback

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"go.idp.xyz/idp-gateway/internal/gatewayconfig/domain"
)

const (
	dumpPath    = "/config_dump" // 生效的运行配置。不用 /api/config/effective：它显示的是文件
	runtimePath = "/api/runtime" // 上一次加载的结果、存储模式、构建
	// maxBody 是一个应答最多读多少。锁定版本上一份几条路由的配置的 /config_dump 是十几 KB。
	maxBody = 64 << 20
)

// Config 说明回读口在哪里、怎么连。
type Config struct {
	// Address 是回读口的 host:port。
	Address string
	// TLS 出示发布器的证书，并按名字验证回读口的证书（workloadtls.ClientConfig）。
	TLS *tls.Config
	// Timeout 是一次请求最长多久；零值取 3 秒。
	Timeout time.Duration
}

// Client 读一个网关的回读口。
type Client struct {
	address string
	host    string
	http    *http.Client
	limit   int64
}

// New 构造回读口的客户端。它不在这里连接。
func New(config Config) (*Client, error) {
	if _, _, err := net.SplitHostPort(config.Address); err != nil {
		return nil, fmt.Errorf("readback: address: %w", err)
	}
	if config.TLS == nil || config.TLS.ServerName == "" || len(config.TLS.Certificates) == 0 || config.TLS.RootCAs == nil {
		return nil, errors.New("readback: a TLS configuration with a client certificate, a CA and the server name is required")
	}
	timeout := config.Timeout
	if timeout == 0 {
		timeout = 3 * time.Second
	}
	return &Client{
		address: config.Address,
		host:    config.TLS.ServerName,
		limit:   maxBody,
		http: &http.Client{
			Timeout: timeout,
			// 每次读都是一条新连接：网关重启之后不会拿着一条已经断了的连接去读。
			Transport: &http.Transport{TLSClientConfig: config.TLS.Clone(), DisableKeepAlives: true, Proxy: nil},
			// 回读口不该重定向到别处。
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}, nil
}

// runtime 是 /api/runtime 里用到的部分。用指针是为了分清"没有这一项"和"值为假"。
type runtime struct {
	Build *struct {
		Version     string `json:"version"`
		GitRevision string `json:"gitRevision"`
	} `json:"build"`
	UI *struct {
		ConfigStoreMode string `json:"configStoreMode"`
	} `json:"ui"`
	ConfigReload *struct {
		Synchronized *bool   `json:"synchronized"`
		LastError    *string `json:"lastError"`
	} `json:"configReload"`
}

// Observe 读网关此刻在跑什么。两个接口里任何一个没有按预期回答，这一次就算没有读到。
func (c *Client) Observe(ctx context.Context) (domain.Observation, error) {
	dump, err := c.get(ctx, dumpPath)
	if err != nil {
		return domain.Observation{}, err
	}
	raw, err := c.get(ctx, runtimePath)
	if err != nil {
		return domain.Observation{}, err
	}
	digest, err := domain.PublishedDigest(dump)
	if err != nil {
		return domain.Observation{}, fmt.Errorf("readback: %s: %w", dumpPath, err)
	}
	settings, err := domain.StartupSettings(dump)
	if err != nil {
		return domain.Observation{}, fmt.Errorf("readback: %s: %w", dumpPath, err)
	}
	var state runtime
	if err := json.Unmarshal(raw, &state); err != nil {
		return domain.Observation{}, fmt.Errorf("readback: %s is not JSON: %w", runtimePath, err)
	}
	if state.Build == nil || state.UI == nil || state.ConfigReload == nil || state.ConfigReload.Synchronized == nil {
		return domain.Observation{}, fmt.Errorf("readback: %s does not have build, ui and configReload.synchronized", runtimePath)
	}
	observation := domain.Observation{
		Digest:       digest,
		Settings:     settings,
		Synchronized: *state.ConfigReload.Synchronized,
		StorageMode:  state.UI.ConfigStoreMode,
		Version:      state.Build.Version,
		Revision:     state.Build.GitRevision,
	}
	if state.ConfigReload.LastError != nil {
		observation.LastError = *state.ConfigReload.LastError
	}
	return observation, nil
}

func (c *Client) get(ctx context.Context, path string) ([]byte, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+c.address+path, nil)
	if err != nil {
		return nil, fmt.Errorf("readback: %w", err)
	}
	request.Host = c.host
	response, err := c.http.Do(request)
	if err != nil {
		return nil, fmt.Errorf("readback: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("readback: GET %s answered %d", path, response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, c.limit+1))
	if err != nil {
		return nil, fmt.Errorf("readback: GET %s: %w", path, err)
	}
	if int64(len(body)) > c.limit {
		return nil, fmt.Errorf("readback: GET %s answered more than %d bytes", path, c.limit)
	}
	return body, nil
}
