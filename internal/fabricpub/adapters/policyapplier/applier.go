// Package policyapplier 原子换上 gateway-authz 正在读的策略文件，再用发布器证书确认
// GET /v1/egress/policy-version 已经报出想要的版本。确认不了就把旧文件换回去。
package policyapplier

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"go.idp.xyz/idp-gateway/internal/fabricpub/ports"
)

// Config 是策略文件和版本查询的地址。HTTP 非空时用它（测试）；否则用 TLS 自己建客户端。
type Config struct {
	Path       string
	AuthzURL   string
	ServerName string
	TLS        *tls.Config
	Timeout    time.Duration
	Interval   time.Duration
	HTTP       *http.Client
}

// Applier 写一个策略文件并轮询版本。
type Applier struct {
	path     string
	endpoint string
	host     string
	client   *http.Client
	timeout  time.Duration
	interval time.Duration
	mode     fs.FileMode
}

// New 检查参数。地址必须是 https，路径的父目录必须已经存在。
func New(cfg Config) (*Applier, error) {
	if cfg.Path == "" || cfg.AuthzURL == "" || cfg.ServerName == "" {
		return nil, errors.New("policy applier: policy file, authz address and server name are required")
	}
	parsed, err := url.Parse(cfg.AuthzURL)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
		return nil, errors.New("policy applier: authz address must be https://host:port")
	}
	info, err := os.Lstat(filepath.Dir(cfg.Path))
	if err != nil || !info.IsDir() {
		return nil, errors.New("policy applier: the policy file's directory must exist")
	}
	mode := fs.FileMode(0o644)
	if file, err := os.Lstat(cfg.Path); err == nil {
		if file.Mode()&os.ModeSymlink != 0 || !file.Mode().IsRegular() {
			return nil, errors.New("policy applier: the policy file must be a regular file")
		}
		mode = file.Mode().Perm()
	} else if !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("policy applier: %w", err)
	}
	client := cfg.HTTP
	if client == nil {
		if cfg.TLS == nil {
			return nil, errors.New("policy applier: a TLS configuration is required")
		}
		client = &http.Client{
			Timeout: 2 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: cfg.TLS.Clone(), DisableKeepAlives: true, Proxy: nil,
			},
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		}
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	interval := cfg.Interval
	if interval <= 0 {
		interval = 100 * time.Millisecond
	}
	return &Applier{
		path: cfg.Path, endpoint: strings.TrimRight(cfg.AuthzURL, "/") + "/v1/egress/policy-version",
		host: cfg.ServerName, client: client, timeout: timeout, interval: interval, mode: mode,
	}, nil
}

// Apply 换上新文件并等到版本对上。对不上时换回 previous；换不回时错误带 ErrPartial。
func (a *Applier) Apply(ctx context.Context, policyJSON []byte, wantVersion string) ([]byte, error) {
	if wantVersion == "" || len(policyJSON) == 0 {
		return nil, errors.New("policy applier: version and policy are required")
	}
	previous, existed, err := readFile(a.path)
	if err != nil {
		return nil, err
	}
	if err := replaceFile(filepath.Dir(a.path), a.path, policyJSON, a.mode); err != nil {
		return nil, err
	}
	deadline := time.Now().Add(a.timeout)
	for {
		version, err := a.version(ctx)
		if err == nil && version == wantVersion {
			if !existed {
				return nil, nil
			}
			return previous, nil
		}
		if ctx.Err() != nil || time.Now().After(deadline) {
			break
		}
		timer := time.NewTimer(a.interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			break
		case <-timer.C:
		}
		if ctx.Err() != nil || time.Now().After(deadline) {
			break
		}
	}
	restoreFrom := previous
	if !existed {
		restoreFrom = nil
	}
	if err := a.Restore(ctx, restoreFrom); err != nil {
		return nil, fmt.Errorf("%w: %v", ports.ErrPartial, err)
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return nil, errors.New("policy applier: policy version was not observed")
}

// Restore 把策略文件换成 previous。previous 为 nil 时删掉文件。
func (a *Applier) Restore(_ context.Context, previous []byte) error {
	if previous == nil {
		if err := os.Remove(a.path); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		return syncDir(filepath.Dir(a.path))
	}
	return replaceFile(filepath.Dir(a.path), a.path, previous, a.mode)
}

func (a *Applier) version(ctx context.Context) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.endpoint, nil)
	if err != nil {
		return "", err
	}
	req.Host = a.host
	resp, err := a.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", errors.New("policy applier: version endpoint refused")
	}
	var decoded struct {
		PolicyVersion string `json:"policy_version"`
	}
	if err := json.Unmarshal(body, &decoded); err != nil {
		return "", err
	}
	return decoded.PolicyVersion, nil
}

func readFile(path string) ([]byte, bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, false, errors.New("policy applier: the policy file must be a regular file")
	}
	body, err := os.ReadFile(path)
	return body, true, err
}

func replaceFile(dir, path string, content []byte, mode fs.FileMode) (err error) {
	file, err := os.CreateTemp(dir, ".policy-*.tmp")
	if err != nil {
		return err
	}
	tmp := file.Name()
	defer func() {
		if err != nil {
			_ = os.Remove(tmp)
		}
	}()
	if err = file.Chmod(mode); err != nil {
		_ = file.Close()
		return err
	}
	if _, err = file.Write(content); err != nil {
		_ = file.Close()
		return err
	}
	if err = file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if err = file.Close(); err != nil {
		return err
	}
	if err = os.Rename(tmp, path); err != nil {
		return err
	}
	return syncDir(dir)
}

func syncDir(dir string) error {
	entry, err := os.Open(dir)
	if err != nil {
		return err
	}
	err = entry.Sync()
	if closeErr := entry.Close(); err == nil {
		err = closeErr
	}
	return err
}
