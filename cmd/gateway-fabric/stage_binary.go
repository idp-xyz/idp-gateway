package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"go.idp.xyz/idp-gateway/internal/gatewayconfig/adapters/readback"
	gdomain "go.idp.xyz/idp-gateway/internal/gatewayconfig/domain"
	gports "go.idp.xyz/idp-gateway/internal/gatewayconfig/ports"
)

// binaryStaging 用锁定的 agentgateway 二进制在本机做离线加载：起一个短命进程，经回读口取运行配置摘要，然后停掉它。
//
// 快照原样交给这个进程。PublishedDigest 去掉的是顶层 config（adminAddr、statsAddr、readinessAddr），
// gateways 里的端口和 bindAddress 仍算进摘要。改这些端口，或给没有 bindAddress 的 read-back 补一个，
// 摘要就和池里那份对不上。read-back 绑的是 0.0.0.0，同一网络命名空间里第二个进程会因 Address already in use 退出。
// 那种情况用 --staging-image：临时容器有自己的网络命名空间，配置字节不变。本模式只在这些端口空着时用
// （池在别的网络命名空间，或另一台机器上）。
type binaryStaging struct {
	binary   string
	lockFile string
	listen   string
	tlsDir   string
	tls      *tls.Config
	timeout  time.Duration
}

func newBinaryStaging(binary, lockFile, listen, tlsDir string, clientTLS *tls.Config) (*binaryStaging, error) {
	if binary == "" || lockFile == "" || listen == "" {
		return nil, errors.New("staging: binary, lock file and listen address are required")
	}
	if clientTLS == nil {
		return nil, errors.New("staging: a read-back TLS configuration is required")
	}
	if tlsDir != "" {
		info, err := os.Stat(tlsDir)
		if err != nil || !info.IsDir() {
			return nil, fmt.Errorf("staging: tls directory %q must exist", tlsDir)
		}
	}
	return &binaryStaging{binary: binary, lockFile: lockFile, listen: listen, tlsDir: tlsDir, tls: clientTLS, timeout: 20 * time.Second}, nil
}

func (s *binaryStaging) Load(ctx context.Context, snapshot gdomain.Snapshot) (gdomain.Observation, error) {
	none := gdomain.Observation{}
	if snapshot.IsZero() {
		return none, errors.New("staging: nothing to load")
	}
	if err := matchLock(s.binary, s.lockFile); err != nil {
		return none, err
	}
	dir, err := os.MkdirTemp("", "fabric-stage-")
	if err != nil {
		return none, err
	}
	defer os.RemoveAll(dir)
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), snapshot.Content(), 0o644); err != nil {
		return none, err
	}
	// 编译出的相对路径是 tls/...。pool.tls_dir 是 tls，jwks 是 tls/jwks.json。软链必须叫 tls，不能改名。
	if s.tlsDir != "" {
		if err := os.Symlink(s.tlsDir, filepath.Join(dir, "tls")); err != nil {
			return none, err
		}
	}
	env, err := childEnv()
	if err != nil {
		return none, err
	}
	cmd := exec.Command(s.binary, "-f", "config.yaml")
	cmd.Dir = dir
	cmd.Env = env
	var output lockedBuf
	cmd.Stdout = &output
	cmd.Stderr = &output
	if err := cmd.Start(); err != nil {
		return none, err
	}
	waited := make(chan error, 1)
	go func() { waited <- cmd.Wait() }()
	// Kill 之后必须把 Wait 收掉。只 Kill 不收，子进程会停在僵尸上，测试结束时和父进程抢退出状态。
	reaped := false
	reap := func() {
		if reaped {
			return
		}
		reaped = true
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		<-waited
	}
	defer reap()
	client, err := readback.New(readback.Config{Address: s.listen, TLS: s.tls, Timeout: 2 * time.Second})
	if err != nil {
		return none, err
	}
	deadline := time.Now().Add(s.timeout)
	for {
		select {
		case err := <-waited:
			waited <- err
			return none, &gports.RejectedError{Reason: processExit(output.String(), err)}
		default:
		}
		observed, err := client.Observe(ctx)
		if err == nil && observed.Digest != "" && observed.Synchronized && observed.StorageMode == gdomain.StorageReadOnly {
			return observed, nil
		}
		if time.Now().After(deadline) {
			return none, errors.New("staging: timed out waiting for read-back")
		}
		timer := time.NewTimer(50 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return none, ctx.Err()
		case err := <-waited:
			timer.Stop()
			waited <- err
			return none, &gports.RejectedError{Reason: processExit(output.String(), err)}
		case <-timer.C:
		}
	}
}

// childEnv 是短命进程的环境。SESSION_KEY 每次现做，不从父进程继承；代理变量拿掉，回环不走代理。
func childEnv() ([]string, error) {
	env := make([]string, 0, len(os.Environ())+1)
	for _, item := range os.Environ() {
		key, _, _ := strings.Cut(item, "=")
		if key == "SESSION_KEY" || strings.Contains(strings.ToLower(key), "proxy") {
			continue
		}
		env = append(env, item)
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	return append(env, "SESSION_KEY="+hex.EncodeToString(key)), nil
}

// lockedBuf 让子进程写日志和父进程读日志可以同时发生。strings.Builder 不能这样用。
type lockedBuf struct {
	mu sync.Mutex
	b  strings.Builder
}

func (l *lockedBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuf) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

func matchLock(binary, lockFile string) error {
	raw, err := os.ReadFile(lockFile)
	if err != nil {
		return fmt.Errorf("staging: %w", err)
	}
	var lock struct {
		SHA256 map[string]string `json:"sha256"`
	}
	if err := json.Unmarshal(raw, &lock); err != nil || len(lock.SHA256) == 0 {
		return errors.New("staging: lock file has no sha256 entries")
	}
	got, err := fileSHA256(binary)
	if err != nil {
		return err
	}
	for _, want := range lock.SHA256 {
		if strings.EqualFold(strings.TrimSpace(want), got) {
			return nil
		}
	}
	return fmt.Errorf("staging: agentgateway sha256 %s does not match %s", got, lockFile)
}

func fileSHA256(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	sum := sha256.New()
	if _, err := io.Copy(sum, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(sum.Sum(nil)), nil
}

func processExit(output string, err error) string {
	text := oneLine(output)
	if text == "" && err != nil {
		text = oneLine(err.Error())
	}
	if text == "" {
		text = "agentgateway exited before read-back"
	}
	return text
}
