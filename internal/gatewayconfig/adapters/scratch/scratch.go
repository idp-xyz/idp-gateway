// Package scratch 是发布之前的离线加载（docs/adr/ADR-0010.md 第 6、10 条）：用要部署的那个镜像
// 另起一个网关容器加载这份快照，经它的回读口读它报告的运行配置，然后删掉容器。
//
// 容器由本机的 docker 命令行来起，做法与 tests/integration/compose/run.py 的 stage() 相同。
// 它不接流量：收业务请求的监听只绑容器自己的回环，映射到本机的只有回读口。
package scratch

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"go.idp.xyz/idp-gateway/internal/gatewayconfig/domain"
	"go.idp.xyz/idp-gateway/internal/gatewayconfig/ports"
)

// 容器里的布局。池里的网关容器必须是同一个布局：配置里的相对路径（证书等）是相对工作目录解析的，
// 两边不同，离线加载的结果就说明不了池里会怎样。internal 里有一条测试拿它对着
// tests/integration/compose/compose.yml 核对。
const (
	WorkingDirectory = "/work"
	ConfigMount      = "/work/config"
	TLSMount         = "/work/tls"
	ConfigFile       = "config.yaml"
	ConfigArgument   = "config/config.yaml"
)

// Config 说明离线加载用什么起、在哪里起。
type Config struct {
	// Image 是要部署的镜像，必须按摘要引用（仓库@sha256:…）。
	Image string
	// Name 是那个临时容器的名字。同名的容器会先被删掉。
	Name string
	// TLSDirectory 是本机上的一个目录，只读挂到容器的 /work/tls：回读口的证书，以及配置引用的别的文件。
	TLSDirectory string
	// WorkDirectory 是本机上放候选配置的地方，每次加载在它下面建一个以容器名字命名的目录，用完删掉。
	// docker 要能挂载它。
	WorkDirectory string
	// Publish 是回读口映射到本机的地址，host:port。只能是回环地址。
	Publish string
	// ContainerPort 是回读口在容器里的端口，由快照的配置决定。
	ContainerPort int
	// User 是容器里的用户（uid:gid）；空值取运行本进程的用户，好让它读得了挂进去的文件。
	User string
	// ReadBack 读那个临时容器的回读口（地址就是 Publish）。
	ReadBack ports.ReadBack
	// StartTimeout 是最多等它多久；零值取 20 秒。
	StartTimeout time.Duration
	// Docker 执行一条 docker 命令：env 加进它的环境，返回它的全部输出。零值用本机的 docker 命令行。
	Docker func(ctx context.Context, env []string, argv ...string) (string, error)
}

// Staging 用临时容器做离线加载。
type Staging struct {
	config Config
	docker func(ctx context.Context, env []string, argv ...string) (string, error)
	pause  time.Duration
}

// New 检查配置。它不在这里碰 docker。
func New(config Config) (*Staging, error) {
	repository, digest, found := strings.Cut(config.Image, "@sha256:")
	if !found || repository == "" || len(digest) != 64 || strings.Trim(digest, "0123456789abcdef") != "" {
		return nil, fmt.Errorf("scratch: image %q is not referenced by digest (repository@sha256:…)", config.Image)
	}
	host, port, err := net.SplitHostPort(config.Publish)
	if err != nil {
		return nil, fmt.Errorf("scratch: publish address: %w", err)
	}
	if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
		return nil, fmt.Errorf("scratch: the read-back listener of the scratch gateway may only be published on a loopback address, not %q", host)
	}
	if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		return nil, fmt.Errorf("scratch: publish port %q", port)
	}
	if config.ContainerPort < 1 || config.ContainerPort > 65535 {
		return nil, fmt.Errorf("scratch: container port %d", config.ContainerPort)
	}
	if config.Name == "" || strings.ContainsAny(config.Name, " \t/") || strings.HasPrefix(config.Name, "-") {
		return nil, fmt.Errorf("scratch: container name %q", config.Name)
	}
	for what, dir := range map[string]string{"TLS directory": config.TLSDirectory, "work directory": config.WorkDirectory} {
		if info, err := os.Stat(dir); err != nil || !info.IsDir() || !filepath.IsAbs(dir) {
			return nil, fmt.Errorf("scratch: %s %q must be an existing directory given by its absolute path", what, dir)
		}
	}
	if config.ReadBack == nil {
		return nil, errors.New("scratch: a way to read the scratch gateway back is required")
	}
	if config.User == "" {
		config.User = fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid())
	}
	if config.StartTimeout == 0 {
		config.StartTimeout = 20 * time.Second
	}
	if config.Docker == nil {
		config.Docker = docker
	}
	return &Staging{config: config, docker: config.Docker, pause: 200 * time.Millisecond}, nil
}

func docker(ctx context.Context, env []string, argv ...string) (string, error) {
	command := exec.CommandContext(ctx, "docker", argv...)
	command.Env = append(os.Environ(), env...)
	output, err := command.CombinedOutput()
	return string(output), err
}

// Load 起一个临时容器加载这份快照。容器起来之后自己退出了，说明网关加载不了这份文件：
// 返回 *ports.RejectedError，原因是它退出前说的最后一句。
//
// 网关因为别的缘故起不来（读不了挂进去的文件等）时，这里分辨不出来，同样报成拒绝；原因里写着它说了什么。
func (s *Staging) Load(ctx context.Context, snapshot domain.Snapshot) (domain.Observation, error) {
	none := domain.Observation{}
	if snapshot.IsZero() {
		return none, errors.New("scratch: nothing to load")
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return none, fmt.Errorf("scratch: %w", err)
	}

	// 候选配置放在以容器名字命名的目录里。同名的容器同时只能有一个，这个目录也就只有一个用它的人。
	// 上一次没收拾干净的容器和目录（发布器被强行杀掉时来不及收拾）先清掉，先容器后目录。
	name := s.config.Name
	candidate := filepath.Join(s.config.WorkDirectory, "candidate-"+name)
	_, _ = s.docker(ctx, nil, "rm", "-f", name)
	if err := os.RemoveAll(candidate); err != nil {
		return none, fmt.Errorf("scratch: %w", err)
	}
	// 目录只有属主能进。容器里的用户默认就是属主；不是时由调用方保证它读得了。
	if err := os.Mkdir(candidate, 0o700); err != nil {
		return none, fmt.Errorf("scratch: %w", err)
	}
	defer os.RemoveAll(candidate)
	if err := os.WriteFile(filepath.Join(candidate, ConfigFile), snapshot.Content(), 0o644); err != nil {
		return none, fmt.Errorf("scratch: %w", err)
	}
	defer func() {
		// 删容器不随 ctx 取消：留下它，下一次加载会撞上它占着的端口。
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		defer cancel()
		_, _ = s.docker(cleanup, nil, "rm", "-f", name)
	}()
	// 会话密钥只给这个临时容器用。它经 docker 命令行自己的环境传进去，不出现在命令行参数里。
	if output, err := s.docker(ctx, []string{"SESSION_KEY=" + hex.EncodeToString(key)},
		"run", "-d", "--name", name,
		"--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
		"--user", s.config.User,
		"-p", fmt.Sprintf("%s:%d", s.config.Publish, s.config.ContainerPort),
		"-v", candidate+":"+ConfigMount+":ro",
		"-v", s.config.TLSDirectory+":"+TLSMount+":ro",
		"-w", WorkingDirectory,
		"-e", "SESSION_KEY",
		s.config.Image, "-f", ConfigArgument); err != nil {
		return none, fmt.Errorf("scratch: docker run: %w: %s", err, lastLine(output))
	}

	deadline := time.Now().Add(s.config.StartTimeout)
	for {
		state, err := s.docker(ctx, nil, "inspect", "-f", "{{.State.Running}} {{.State.ExitCode}}", name)
		if err != nil {
			return none, fmt.Errorf("scratch: docker inspect: %w: %s", err, lastLine(state))
		}
		if fields := strings.Fields(state); len(fields) == 2 && fields[0] == "false" {
			logs, _ := s.docker(ctx, nil, "logs", "--tail", "50", name)
			said := reason(logs)
			if fields[1] == "0" {
				return none, fmt.Errorf("scratch: the gateway exited with code 0 right after starting: %s", said)
			}
			return none, &ports.RejectedError{Reason: said}
		}
		observed, err := s.config.ReadBack.Observe(ctx)
		if err == nil {
			return observed, nil
		}
		if !time.Now().Before(deadline) {
			return none, fmt.Errorf("scratch: the gateway is running but did not answer on its read-back listener within %s: %w", s.config.StartTimeout, err)
		}
		timer := time.NewTimer(s.pause)
		select {
		case <-ctx.Done():
			timer.Stop()
			return none, fmt.Errorf("scratch: %w", ctx.Err())
		case <-timer.C:
		}
	}
}

func lastLine(output string) string {
	lines := strings.Split(strings.TrimSpace(output), "\n")
	return strings.TrimSpace(lines[len(lines)-1])
}

// reason 从网关退出前的日志里取出它给的原因：最后一个以 "Error: " 开头的行。它后面可以还跟着
// 几行 "Caused by:"，那些只是把同一个原因再拆开说一遍。没有这样的行时取最后一行。
func reason(logs string) string {
	lines := strings.Split(strings.TrimSpace(logs), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		if said, ok := strings.CutPrefix(strings.TrimSpace(lines[i]), "Error: "); ok {
			return said
		}
	}
	return strings.TrimSpace(lines[len(lines)-1])
}
