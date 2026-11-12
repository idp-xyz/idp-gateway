// Package container 是单机上的网关进程：一个 docker 容器（docs/adr/ADR-0010.md 第 10 条）。
// 重启它用本机的 docker 命令行，做法与 tests/integration/compose 的 SH-06、SH-07 相同。
//
// 单机上一个池只有这一个网关实例，重启期间新来的请求没有别处可去。在途的请求有多久做完，
// 由网关配置里的 connectionTerminationDeadline 和容器的停止时限两样决定：容器的停止时限更短时，
// 到时 docker 会直接杀掉进程。
package container

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// defaultStopTimeout 是容器自己没有设停止时限时 docker 用的那个。
const defaultStopTimeout = 10 * time.Second

// Config 说明是哪个容器。
type Config struct {
	// Name 是网关容器的名字或 ID。
	Name string
	// ConfigDirectory 是池的配置目录，Mount 是它在容器里的位置。重启之前要核对这个容器挂的
	// 确实是这个目录：名字写错了，重启的就是别人的容器。
	ConfigDirectory string
	Mount           string
	// StopTimeout 是让 docker 等网关多久才杀掉它；零值用容器自己设的（没有设时 docker 用 10 秒）。
	StopTimeout time.Duration
	// Docker 执行一条 docker 命令，返回它的全部输出。零值用本机的 docker 命令行。
	Docker func(ctx context.Context, env []string, argv ...string) (string, error)
}

// Container 是一个池的网关容器。
type Container struct {
	config Config
	// grace 是重启命令在停止时限之外最多再等多久。
	grace time.Duration
	// configured 是 Verify 读到的、容器自己设的停止时限。
	configured time.Duration
}

// New 检查配置。它不在这里碰 docker。
func New(config Config) (*Container, error) {
	if config.Name == "" || strings.ContainsAny(config.Name, " \t") || strings.HasPrefix(config.Name, "-") {
		return nil, fmt.Errorf("container: container name %q", config.Name)
	}
	if !filepath.IsAbs(config.ConfigDirectory) {
		absolute, err := filepath.Abs(config.ConfigDirectory)
		if err != nil {
			return nil, fmt.Errorf("container: %w", err)
		}
		config.ConfigDirectory = absolute
	}
	if !strings.HasPrefix(config.Mount, "/") {
		return nil, fmt.Errorf("container: mount point %q is not an absolute path", config.Mount)
	}
	if config.StopTimeout < 0 || config.StopTimeout%time.Second != 0 {
		return nil, fmt.Errorf("container: stop timeout %s must be a whole number of seconds", config.StopTimeout)
	}
	if config.Docker == nil {
		config.Docker = docker
	}
	return &Container{config: config, grace: 30 * time.Second, configured: defaultStopTimeout}, nil
}

func docker(ctx context.Context, env []string, argv ...string) (string, error) {
	command := exec.CommandContext(ctx, "docker", argv...)
	command.Env = append(os.Environ(), env...)
	detach(command)
	output, err := command.CombinedOutput()
	return string(output), err
}

// mount 是 docker inspect 报告的一个挂载里用到的部分。
type mount struct {
	Type        string `json:"Type"`
	Source      string `json:"Source"`
	Destination string `json:"Destination"`
}

// Verify 核对这个容器在跑，并且把池的配置目录挂在了网关读配置的位置上。
func (c *Container) Verify(ctx context.Context) error {
	output, err := c.config.Docker(ctx, nil, "inspect", "-f", "{{json .State.Running}} {{json .Config.StopTimeout}} {{json .Mounts}}", c.config.Name)
	if err != nil {
		return fmt.Errorf("container: docker inspect %s: %w: %s", c.config.Name, err, lastLine(output))
	}
	fields := strings.SplitN(lastLine(output), " ", 3)
	var (
		running bool
		timeout *int
		mounts  []mount
	)
	if len(fields) != 3 || json.Unmarshal([]byte(fields[0]), &running) != nil ||
		json.Unmarshal([]byte(fields[1]), &timeout) != nil || json.Unmarshal([]byte(fields[2]), &mounts) != nil {
		return fmt.Errorf("container: docker inspect %s gave something unexpected: %s", c.config.Name, lastLine(output))
	}
	if !running {
		return fmt.Errorf("container: %s is not running", c.config.Name)
	}
	if timeout != nil && *timeout > 0 {
		c.configured = time.Duration(*timeout) * time.Second
	}
	var mounted []string
	for _, m := range mounts {
		if m.Destination != c.config.Mount {
			continue
		}
		if m.Type == "bind" && sameDirectory(m.Source, c.config.ConfigDirectory) {
			return nil
		}
		mounted = append(mounted, m.Source)
	}
	if len(mounted) == 0 {
		return fmt.Errorf("container: %s has nothing mounted at %s: it is not the gateway of this pool", c.config.Name, c.config.Mount)
	}
	return fmt.Errorf("container: %s has %s mounted at %s, not the configuration directory of this pool (%s)",
		c.config.Name, strings.Join(mounted, ", "), c.config.Mount, c.config.ConfigDirectory)
}

// sameDirectory 报告两个路径是不是同一个目录。docker 报告的是它那边的路径；经符号链接到的也算。
func sameDirectory(a, b string) bool {
	if filepath.Clean(a) == filepath.Clean(b) {
		return true
	}
	resolvedA, errA := filepath.EvalSymlinks(a)
	resolvedB, errB := filepath.EvalSymlinks(b)
	return errA == nil && errB == nil && resolvedA == resolvedB
}

// Restart 重启容器：docker 先发终止信号，等网关把在途的请求做完再退出，最多等到停止时限，然后起一个新进程。
//
// 命令一发出就不随 ctx 取消。docker 命令行中途被杀掉，那次重启守护进程照样做完（docker 29.8.1 上实测；
// 更早的版本没有试过），但这里就不知道它什么时候做完、做成了没有。
func (c *Container) Restart(ctx context.Context) error {
	argv := []string{"restart"}
	stop := c.configured
	if c.config.StopTimeout > 0 {
		stop = c.config.StopTimeout
		argv = append(argv, "-t", strconv.Itoa(int(stop/time.Second)))
	}
	bounded, cancel := context.WithTimeout(context.WithoutCancel(ctx), stop+c.grace)
	defer cancel()
	output, err := c.config.Docker(bounded, nil, append(argv, c.config.Name)...)
	if err != nil {
		if errors.Is(bounded.Err(), context.DeadlineExceeded) {
			return fmt.Errorf("container: docker restart %s did not return within %s", c.config.Name, stop+c.grace)
		}
		return fmt.Errorf("container: docker restart %s: %w: %s", c.config.Name, err, lastLine(output))
	}
	return nil
}

func lastLine(output string) string {
	lines := strings.Split(strings.TrimSpace(output), "\n")
	return strings.TrimSpace(lines[len(lines)-1])
}
