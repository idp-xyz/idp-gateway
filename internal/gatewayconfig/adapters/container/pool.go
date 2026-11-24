package container

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"go.idp.xyz/idp-gateway/internal/gatewayconfig/domain"
)

// 单机上一个池里常驻的三个服务在 deploy/compose/compose.yml 里的名字。
const (
	// HolderService 只占着网络命名空间和本机上的端口。
	HolderService = "netns"
	// GatewayService 是网关。
	GatewayService = "agentgateway"
	// FrontService 是对外收业务请求的前置代理。
	FrontService = "front"
)

// EgressService 是网关启动之前装出口规则的那一步（pin-egress.sh）。看守让它 forget 时用的是它。
const EgressService = "egress"

// steps 是部署文件里跑完就退出的几步：compose.yml 的 place、egress、confirm，provider-signer.yml 的 signer-egress。
// 它们以 0 退出是做完了，不是死了。
var steps = []string{"place", EgressService, "confirm", "signer-egress"}

// DefaultProject 是 deploy/compose/compose.yml 里写的项目名。
const DefaultProject = "idp-gateway-pool"

// docker compose 给它起的每个容器贴的标签。
const (
	projectLabel = "com.docker.compose.project"
	serviceLabel = "com.docker.compose.service"
	// oneOffLabel 的值是 True 的，是 docker compose run 临时起的容器，不是池里的。
	oneOffLabel = "com.docker.compose.oneoff"
)

// memberFormat 让 docker inspect 每个容器答一行，各项之间是制表符。每一项都是 JSON：
// JSON 里的制表符是转义过的，所以按制表符切不会切错。
var memberFormat = strings.Join([]string{
	`{{json (index .Config.Labels "` + serviceLabel + `")}}`,
	`{{json (index .Config.Labels "` + oneOffLabel + `")}}`,
	`{{json .State.Running}}`,
	`{{json .State.Status}}`,
	`{{json .State.ExitCode}}`,
	`{{json .State.StartedAt}}`,
}, "\t")

// servicesFormat 让 docker inspect 为另外照看的服务（ADR-0024）每个容器答一行，写法与 memberFormat 相同。
// 最后一项是它接着的各个网络：哪个网络、在那里的地址。
var servicesFormat = strings.Join([]string{
	`{{json .Name}}`,
	`{{json (index .Config.Labels "` + serviceLabel + `")}}`,
	`{{json (index .Config.Labels "` + oneOffLabel + `")}}`,
	`{{json .State.Running}}`,
	`{{json .State.Status}}`,
	`{{json .State.ExitCode}}`,
	`{{json .NetworkSettings.Networks}}`,
}, "\t")

var (
	projectName = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]*$`)
	containerID = regexp.MustCompile(`^[0-9a-f]{64}$`)
	envName     = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	// serviceName 是 compose 认的服务名，不以连字符开头（不然像一个参数）。
	serviceName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)
)

// ErrTend 是 CheckTended 不接受一个服务名时返回的错误（errors.Is）。
var ErrTend = errors.New("container: service to tend")

// CheckTended 核对看守另外照看的服务名（ADR-0024）：要是 compose 认的服务名；不能是三个常驻的（它们本来就看），
// 也不能是跑完就退出的那几步；不能重复。它不看 compose 文件里有没有：那是 Declared。
func CheckTended(names []string) error {
	seen := map[string]bool{}
	for _, name := range names {
		switch {
		case !serviceName.MatchString(name):
			return fmt.Errorf("%w %q: not a compose service name", ErrTend, name)
		case name == HolderService || name == GatewayService || name == FrontService:
			return fmt.Errorf("%w %q: the keeper always looks at %s, %s and %s", ErrTend, name, HolderService, GatewayService, FrontService)
		case slices.Contains(steps, name):
			return fmt.Errorf("%w %q: a step that runs to completion and exits (%s)", ErrTend, name, strings.Join(steps, ", "))
		case seen[name]:
			return fmt.Errorf("%w %q: given more than once", ErrTend, name)
		}
		seen[name] = true
	}
	return nil
}

// defaultEnvFile 是不给变量文件时 docker compose 自己读的那个：当前目录里的 .env。
const defaultEnvFile = ".env"

// ErrEnvFile 是 CheckEnvFiles 不接受一个变量文件时返回的错误（errors.Is）。
var ErrEnvFile = errors.New("container: env file")

// CheckEnvFiles 核对 docker compose 要读的变量文件。files 是给它的那些（--env-file）；一个都不给时
// 是当前目录里的 .env，没有这个文件就没有可核对的。lookup 查本进程的环境。
//
// 为什么要核对：本进程的环境原样交给它跑的 docker compose，而 docker compose 先用环境里的变量，
// 环境里没有的才从文件里取。本进程由 systemd 启动、变量是 systemd 从同一个文件读来的时候
// （单元里的 EnvironmentFile=），两边读法不同的行会让这一次 docker compose 拿到的设置与启动这个池时
// 的不同：容器被重建，或者起不来。值后面跟着注释的、带引号的、带 $ 的行，两边读法都不同。
//
// 所以只接受两边读法相同的写法：空行，# 开头的注释，和 名字=值（值里没有空白、引号、$、#、反斜杠）。
// 环境里已经有同名的变量时，它的值要与文件里的相同。
//
// 返回的错误不带那一行的内容。
func CheckEnvFiles(files []string, lookup func(string) (string, bool)) error {
	if len(files) == 0 {
		if _, err := os.Stat(defaultEnvFile); errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		files = []string{defaultEnvFile}
	}
	type setting struct {
		value, path string
		line        int
	}
	// 同一个名字出现几次时，docker compose 和 systemd 用的都是最后那一次。
	settings := map[string]setting{}
	var names []string
	for _, path := range files {
		content, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("container: env file: %w", err)
		}
		for i, line := range strings.Split(string(content), "\n") {
			if rest := strings.TrimLeft(line, " \t"); rest == "" || strings.HasPrefix(rest, "#") {
				continue
			}
			name, value, assigned := strings.Cut(line, "=")
			if !assigned || !envName.MatchString(name) || !plainValue(value) {
				return fmt.Errorf("%w %s, line %d: only NAME=value lines are accepted, with no whitespace, quotes, $, # or backslash in them: "+
					"systemd and docker compose read other lines differently", ErrEnvFile, path, i+1)
			}
			if _, seen := settings[name]; !seen {
				names = append(names, name)
			}
			settings[name] = setting{value: value, path: path, line: i + 1}
		}
	}
	for _, name := range names {
		s := settings[name]
		if current, set := lookup(name); set && current != s.value {
			return fmt.Errorf("%w %s, line %d: %s has another value in the environment of this command, and docker compose would use that one",
				ErrEnvFile, s.path, s.line, name)
		}
	}
	return nil
}

// plainValue 报告一个值是不是 systemd 和 docker compose 读出来一样的那种。
func plainValue(value string) bool {
	if !utf8.ValidString(value) {
		return false
	}
	for _, r := range value {
		if unicode.IsSpace(r) || unicode.IsControl(r) || strings.ContainsRune("\"'$#\\`", r) {
			return false
		}
	}
	return true
}

// PoolConfig 说明是哪个 compose 项目，启动它的命令怎么写。
type PoolConfig struct {
	// Project 是 compose 的项目名：看容器、起容器都按它。
	Project string
	// Files 是 compose 文件（-f），EnvFiles 是变量文件（--env-file）。都不给时，docker compose 自己
	// 在当前目录里找 compose.yml 和 .env，与在那个目录里手工跑 docker compose up -d 一样。
	// 变量文件要先经 CheckEnvFiles 核对。
	Files    []string
	EnvFiles []string
	// Timeout 是启动命令、停止命令各自最多跑多久。到时 docker 命令行被杀掉，已经起来的容器留着。
	Timeout time.Duration
	// Docker 执行一条 docker 命令，返回它的全部输出。零值用本机的 docker 命令行。
	Docker func(ctx context.Context, env []string, argv ...string) (string, error)
}

// Pool 是单机上一个池的容器：一个 docker compose 项目。
type Pool struct {
	config PoolConfig
	// look 是看一眼容器最多用多久。
	look time.Duration
}

// NewPool 检查配置。它不在这里碰 docker。
func NewPool(config PoolConfig) (*Pool, error) {
	if !projectName.MatchString(config.Project) {
		return nil, fmt.Errorf("container: compose project name %q", config.Project)
	}
	for _, path := range append(append([]string{}, config.Files...), config.EnvFiles...) {
		if path == "" || strings.HasPrefix(path, "-") {
			return nil, fmt.Errorf("container: compose file %q", path)
		}
	}
	if config.Timeout <= 0 {
		return nil, fmt.Errorf("container: timeout %s for the compose commands must be positive", config.Timeout)
	}
	if config.Docker == nil {
		config.Docker = docker
	}
	return &Pool{config: config, look: 30 * time.Second}, nil
}

// listed 跑一条列出这个项目的什么的 docker 命令（docker ps、docker network ls），返回其中的 ID。
// what 是错误里说的命令名。
func (p *Pool) listed(ctx context.Context, what string, argv ...string) ([]string, error) {
	output, err := p.config.Docker(ctx, nil, append(argv, "-q", "--no-trunc", "--filter", "label="+projectLabel+"="+p.config.Project)...)
	if err != nil {
		return nil, fmt.Errorf("container: docker %s: %w: %s", what, err, lastLine(output))
	}
	// 命令行写到标准错误上的警告也在输出里：不是 ID 的行不算。
	var ids []string
	for _, line := range strings.Split(output, "\n") {
		if id := strings.TrimSpace(line); containerID.MatchString(id) {
			ids = append(ids, id)
		}
	}
	return ids, nil
}

// containers 列出这个项目的全部容器，在跑的和不在跑的。
func (p *Pool) containers(ctx context.Context) ([]string, error) {
	return p.listed(ctx, "ps", "ps", "-a")
}

// Members 看这个项目的容器里常驻的那三个。别的服务（跑完就退出的那两步、别人加进来的）不看。
func (p *Pool) Members(ctx context.Context) (domain.Members, error) {
	var members domain.Members
	bounded, cancel := context.WithTimeout(ctx, p.look)
	defer cancel()
	ids, err := p.containers(bounded)
	if err != nil {
		return members, err
	}
	if len(ids) == 0 {
		return members, nil // 这个项目一个容器都没有
	}
	output, err := p.config.Docker(bounded, nil, append([]string{"inspect", "-f", memberFormat}, ids...)...)
	if err != nil {
		// 多半是刚才列出来的容器这时已经被删了：下一眼再看。
		return members, fmt.Errorf("container: docker inspect: %w: %s", err, lastLine(output))
	}
	found := map[string]*domain.Member{HolderService: &members.Holder, GatewayService: &members.Gateway, FrontService: &members.Front}
	seen := map[string]bool{}
	answered := 0
	for _, line := range strings.Split(output, "\n") {
		if !strings.Contains(line, "\t") {
			continue // 警告之类
		}
		var (
			service, oneOff, status, startedAt string
			running                            bool
			exitCode                           int
		)
		fields := strings.Split(strings.TrimRight(line, "\r"), "\t")
		targets := []any{&service, &oneOff, &running, &status, &exitCode, &startedAt}
		if len(fields) != len(targets) {
			return domain.Members{}, fmt.Errorf("container: docker inspect gave something unexpected: %s", line)
		}
		for i, target := range targets {
			if err := json.Unmarshal([]byte(fields[i]), target); err != nil {
				return domain.Members{}, fmt.Errorf("container: docker inspect gave something unexpected: %s", line)
			}
		}
		answered++
		member, ok := found[service]
		if !ok || strings.EqualFold(oneOff, "true") {
			continue
		}
		if seen[service] {
			return domain.Members{}, fmt.Errorf("container: project %s has more than one container for service %s", p.config.Project, service)
		}
		seen[service] = true
		started, err := time.Parse(time.RFC3339Nano, startedAt)
		if err != nil {
			return domain.Members{}, fmt.Errorf("container: docker inspect gave something unexpected: %s", line)
		}
		member.Running, member.Started, member.State = running, started, status
		if !running && (status == "exited" || status == "dead") {
			member.State = fmt.Sprintf("%s (%d)", status, exitCode)
		}
	}
	if answered != len(ids) {
		return domain.Members{}, fmt.Errorf("container: docker inspect described %d of the %d containers of project %s", answered, len(ids), p.config.Project)
	}
	return members, nil
}

// Start 跑 docker compose up -d：没有在跑的容器按 compose 文件规定的先后起起来，在跑着的不动。
// 网关启动之前的 place、之后的 confirm 都在这条命令里；有一步没有通过，命令以非零码结束。
func (p *Pool) Start(ctx context.Context) error {
	return p.compose(ctx, "up", "-d")
}

// StopDependents 跑 docker compose stop front agentgateway。docker compose 先停前置代理，再停网关，
// 各自等在途的请求做完，等多久由 compose 文件定。
func (p *Pool) StopDependents(ctx context.Context) error {
	return p.compose(ctx, "stop", FrontService, GatewayService)
}

// Forget 跑 docker compose run --rm --no-deps egress forget：在网关的网络命名空间里，出口规则丢掉钉住的每一个
// 地址，按现在的解析重新钉（pin-egress.sh 的 forget）。网关和 netns 要在跑；在跑着的网关不跟着变。
func (p *Pool) Forget(ctx context.Context) error {
	return p.compose(ctx, "run", "--rm", "--no-deps", EgressService, "forget")
}

// Declared 跑 docker compose config --services：给的这几个 compose 文件里有哪些服务（只算开着的 profile 里的）。
// 用的项目名、文件和变量文件与启动命令的相同。
func (p *Pool) Declared(ctx context.Context) ([]string, error) {
	bounded, cancel := context.WithTimeout(ctx, p.look)
	defer cancel()
	output, err := p.config.Docker(bounded, nil, append(p.composeArgv(), "config", "--services")...)
	if err != nil {
		return nil, fmt.Errorf("container: docker compose config --services: %w: %s", err, lastLine(output))
	}
	// 警告也在输出里：不是服务名的行不算。
	var names []string
	for _, line := range strings.Split(output, "\n") {
		if name := strings.TrimSpace(line); serviceName.MatchString(name) {
			names = append(names, name)
		}
	}
	return names, nil
}

// endpoint 是 docker inspect 报告的一个容器在一个网络上的那一端里用到的部分。
type endpoint struct {
	NetworkID string `json:"NetworkID"`
	IPAddress string `json:"IPAddress"`
}

// Services 看这个项目里这几个服务的每一个容器（ADR-0024）：在不在跑，在这个项目的网络上的 IPv4 地址。
// 别的项目的网络（比如 external 的那种）上的地址不算：网关只在项目的网络上按名字找它们。
func (p *Pool) Services(ctx context.Context, names []string) ([]domain.Service, error) {
	services := make([]domain.Service, len(names))
	index := map[string]int{}
	for i, name := range names {
		services[i].Name, index[name] = name, i
	}
	bounded, cancel := context.WithTimeout(ctx, p.look)
	defer cancel()
	ids, err := p.containers(bounded)
	if err != nil {
		return nil, err
	}
	if len(ids) == 0 {
		return services, nil // 这个项目一个容器都没有
	}
	output, err := p.config.Docker(bounded, nil, append([]string{"inspect", "-f", servicesFormat}, ids...)...)
	if err != nil {
		return nil, fmt.Errorf("container: docker inspect: %w: %s", err, lastLine(output))
	}
	networks, err := p.listed(bounded, "network ls", "network", "ls")
	if err != nil {
		return nil, err
	}
	ours := map[string]bool{}
	for _, network := range networks {
		ours[network] = true
	}
	answered := 0
	for _, line := range strings.Split(output, "\n") {
		if !strings.Contains(line, "\t") {
			continue // 警告之类
		}
		var (
			name, service, oneOff, status string
			running                       bool
			exitCode                      int
			attached                      map[string]endpoint
		)
		fields := strings.Split(strings.TrimRight(line, "\r"), "\t")
		targets := []any{&name, &service, &oneOff, &running, &status, &exitCode, &attached}
		if len(fields) != len(targets) {
			return nil, fmt.Errorf("container: docker inspect gave something unexpected: %s", line)
		}
		for i, target := range targets {
			if err := json.Unmarshal([]byte(fields[i]), target); err != nil {
				return nil, fmt.Errorf("container: docker inspect gave something unexpected: %s", line)
			}
		}
		answered++
		at, ok := index[service]
		if !ok || strings.EqualFold(oneOff, "true") {
			continue
		}
		replica := domain.Replica{Name: strings.TrimPrefix(name, "/"), Running: running, State: status}
		if !running && (status == "exited" || status == "dead") {
			replica.State = fmt.Sprintf("%s (%d)", status, exitCode)
		}
		for _, end := range attached {
			if address, err := netip.ParseAddr(end.IPAddress); err == nil && address.Is4() && ours[end.NetworkID] {
				replica.Addresses = append(replica.Addresses, address.String())
			}
		}
		sort.Strings(replica.Addresses)
		services[at].Replicas = append(services[at].Replicas, replica)
	}
	if answered != len(ids) {
		return nil, fmt.Errorf("container: docker inspect described %d of the %d containers of project %s", answered, len(ids), p.config.Project)
	}
	for i := range services {
		sort.Slice(services[i].Replicas, func(a, b int) bool { return services[i].Replicas[a].Name < services[i].Replicas[b].Name })
	}
	return services, nil
}

// composeArgv 是每条 docker compose 命令的开头：项目名，变量文件，compose 文件。
func (p *Pool) composeArgv() []string {
	argv := []string{"compose", "-p", p.config.Project}
	for _, path := range p.config.EnvFiles {
		argv = append(argv, "--env-file", path)
	}
	for _, path := range p.config.Files {
		argv = append(argv, "-f", path)
	}
	return argv
}

// compose 跑一条 docker compose 命令。命令一发出就不随 ctx 取消，只受 Timeout 限制。
func (p *Pool) compose(ctx context.Context, command ...string) error {
	bounded, cancel := context.WithTimeout(context.WithoutCancel(ctx), p.config.Timeout)
	defer cancel()
	output, err := p.config.Docker(bounded, nil, append(p.composeArgv(), command...)...)
	if err != nil {
		name := "docker compose " + strings.Join(command, " ")
		if errors.Is(bounded.Err(), context.DeadlineExceeded) {
			return fmt.Errorf("container: %s did not return within %s", name, p.config.Timeout)
		}
		return fmt.Errorf("container: %s: %w: %s", name, err, lastLine(output))
	}
	return nil
}
