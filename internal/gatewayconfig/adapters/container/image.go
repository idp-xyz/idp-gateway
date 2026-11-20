package container

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"go.idp.xyz/idp-gateway/internal/gatewayconfig/ports"
)

// composeTimeout 是 docker compose up --force-recreate 最多跑多久。
// 到时只杀掉 docker 命令行；已经重建的容器留着，由调用的人把原来的镜像引用写回去再重建一次。
const composeTimeout = 3 * time.Minute

// gatewayImageVariable 是 compose 文件里网关镜像的那个变量（deploy/compose/compose.yml）。
const gatewayImageVariable = "GATEWAY_IMAGE"

// ImageSwapConfig 说明换哪一个容器的镜像，以及 compose 怎么写。
type ImageSwapConfig struct {
	// Container 是网关容器的名字或 ID。ConfigDirectory 是池的配置目录，Mount 是它在容器里的位置。
	// 动手之前要核对这个容器挂的确实是这个目录。
	Container       string
	ConfigDirectory string
	Mount           string
	// ComposeFile 是 compose 文件（-f），EnvFile 是变量文件（--env-file）。
	// 变量文件里要已经有 GATEWAY_IMAGE，没有就不补。
	ComposeFile string
	EnvFile     string
	// Service 是要重建的那一个服务，部署文件里是 agentgateway。
	Service string
	// Docker 执行一条 docker 命令：env 盖过同名的环境变量，返回它的全部输出。零值用本机的 docker 命令行。
	Docker func(ctx context.Context, env []string, argv ...string) (string, error)
}

// ImageSwap 把一个池的网关镜像换成另一个摘要引用。
type ImageSwap struct {
	container string
	configDir string
	mount     string
	compose   string
	envFile   string
	service   string
	docker    func(ctx context.Context, env []string, argv ...string) (string, error)
}

// NewImageSwap 检查配置。它不在这里碰 docker，也不读变量文件。
func NewImageSwap(config ImageSwapConfig) (*ImageSwap, error) {
	if config.Container == "" || strings.ContainsAny(config.Container, " \t") || strings.HasPrefix(config.Container, "-") {
		return nil, fmt.Errorf("container: container name %q", config.Container)
	}
	if !filepath.IsAbs(config.ConfigDirectory) {
		return nil, fmt.Errorf("container: configuration directory %q must be given by its absolute path", config.ConfigDirectory)
	}
	if !strings.HasPrefix(config.Mount, "/") {
		return nil, fmt.Errorf("container: mount point %q is not an absolute path", config.Mount)
	}
	if config.ComposeFile == "" || strings.HasPrefix(config.ComposeFile, "-") {
		return nil, fmt.Errorf("container: compose file %q", config.ComposeFile)
	}
	if config.EnvFile == "" || strings.HasPrefix(config.EnvFile, "-") {
		return nil, fmt.Errorf("container: env file %q", config.EnvFile)
	}
	if config.Service == "" || strings.ContainsAny(config.Service, " \t") || strings.HasPrefix(config.Service, "-") {
		return nil, fmt.Errorf("container: service name %q", config.Service)
	}
	if config.Docker == nil {
		config.Docker = docker
	}
	return &ImageSwap{
		container: config.Container, configDir: config.ConfigDirectory, mount: config.Mount,
		compose: config.ComposeFile, envFile: config.EnvFile, service: config.Service, docker: config.Docker,
	}, nil
}

// configurationMounted 报告 mounts 里有没有把 hostDir 以 bind 挂在 destination。
// 没有，或者挂的是别的目录，返回的错误说明这不是这个池的网关容器。
func configurationMounted(mounts []mount, containerName, destination, hostDir string) error {
	var mounted []string
	for _, m := range mounts {
		if m.Destination != destination {
			continue
		}
		if m.Type == "bind" && sameDirectory(m.Source, hostDir) {
			return nil
		}
		mounted = append(mounted, m.Source)
	}
	if len(mounted) == 0 {
		return fmt.Errorf("container: %s has nothing mounted at %s: it is not the gateway of this pool", containerName, destination)
	}
	return fmt.Errorf("container: %s has %s mounted at %s, not the configuration directory of this pool (%s)",
		containerName, strings.Join(mounted, ", "), destination, hostDir)
}

// Current 读容器现在的镜像引用，并核对配置目录的挂载。对不上就返回错误，什么都不改。
// docker 的输出不写进错误：重建失败时那份输出里可能有仓库的令牌，这里同样不带出来。
func (s *ImageSwap) Current(ctx context.Context) (string, error) {
	output, err := s.docker(ctx, nil, "inspect", "-f", "{{json .Config.Image}} {{json .Mounts}}", s.container)
	if err != nil {
		return "", fmt.Errorf("container: docker inspect %s failed", s.container)
	}
	var reference string
	var mounts []mount
	decoder := json.NewDecoder(strings.NewReader(strings.TrimSpace(lastLine(output))))
	if decoder.Decode(&reference) != nil || decoder.Decode(&mounts) != nil || reference == "" {
		return "", fmt.Errorf("container: docker inspect %s gave something unexpected", s.container)
	}
	if err := configurationMounted(mounts, s.container, s.mount, s.configDir); err != nil {
		return "", err
	}
	return reference, nil
}

// PointAt 把 GATEWAY_IMAGE 改成 reference，再只重建这一个服务。
// 参数只有：compose -f <文件> --env-file <文件> up -d --no-deps --force-recreate <服务>。
func (s *ImageSwap) PointAt(ctx context.Context, reference string) error {
	if err := assignEnv(s.envFile, gatewayImageVariable, reference); err != nil {
		return err
	}
	// 文件已经是这一份。从这里起失败都算重建没有成功，好让调用的人把原来的引用写回去。
	// 不把 docker 的输出带回：里面可能有仓库的令牌。
	// docker compose 优先用进程环境里的同名变量，所以把刚写进文件的值传给这条命令，盖过继承来的旧值。
	// 参数只有这一串，不加 pull、down，也不带别的服务。
	bounded, cancel := context.WithTimeout(context.WithoutCancel(ctx), composeTimeout)
	defer cancel()
	_, err := s.docker(bounded, []string{gatewayImageVariable + "=" + reference},
		"compose", "-f", s.compose, "--env-file", s.envFile, "up", "-d", "--no-deps", "--force-recreate", s.service)
	if err != nil {
		return fmt.Errorf("%w", ports.ErrImageRecreate)
	}
	return nil
}

// assignEnv 把 path 里名叫 key 的赋值改成 value。别的行一个字节都不改。
// 文件里没有这个名字时拒绝，不在末尾补一行。写的时候先写同目录的临时文件，再改名。
func assignEnv(path, key, value string) error {
	if !envName.MatchString(key) || !plainValue(value) {
		return fmt.Errorf("container: env file %s: %s is not a plain NAME=value setting", path, key)
	}
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("container: env file: %w", err)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("container: env file: %w", err)
	}
	text := string(content)
	lines := strings.Split(text, "\n")
	found := false
	for i, line := range lines {
		if rest := strings.TrimLeft(line, " \t"); rest == "" || strings.HasPrefix(rest, "#") {
			continue
		}
		name, current, assigned := strings.Cut(line, "=")
		if !assigned || !envName.MatchString(name) || !plainValue(current) {
			return fmt.Errorf("%w %s, line %d: only NAME=value lines are accepted, with no whitespace, quotes, $, # or backslash in them",
				ErrEnvFile, path, i+1)
		}
		if name == key {
			lines[i] = name + "=" + value
			found = true
		}
	}
	if !found {
		return fmt.Errorf("container: env file %s: %s is not set", path, key)
	}
	rewritten := strings.Join(lines, "\n")
	if rewritten == text {
		return nil // 已经是这个值，不必再写一遍
	}
	return writeAtomically(path, []byte(rewritten), info.Mode().Perm())
}

// writeAtomically 在 path 所在的目录里写临时文件，落盘，再改名盖掉 path。
// 改名是原子的：读这个文件的人看到的要么是旧的整份，要么是新的整份。
func writeAtomically(path string, content []byte, mode fs.FileMode) error {
	dir := filepath.Dir(path)
	file, err := os.CreateTemp(dir, ".gateway-image-*")
	if err != nil {
		return fmt.Errorf("container: env file: %w", err)
	}
	temporary := file.Name()
	renamed := false
	defer func() {
		if !renamed {
			_ = os.Remove(temporary)
		}
	}()
	_, err = file.Write(content)
	if err == nil {
		err = file.Chmod(mode)
	}
	if err == nil {
		err = file.Sync()
	}
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return fmt.Errorf("container: env file: %w", err)
	}
	if err = os.Rename(temporary, path); err != nil {
		return fmt.Errorf("container: env file: %w", err)
	}
	renamed = true
	// 目录项落盘失败时，文件本身已经是改完的整份。不把这一步当成没写上。
	if directory, err := os.Open(dir); err == nil {
		_ = directory.Sync()
		_ = directory.Close()
	}
	return nil
}
