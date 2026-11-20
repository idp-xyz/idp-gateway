package main

// reimage 把一个池的网关镜像换成另一个摘要引用。它是重启那一类操作，不是一次普通发布
// （docs/adr/ADR-0010.md 第 10 条「要重启网关的变更」）。配置文件不动，发布器的证书也不换。
//
//	gateway-control reimage --image <repository>@sha256:<64 hex> --container <name> --config-dir <abs> --mount <container path> --compose-file <file> --compose-env-file <file> --service agentgateway --read-back <host:port> --read-back-name <name> --tls-cert --tls-key --tls-ca
//
// 先看容器现在的镜像，并核对它把 --config-dir 挂在 --mount。不是这个池的容器就拒绝，什么都不改。
// 已经是要换成的那个摘要：UNCHANGED，不重建。否则只改变量文件里已有的 GATEWAY_IMAGE，
// 再执行 docker compose -f <文件> --env-file <文件> up -d --no-deps --force-recreate <服务>。
// 回读口看到网关起来才算换成了；摘要不必变化，因为配置文件没有变。
// 重建或回读没有成，把原来的 GATEWAY_IMAGE 写回去再重建一次。
//
// 标准输出一行 JSON：outcome、previous（动手之前 inspect 返回的镜像引用）、image（调用者给的那一个）。
// 不打印 docker 的原始输出，里面可能有仓库的令牌。
//
// 退出码：
//
//	0  ACTIVE：新镜像起来了。UNCHANGED：容器已经在跑这个摘要
//	1  还没有改变量文件（参数所指的容器不对、文件里没有 GATEWAY_IMAGE、镜像不是按摘要引用）。原因在标准错误上，没有 JSON
//	2  命令行写得不对
//	4  RESTORED：没有换成，原来的镜像引用已经写回去并重建
//	5  UNKNOWN：没有换成，把原来的引用写回去再重建也没有成

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"time"

	"go.idp.xyz/idp-gateway/internal/gatewayconfig/adapters/container"
	"go.idp.xyz/idp-gateway/internal/gatewayconfig/application"
	"go.idp.xyz/idp-gateway/internal/gatewayconfig/domain"
)

// reimageLine 是标准输出上的那一行 JSON。
type reimageLine struct {
	Outcome  string `json:"outcome"`
	Previous string `json:"previous"`
	Image    string `json:"image"`
}

func runReimage(ctx context.Context, args []string, stdout, stderr io.Writer, docker dockerRunner) int {
	image, swap, timing, pool, err := parseReimage(args, stderr)
	if err != nil {
		if !errors.Is(err, flag.ErrHelp) {
			fmt.Fprintln(stderr, "gateway-control:", err)
		}
		return exitUsage
	}
	swap.Docker = docker
	// 按标签引用的在这里就挡住，还不碰 docker。与离线加载用的是同一条规则。
	if err := domain.ImageReference(image); err != nil {
		fmt.Fprintln(stderr, "gateway-control:", err)
		return exitError
	}
	reader, err := reader(pool)
	if err != nil {
		fmt.Fprintln(stderr, "gateway-control:", err)
		return exitError
	}
	images, err := container.NewImageSwap(swap)
	if err != nil {
		fmt.Fprintln(stderr, "gateway-control:", err)
		return exitError
	}
	reimager, err := application.NewReimager(images, reader, timing)
	if err != nil {
		fmt.Fprintln(stderr, "gateway-control:", err)
		return exitError
	}
	result, err := reimager.Reimage(ctx, image)
	if err != nil {
		fmt.Fprintln(stderr, "gateway-control:", err)
		return exitError
	}
	if err := json.NewEncoder(stdout).Encode(reimageLine{
		Outcome: string(result.Outcome), Previous: result.Previous, Image: result.Image,
	}); err != nil {
		fmt.Fprintln(stderr, "gateway-control:", err)
		return exitError
	}
	return reimageExit(result.Outcome)
}

func reimageExit(outcome application.Outcome) int {
	switch outcome {
	case application.OutcomeActive, application.OutcomeUnchanged:
		return exitActive
	case application.OutcomeRestored:
		return exitRestored
	default:
		return exitUnknown
	}
}

func parseReimage(args []string, output io.Writer) (string, container.ImageSwapConfig, application.Timing, endpoint, error) {
	var (
		image   string
		swap    container.ImageSwapConfig
		pool    endpoint
		timing  = application.DefaultTiming()
		settle  time.Duration
		timeout time.Duration
	)
	flags := flag.NewFlagSet("gateway-control reimage", flag.ContinueOnError)
	flags.SetOutput(output)
	flags.StringVar(&image, "image", "", "要换成的网关镜像，按摘要引用（仓库@sha256: 加 64 位小写十六进制）；按标签引用的拒绝")
	flags.StringVar(&swap.Container, "container", "", "池里的网关容器的名字或 ID")
	flags.StringVar(&swap.ConfigDirectory, "config-dir", "", "池的配置目录，绝对路径：要核对容器挂的就是它")
	flags.StringVar(&swap.Mount, "mount", "", "这个目录在容器里的挂载点，绝对路径")
	flags.StringVar(&swap.ComposeFile, "compose-file", "", "compose 文件")
	flags.StringVar(&swap.EnvFile, "compose-env-file", "", "给 docker compose 的变量文件，里面要已经有 GATEWAY_IMAGE=值；只改这一项")
	flags.StringVar(&swap.Service, "service", "", "要重建的服务，部署文件里的网关是 agentgateway")
	flags.StringVar(&pool.address, "read-back", "", "池里网关的回读口，host:port")
	flags.StringVar(&pool.name, "read-back-name", "", "回读口证书上的名字")
	flags.StringVar(&pool.cert, "tls-cert", "", "发布器的证书（PEM）")
	flags.StringVar(&pool.key, "tls-key", "", "发布器的私钥（PEM）")
	flags.StringVar(&pool.ca, "tls-ca", "", "签发回读口证书的 CA（PEM）")
	flags.DurationVar(&settle, "settle", timing.Settle, "重建之后至少过这么久，读到网关起来了才算数")
	flags.DurationVar(&timeout, "timeout", timing.Timeout, "最多等网关这么久；到时没有起来就把原来的镜像引用写回去再重建一次")
	if err := flags.Parse(args); err != nil {
		return "", swap, timing, pool, err
	}
	if flags.NArg() > 0 {
		return "", swap, timing, pool, fmt.Errorf("unexpected argument %q", flags.Arg(0))
	}
	required := map[string]*string{
		"image": &image, "container": &swap.Container, "config-dir": &swap.ConfigDirectory,
		"mount": &swap.Mount, "compose-file": &swap.ComposeFile, "compose-env-file": &swap.EnvFile,
		"service": &swap.Service, "read-back": &pool.address, "read-back-name": &pool.name,
		"tls-cert": &pool.cert, "tls-key": &pool.key, "tls-ca": &pool.ca,
	}
	var missing []string
	flags.VisitAll(func(f *flag.Flag) {
		if target, ok := required[f.Name]; ok && *target == "" {
			missing = append(missing, "--"+f.Name)
		}
	})
	if len(missing) > 0 {
		return "", swap, timing, pool, errors.New("missing required flags: " + strings.Join(missing, ", "))
	}
	if !filepath.IsAbs(swap.ConfigDirectory) {
		return "", swap, timing, pool, fmt.Errorf("--config-dir must be an absolute path, got %q", swap.ConfigDirectory)
	}
	timing.Settle, timing.Timeout = settle, timeout
	return image, swap, timing, pool, nil
}
