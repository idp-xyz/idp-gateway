// Command gateway-control 是控制面的命令行。现在它只会一件事：把一份网关配置发布到单机上的
// 一个池（docs/adr/ADR-0010.md 第 10 条）。
//
//	gateway-control publish --snapshot <文件> --config-dir <池的配置目录> --read-back <host:port> …
//
// 发布的结果以 JSON 写到标准输出；退出码说明池现在的状态：
//
//	0  ACTIVE：这份配置正在网关上生效
//	1  出了错，池没有被碰过（这时没有 JSON，原因在标准错误上）
//	2  命令行写得不对（缺参数、不认识的参数），什么都没做
//	3  没有发布，池没有被碰过（REFUSED、RESTART_REQUIRED、POOL_NOT_READY）
//	4  RESTORED：换上去了但没有生效，上一份已经放回去并得到确认
//	5  UNKNOWN：换上去了，没有生效，也没能确认放回去了；要对账
//
// 发布途中收到 SIGINT、SIGTERM 或 SIGHUP 时它不立刻退出：还没碰过池的，以退出码 1 结束；
// 已经换上文件的，先把上一份放回去，结局是 RESTORED 或 UNKNOWN。
//
// 它不在请求路径上。RouteIntent 到网关配置的编译、发布的状态和审批、对账都还没有。
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"go.idp.xyz/idp-gateway/internal/gatewayconfig/adapters/directory"
	"go.idp.xyz/idp-gateway/internal/gatewayconfig/adapters/readback"
	"go.idp.xyz/idp-gateway/internal/gatewayconfig/adapters/scratch"
	"go.idp.xyz/idp-gateway/internal/gatewayconfig/application"
	"go.idp.xyz/idp-gateway/internal/gatewayconfig/domain"
	"go.idp.xyz/idp-gateway/internal/platform/workloadtls"
)

const (
	exitActive       = 0
	exitError        = 1
	exitUsage        = 2
	exitNotPublished = 3
	exitRestored     = 4
	exitUnknown      = 5
)

// dockerRunner 是 scratch.Config.Docker 的类型；nil 表示用本机的 docker 命令行。
type dockerRunner = func(ctx context.Context, env []string, argv ...string) (string, error)

func main() {
	// 被叫停时不立刻退出：文件已经换上去的，Publish 先把上一份放回去再返回。终端断了（SIGHUP）也算，
	// 不然留在池里的就是一份没有确认过的文件。
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Stdout, os.Stderr, nil))
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer, docker dockerRunner) int {
	if len(args) == 0 || args[0] != "publish" {
		fmt.Fprintln(stderr, "usage: gateway-control publish [flags]   (gateway-control publish --help lists them)")
		return exitUsage
	}
	o, err := parse(args[1:], stderr)
	if err != nil {
		if !errors.Is(err, flag.ErrHelp) {
			fmt.Fprintln(stderr, "gateway-control:", err)
		}
		return exitUsage
	}
	result, err := publish(ctx, o, docker)
	if err != nil {
		fmt.Fprintln(stderr, "gateway-control:", err)
		return exitError
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(report(result)); err != nil {
		fmt.Fprintln(stderr, "gateway-control:", err)
	}
	return exitCode(result.Outcome)
}

func exitCode(outcome application.Outcome) int {
	switch outcome {
	case application.OutcomeActive:
		return exitActive
	case application.OutcomeRefused, application.OutcomeRestartRequired, application.OutcomePoolNotReady:
		return exitNotPublished
	case application.OutcomeRestored:
		return exitRestored
	default: // UNKNOWN，以及任何这里不认识的结局：不认识的不当成成功
		return exitUnknown
	}
}

type options struct {
	snapshot  string
	configDir string
	image     string
	pool      endpoint
	staging   endpoint
	// 离线加载用的临时容器
	stagingName    string
	stagingTLSDir  string
	stagingWorkDir string
	stagingPort    int
	stagingTimeout time.Duration
	timing         application.Timing
}

// endpoint 是一个回读口和读它用的证书。
type endpoint struct {
	address, name, cert, key, ca string
}

func parse(args []string, output io.Writer) (options, error) {
	o := options{timing: application.DefaultTiming()}
	flags := flag.NewFlagSet("gateway-control publish", flag.ContinueOnError)
	flags.SetOutput(output)
	required := map[string]*string{}
	text := func(target *string, name, usage string, mandatory bool) {
		flags.StringVar(target, name, "", usage)
		if mandatory {
			required[name] = target
		}
	}
	text(&o.snapshot, "snapshot", "要发布的网关配置文件", true)
	text(&o.configDir, "config-dir", "池的配置目录：挂进网关容器的那个目录，里面的 "+scratch.ConfigFile+" 是网关读的文件", true)
	text(&o.image, "image", "池里跑的网关镜像，按摘要引用（仓库@sha256:…）；离线加载用同一个", true)
	text(&o.pool.address, "read-back", "池里网关的回读口，host:port", true)
	text(&o.pool.name, "read-back-name", "回读口证书上的名字", true)
	text(&o.pool.cert, "tls-cert", "发布器的证书（PEM）", true)
	text(&o.pool.key, "tls-key", "发布器的私钥（PEM）", true)
	text(&o.pool.ca, "tls-ca", "签发回读口证书的 CA（PEM）", true)
	text(&o.staging.address, "staging-publish", "离线加载用的临时容器，回读口映射到本机的哪个回环地址，host:port", true)
	text(&o.stagingTLSDir, "staging-tls-dir", "挂进临时容器 "+scratch.TLSMount+" 的目录（绝对路径）", true)
	text(&o.stagingWorkDir, "staging-work-dir", "放候选配置的目录（绝对路径），docker 要能挂载它", true)
	text(&o.stagingName, "staging-name", "临时容器的名字", true)
	flags.IntVar(&o.stagingPort, "staging-container-port", 0, "回读口在容器里的端口（由配置里的回读监听决定）")
	text(&o.staging.name, "staging-read-back-name", "临时容器回读口证书上的名字；不设则与 --read-back-name 相同", false)
	text(&o.staging.cert, "staging-tls-cert", "读临时容器回读口用的证书；不设则与 --tls-cert 相同", false)
	text(&o.staging.key, "staging-tls-key", "读临时容器回读口用的私钥；不设则与 --tls-key 相同", false)
	text(&o.staging.ca, "staging-tls-ca", "签发临时容器回读口证书的 CA；不设则与 --tls-ca 相同", false)
	flags.DurationVar(&o.stagingTimeout, "staging-timeout", 20*time.Second, "最多等临时容器里的网关这么久")
	flags.DurationVar(&o.timing.Settle, "settle", o.timing.Settle, "换上文件之后至少过这么久，读到的才算数")
	flags.DurationVar(&o.timing.Timeout, "timeout", o.timing.Timeout, "最多等网关这么久；到时没有生效就把上一份放回去")
	if err := flags.Parse(args); err != nil {
		return o, err
	}
	if flags.NArg() > 0 {
		return o, fmt.Errorf("unexpected argument %q", flags.Arg(0))
	}
	var missing []string
	flags.VisitAll(func(f *flag.Flag) {
		if target, ok := required[f.Name]; ok && *target == "" {
			missing = append(missing, "--"+f.Name)
		}
	})
	if o.stagingPort == 0 {
		missing = append(missing, "--staging-container-port")
	}
	if len(missing) > 0 {
		return o, errors.New("missing required flags: " + strings.Join(missing, ", "))
	}
	if o.stagingTimeout <= 0 {
		return o, errors.New("--staging-timeout must be positive")
	}
	// 读临时容器的证书要么整套另给，要么整套沿用池的：混着用多半是写错了。
	own := 0
	for _, value := range []string{o.staging.cert, o.staging.key, o.staging.ca} {
		if value != "" {
			own++
		}
	}
	switch own {
	case 0:
		o.staging.cert, o.staging.key, o.staging.ca = o.pool.cert, o.pool.key, o.pool.ca
	case 3:
	default:
		return o, errors.New("--staging-tls-cert, --staging-tls-key and --staging-tls-ca go together")
	}
	if o.staging.name == "" {
		o.staging.name = o.pool.name
	}
	return o, nil
}

func reader(e endpoint) (*readback.Client, error) {
	config, err := workloadtls.ClientConfig(e.cert, e.key, e.ca, e.name)
	if err != nil {
		return nil, err
	}
	return readback.New(readback.Config{Address: e.address, TLS: config})
}

// publish 把各部分装起来，做一次发布。返回错误时池没有被碰过。
func publish(ctx context.Context, o options, docker dockerRunner) (application.Result, error) {
	content, err := os.ReadFile(o.snapshot)
	if err != nil {
		return application.Result{}, err
	}
	snapshot, err := domain.NewSnapshot(content)
	if err != nil {
		return application.Result{}, fmt.Errorf("%s: %w", o.snapshot, err)
	}
	delivery, err := directory.New(o.configDir, scratch.ConfigFile)
	if err != nil {
		return application.Result{}, err
	}
	pool, err := reader(o.pool)
	if err != nil {
		return application.Result{}, fmt.Errorf("read-back of the pool: %w", err)
	}
	candidate, err := reader(o.staging)
	if err != nil {
		return application.Result{}, fmt.Errorf("read-back of the scratch gateway: %w", err)
	}
	staging, err := scratch.New(scratch.Config{
		Image: o.image, Name: o.stagingName, TLSDirectory: o.stagingTLSDir, WorkDirectory: o.stagingWorkDir,
		Publish: o.staging.address, ContainerPort: o.stagingPort, ReadBack: candidate, Docker: docker,
		StartTimeout: o.stagingTimeout,
	})
	if err != nil {
		return application.Result{}, err
	}
	publisher, err := application.New(staging, delivery, pool, o.timing)
	if err != nil {
		return application.Result{}, err
	}
	return publisher.Publish(ctx, snapshot)
}

// outcome 是写到标准输出的那份 JSON。
type outcome struct {
	Outcome string `json:"outcome"`
	// Reason 说明为什么不是 ACTIVE；ACTIVE 时为空。
	Reason string `json:"reason"`
	// Snapshot 和 Previous 是要发布的和发布之前放在那里的文件的 SHA-256。
	Snapshot string `json:"snapshot"`
	Previous string `json:"previous"`
	// Replaced 为真表示这一次往池的配置目录里写过。
	Replaced bool `json:"replaced"`
	// ExpectedDigest 是离线加载得到的运行配置摘要；离线加载没有通过时为空。
	ExpectedDigest string `json:"expected_digest"`
	// Restart 在 RESTART_REQUIRED 时列出不同的启动设置。
	Restart []string `json:"restart"`
	// Observed 是最后一次从池里的网关读到的；一次都没读时为 null。
	Observed *observed `json:"observed"`
}

type observed struct {
	Digest       string `json:"digest"`
	Synchronized bool   `json:"synchronized"`
	LastError    string `json:"last_error"`
	StorageMode  string `json:"storage_mode"`
	Version      string `json:"version"`
	Revision     string `json:"revision"`
}

func report(result application.Result) outcome {
	o := outcome{
		Outcome: string(result.Outcome), Reason: result.Reason,
		Snapshot: result.Snapshot, Previous: result.Previous, Replaced: result.Replaced,
		ExpectedDigest: result.Expected, Restart: result.Restart,
	}
	if o.Restart == nil {
		o.Restart = []string{}
	}
	// 读到过的观察一定带着摘要。
	if seen := result.Observed; seen.Digest != "" {
		o.Observed = &observed{
			Digest: seen.Digest, Synchronized: seen.Synchronized, LastError: seen.LastError,
			StorageMode: seen.StorageMode, Version: seen.Version, Revision: seen.Revision,
		}
	}
	return o
}
