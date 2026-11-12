// Command gateway-control 是控制面的命令行。现在它管的是单机上的一个池（docs/adr/ADR-0010.md 第 10 条）：
//
//	gateway-control publish   --snapshot <文件> --config-dir <池的配置目录> --read-back <host:port> …
//	gateway-control restart   [--snapshot <文件>] --container <网关容器> …   （其余参数与 publish 相同）
//	gateway-control reconcile --config-dir <池的配置目录> --read-back <host:port> …
//	gateway-control place     --config-dir <池的配置目录>
//
// publish 把一份网关配置发布到池里，网关不重启。restart 发布一份要重启网关才能全部生效的配置
// （启动设置变了的那种），会让这个池中断一下；不给 --snapshot 时，用的是这个池上最后一次得到确认的那一份。
// reconcile 对账：池和记录对不上时，把最后一次得到确认的那一份放回去。
// place 是网关启动之前做的：放在目录里的不是最后一次得到确认的那一份，就把那一份放回去。它不读网关。
//
// 记录是配置目录里的一个文件（.config.yaml.confirmed），由这个命令自己写：每次发布得到网关确认之后，
// 记下是哪一份。放在那里的不是记录的那一份时，publish 和 restart 不动手（POOL_NOT_READY），先要 reconcile；
// 只有一种情况 publish 自己补得上：放在那里的正是要发布的这一份，网关也报告它在生效。
//
// 这个命令不是常驻的服务，四条命令都要有人来叫。deploy/compose 在启动一个池时叫其中两条：网关启动之前
// place，网关起来之后 reconcile，对上了才开前置代理。发布器被强行杀掉而池没有重新启动时，仍要有人或者
// 定时任务来跑 reconcile。
//
// 结果以 JSON 写到标准输出；退出码说明池现在的状态：
//
//	0  ACTIVE：这份配置正在网关上生效。IN_SYNC：池就是记录的样子，什么都没有写。
//	   place 的两个结局：IN_PLACE，记录的那一份放在目录里了；NO_RECORD，还没有确认过任何发布，
//	   什么都没有写。两个都表示网关可以启动
//	1  出了错，池没有被碰过（这时没有 JSON，原因在标准错误上）
//	2  命令行写得不对（缺参数、不认识的参数），什么都没做
//	3  什么都没有做，池没有被碰过（REFUSED、RESTART_REQUIRED、POOL_NOT_READY、UNCONFIRMED）
//	4  RESTORED：换上去了但没有生效，上一份已经放回去并得到确认。对账时：记录的那一份已经放回去并得到确认
//	5  UNKNOWN：换上去了，没有生效，也没能确认放回去了；要对账。对账时：没能确认网关在跑记录的那一份。
//	   place 时：记录的那一份没能放回去，不该启动网关
//	6  RESTART_PENDING：文件和运行配置都对得上，但网关的启动设置不是确认那份配置时的那一套；要重启
//
// 途中收到 SIGINT、SIGTERM 或 SIGHUP 时它不立刻退出：还没碰过池的，以退出码 1 结束；
// 已经换上文件的，先把上一份放回去，结局是 RESTORED 或 UNKNOWN。重启一旦开始就做完。
// 被强行杀掉时它来不及收拾，留下的由下一次 reconcile 或 place 收拾。
//
// 它不在请求路径上。RouteIntent 到网关配置的编译、发布的状态和审批都还没有。
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

	"go.idp.xyz/idp-gateway/internal/gatewayconfig/adapters/container"
	"go.idp.xyz/idp-gateway/internal/gatewayconfig/adapters/directory"
	"go.idp.xyz/idp-gateway/internal/gatewayconfig/adapters/readback"
	"go.idp.xyz/idp-gateway/internal/gatewayconfig/adapters/scratch"
	"go.idp.xyz/idp-gateway/internal/gatewayconfig/application"
	"go.idp.xyz/idp-gateway/internal/gatewayconfig/domain"
	"go.idp.xyz/idp-gateway/internal/platform/workloadtls"
)

const (
	exitActive         = 0
	exitError          = 1
	exitUsage          = 2
	exitNotDone        = 3
	exitRestored       = 4
	exitUnknown        = 5
	exitRestartPending = 6
)

const (
	commandPublish   = "publish"
	commandRestart   = "restart"
	commandReconcile = "reconcile"
	commandPlace     = "place"
)

// dockerRunner 是 scratch.Config.Docker 的类型；nil 表示用本机的 docker 命令行。
type dockerRunner = func(ctx context.Context, env []string, argv ...string) (string, error)

func main() {
	// 被叫停时不立刻退出：文件已经换上去的，先把上一份放回去再返回。终端断了（SIGHUP）也算，
	// 不然留在池里的就是一份没有确认过的文件。
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Stdout, os.Stderr, nil))
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer, docker dockerRunner) int {
	known := map[string]bool{commandPublish: true, commandRestart: true, commandReconcile: true, commandPlace: true}
	if len(args) == 0 || !known[args[0]] {
		fmt.Fprintln(stderr, "usage: gateway-control publish|restart|reconcile|place [flags]   (gateway-control <command> --help lists them)")
		return exitUsage
	}
	o, err := parse(args[0], args[1:], stderr)
	if err != nil {
		if !errors.Is(err, flag.ErrHelp) {
			fmt.Fprintln(stderr, "gateway-control:", err)
		}
		return exitUsage
	}
	var result application.Result
	switch o.command {
	case commandPlace:
		result, err = place(ctx, o)
	case commandReconcile:
		result, err = reconcile(ctx, o)
	default:
		result, err = publish(ctx, o, docker)
	}
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
	case application.OutcomeActive, application.OutcomeInSync, application.OutcomeInPlace, application.OutcomeNoRecord:
		return exitActive
	case application.OutcomeRefused, application.OutcomeRestartRequired, application.OutcomePoolNotReady, application.OutcomeUnconfirmed:
		return exitNotDone
	case application.OutcomeRestored:
		return exitRestored
	case application.OutcomeRestartPending:
		return exitRestartPending
	default: // UNKNOWN，以及任何这里不认识的结局：不认识的不当成成功
		return exitUnknown
	}
}

type options struct {
	command   string
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
	// 重启用的：池里的网关容器
	container   string
	stopTimeout time.Duration
}

// endpoint 是一个回读口和读它用的证书。
type endpoint struct {
	address, name, cert, key, ca string
}

func parse(command string, args []string, output io.Writer) (options, error) {
	o := options{command: command, timing: application.DefaultTiming()}
	flags := flag.NewFlagSet("gateway-control "+command, flag.ContinueOnError)
	flags.SetOutput(output)
	required := map[string]*string{}
	text := func(target *string, name, usage string, mandatory bool) {
		flags.StringVar(target, name, "", usage)
		if mandatory {
			required[name] = target
		}
	}
	// 四条命令都要的：池的配置目录。
	text(&o.configDir, "config-dir", "池的配置目录：挂进网关容器的那个目录，里面的 "+scratch.ConfigFile+" 是网关读的文件", true)
	if command != commandPlace {
		// place 是网关启动之前做的，没有回读口可读；其余三条都要回读口和读它用的证书。
		text(&o.pool.address, "read-back", "池里网关的回读口，host:port", true)
		text(&o.pool.name, "read-back-name", "回读口证书上的名字", true)
		text(&o.pool.cert, "tls-cert", "发布器的证书（PEM）", true)
		text(&o.pool.key, "tls-key", "发布器的私钥（PEM）", true)
		text(&o.pool.ca, "tls-ca", "签发回读口证书的 CA（PEM）", true)
		flags.DurationVar(&o.timing.Settle, "settle", o.timing.Settle, "换上文件之后至少过这么久，读到的才算数")
		flags.DurationVar(&o.timing.Timeout, "timeout", o.timing.Timeout, "最多等网关这么久；到时没有生效就把上一份放回去")
	}
	staged := command == commandPublish || command == commandRestart
	if staged {
		// 发布和重启要的：要发布的快照，和离线加载它用的东西。
		if command == commandPublish {
			text(&o.snapshot, "snapshot", "要发布的网关配置文件", true)
		} else {
			text(&o.snapshot, "snapshot", "要发布的网关配置文件；不给时用这个池上最后一次得到确认的那一份", false)
			text(&o.container, "container", "池里的网关容器的名字或 ID：要重启的就是它", true)
			flags.DurationVar(&o.stopTimeout, "stop-timeout", 0, "让 docker 等网关多久才杀掉它（整秒）；不设则用容器自己设的")
		}
		text(&o.image, "image", "池里跑的网关镜像，按摘要引用（仓库@sha256:…）；离线加载用同一个", true)
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
	}
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
	if staged && o.stagingPort == 0 {
		missing = append(missing, "--staging-container-port")
	}
	if len(missing) > 0 {
		return o, errors.New("missing required flags: " + strings.Join(missing, ", "))
	}
	if !staged {
		return o, nil
	}
	if o.stagingTimeout <= 0 {
		return o, errors.New("--staging-timeout must be positive")
	}
	if o.stopTimeout < 0 || o.stopTimeout%time.Second != 0 {
		return o, errors.New("--stop-timeout must be a whole number of seconds")
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

// publish 把各部分装起来，做一次发布（publish）或一次带重启的发布（restart）。返回错误时池没有被碰过。
func publish(ctx context.Context, o options, docker dockerRunner) (application.Result, error) {
	none := application.Result{}
	delivery, err := directory.New(o.configDir, scratch.ConfigFile)
	if err != nil {
		return none, err
	}
	// 只有 restart 可以不给快照：那时用的是记录里的那一份，由发布器占着池之后去读。
	var snapshot domain.Snapshot
	if o.snapshot != "" {
		content, err := os.ReadFile(o.snapshot)
		if err != nil {
			return none, err
		}
		if snapshot, err = domain.NewSnapshot(content); err != nil {
			return none, fmt.Errorf("%s: %w", o.snapshot, err)
		}
	}
	pool, err := reader(o.pool)
	if err != nil {
		return none, fmt.Errorf("read-back of the pool: %w", err)
	}
	candidate, err := reader(o.staging)
	if err != nil {
		return none, fmt.Errorf("read-back of the scratch gateway: %w", err)
	}
	staging, err := scratch.New(scratch.Config{
		Image: o.image, Name: o.stagingName, TLSDirectory: o.stagingTLSDir, WorkDirectory: o.stagingWorkDir,
		Publish: o.staging.address, ContainerPort: o.stagingPort, ReadBack: candidate, Docker: docker,
		StartTimeout: o.stagingTimeout,
	})
	if err != nil {
		return none, err
	}
	publisher, err := application.New(staging, delivery, pool, o.timing)
	if err != nil {
		return none, err
	}
	if o.command != commandRestart {
		return publisher.Publish(ctx, snapshot)
	}
	gateway, err := container.New(container.Config{
		Name: o.container, ConfigDirectory: o.configDir, Mount: scratch.ConfigMount, StopTimeout: o.stopTimeout, Docker: docker,
	})
	if err != nil {
		return none, err
	}
	if o.snapshot != "" {
		return publisher.WithProcess(gateway).Restart(ctx, snapshot)
	}
	result, err := publisher.WithProcess(gateway).RestartConfirmed(ctx)
	if errors.Is(err, application.ErrNothingConfirmed) {
		err = fmt.Errorf("no --snapshot was given: %w", err)
	}
	return result, err
}

// reconcile 把各部分装起来，对一次账。返回错误时什么都没做。
func reconcile(ctx context.Context, o options) (application.Result, error) {
	none := application.Result{}
	delivery, err := directory.New(o.configDir, scratch.ConfigFile)
	if err != nil {
		return none, err
	}
	pool, err := reader(o.pool)
	if err != nil {
		return none, fmt.Errorf("read-back of the pool: %w", err)
	}
	reconciler, err := application.NewReconciler(delivery, pool, o.timing)
	if err != nil {
		return none, err
	}
	return reconciler.Reconcile(ctx)
}

// place 在网关启动之前把记录的那一份放到位。它只碰配置目录。返回错误时什么都没做。
func place(ctx context.Context, o options) (application.Result, error) {
	delivery, err := directory.New(o.configDir, scratch.ConfigFile)
	if err != nil {
		return application.Result{}, err
	}
	return application.Place(ctx, delivery)
}

// outcome 是写到标准输出的那份 JSON。
type outcome struct {
	Outcome string `json:"outcome"`
	// Reason 说明为什么不是 ACTIVE（对账时：为什么不是 IN_SYNC）；是的时候为空。
	// place 时说明为什么要往回放，或者为什么没有可放的；本来就在那里时为空。
	Reason string `json:"reason"`
	// Snapshot 是要发布的那个文件的 SHA-256（对账和 place 时是记录里确认过的那一份，没有记录时为空）；
	// Previous 是动手之前放在那里的。
	Snapshot string `json:"snapshot"`
	Previous string `json:"previous"`
	// Replaced 为真表示这一次往池的配置目录里写过配置；Restarted 为真表示这一次重启过网关。
	Replaced  bool `json:"replaced"`
	Restarted bool `json:"restarted"`
	// ExpectedDigest 是期望的运行配置摘要：来自离线加载（没有通过时为空），对账和 place 时来自记录。
	ExpectedDigest string `json:"expected_digest"`
	// Restart 列出不同的启动设置：RESTART_REQUIRED、RESTART_PENDING，以及 restart 要改的那几项。
	Restart []string `json:"restart"`
	// Observed 是最后一次从池里的网关读到的；一次都没读到时为 null。place 不读网关，总是 null。
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
		Snapshot: result.Snapshot, Previous: result.Previous, Replaced: result.Replaced, Restarted: result.Restarted,
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
