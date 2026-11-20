// Command gateway-control 是控制面的命令行。现在它管的是单机上的一个池（docs/adr/ADR-0010.md 第 10 条）：
//
//	gateway-control publish   --snapshot <文件> --config-dir <池的配置目录> --read-back <host:port> …
//	gateway-control restart   [--snapshot <文件>] --container <网关容器> …   （其余参数与 publish 相同）
//	gateway-control reconcile --config-dir <池的配置目录> --read-back <host:port> …
//	gateway-control place     --config-dir <池的配置目录>
//	gateway-control keep      --config-dir <池的配置目录> --read-back <host:port> … [--compose-file <文件>]
//
// 另有三条命令不属于池，对着一个 gateway-authz 的撤销接口发一次请求（revoke.go，docs/adr/ADR-0012.md V1.2）：
//
//	gateway-control revoke      --account <账户> --reason <原因> --authz <host:port> --authz-name <名字> --tls-cert … --tls-key … --tls-ca …
//	gateway-control restore     --account <账户> --authz … （其余同上）
//	gateway-control revocations --authz … （其余同上）
//	gateway-control ban         --operation <operation_id> --reason <原因> --authz … （证书参数与 revoke 相同）
//	gateway-control unban       --operation <operation_id> --authz … （其余与 ban 相同，不要 --reason）
//
// 另有三条对着池的发布历史（history.go，docs/adr/ADR-0013.md）：
//
//	gateway-control releases --history-dir <目录> --pool <名字> --config-dir <池的配置目录>
//	gateway-control release  --history-dir <目录> --pool <名字> --id <编号>
//	gateway-control rollback --history-dir <目录> --pool <名字> --to <编号> [--with-restart] …   （其余同 publish、restart）
//
// 另有一条把身份提供者的 JWKS 同步到本机文件（jwks.go）：
//
//	gateway-control sync-jwks --url <JWKS 地址> --output <文件> [--once] …
//
// 另有一条把出站或入口编译规格编译成网关配置和策略 JSON，或只做 RouteIntent 预检（compile.go）：
//
//	gateway-control compile --spec <规格> --output-gateway <yaml> --output-policy <json> [--agentgateway <二进制>] [--lock-file <锁>] [--tls-dir <目录>]
//	gateway-control compile --preflight-only --intents <意图.json> [--provider-registry <登记表>]
//
// 另有一条把池里的网关镜像换成另一个摘要（reimage.go，ADR-0010 第 10 条「要重启网关的变更」）：
//
//	gateway-control reimage --image <repository>@sha256:<64 hex> --container <name> --config-dir <abs> --mount <container path> --compose-file <file> --compose-env-file <file> --service agentgateway --read-back <host:port> --read-back-name <name> --tls-cert --tls-key --tls-ca
//
// 它不改配置文件，也不改锁定的镜像。结局和退出码在 reimage.go 的开头。
//
// 它们的结局和退出码在 revoke.go、history.go、jwks.go、compile.go、reimage.go 的开头写着；下面说的退出码是前五条命令的，加上 rollback。
//
// publish 把一份网关配置发布到池里，网关不重启。restart 发布一份要重启网关才能全部生效的配置
// （启动设置变了的那种），会让这个池中断一下；不给 --snapshot 时，用的是这个池上最后一次得到确认的那一份。
// reconcile 对账：池和记录对不上时，把最后一次得到确认的那一份放回去。
// place 是网关启动之前做的：放在目录里的不是最后一次得到确认的那一份，就把那一份放回去。它不读网关。
//
// 记录是配置目录里的一个文件（.config.yaml.confirmed），由这个命令自己写：每次发布得到网关确认之后，
// 记下是哪一份（只记最后一条，是下发的依据）。发布过什么、谁发起的、每一步和结局，在发布历史里：
// publish、restart、reconcile、keep 给了 --history-dir 才记，不给就与没有历史时一字不差（ADR-0013）。
// 历史是先写后做：每一步动手之前先把它写进历史并落盘，写不进去就不做，退出码 1，池没有被碰过。放在那里的不是记录的那一份时，publish 和 restart 不动手（POOL_NOT_READY），先要 reconcile；
// 只有一种情况 publish 自己补得上：放在那里的正是要发布的这一份，网关也报告它在生效。
//
// 前四条命令做完就退出，要有人来叫。deploy/compose 在启动一个池时叫其中两条：网关启动之前 place，
// 网关起来之后 reconcile，对上了才开前置代理。
//
// keep 是常驻的：它守着这个池，直到被叫停。池里常驻的容器有没在跑的，它跑启动这个池的那条命令
// （docker compose up -d，所以仍然先 place、后 reconcile、对上了才开前置代理）；网关在跑时，它隔一阵
// 对一次账。另一次发布正占着这个池时它不动手。它每报告一次往标准输出写一行 JSON，格式见 tended。
// 要让这个池停着，先停它。
//
// 这些命令要以池的配置目录的属主的身份运行，别的账号占不了这个池。
//
// 前四条命令的结果以 JSON 写到标准输出；退出码说明池现在的状态：
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
//	8  ACTIVE_NOT_RECORDED（只在给了 --history-dir 时）：这份配置正在网关上生效，池的记录也记下了，
//	   只是历史里的 ACTIVE 那一行没有写进去；池没有问题。标准错误里说历史停在哪一步；再跑一次同样的 publish
//	   是安全的（它补全历史），reconcile 也会补。7 是撤销命令的
//
// 途中收到 SIGINT、SIGTERM 或 SIGHUP 时它不立刻退出：还没碰过池的，以退出码 1 结束；
// 已经换上文件的，先把上一份放回去，结局是 RESTORED 或 UNKNOWN。重启一旦开始就做完。
// 被强行杀掉时它来不及收拾，留下的由下一次 reconcile 或 place 收拾。
//
// keep 的退出码：收到这几个信号时把手上的那一步做完，以 0 结束；一开始就装不起来、占不了这个池时是 1；
// 命令行写得不对是 2。池出了什么事不在退出码里，在它写的那些行里。
//
// keep 把自己的环境原样交给它跑的 docker compose。给 docker compose 的变量文件（--compose-env-file，
// 不给时是当前目录里的 .env）里只能有 名字=值 这样的行，环境里同名的变量要与文件里的相同：不然这一次
// docker compose 拿到的设置会与启动这个池时的不同。不合要求时 keep 不启动，退出码也是 2。
//
// keep 有事才写一行，安稳的时候不出声。给了 --metrics-listen 时，它另在那个地址的 /metrics 上给出指标
// （Prometheus 的文本格式），每看完一眼更新一次：池现在的样子、对账的结局、上一眼是什么时候看完的。
// 告警靠的是这些数（deploy/compose 里有一份规则）。那个地址占不了时它不启动，退出码 1。
//
// 它不在请求路径上。RouteIntent 到网关配置的编译是单独的 compile 命令（compile.go），不在这几条发布命令里；
// 批准（要等 Fabric 的发布意图）还没有。发布的状态只记
// G03 状态机里发布器自己经手的那一段（STAGED 到 ACTIVE、FAILED、UNKNOWN），见 ADR-0013 第 2 条。
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"go.idp.xyz/idp-gateway/internal/gatewayconfig/adapters/container"
	"go.idp.xyz/idp-gateway/internal/gatewayconfig/adapters/directory"
	"go.idp.xyz/idp-gateway/internal/gatewayconfig/adapters/readback"
	"go.idp.xyz/idp-gateway/internal/gatewayconfig/adapters/scratch"
	"go.idp.xyz/idp-gateway/internal/gatewayconfig/adapters/telemetry"
	"go.idp.xyz/idp-gateway/internal/gatewayconfig/application"
	"go.idp.xyz/idp-gateway/internal/gatewayconfig/domain"
	"go.idp.xyz/idp-gateway/internal/gatewayconfig/ports"
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
	// exitActiveNotRecorded：池确实是 ACTIVE，历史里的 ACTIVE 那一行没有写进去（ADR-0013）。7 是撤销命令的。
	exitActiveNotRecorded = 8
)

const (
	commandPublish   = "publish"
	commandRestart   = "restart"
	commandReconcile = "reconcile"
	commandPlace     = "place"
	commandKeep      = "keep"
	// rollback 回到历史里的一份快照（history.go）：flag 与 publish、restart 同一套。
	commandRollback = "rollback"
	commandCompile  = "compile"
	commandReimage  = "reimage"
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
	known := map[string]bool{commandPublish: true, commandRestart: true, commandReconcile: true, commandPlace: true, commandKeep: true, commandRollback: true}
	if len(args) > 0 && isRevocationCommand(args[0]) {
		return runRevocation(ctx, args[0], args[1:], stdout, stderr)
	}
	if len(args) > 0 && isHistoryReadCommand(args[0]) {
		return runHistoryRead(ctx, args[0], args[1:], stdout, stderr)
	}
	if len(args) > 0 && isJWKSCommand(args[0]) {
		return runJWKS(ctx, args[1:], stdout, stderr)
	}
	if len(args) > 0 && args[0] == commandCompile {
		return runCompile(ctx, args[1:], stdout, stderr)
	}
	if len(args) > 0 && args[0] == commandReimage {
		return runReimage(ctx, args[1:], stdout, stderr, docker)
	}
	if len(args) == 0 || !known[args[0]] {
		fmt.Fprintln(stderr, "usage: gateway-control publish|restart|reconcile|place|keep [flags]   (gateway-control <command> --help lists them)")
		fmt.Fprintln(stderr, "       gateway-control reimage --image <repository>@sha256:<64 hex> --container <name> --config-dir <abs> --mount <container path> --compose-file <file> --compose-env-file <file> --service agentgateway --read-back <host:port> --read-back-name <name> --tls-cert --tls-key --tls-ca")
		fmt.Fprintln(stderr, "       gateway-control compile --spec <file> --output-gateway <file> --output-policy <file>")
		fmt.Fprintln(stderr, "       gateway-control compile --preflight-only --intents <file> [--provider-registry <file>]")
		fmt.Fprintln(stderr, "       gateway-control revoke|restore|revocations [flags]   (revoke or lift the revocation of a Provider account in gateway-authz, or read its table)")
		fmt.Fprintln(stderr, "       gateway-control ban|unban [flags]   (ban an operation for every account, or lift that ban)")
		fmt.Fprintln(stderr, "       gateway-control releases|release|rollback [flags]   (the release history of a pool: list it, show one release, roll back to one)")
		fmt.Fprintln(stderr, "       gateway-control sync-jwks [flags]   (copy a JWKS document from an identity provider to a local file and keep it fresh)")
		return exitUsage
	}
	o, err := parse(args[0], args[1:], stderr)
	if err != nil {
		if !errors.Is(err, flag.ErrHelp) {
			fmt.Fprintln(stderr, "gateway-control:", err)
		}
		return exitUsage
	}
	if o.command == commandKeep {
		return keep(ctx, o, stdout, stderr, docker)
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
	// 只有给了发布历史时才会有这两样；没有历史时标准错误上多不出一个字。
	if result.Outcome == application.OutcomeActiveNotRecorded {
		fmt.Fprintln(stderr, "gateway-control: ACTIVE_NOT_RECORDED:", result.Reason)
	}
	for _, warning := range result.Warnings {
		fmt.Fprintln(stderr, "gateway-control: history:", warning)
	}
	return exitCode(result.Outcome)
}

func exitCode(outcome application.Outcome) int {
	switch outcome {
	case application.OutcomeActive, application.OutcomeInSync, application.OutcomeInPlace, application.OutcomeNoRecord, application.OutcomeUnchanged:
		return exitActive
	case application.OutcomeRefused, application.OutcomeRestartRequired, application.OutcomePoolNotReady, application.OutcomeUnconfirmed:
		return exitNotDone
	case application.OutcomeRestored:
		return exitRestored
	case application.OutcomeRestartPending:
		return exitRestartPending
	case application.OutcomeActiveNotRecorded:
		return exitActiveNotRecorded
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
	// 看守用的：几个间隔，和启动这个池的那条 docker compose 命令怎么写
	pace            application.Pace
	composeProject  string
	composeFiles    list
	composeEnvFiles list
	composeTimeout  time.Duration
	// 看守在哪个地址上给出指标；空表示不给
	metricsListen string
	// 发布历史（ADR-0013）：历史目录；池的标识；操作员的备注（未经核实）。historyDir 为空表示没有历史。
	historyDir string
	poolName   string
	note       string
	// rollback：回到历史里的哪一条，要不要在需要时重启网关
	rollbackTo  uint64
	withRestart bool
}

// endpoint 是一个回读口和读它用的证书。
type endpoint struct {
	address, name, cert, key, ca string
}

// list 是一个可以给多次的参数。
type list []string

func (l *list) String() string { return strings.Join(*l, ",") }

func (l *list) Set(value string) error {
	*l = append(*l, value)
	return nil
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
	// 每条命令都要的：池的配置目录。
	text(&o.configDir, "config-dir", "池的配置目录：挂进网关容器的那个目录，里面的 "+scratch.ConfigFile+" 是网关读的文件", true)
	if command != commandPlace {
		// place 是网关启动之前做的，没有回读口可读；其余几条都要回读口和读它用的证书。
		text(&o.pool.address, "read-back", "池里网关的回读口，host:port", true)
		text(&o.pool.name, "read-back-name", "回读口证书上的名字", true)
		text(&o.pool.cert, "tls-cert", "发布器的证书（PEM）", true)
		text(&o.pool.key, "tls-key", "发布器的私钥（PEM）", true)
		text(&o.pool.ca, "tls-ca", "签发回读口证书的 CA（PEM）", true)
		flags.DurationVar(&o.timing.Settle, "settle", o.timing.Settle, "换上文件之后至少过这么久，读到的才算数")
		flags.DurationVar(&o.timing.Timeout, "timeout", o.timing.Timeout, "最多等网关这么久；到时没有生效就把上一份放回去")
	}
	if command == commandKeep {
		o.pace = application.DefaultPace()
		flags.DurationVar(&o.pace.Interval, "interval", o.pace.Interval, "隔多久看一眼池里常驻的容器")
		flags.DurationVar(&o.pace.Reconcile, "reconcile-interval", o.pace.Reconcile, "网关在跑时，隔多久对一次账")
		flags.DurationVar(&o.pace.MaxBackoff, "max-backoff", o.pace.MaxBackoff, "动了手却没修好时，两次动手之间最长隔多久")
		flags.StringVar(&o.composeProject, "compose-project", container.DefaultProject, "docker compose 的项目名：看容器、起容器都按它")
		flags.Var(&o.composeFiles, "compose-file", "compose 文件，可以给多次；不给时 docker compose 用当前目录里的 compose.yml")
		flags.Var(&o.composeEnvFiles, "compose-env-file", "给 docker compose 的变量文件，可以给多次；不给时它用当前目录里的 .env。文件里只能有 名字=值 这样的行")
		flags.DurationVar(&o.composeTimeout, "compose-timeout", 3*time.Minute, "启动命令、停止命令各自最多跑多久")
		flags.StringVar(&o.metricsListen, "metrics-listen", "", "在这个地址的 "+telemetry.Path+" 上给出指标（Prometheus 的文本格式），host:port；不给就不开")
	}
	staged := command == commandPublish || command == commandRestart || command == commandRollback
	if command != commandPlace {
		// 发布历史（ADR-0013）：不给 --history-dir 时命令与没有历史时完全相同。
		flags.StringVar(&o.historyDir, "history-dir", "", historyDirUsage(command))
		flags.StringVar(&o.poolName, "pool", "", "池的标识，写进历史里每一条；给了 --history-dir 就要给（字母、数字、点、下划线、连字符，最长 64 个字符）")
	}
	if staged {
		flags.StringVar(&o.note, "note", "", "操作员的备注，写进历史，不必填，最长 512 字节，不许有控制字符；没有人核实它，不要往里放秘密")
	}
	if staged {
		// 发布和重启要的：要发布的快照，和离线加载它用的东西。
		switch command {
		case commandPublish:
			text(&o.snapshot, "snapshot", "要发布的网关配置文件", true)
		case commandRestart:
			text(&o.snapshot, "snapshot", "要发布的网关配置文件；不给时用这个池上最后一次得到确认的那一份", false)
			text(&o.container, "container", "池里的网关容器的名字或 ID：要重启的就是它", true)
			flags.DurationVar(&o.stopTimeout, "stop-timeout", 0, "让 docker 等网关多久才杀掉它（整秒）；不设则用容器自己设的")
		default:
			// rollback：快照来自历史。要重启时才要网关容器。
			flags.Uint64Var(&o.rollbackTo, "to", 0, "回到历史里的这一条（编号）：它放上去的那份快照，必须到过 ACTIVE；走的是 publish 的全套检查，记成新的一条")
			flags.BoolVar(&o.withRestart, "with-restart", false, "快照的启动设置与网关启动时不同时重启网关（像 restart）；不给就是 RESTART_REQUIRED，什么都不做")
			text(&o.container, "container", "池里的网关容器的名字或 ID：--with-restart 时要重启的就是它", false)
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
	if command == commandRollback {
		if o.rollbackTo == 0 {
			missing = append(missing, "--to")
		}
		if o.historyDir == "" {
			missing = append(missing, "--history-dir")
		}
		if o.withRestart && o.container == "" {
			missing = append(missing, "--container")
		}
	}
	if len(missing) > 0 {
		return o, errors.New("missing required flags: " + strings.Join(missing, ", "))
	}
	if command != commandPlace {
		if err := checkHistoryFlags(flags, &o); err != nil {
			return o, err
		}
	}
	if command == commandKeep {
		switch {
		case o.pace.Interval <= 0 || o.pace.Reconcile <= 0:
			return o, errors.New("--interval and --reconcile-interval must be positive")
		case o.pace.MaxBackoff < o.pace.Interval:
			return o, errors.New("--max-backoff must not be shorter than --interval")
		case o.composeTimeout <= 0:
			return o, errors.New("--compose-timeout must be positive")
		}
		// 给了这个参数却是空的，多半是变量文件里漏了那一项：当成"不开"的话，告警就悄悄没有了。
		// 地址要写全：只写端口是在所有网卡上听，这些数没有设防。
		given := false
		flags.Visit(func(f *flag.Flag) { given = given || f.Name == "metrics-listen" })
		if given {
			if host, port, err := net.SplitHostPort(o.metricsListen); err != nil || host == "" || port == "" {
				return o, fmt.Errorf("--metrics-listen must be host:port, with the host written out; got %q", o.metricsListen)
			}
		}
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
	// 发布历史：打不开就到此为止，池没有被碰过。
	history, err := openHistoryFor(o)
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
	if history != nil {
		publisher.WithHistory(history, application.ReleaseMeta{Command: o.command, By: initiator(o), Note: o.note})
	}
	if o.command == commandPublish {
		return publisher.Publish(ctx, snapshot)
	}
	if o.command == commandRollback && !o.withRestart {
		return publisher.Rollback(ctx, o.rollbackTo, false)
	}
	gateway, err := container.New(container.Config{
		Name: o.container, ConfigDirectory: o.configDir, Mount: scratch.ConfigMount, StopTimeout: o.stopTimeout, Docker: docker,
	})
	if err != nil {
		return none, err
	}
	if o.command == commandRollback {
		return publisher.WithProcess(gateway).Rollback(ctx, o.rollbackTo, true)
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
	// 历史打不开不改变对账：照常对，在警告里说一句。
	history, note := openHistoryForTending(o)
	if history != nil && note == "" {
		reconciler.WithHistory(history)
	}
	result, err := reconciler.Reconcile(ctx)
	if note != "" && err == nil {
		result.Warnings = append([]string{note}, result.Warnings...)
	}
	return result, err
}

// place 在网关启动之前把记录的那一份放到位。它只碰配置目录。返回错误时什么都没做。
func place(ctx context.Context, o options) (application.Result, error) {
	delivery, err := directory.New(o.configDir, scratch.ConfigFile)
	if err != nil {
		return application.Result{}, err
	}
	return application.Place(ctx, delivery)
}

// keep 把各部分装起来，守着这个池，直到被叫停。每报告一次往标准输出写一行 JSON。
func keep(ctx context.Context, o options, stdout, stderr io.Writer, docker dockerRunner) int {
	fail := func(err error) int {
		fmt.Fprintln(stderr, "gateway-control:", err)
		return exitError
	}
	// 给 docker compose 的变量文件里有它和 systemd 读法不同的行时，再起一次也一样：与命令行写错了同样对待。
	if err := container.CheckEnvFiles(o.composeEnvFiles, os.LookupEnv); err != nil {
		if errors.Is(err, container.ErrEnvFile) {
			fmt.Fprintln(stderr, "gateway-control:", err)
			return exitUsage
		}
		return fail(err)
	}
	delivery, err := directory.New(o.configDir, scratch.ConfigFile)
	if err != nil {
		return fail(err)
	}
	pool, err := reader(o.pool)
	if err != nil {
		return fail(fmt.Errorf("read-back of the pool: %w", err))
	}
	project, err := container.NewPool(container.PoolConfig{
		Project: o.composeProject, Files: o.composeFiles, EnvFiles: o.composeEnvFiles, Timeout: o.composeTimeout, Docker: docker,
	})
	if err != nil {
		return fail(err)
	}
	keeper, err := application.NewKeeper(project, delivery, pool, o.timing, o.pace)
	if err != nil {
		return fail(err)
	}
	// 历史打不开不让看守停：照常看、照常对账、照常起容器，只是不补历史。开头说一次，之后补不成的话
	// 每一次对账的那一行里有 history_notes。
	history, note := openHistoryForTending(o)
	if history != nil {
		keeper.WithHistory(history)
	}
	if note != "" {
		fmt.Fprintln(stderr, "gateway-control: history:", note)
	}
	// 先试一下占不占得了这个池：账号不对、目录写不了，现在就说，不等到池出了事要动手的时候。
	// 正好有一次发布占着它不算。
	release, err := delivery.Hold(ctx)
	switch {
	case err == nil:
		release()
	case !errors.Is(err, ports.ErrBusy):
		return fail(err)
	}
	if o.metricsListen != "" {
		// 占不了这个地址就不启动：不然看守在跑，监控却读不到它，分不清是哪一种。
		listener, err := net.Listen("tcp", o.metricsListen)
		if err != nil {
			return fail(fmt.Errorf("metrics: %w", err))
		}
		metrics := telemetry.New(o.composeProject, o.pace, time.Now())
		server := &http.Server{
			Handler: metrics.Handler(), ReadHeaderTimeout: 5 * time.Second,
			ErrorLog: log.New(stderr, "gateway-control: metrics: ", 0),
		}
		go func() { _ = server.Serve(listener) }()
		defer server.Close()
		keeper.Watch(func(tending application.Tending) { metrics.Observe(tending, time.Now()) })
	}
	encoder := json.NewEncoder(stdout)
	keeper.Run(ctx, func(tending application.Tending) {
		if err := encoder.Encode(describe(tending, time.Now())); err != nil {
			fmt.Fprintln(stderr, "gateway-control:", err)
		}
	})
	return exitActive
}

// tended 是 keep 每报告一次写到标准输出的那一行 JSON。它有事才写：动过容器的，往回放过文件的，
// 以及池的样子或对账的结局与上一行不同的。
type tended struct {
	Time string `json:"time"`
	// Pool 是这一眼看到的三个常驻容器（动手之前的样子）；没看成时为 null。
	// Condition 是它们合起来的样子：whole 都在跑；down 有没在跑的；orphaned 网关或前置代理接着的
	// 是一个已经不在了的网络命名空间。Why 是依据，whole 时为空。
	Pool      *members `json:"pool"`
	Condition string   `json:"condition"`
	Why       string   `json:"why"`
	// Busy 为真：另一次发布正占着这个池，该做的这一次没有做。
	Busy bool `json:"busy"`
	// Action 是这一次对容器做了什么：空串是没有动；start 是跑了启动命令；stop+start 是先停下接错了
	// 命名空间的再跑启动命令；stop 是停的那一步没做成，没有接着启动。
	Action string `json:"action"`
	// StartError 是启动命令没有成功时它说的；成功或者没跑时为空。
	StartError string `json:"start_error"`
	// After 是动过手之后的三个容器；没有动手、或者之后没看成时为 null。Repaired 为真表示它们都好了。
	After    *members `json:"after"`
	Repaired bool     `json:"repaired"`
	// RetryInSeconds：动了手却没修好时，离下一次动手还有多久。
	RetryInSeconds float64 `json:"retry_in_seconds"`
	// Reconcile 是这一次对账的结果，与 reconcile 命令写的是同一种；这一次没有对账时为 null。
	Reconcile *outcome `json:"reconcile"`
	// Error：这一眼没看成，或者有一步没做成。
	Error string `json:"error"`
	// HistoryNotes 是对账时发布历史那一边要说的：补不成、读不成，或者没有补。没有给历史时没有这一项。
	HistoryNotes []string `json:"history_notes,omitempty"`
}

// members 的三个名字是 deploy/compose/compose.yml 里的服务名。
type members struct {
	Holder  member `json:"netns"`
	Gateway member `json:"agentgateway"`
	Front   member `json:"front"`
}

type member struct {
	Running bool `json:"running"`
	// State 是 docker 报告的状态，退出了的带着退出码；没有这个容器时为空。
	State string `json:"state"`
	// Started 是它这一次启动的时刻；从来没有启动过时为空。
	Started string `json:"started"`
}

func describe(tending application.Tending, now time.Time) tended {
	line := tended{
		Time: now.UTC().Format(time.RFC3339), Condition: string(tending.Condition), Why: tending.Why, Busy: tending.Busy,
		StartError: tending.StartErr, Repaired: tending.Repaired(), RetryInSeconds: tending.RetryIn.Seconds(),
	}
	if tending.Condition != "" {
		line.Pool = containers(tending.Members)
	}
	if tending.After != nil {
		line.After = containers(*tending.After)
	}
	switch {
	case tending.Stopped && tending.Started:
		line.Action = "stop+start"
	case tending.Started:
		line.Action = "start"
	case tending.Stopped:
		line.Action = "stop"
	}
	if tending.Reconciled != nil {
		reconciled := report(*tending.Reconciled)
		line.Reconcile = &reconciled
		line.HistoryNotes = tending.Reconciled.Warnings
	}
	if tending.Err != nil {
		line.Error = tending.Err.Error()
	}
	return line
}

func containers(seen domain.Members) *members {
	one := func(m domain.Member) member {
		described := member{Running: m.Running, State: m.State}
		if !m.Started.IsZero() {
			described.Started = m.Started.UTC().Format(time.RFC3339Nano)
		}
		return described
	}
	return &members{Holder: one(seen.Holder), Gateway: one(seen.Gateway), Front: one(seen.Front)}
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
	// Release 是这一次在发布历史里的编号；HistorySettled 是对账给哪几条没有结局的补了结局。
	// 没有给历史时两样都没有（不写出来，输出与没有历史时一字不差）。
	Release        uint64   `json:"release,omitempty"`
	HistorySettled []uint64 `json:"history_settled,omitempty"`
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
		ExpectedDigest: result.Expected, Restart: result.Restart, Release: result.Release, HistorySettled: result.Settled,
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
