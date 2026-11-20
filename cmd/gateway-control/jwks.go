package main

// sync-jwks 把身份提供者的 JWKS 同步到本机的一个文件。网关读的是这个文件，不是那个 URL：
// 锁定的 agentgateway 1.7.0 在文件被原子替换之后会自己重新加载密钥，而按 URL 去取时遇到不认识的
// kid 不会立刻重取。取失败时，上一次成功的密钥只在 --max-stale 之内继续使用；给了 --empty-on-stale
// 就在超过之后把文件写成空密钥集，验证就此失败关闭。
//
//	gateway-control sync-jwks --url <地址> --output <文件> [--once] [--interval 15s]
//	    [--timeout 3s] [--max-stale 15m] [--empty-on-stale] [--mode 0644]
//	    [--plain-http-host <主机名>] [--tls-ca <文件>] [--tls-cert <文件>] [--tls-key <文件>]
//	    [--metrics-listen <host:port>]
//
// --once 只做一轮，往标准输出写一行 JSON，然后退出。常驻时启动就做一轮，之后按 --interval 重复；
// 只在状态变化时写一行（更新了、取失败了、过期了、从失败里恢复了），安稳的时候不出声，和 keep 一样。
// 收到 SIGINT、SIGTERM 或 SIGHUP（main 里已经挂上了这三个）时，进行中的这一轮结束之后以 0 退出。
//
// 结局和退出码：
//
//	0  UPDATED：写了一份新的密钥集。UNCHANGED：和文件里的是同一套密钥，没有重写
//	1  FETCH_FAILED：没取到，或取到的不是合格的公钥集；期限之内原来的文件不动。
//	   STALE_EXPIRED：失败而且已经超过 --max-stale。给了 --empty-on-stale 时文件被写成 {"keys":[]}
//	   （cleared 为 true）。常驻模式下这些写在输出的行里，进程继续；--once 时以 1 退出
//	2  命令行写得不对，什么都没做
//
// 还没有写出 JSON 就失败（证书文件读不了、--metrics-listen 绑不上）也是 1，原因在标准错误上。
//
// 启动时如果 --output 已经是一份合格的密钥集，把它的摘要当作当前摘要，并把“上次成功”记成启动时刻：
// 进程刚起来的这一段也算在 --max-stale 里。不读文件的修改时间，存储端口不提供。

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"go.idp.xyz/idp-gateway/internal/jwkssync/adapters/filestore"
	"go.idp.xyz/idp-gateway/internal/jwkssync/adapters/httpfetch"
	jwksmetrics "go.idp.xyz/idp-gateway/internal/jwkssync/adapters/metrics"
	"go.idp.xyz/idp-gateway/internal/jwkssync/application"
)

const commandSyncJWKS = "sync-jwks"

func isJWKSCommand(command string) bool { return command == commandSyncJWKS }

type jwksOptions struct {
	url           string
	output        string
	once          bool
	interval      time.Duration
	timeout       time.Duration
	maxStale      time.Duration
	emptyOnStale  bool
	mode          fs.FileMode
	plainHTTPHost string
	tlsCA         string
	tlsCert       string
	tlsKey        string
	metricsListen string
}

func parseJWKS(args []string, output io.Writer) (jwksOptions, error) {
	var o jwksOptions
	var modeText string
	flags := flag.NewFlagSet("gateway-control "+commandSyncJWKS, flag.ContinueOnError)
	flags.SetOutput(output)
	flags.StringVar(&o.url, "url", "", "身份提供者的 JWKS 地址")
	flags.StringVar(&o.output, "output", "", "写到本机的这个文件")
	flags.BoolVar(&o.once, "once", false, "只同步一轮，写一行 JSON 后退出")
	flags.DurationVar(&o.interval, "interval", 15*time.Second, "常驻时两轮之间隔多久，必须大于 0")
	flags.DurationVar(&o.timeout, "timeout", 3*time.Second, "一次取回最多等多久，必须大于 0")
	flags.DurationVar(&o.maxStale, "max-stale", 15*time.Minute, "取失败时沿用上一次成功密钥的最长时间；0 表示不因过期作废")
	flags.BoolVar(&o.emptyOnStale, "empty-on-stale", false, "超过 --max-stale 时把文件写成空密钥集")
	flags.StringVar(&modeText, "mode", "0644", "文件权限，0600 或 0644")
	flags.StringVar(&o.plainHTTPHost, "plain-http-host", "", "唯一允许明文 http 的裸主机名；空表示只有回环地址可以用明文")
	flags.StringVar(&o.tlsCA, "tls-ca", "", "信任的 CA（PEM）；给出之后不再使用系统根证书")
	flags.StringVar(&o.tlsCert, "tls-cert", "", "访问身份提供者时出示的客户端证书（PEM），要和 --tls-key 一起给")
	flags.StringVar(&o.tlsKey, "tls-key", "", "客户端证书的私钥（PEM），要和 --tls-cert 一起给")
	flags.StringVar(&o.metricsListen, "metrics-listen", "", "常驻时在这个地址的 "+jwksmetrics.Path+" 上给出指标，host:port；不给就不开")
	flags.Usage = func() {
		fmt.Fprintf(output, "Usage of gateway-control %s:\n", commandSyncJWKS)
		flags.PrintDefaults()
		fmt.Fprint(output, jwksOutcomesHelp)
	}
	if err := flags.Parse(args); err != nil {
		return o, err
	}
	if flags.NArg() > 0 {
		return o, fmt.Errorf("unexpected argument %q", flags.Arg(0))
	}
	var missing []string
	if o.url == "" {
		missing = append(missing, "--url")
	}
	if o.output == "" {
		missing = append(missing, "--output")
	}
	if len(missing) > 0 {
		return o, errors.New("missing required flags: " + strings.Join(missing, ", "))
	}
	switch {
	case o.interval <= 0:
		return o, errors.New("--interval must be positive")
	case o.timeout <= 0:
		return o, errors.New("--timeout must be positive")
	case o.maxStale < 0:
		return o, errors.New("--max-stale must not be negative")
	}
	mode, err := jwksMode(modeText)
	if err != nil {
		return o, err
	}
	o.mode = mode
	if (o.tlsCert == "") != (o.tlsKey == "") {
		return o, errors.New("--tls-cert and --tls-key must be set together")
	}
	if _, err := httpfetch.ParseURL(o.url, o.plainHTTPHost); err != nil {
		return o, err
	}
	metricsGiven := false
	flags.Visit(func(f *flag.Flag) {
		metricsGiven = metricsGiven || f.Name == "metrics-listen"
	})
	if metricsGiven && o.once {
		return o, errors.New("--metrics-listen is not used with --once")
	}
	if metricsGiven {
		if host, port, err := net.SplitHostPort(o.metricsListen); err != nil || host == "" || port == "" {
			return o, fmt.Errorf("--metrics-listen must be host:port, with the host written out; got %q", o.metricsListen)
		}
	}
	return o, nil
}

func jwksMode(text string) (fs.FileMode, error) {
	switch text {
	case "0600":
		return 0o600, nil
	case "0644":
		return 0o644, nil
	default:
		return 0, errors.New("--mode must be 0600 or 0644")
	}
}

const jwksOutcomesHelp = `
Standard output is one JSON object per line. outcome (exit code with --once):
  UPDATED (0)         a new key set was written
  UNCHANGED (0)       the key set matches the file; the file was not rewritten
  FETCH_FAILED (1)    the fetch or the document failed; within --max-stale the file is left as it was
  STALE_EXPIRED (1)   the fetch failed and the last success is older than --max-stale;
                      with --empty-on-stale the file is replaced by {"keys":[]} and "cleared" is true
Without --once the process keeps going and exits 0 on SIGINT, SIGTERM or SIGHUP.
Exit 1 before any JSON: a file could not be read, or --metrics-listen could not be bound.
Exit 2: the command line is wrong.
`

// jwksLine 是标准输出上的一行 JSON。
type jwksLine struct {
	Time     string   `json:"time"`
	Outcome  string   `json:"outcome"`
	KeyCount int      `json:"key_count"`
	KIDs     []string `json:"kids"`
	Digest   string   `json:"digest"`
	Stale    bool     `json:"stale"`
	Cleared  bool     `json:"cleared"`
	Error    string   `json:"error,omitempty"`
}

func writeJWKSLine(w io.Writer, result application.Result) error {
	kids := result.KIDs
	if kids == nil {
		kids = []string{}
	}
	at := result.At
	if at.IsZero() {
		at = time.Now()
	}
	return json.NewEncoder(w).Encode(jwksLine{
		Time: at.UTC().Format(time.RFC3339Nano), Outcome: string(result.Outcome), KeyCount: result.KeyCount,
		KIDs: kids, Digest: result.Digest, Stale: result.Stale, Cleared: result.Cleared, Error: result.Error,
	})
}

func jwksExit(outcome application.Outcome) int {
	switch outcome {
	case application.OutcomeUpdated, application.OutcomeUnchanged:
		return exitActive
	default:
		return exitError
	}
}

// jwksChanged 报告这一行该不该写出来。第一轮一定写。之后只在这些时候写：密钥集更新了、
// 进入取失败、进入过期、从失败或过期恢复成同一套密钥。同一种失败重复出现时不写，
// 写过一次之后每一轮都没变化时也不写。
func jwksChanged(previous application.Outcome, reported bool, result application.Result) bool {
	if !reported {
		return true
	}
	switch result.Outcome {
	case application.OutcomeUpdated:
		return true
	case application.OutcomeUnchanged:
		return previous == application.OutcomeFetchFailed || previous == application.OutcomeStaleExpired
	default:
		return result.Outcome != previous
	}
}

func runJWKS(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	o, err := parseJWKS(args, stderr)
	if err != nil {
		if !errors.Is(err, flag.ErrHelp) {
			fmt.Fprintln(stderr, "gateway-control:", err)
		}
		return exitUsage
	}
	tlsConfig, err := jwksTLS(o.tlsCA, o.tlsCert, o.tlsKey)
	if err != nil {
		fmt.Fprintln(stderr, "gateway-control:", err)
		return exitError
	}
	client, err := httpfetch.New(httpfetch.Config{
		URL: o.url, PlainHTTPHost: o.plainHTTPHost, Timeout: o.timeout, MaxBodyBytes: httpfetch.DefaultMaxBodyBytes, TLS: tlsConfig,
	})
	if err != nil {
		fmt.Fprintln(stderr, "gateway-control:", err)
		return exitError
	}
	store, err := filestore.New(o.output, o.mode)
	if err != nil {
		fmt.Fprintln(stderr, "gateway-control:", err)
		return exitError
	}
	syncer, err := application.New(application.Config{
		Fetcher: client, Store: store, MaxStale: o.maxStale, EmptyOnStale: o.emptyOnStale,
	})
	if err != nil {
		fmt.Fprintln(stderr, "gateway-control:", err)
		return exitError
	}
	if o.once {
		result := syncer.Step(ctx)
		if err := writeJWKSLine(stdout, result); err != nil {
			fmt.Fprintln(stderr, "gateway-control:", err)
		}
		return jwksExit(result.Outcome)
	}
	var recorder *jwksmetrics.Metrics
	if o.metricsListen != "" {
		listener, err := net.Listen("tcp", o.metricsListen)
		if err != nil {
			fmt.Fprintln(stderr, "gateway-control:", fmt.Errorf("metrics: %w", err))
			return exitError
		}
		recorder = jwksmetrics.New()
		server := &http.Server{
			Handler: recorder.Handler(), ReadHeaderTimeout: 5 * time.Second,
			ErrorLog: log.New(stderr, "gateway-control: metrics: ", 0),
		}
		go func() { _ = server.Serve(listener) }()
		defer server.Close()
	}
	var previous application.Outcome
	reported := false
	for {
		if ctx.Err() != nil {
			return exitActive
		}
		result := syncer.Step(ctx)
		if ctx.Err() != nil {
			return exitActive
		}
		if recorder != nil {
			recorder.Observe(result)
		}
		if jwksChanged(previous, reported, result) {
			if err := writeJWKSLine(stdout, result); err != nil {
				fmt.Fprintln(stderr, "gateway-control:", err)
			}
			previous = result.Outcome
			reported = true
		}
		if !waitJWKS(ctx, o.interval) {
			return exitActive
		}
	}
}

func waitJWKS(ctx context.Context, interval time.Duration) bool {
	timer := time.NewTimer(interval)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

// jwksTLS 组装访问身份提供者的 TLS 配置。三个文件都不给时返回 nil，由传输层使用系统根。
// 给了 --tls-ca 就只信任这份 CA。客户端证书两个文件要一起给，这一点由解析参数时先查过。
func jwksTLS(caFile, certFile, keyFile string) (*tls.Config, error) {
	if caFile == "" && certFile == "" && keyFile == "" {
		return nil, nil
	}
	config := &tls.Config{MinVersion: tls.VersionTLS12}
	if caFile != "" {
		pemBytes, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("tls ca: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pemBytes) {
			return nil, errors.New("tls ca: no certificate found")
		}
		config.RootCAs = pool
	}
	if certFile != "" || keyFile != "" {
		pair, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, fmt.Errorf("tls client certificate: %w", err)
		}
		config.Certificates = []tls.Certificate{pair}
	}
	return config, nil
}
