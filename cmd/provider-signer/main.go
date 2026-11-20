// Command provider-signer 是网关与承运商之间的签名适配器（docs/adr/ADR-0014.md）：第一家是顺丰国际。
//
// 网关把调用方的明文 JSON 经双向 TLS 交给它，Authorization 头里带着这次请求的
// `Sf-OpenApi <appKey>;<accessToken>;<encodingAesKey>`；它加密正文、签名、向承运商发一次请求，
// 再把应答解密，明文交回网关。它不存任何秘密，没有凭证文件：要用的都在每个请求的头里。
//
// 它在请求路径上：只用标准库。操作表是写死的（见 internal/providersigner/domain），承运商的地址
// 只来自 --carrier-url，调用方的任何东西都到不了承运商。除了操作表里的几个 POST 路径，没有别的接口。
//
// --cb-failure-threshold 与 --cb-open-duration 是被动熔断：连续若干次承运商故障后，在打开时长内
// 直接回答 503 carrier_circuit_open，不再联系承运商。阈值为 0 时关闭，这是默认。
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"go.idp.xyz/idp-gateway/internal/platform/workloadtls"
	"go.idp.xyz/idp-gateway/internal/providersigner/adapters/carrierhttp"
	"go.idp.xyz/idp-gateway/internal/providersigner/adapters/httpapi"
	"go.idp.xyz/idp-gateway/internal/providersigner/application"
	"go.idp.xyz/idp-gateway/internal/providersigner/domain"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	err := run(ctx, os.Args[1:], os.Stderr, nil)
	switch {
	case errors.Is(err, flag.ErrHelp):
		os.Exit(2)
	case err != nil:
		fmt.Fprintln(os.Stderr, "provider-signer:", err)
		os.Exit(1)
	}
}

type options struct {
	listen             string
	tlsCert            string
	tlsKey             string
	clientCA           string
	gatewayIdentity    string
	carrierURL         string
	plainHTTPHost      string
	carrierTimeout     time.Duration
	lang               string
	maxRequestBytes    int64
	maxResponseBytes   int64
	cbFailureThreshold int
	cbOpenDuration     time.Duration
}

func parse(args []string, output io.Writer) (options, error) {
	var o options
	flags := flag.NewFlagSet("provider-signer", flag.ContinueOnError)
	flags.SetOutput(output)
	required := map[string]*string{}
	add := func(target *string, name, usage string, mandatory bool) {
		flags.StringVar(target, name, "", usage)
		if mandatory {
			required[name] = target
		}
	}
	add(&o.listen, "listen", "监听地址，host:port", true)
	add(&o.tlsCert, "tls-cert", "本服务的证书（PEM）", true)
	add(&o.tlsKey, "tls-key", "本服务的私钥（PEM）", true)
	add(&o.clientCA, "client-ca", "签发网关工作负载证书的 CA（PEM）", true)
	add(&o.gatewayIdentity, "gateway-identity", "唯一被服务的对端身份（网关证书里的 URI）", true)
	add(&o.carrierURL, "carrier-url", "承运商的 dispatch 地址，完整的，例如 https://api-ifsp.sf.global/openapi/api/dispatch；"+
		"只可见 ASCII，没有用户信息、查询串和片段；协议是 https，http 只许用在回环地址字面量（127.0.0.0/8 或 ::1，localhost 不算）"+
		"或 --carrier-plain-http-host 指定的主机上", true)
	add(&o.plainHTTPHost, "carrier-plain-http-host", "唯一一个允许对它用明文 http 的 --carrier-url 主机名（承运商的沙箱没有 TLS）；"+
		"必须是裸主机名，不含 / : @ ? #；默认空，即没有这样的主机", false)
	flags.DurationVar(&o.carrierTimeout, "carrier-timeout", 8*time.Second, "与承运商的整次交换的时限，必须大于 0；"+
		"必须小于网关路由的超时（9 秒），否则网关先放弃，这里的答复就没有人收了")
	flags.StringVar(&o.lang, "lang", "en", "请求头 lang 的值，en、zh-CN、zh-HK 之一")
	flags.Int64Var(&o.maxRequestBytes, "max-request-bytes", 1<<20, "接受网关的请求正文的上限（字节），必须大于 0")
	flags.Int64Var(&o.maxResponseBytes, "max-response-bytes", 4<<20, "接受承运商的应答正文的上限（字节），必须大于 0")
	flags.IntVar(&o.cbFailureThreshold, "cb-failure-threshold", 0, "被动熔断：连续多少次承运商故障后打开电路。0 表示关闭；必须 >= 0")
	flags.DurationVar(&o.cbOpenDuration, "cb-open-duration", 30*time.Second, "电路打开后持续的时间；--cb-failure-threshold 大于 0 时必须大于 0")
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
	if len(missing) > 0 {
		return o, errors.New("missing required flags: " + strings.Join(missing, ", "))
	}
	switch {
	case o.carrierTimeout <= 0:
		return o, errors.New("--carrier-timeout must be greater than zero")
	case !domain.ValidLanguage(o.lang):
		return o, errors.New("--lang must be one of en, zh-CN, zh-HK")
	case o.maxRequestBytes <= 0:
		return o, errors.New("--max-request-bytes must be greater than zero")
	case o.maxResponseBytes <= 0:
		return o, errors.New("--max-response-bytes must be greater than zero")
	case o.cbFailureThreshold < 0:
		return o, errors.New("--cb-failure-threshold must not be negative")
	case o.cbFailureThreshold > 0 && o.cbOpenDuration <= 0:
		return o, errors.New("--cb-open-duration must be greater than zero")
	}
	return o, nil
}

// run 启动服务，直到 ctx 取消。ready 非 nil 时在开始接受连接前被调用一次。
func run(ctx context.Context, args []string, output io.Writer, ready func(net.Addr)) error {
	o, err := parse(args, output)
	if err != nil {
		return err
	}
	logger := slog.New(slog.NewJSONHandler(output, nil))

	carrier, err := carrierhttp.New(carrierhttp.Config{URL: o.carrierURL, PlainHTTPHost: o.plainHTTPHost,
		Timeout: o.carrierTimeout, MaxResponseBytes: o.maxResponseBytes})
	if err != nil {
		return fmt.Errorf("--carrier-url: %w", err)
	}
	var serviceOptions []application.Option
	if o.cbFailureThreshold > 0 {
		breaker, err := domain.NewCircuitBreaker(domain.CircuitBreakerConfig{
			FailureThreshold: o.cbFailureThreshold, OpenDuration: o.cbOpenDuration,
		})
		if err != nil {
			return err
		}
		serviceOptions = append(serviceOptions, application.WithCircuitBreaker(breaker))
	}
	service, err := application.New(carrier, application.Settings{Lang: o.lang, MaxRequestBytes: o.maxRequestBytes}, serviceOptions...)
	if err != nil {
		return err
	}
	tlsConfig, err := workloadtls.ServerConfig(o.tlsCert, o.tlsKey, o.clientCA)
	if err != nil {
		return err
	}

	listener, err := net.Listen("tcp", o.listen)
	if err != nil {
		return err
	}
	server := newServer(httpapi.New(service, o.gatewayIdentity, logger), tlsConfig, o.carrierTimeout, logger)
	logger.Info("provider-signer listening", "addr", listener.Addr().String(),
		"gateway_identity", o.gatewayIdentity, "carrier_host", carrier.Host(), "carrier_scheme", carrier.Scheme(),
		"plain_http_host", o.plainHTTPHost, "lang", o.lang, "carrier_timeout", o.carrierTimeout.String(),
		"max_request_bytes", o.maxRequestBytes, "max_response_bytes", o.maxResponseBytes,
		"operations", len(domain.Operations()),
		"cb_failure_threshold", o.cbFailureThreshold, "cb_open_duration", o.cbOpenDuration.String())
	if ready != nil {
		ready(listener.Addr())
	}

	served := make(chan error, 1)
	go func() { served <- server.ServeTLS(listener, "", "") }()
	select {
	case err := <-served:
		return err
	case <-ctx.Done():
	}
	// 停止接受新连接，等在途的调用答完。
	shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdown); err != nil {
		return fmt.Errorf("shutdown: %w", err)
	}
	logger.Info("provider-signer stopped")
	return nil
}

// newServer 按规定的时限和上限构造 http.Server。单独成函数，是为了让测试能直接核对这些数。
func newServer(handler http.Handler, tlsConfig *tls.Config, carrierTimeout time.Duration, logger *slog.Logger) *http.Server {
	return &http.Server{
		Handler:           handler,
		TLSConfig:         tlsConfig,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		// 写答复的时限要比向承运商等答复的时限长：承运商用满时限之后还要把答复写给网关。
		WriteTimeout:   carrierTimeout + 5*time.Second,
		IdleTimeout:    60 * time.Second,
		MaxHeaderBytes: 64 << 10,
		ErrorLog:       log.New(&serverLogWriter{logger: logger}, "", 0),
	}
}

// serverLogWriter 把 net/http 自己写的日志行（被拒绝的 TLS 握手等）并入结构化日志。
type serverLogWriter struct{ logger *slog.Logger }

func (w *serverLogWriter) Write(p []byte) (int, error) {
	w.logger.Warn("http server", "detail", strings.TrimSpace(string(p)))
	return len(p), nil
}
