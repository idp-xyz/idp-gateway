// Command gateway-authz 是出站请求的判定与凭证服务，agentgateway 的 ExtAuthZ 目标。
//
// 它在请求路径上：只用标准库，不连数据库。第一版从文件读登记表和凭证，撤销状态放在
// 内存里，这三样都是占位（见 docs/adr/ADR-0009.md）。
package main

import (
	"context"
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

	"go.idp.xyz/idp-gateway/internal/egressauthz/adapters/filestore"
	"go.idp.xyz/idp-gateway/internal/egressauthz/adapters/httpapi"
	"go.idp.xyz/idp-gateway/internal/egressauthz/adapters/memory"
	"go.idp.xyz/idp-gateway/internal/egressauthz/application"
	"go.idp.xyz/idp-gateway/internal/platform/workloadtls"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	err := run(ctx, os.Args[1:], os.Stderr, nil)
	switch {
	case errors.Is(err, flag.ErrHelp):
		os.Exit(2)
	case err != nil:
		fmt.Fprintln(os.Stderr, "gateway-authz:", err)
		os.Exit(1)
	}
}

type options struct {
	listen          string
	tlsCert         string
	tlsKey          string
	clientCA        string
	policy          string
	credentials     string
	gatewayIdentity string
	brokerIdentity  string
}

func parse(args []string, output io.Writer) (options, error) {
	var o options
	flags := flag.NewFlagSet("gateway-authz", flag.ContinueOnError)
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
	add(&o.clientCA, "client-ca", "签发调用方工作负载证书的 CA（PEM）", true)
	add(&o.policy, "policy", "出站登记表（JSON）", true)
	add(&o.credentials, "credentials", "凭证文件（JSON：凭证句柄 -> Bearer 令牌），权限须为 0600 或更严", true)
	add(&o.gatewayIdentity, "gateway-identity", "网关工作负载的身份（证书里的 URI）：可以要判定和凭证", true)
	add(&o.brokerIdentity, "broker-identity", "本地 Broker 工作负载的身份：只能要判定；不设则没有这样的调用方", false)
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
	if o.brokerIdentity == o.gatewayIdentity {
		return o, errors.New("--broker-identity must differ from --gateway-identity: the broker may not ask for credentials")
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

	policy, err := filestore.LoadPolicy(o.policy)
	if err != nil {
		return err
	}
	credentials, err := filestore.LoadCredentials(o.credentials)
	if err != nil {
		return err
	}
	tlsConfig, err := workloadtls.ServerConfig(o.tlsCert, o.tlsKey, o.clientCA)
	if err != nil {
		return err
	}

	revocations := &memory.Revocations{}
	callers := httpapi.Callers{Gateway: o.gatewayIdentity, Broker: o.brokerIdentity}
	service := application.New(policy, credentials, revocations)
	var handler http.Handler = httpapi.New(service, callers, logger)
	var serverLog io.Writer = &serverLogWriter{logger: logger}
	handler, serverLog, err = install(handler, serverLog, seams{listen: o.listen, callers: callers, revocations: revocations, logger: logger})
	if err != nil {
		return err
	}

	listener, err := net.Listen("tcp", o.listen)
	if err != nil {
		return err
	}
	server := &http.Server{
		Handler:           handler,
		TLSConfig:         tlsConfig,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    64 << 10,
		ErrorLog:          log.New(serverLog, "", 0),
	}
	logger.Info("gateway-authz listening", "addr", listener.Addr().String(), "build", buildFlavor,
		"policy_version", policy.Version, "operations", len(policy.Operations), "credentials", credentials.Len(),
		"gateway_identity", o.gatewayIdentity, "broker_identity", o.brokerIdentity)
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
	// 停止接受新连接，等在途的判定答完。
	shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdown); err != nil {
		return fmt.Errorf("shutdown: %w", err)
	}
	logger.Info("gateway-authz stopped")
	return nil
}

// serverLogWriter 把 net/http 自己写的日志行（被拒绝的 TLS 握手等）并入结构化日志。
type serverLogWriter struct{ logger *slog.Logger }

func (w *serverLogWriter) Write(p []byte) (int, error) {
	w.logger.Warn("http server", "detail", strings.TrimSpace(string(p)))
	return len(p), nil
}
