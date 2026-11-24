// Command sf-token-coordinator 是顺丰国际访问令牌的跨实例租约协调器（docs/adr/ADR-0022.md）。
//
// 承运商写明取了新令牌旧的就失效。多个 gateway-authz 副本各取各的，会互相作废；进程重启再取一次，
// 也会踢掉还在路上的那一枚。副本改为来这里问：已经有还能用的令牌就拿走，没有才由一个持有者去取，
// 取到先落盘再交给其余副本。本进程不持有 app_secret 和 encoding_aes_key，只保存访问令牌。
//
// 它在请求路径上：只用标准库。只接受 --authz-identity 那一个工作负载身份，双向 TLS 的证书和 CA
// 按文件热重载。协调器自己不可用时，调用方必须失败关闭，不得退回去单独向承运商取票。
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
	"go.idp.xyz/idp-gateway/internal/sflease/adapters/filestore"
	"go.idp.xyz/idp-gateway/internal/sflease/adapters/httpapi"
	"go.idp.xyz/idp-gateway/internal/sflease/application"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	err := run(ctx, os.Args[1:], os.Stderr, nil)
	switch {
	case errors.Is(err, flag.ErrHelp):
		os.Exit(2)
	case err != nil:
		fmt.Fprintln(os.Stderr, "sf-token-coordinator:", err)
		os.Exit(1)
	}
}

type options struct {
	listen        string
	tlsCert       string
	tlsKey        string
	clientCA      string
	authzIdentity string
	leaseFile     string
}

func parse(args []string, output io.Writer) (options, error) {
	var o options
	flags := flag.NewFlagSet("sf-token-coordinator", flag.ContinueOnError)
	flags.SetOutput(output)
	required := map[string]*string{}
	add := func(target *string, name, usage string) {
		flags.StringVar(target, name, "", usage)
		required[name] = target
	}
	add(&o.listen, "listen", "监听地址，host:port")
	add(&o.tlsCert, "tls-cert", "本服务的证书（PEM）；文件替换后下一次握手用新的")
	add(&o.tlsKey, "tls-key", "本服务的私钥（PEM）；文件替换后下一次握手用新的")
	add(&o.clientCA, "client-ca", "签发 gateway-authz 工作负载证书的 CA（PEM）；文件替换后下一次握手用新的")
	add(&o.authzIdentity, "authz-identity", "唯一允许访问协调器的 gateway-authz 工作负载身份（证书里的 SPIFFE URI）")
	add(&o.leaseFile, "lease-file", "租约文件的路径，权限须为 0600 或更严；父目录必须已经存在；不存在时创建空文件")
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
	if strings.ContainsAny(o.leaseFile, "\r\n") || strings.ContainsAny(o.listen, "\r\n") {
		return o, errors.New("--listen and --lease-file must be a single line")
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
	store, err := filestore.Open(o.leaseFile)
	if err != nil {
		return err
	}
	coord, err := application.New(store, nil)
	if err != nil {
		return err
	}
	tlsConfig, err := workloadtls.ServerConfigWithLogger(o.tlsCert, o.tlsKey, o.clientCA, logger)
	if err != nil {
		return err
	}
	listener, err := net.Listen("tcp", o.listen)
	if err != nil {
		return err
	}
	server := newServer(httpapi.New(coord, o.authzIdentity, logger), tlsConfig, logger)
	logger.Info("sf-token-coordinator listening", "addr", listener.Addr().String(), "authz_identity", o.authzIdentity)
	if ready != nil {
		ready(listener.Addr())
	}
	served := make(chan error, 1)
	go func() { served <- server.ServeTLS(listener, "", "") }()
	select {
	case err := <-served:
		stopCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		_ = server.Shutdown(stopCtx)
		cancel()
		if errors.Is(err, http.ErrServerClosed) {
			logger.Info("sf-token-coordinator stopped")
			return nil
		}
		return err
	case <-ctx.Done():
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdown); err != nil {
		return fmt.Errorf("shutdown: %w", err)
	}
	logger.Info("sf-token-coordinator stopped")
	return nil
}

func newServer(handler http.Handler, tlsConfig *tls.Config, logger *slog.Logger) *http.Server {
	return &http.Server{
		Handler:           handler,
		TLSConfig:         tlsConfig,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    64 << 10,
		ErrorLog:          log.New(&serverLogWriter{logger: logger}, "", 0),
	}
}

// serverLogWriter 把 net/http 自己写的日志行并入结构化日志。那些行里没有请求正文。
type serverLogWriter struct{ logger *slog.Logger }

func (w *serverLogWriter) Write(p []byte) (int, error) {
	w.logger.Warn("http server", "detail", strings.TrimSpace(string(p)))
	return len(p), nil
}
