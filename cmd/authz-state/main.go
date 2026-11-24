// Command authz-state 是 gateway-authz 的撤销/封禁与配额协调器（docs/adr/ADR-0023.md）。
//
// 两个进程共用一份撤销文件时，撤销和封禁已经能对上。跨机器对不上，限流桶也各算各的。
// 副本改为来这里改撤销表、读快照、扣配额。本进程不持有承运商密钥。配额桶只在内存里，
// 重启之后每个键都是满的。不传协调参数时，gateway-authz 仍用本地文件和本地桶。
//
// 它在请求路径上：只用标准库。只接受 --authz-identity 那一个工作负载身份。协调器不可用时，
// 调用方必须失败关闭，不得用过期的本地快照放行。
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

	"go.idp.xyz/idp-gateway/internal/authzstate/adapters/filestore"
	"go.idp.xyz/idp-gateway/internal/authzstate/adapters/httpapi"
	"go.idp.xyz/idp-gateway/internal/authzstate/application"
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
		fmt.Fprintln(os.Stderr, "authz-state:", err)
		os.Exit(1)
	}
}

type options struct {
	listen        string
	tlsCert       string
	tlsKey        string
	clientCA      string
	authzIdentity string
	stateFile     string
}

func parse(args []string, output io.Writer) (options, error) {
	var o options
	flags := flag.NewFlagSet("authz-state", flag.ContinueOnError)
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
	add(&o.authzIdentity, "authz-identity", "唯一允许访问协调器的 gateway-authz 工作负载身份（证书里的 SPIFFE URI）。每个副本出示同一枚 URI")
	add(&o.stateFile, "state-file", "撤销/封禁文件的路径，权限须为 0600 或更严；拒绝符号链接和 group/other 可读；父目录必须已经存在；不存在时创建空文件。配额桶不写进这个文件")
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
	if strings.ContainsAny(o.stateFile, "\r\n") || strings.ContainsAny(o.listen, "\r\n") {
		return o, errors.New("--listen and --state-file must be a single line")
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
	store, err := filestore.Open(o.stateFile)
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
	logger.Info("authz-state listening",
		"addr", listener.Addr().String(), "authz_identity", o.authzIdentity,
		"quota", "memory_only_restart_refills")
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
			logger.Info("authz-state stopped")
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
	logger.Info("authz-state stopped")
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
