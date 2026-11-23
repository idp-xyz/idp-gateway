// Command gateway-console 是回环上的管理 BFF。它读一份审计 JSONL，并在给了撤销者证书时，
// 把撤销、恢复和封禁交给 gateway-authz 已经有的接口。它不发布路由，也不回滚快照。
//
//	gateway-console [--listen 127.0.0.1:19100] [--audit-log <文件>] [--ui <目录>]
//	    [--authz <host:port> --authz-name <名字> --tls-cert <文件> --tls-key <文件> --tls-ca <文件>]
//	    [--timeout 5s]
//
// --listen 只能是回环地址上的 host:port，写成 IP，不写主机名。0.0.0.0 和空主机拒掉，进程不监听。
// 五个 --authz / --tls-* 要么都给，要么都不给。都不给时，撤销和封禁的路径是 404，审计读取仍可用。
// 不给 --audit-log 时，GET /v1/audit 是 404。
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"go.idp.xyz/idp-gateway/internal/egressauthz/adapters/revokerclient"
	"go.idp.xyz/idp-gateway/internal/platform/workloadtls"
)

const (
	exitOK    = 0
	exitError = 1
	exitUsage = 2

	defaultListen  = "127.0.0.1:19100"
	defaultTimeout = 5 * time.Second
)

type options struct {
	listen   string
	auditLog string
	ui       string
	address  string
	name     string
	cert     string
	key      string
	ca       string
	timeout  time.Duration
	authzSet bool
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	o, err := parse(args, stderr)
	if err != nil {
		if !errors.Is(err, flag.ErrHelp) {
			fmt.Fprintln(stderr, "gateway-console:", err)
		}
		return exitUsage
	}
	var client *revokerclient.Client
	if o.authzSet {
		tlsConfig, err := workloadtls.ClientConfig(o.cert, o.key, o.ca, o.name)
		if err != nil {
			fmt.Fprintln(stderr, "gateway-console:", err)
			return exitError
		}
		client, err = revokerclient.New(revokerclient.Config{Address: o.address, TLS: tlsConfig, Timeout: o.timeout})
		if err != nil {
			fmt.Fprintln(stderr, "gateway-console:", err)
			return exitError
		}
	}
	handler := handlerFor(o.auditLog, client, o.ui)
	listener, err := net.Listen("tcp", o.listen)
	if err != nil {
		fmt.Fprintln(stderr, "gateway-console:", err)
		return exitError
	}
	server := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    8 << 10,
	}
	fmt.Fprintf(stderr, "gateway-console: listening on %s audit=%t authz=%t ui=%t\n", listener.Addr(), o.auditLog != "", o.authzSet, o.ui != "")
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	errc := make(chan error, 1)
	go func() { errc <- server.Serve(listener) }()
	select {
	case err := <-errc:
		if errors.Is(err, http.ErrServerClosed) {
			return exitOK
		}
		fmt.Fprintln(stderr, "gateway-console:", err)
		return exitError
	case <-ctx.Done():
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdown); err != nil {
		fmt.Fprintln(stderr, "gateway-console:", err)
		return exitError
	}
	return exitOK
}

func parse(args []string, stderr io.Writer) (options, error) {
	var o options
	flags := flag.NewFlagSet("gateway-console", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.StringVar(&o.listen, "listen", defaultListen, "监听地址，只能是回环 IP 加端口，例如 127.0.0.1:19100")
	flags.StringVar(&o.auditLog, "audit-log", "", "审计 JSONL。不给则 GET /v1/audit 是 404。文件须是普通文件且组和其他人不可读")
	flags.StringVar(&o.ui, "ui", "", "静态页面目录，通常是 console/dist。不给则只有 /v1 接口。必须是目录，不能是符号链接")
	flags.StringVar(&o.address, "authz", "", "gateway-authz 的地址，host:port。和证书四个参数一起给，或不给")
	flags.StringVar(&o.name, "authz-name", "", "验证 gateway-authz 证书时要对上的名字")
	flags.StringVar(&o.cert, "tls-cert", "", "撤销者的证书（PEM）")
	flags.StringVar(&o.key, "tls-key", "", "撤销者的私钥（PEM）")
	flags.StringVar(&o.ca, "tls-ca", "", "签发 gateway-authz 证书的 CA（PEM）")
	flags.DurationVar(&o.timeout, "timeout", defaultTimeout, "向 gateway-authz 发一次请求最多等多久")
	if err := flags.Parse(args); err != nil {
		return o, err
	}
	if flags.NArg() > 0 {
		return o, fmt.Errorf("unexpected argument %q", flags.Arg(0))
	}
	if err := validateListen(o.listen); err != nil {
		return o, err
	}
	if strings.ContainsAny(o.auditLog, "\r\n") {
		return o, errors.New("--audit-log must be a single line")
	}
	if o.ui != "" {
		if err := checkUIDir(o.ui); err != nil {
			return o, err
		}
	}
	given := 0
	for _, v := range []string{o.address, o.name, o.cert, o.key, o.ca} {
		if v != "" {
			given++
		}
	}
	if given != 0 && given != 5 {
		return o, errors.New("--authz, --authz-name, --tls-cert, --tls-key and --tls-ca go together")
	}
	o.authzSet = given == 5
	if o.authzSet {
		if host, port, err := net.SplitHostPort(o.address); err != nil || host == "" || port == "" {
			return o, fmt.Errorf("--authz must be host:port, with the host written out; got %q", o.address)
		}
	}
	if o.timeout <= 0 {
		return o, errors.New("--timeout must be positive")
	}
	return o, nil
}

// validateListen 只接受回环 IP 加端口。主机名不解析：localhost 不在这里放行。
// 不合格时调用方还没有 Listen。
func validateListen(addr string) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil || host == "" || port == "" {
		return fmt.Errorf("--listen must be a loopback IP and port, got %q", addr)
	}
	if _, err := net.LookupPort("tcp", port); err != nil {
		return fmt.Errorf("--listen must be a loopback IP and port, got %q", addr)
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("--listen must be a loopback IP and port, got %q", addr)
	}
	return nil
}
