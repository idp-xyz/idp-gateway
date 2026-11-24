// Command gateway-fabric 是 API Fabric 的发布意图适配器（docs/adr/ADR-0020.md）。
//
// 它在 mTLS 上提供两个路径：POST /v1/route-intents 和 GET /v1/route-intents/{intent_id}/status。
// 一条意图先并进 --pool-base 描述的那一家承运商的当前有效集，用锁定的 agentgateway --validate-only
// 校验，再先换 gateway-authz 的策略文件、确认 policy_version，然后经现有发布器把整份快照送到池上。
//
// 跨限界上下文的装配只发生在这个命令里。internal/fabricpub 不导入 routecompile、gatewayconfig 或 egressauthz。
//
// 离线加载二选一：--staging-image 用临时容器；--staging-binary 用锁定的本机二进制，经回读口取真实摘要。
// 两组参数不能混用。--authz-policy-file、--authz 和 --authz-name 必填，策略文件和网关快照保持同一代。
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"go.idp.xyz/idp-gateway/internal/fabricpub/adapters/filestate"
	"go.idp.xyz/idp-gateway/internal/fabricpub/adapters/httpapi"
	"go.idp.xyz/idp-gateway/internal/fabricpub/adapters/policyapplier"
	fapplication "go.idp.xyz/idp-gateway/internal/fabricpub/application"
	"go.idp.xyz/idp-gateway/internal/fabricpub/domain"
	"go.idp.xyz/idp-gateway/internal/gatewayconfig/adapters/directory"
	"go.idp.xyz/idp-gateway/internal/gatewayconfig/adapters/history"
	"go.idp.xyz/idp-gateway/internal/gatewayconfig/adapters/readback"
	"go.idp.xyz/idp-gateway/internal/gatewayconfig/adapters/scratch"
	gapplication "go.idp.xyz/idp-gateway/internal/gatewayconfig/application"
	gdomain "go.idp.xyz/idp-gateway/internal/gatewayconfig/domain"
	gports "go.idp.xyz/idp-gateway/internal/gatewayconfig/ports"
	"go.idp.xyz/idp-gateway/internal/platform/workloadtls"
	"go.idp.xyz/idp-gateway/internal/routecompile/adapters/binaryvalidator"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	err := run(ctx, os.Args[1:], os.Stderr, nil)
	switch {
	case errors.Is(err, flag.ErrHelp):
		os.Exit(2)
	case err != nil:
		fmt.Fprintln(os.Stderr, "gateway-fabric:", err)
		os.Exit(1)
	}
}

type options struct {
	listen         string
	tlsCert        string
	tlsKey         string
	clientCA       string
	fabricIdentity string

	targetID string
	poolBase string
	bindings string
	stateDir string

	agentgateway  string
	lockFile      string
	compileTLSDir string

	configDir     string
	configName    string
	historyDir    string
	readBack      string
	readBackName  string
	publisherCert string
	publisherKey  string
	publisherCA   string

	authzPolicy string
	authz       string
	authzName   string
	authzCA     string

	stagingImage   string
	stagingName    string
	stagingTLSDir  string
	stagingWorkDir string
	stagingPublish string
	stagingPort    int

	stagingBinary   string
	stagingLockFile string
	stagingListen   string
}

func parse(args []string, output io.Writer) (options, error) {
	var o options
	flags := flag.NewFlagSet("gateway-fabric", flag.ContinueOnError)
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
	add(&o.clientCA, "client-ca", "签发 Fabric 工作负载证书的 CA（PEM）", true)
	add(&o.fabricIdentity, "fabric-identity", "唯一允许调用这两个路径的客户端 SPIFFE URI", true)
	add(&o.targetID, "target-id", "本进程接受的 Fabric target_id", true)
	add(&o.poolBase, "pool-base", "只读的出站 CompileSpec（一家承运商的目录）", true)
	add(&o.bindings, "bindings", "只读的 CredentialBinding JSON，一个对象或一个数组", true)
	add(&o.stateDir, "state-dir", "已经存在的状态目录，权限必须是 0700", true)
	add(&o.agentgateway, "agentgateway", "锁定的 agentgateway 1.7.0 二进制，用于 --validate-only", true)
	add(&o.lockFile, "lock-file", "agentgateway.lock.json，用来核对二进制的 SHA-256", true)
	add(&o.compileTLSDir, "compile-tls-dir", "校验时可以引用的 TLS 目录；没有就由校验器自己准备临时证书", true)
	add(&o.configDir, "config-dir", "池的配置目录，网关挂载的是这个目录", true)
	flags.StringVar(&o.configName, "config-name", "config.yaml", "配置目录里的文件名")
	add(&o.historyDir, "history-dir", "可选的发布历史目录；不设则不写历史", false)
	add(&o.readBack, "read-back", "池里网关的回读口，host:port", true)
	add(&o.readBackName, "read-back-name", "验证回读口证书时要对上的名字", true)
	add(&o.publisherCert, "publisher-cert", "发布器工作负载证书（PEM），用来读回读口和策略版本", true)
	add(&o.publisherKey, "publisher-key", "发布器证书的私钥（PEM）", true)
	add(&o.publisherCA, "publisher-ca", "签发回读口证书的 CA（PEM）", true)
	add(&o.authzPolicy, "authz-policy-file", "gateway-authz 正在读的策略文件，发布时原子换上", true)
	add(&o.authz, "authz", "gateway-authz 的地址，host:port 或 https://host:port", true)
	add(&o.authzName, "authz-name", "验证 gateway-authz 证书时要对上的名字", true)
	add(&o.authzCA, "authz-ca", "签发 gateway-authz 证书的 CA（PEM）；不设则用 --publisher-ca", false)
	add(&o.stagingImage, "staging-image", "离线加载用的镜像（仓库@sha256:…）。和 --staging-binary 二选一", false)
	flags.StringVar(&o.stagingName, "staging-name", "gateway-fabric-stage", "临时容器的名字")
	add(&o.stagingTLSDir, "staging-tls-dir", "容器模式挂进 /work/tls 的目录", false)
	add(&o.stagingWorkDir, "staging-work-dir", "容器模式放候选配置的目录", false)
	add(&o.stagingPublish, "staging-publish", "容器回读口映射到本机的回环地址 host:port", false)
	flags.IntVar(&o.stagingPort, "staging-container-port", 0, "回读口在容器里的端口")
	add(&o.stagingBinary, "staging-binary", "离线加载用的锁定 agentgateway 二进制。和 --staging-image 二选一", false)
	add(&o.stagingLockFile, "staging-lock-file", "核对 --staging-binary 的锁文件", false)
	add(&o.stagingListen, "staging-listen", "本机二进制回读口的回环地址；不设则用 127.0.0.1 加目录里的 readback_port", false)
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
	if err := checkListen(o.listen, "--listen"); err != nil {
		return o, err
	}
	if err := checkListen(o.readBack, "--read-back"); err != nil {
		return o, err
	}
	if len(o.targetID) < 4 || len(o.targetID) > 160 || strings.ContainsAny(o.targetID, " \t\r\n") {
		return o, errors.New("--target-id must be 4 to 160 characters without whitespace")
	}
	if strings.ContainsAny(o.fabricIdentity, " \t\r\n") || !strings.Contains(o.fabricIdentity, "://") {
		return o, errors.New("--fabric-identity must be a URI")
	}
	if o.configName == "" || o.configName != filepath.Base(o.configName) || o.configName == "." || o.configName == ".." {
		return o, errors.New("--config-name must be a plain file name")
	}
	o.authz = normalizeHTTPS(o.authz)
	if _, err := url.Parse(o.authz); err != nil || !strings.HasPrefix(o.authz, "https://") {
		return o, errors.New("--authz must be host:port or https://host:port")
	}
	if err := stagingMode(&o); err != nil {
		return o, err
	}
	return o, nil
}

func stagingMode(o *options) error {
	imageFlags := o.stagingTLSDir != "" || o.stagingWorkDir != "" || o.stagingPublish != "" || o.stagingPort != 0
	binaryFlags := o.stagingLockFile != "" || o.stagingListen != ""
	switch {
	case o.stagingImage != "" && o.stagingBinary != "":
		return errors.New("--staging-image and --staging-binary are mutually exclusive")
	case o.stagingImage == "" && o.stagingBinary == "":
		return errors.New("choose one staging mode: --staging-image or --staging-binary")
	case o.stagingImage != "" && binaryFlags:
		return errors.New("container staging does not take --staging-binary, --staging-lock-file or --staging-listen")
	case o.stagingBinary != "" && imageFlags:
		return errors.New("binary staging does not take the container staging flags")
	case o.stagingImage != "":
		if o.stagingTLSDir == "" || o.stagingWorkDir == "" || o.stagingPublish == "" || o.stagingPort == 0 {
			return errors.New("--staging-image requires --staging-tls-dir, --staging-work-dir, --staging-publish and --staging-container-port")
		}
		if err := checkListen(o.stagingPublish, "--staging-publish"); err != nil {
			return err
		}
		host, _, _ := net.SplitHostPort(o.stagingPublish)
		if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
			return errors.New("--staging-publish must be a loopback address")
		}
	default:
		if o.stagingLockFile == "" {
			return errors.New("--staging-binary requires --staging-lock-file")
		}
		if o.stagingListen != "" {
			if err := checkListen(o.stagingListen, "--staging-listen"); err != nil {
				return err
			}
			host, _, _ := net.SplitHostPort(o.stagingListen)
			if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
				return errors.New("--staging-listen must be a loopback address")
			}
		}
	}
	return nil
}

func checkListen(addr, flagName string) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil || host == "" {
		return fmt.Errorf("%s must be host:port", flagName)
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 0 || n > 65535 || (n == 0 && flagName != "--listen") {
		return fmt.Errorf("%s has an invalid port", flagName)
	}
	return nil
}

func normalizeHTTPS(raw string) string {
	if strings.Contains(raw, "://") {
		return raw
	}
	return "https://" + raw
}

func run(ctx context.Context, args []string, stderr io.Writer, ready func(net.Addr)) error {
	o, err := parse(args, stderr)
	if err != nil {
		return err
	}
	baseRaw, err := os.ReadFile(o.poolBase)
	if err != nil {
		return err
	}
	base, err := domain.ParsePoolBase(baseRaw)
	if err != nil {
		return fmt.Errorf("--pool-base: %w", err)
	}
	if !strings.HasPrefix(base.Pool.Name, "egress-") {
		return errors.New("--pool-base must be an egress pool; ingress and AI are not served by this process")
	}
	bindingRaw, err := os.ReadFile(o.bindings)
	if err != nil {
		return err
	}
	bindings, err := domain.ParseBindings(bindingRaw)
	if err != nil {
		return fmt.Errorf("--bindings: %w", err)
	}
	if o.stagingBinary != "" && o.stagingListen == "" {
		if base.Pool.ReadbackPort < 1 || base.Pool.ReadbackPort > 65535 {
			return errors.New("--staging-listen is required when the pool base has no readback_port")
		}
		o.stagingListen = net.JoinHostPort("127.0.0.1", strconv.Itoa(base.Pool.ReadbackPort))
	}
	store, err := filestate.Open(o.stateDir)
	if err != nil {
		return err
	}
	logger := slog.New(slog.NewJSONHandler(stderr, nil))
	publisherTLS, err := workloadtls.ClientConfigWithLogger(o.publisherCert, o.publisherKey, o.publisherCA, o.readBackName, logger)
	if err != nil {
		return err
	}
	authzCA := o.authzCA
	if authzCA == "" {
		authzCA = o.publisherCA
	}
	authzTLS, err := workloadtls.ClientConfigWithLogger(o.publisherCert, o.publisherKey, authzCA, o.authzName, logger)
	if err != nil {
		return err
	}
	applier, err := policyapplier.New(policyapplier.Config{
		Path: o.authzPolicy, AuthzURL: o.authz, ServerName: o.authzName, TLS: authzTLS,
	})
	if err != nil {
		return err
	}
	staging, err := buildStaging(o, publisherTLS)
	if err != nil {
		return err
	}
	poolRead, err := readback.New(readback.Config{Address: o.readBack, TLS: publisherTLS})
	if err != nil {
		return err
	}
	delivery, err := directory.New(o.configDir, o.configName)
	if err != nil {
		return err
	}
	publisher, err := gapplication.New(staging, delivery, poolRead, gapplication.DefaultTiming())
	if err != nil {
		return err
	}
	reconciler, err := gapplication.NewReconciler(delivery, poolRead, gapplication.DefaultTiming())
	if err != nil {
		return err
	}
	if o.historyDir != "" {
		record, err := history.New(o.historyDir, base.Pool.Name)
		if err != nil {
			return err
		}
		ident, err := workloadtls.CertificateIdentity(o.publisherCert)
		if err != nil {
			return err
		}
		account := ""
		if current, err := user.Current(); err == nil {
			account = current.Username
		}
		publisher.WithHistory(record, gapplication.ReleaseMeta{
			Command: "publish", By: gdomain.Initiator{Workload: ident, Account: account}, Note: "gateway-fabric",
		})
		reconciler.WithHistory(record)
	}
	svc, err := fapplication.New(fapplication.Config{
		TargetID: o.targetID, Base: base, Bindings: bindings, Store: store,
		Compiler: compileAdapter{validator: binaryvalidator.Validator{Binary: o.agentgateway, LockFile: o.lockFile}, tlsDir: o.compileTLSDir},
		Policies: applier, Publisher: &poolPublisher{staging: staging, publisher: publisher, reconciler: reconciler},
	})
	if err != nil {
		return err
	}
	svc.Start(ctx)
	defer svc.Close()
	handler, err := httpapi.NewHandler(svc, o.fabricIdentity)
	if err != nil {
		return err
	}
	serverTLS, err := workloadtls.ServerConfigWithLogger(o.tlsCert, o.tlsKey, o.clientCA, logger)
	if err != nil {
		return err
	}
	listener, err := tls.Listen("tcp", o.listen, serverTLS)
	if err != nil {
		return err
	}
	server := &http.Server{
		Handler:           handler,
		TLSConfig:         serverTLS,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       60 * time.Second,
		BaseContext:       func(net.Listener) context.Context { return ctx },
	}
	errCh := make(chan error, 1)
	go func() { errCh <- server.Serve(listener) }()
	if ready != nil {
		ready(listener.Addr())
	}
	select {
	case <-ctx.Done():
		shut, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = server.Shutdown(shut)
		return nil
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

func buildStaging(o options, publisherTLS *tls.Config) (gports.Staging, error) {
	if o.stagingImage != "" {
		client, err := readback.New(readback.Config{Address: o.stagingPublish, TLS: publisherTLS})
		if err != nil {
			return nil, err
		}
		return scratch.New(scratch.Config{
			Image: o.stagingImage, Name: o.stagingName, TLSDirectory: o.stagingTLSDir,
			WorkDirectory: o.stagingWorkDir, Publish: o.stagingPublish, ContainerPort: o.stagingPort,
			ReadBack: client,
		})
	}
	return newBinaryStaging(o.stagingBinary, o.stagingLockFile, o.stagingListen, o.compileTLSDir, publisherTLS)
}
