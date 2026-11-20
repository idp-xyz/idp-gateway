// Command gateway-authz 是出站请求的判定与凭证服务，agentgateway 的 ExtAuthZ 目标。
//
// 它在请求路径上：只用标准库，不连数据库。第一版从文件读登记表和凭证，撤销状态放在
// 内存里，这三样都是占位（见 docs/adr/ADR-0009.md）。账户的使用授权可以再交给
// Gatekeeper 的 PDP 确认一遍（--gatekeeper-url），不配置时只看登记表。这一跳出示工作负载证书
// （--gatekeeper-tls-*、--gatekeeper-name，四个一起给）；PDP 不在回环地址上时必须给。
//
// 凭证文件有四种，至少给一种（见 docs/adr/ADR-0011.md 和 docs/adr/ADR-0014.md）：--credentials
// 是固定的 Bearer 令牌；--developer-tokens 是账号加开发者令牌，认证头里的随机数每个请求现做；
// --oauth-clients 是 OAuth2 客户端凭证，向令牌端点取访问令牌，--oauth-timeout 是取一次的超时；
// --sf-openapi-apps 是顺丰国际开放平台的应用（appKey、应用密钥、AES 密钥），向承运商取访问令牌，
// 放行时交出 Sf-OpenApi appKey;令牌;AES密钥，由另一个签名适配器拆开使用，--sf-openapi-timeout 是
// 取一次的超时，--sf-openapi-plain-http-host 只为承运商没有 TLS 的沙箱放开一个主机名的明文 http。
// 一个凭证句柄只能出现在其中一个文件里。
//
// 撤销（见 docs/adr/ADR-0012.md）：--revocations 给出保存撤销表的文件，--revoker-identity
// 给出唯一能改它的工作负载身份，两个要一起给。都不给时撤销表在内存里、永远是空的，也没有
// 改它的接口。
//
// --rate-limits 可选。给出时按文件里的配额对每个 Provider 账户限流，超额回答 429 和
// Retry-After，原因码 RATE_LIMITED。不给则不限流。文件里没有秘密。
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
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"go.idp.xyz/idp-gateway/internal/egressauthz/adapters/filestore"
	"go.idp.xyz/idp-gateway/internal/egressauthz/adapters/gatekeeper"
	"go.idp.xyz/idp-gateway/internal/egressauthz/adapters/httpapi"
	"go.idp.xyz/idp-gateway/internal/egressauthz/adapters/memory"
	"go.idp.xyz/idp-gateway/internal/egressauthz/adapters/oauthclient"
	"go.idp.xyz/idp-gateway/internal/egressauthz/adapters/sfopenapi"
	"go.idp.xyz/idp-gateway/internal/egressauthz/application"
	"go.idp.xyz/idp-gateway/internal/egressauthz/ports"
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
	listen                 string
	tlsCert                string
	tlsKey                 string
	clientCA               string
	policy                 string
	credentials            string
	developerTokens        string
	oauthClients           string
	oauthTimeout           time.Duration
	sfOpenAPIApps          string
	sfOpenAPITimeout       time.Duration
	sfOpenAPIPlainHTTPHost string
	gatewayIdentity        string
	brokerIdentity         string
	revocations            string
	revokerIdentity        string
	gatekeeperURL          string
	gatekeeperToken        string
	gatekeeperCert         string
	gatekeeperKey          string
	gatekeeperCA           string
	gatekeeperName         string
	rateLimits             string
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
	add(&o.credentials, "credentials", "凭证文件（JSON：凭证句柄 -> Bearer 令牌），权限须为 0600 或更严；它和 --developer-tokens 至少给一个", false)
	add(&o.developerTokens, "developer-tokens", "开发者令牌文件（JSON：凭证句柄 -> {account, token}），权限须为 0600 或更严；"+
		"认证头是 Hc-OweDeveloper 账号;令牌;随机数，随机数每个请求现做；文件被换掉之后重读", false)
	add(&o.oauthClients, "oauth-clients", "OAuth2 客户端凭证文件（JSON：凭证句柄 -> {token_endpoint, client_id, client_secret, key_version, scope, audience}），"+
		"权限须为 0600 或更严；向令牌端点取访问令牌，按账户缓存；文件被换掉之后重读", false)
	flags.DurationVar(&o.oauthTimeout, "oauth-timeout", oauthclient.DefaultTimeout, "向令牌端点取一次令牌的超时，必须大于 0；要留在网关等 PDP 的时限之内")
	add(&o.sfOpenAPIApps, "sf-openapi-apps", "顺丰国际开放平台应用文件（JSON：凭证句柄 -> {token_endpoint, app_key, app_secret, encoding_aes_key, key_version}），"+
		"权限须为 0600 或更严；向承运商取访问令牌，按句柄缓存；放行时交出 Sf-OpenApi appKey;令牌;AES密钥；文件被换掉之后重读", false)
	flags.DurationVar(&o.sfOpenAPITimeout, "sf-openapi-timeout", sfopenapi.DefaultTimeout, "向承运商令牌端点取一次令牌的超时，必须大于 0；要留在网关等 PDP 的时限之内")
	add(&o.sfOpenAPIPlainHTTPHost, "sf-openapi-plain-http-host", "唯一允许明文 http 令牌端点的主机名（只写主机名，不带协议、端口和路径），"+
		"给承运商没有 TLS 的沙箱用；默认没有这个例外；要和 --sf-openapi-apps 一起给", false)
	add(&o.gatewayIdentity, "gateway-identity", "网关工作负载的身份（证书里的 URI）：可以要判定和凭证", true)
	add(&o.brokerIdentity, "broker-identity", "本地 Broker 工作负载的身份：只能要判定；不设则没有这样的调用方", false)
	add(&o.revocations, "revocations", "撤销文件（JSON：代次和被撤销的账户），权限须为 0600 或更严；启动时读，读不成就不启动；"+
		"之后只由本进程写。要和 --revoker-identity 一起给", false)
	add(&o.revokerIdentity, "revoker-identity", "能改撤销表的工作负载身份：只能撤销、恢复和读出撤销表。要和 --revocations 一起给", false)
	add(&o.gatekeeperURL, "gatekeeper-url", "Gatekeeper PDP 的地址；设了它，登记表放行的请求还要 Gatekeeper 确认账户的使用授权", false)
	add(&o.gatekeeperToken, "gatekeeper-token-file", "访问 Gatekeeper PDP 的 Bearer 令牌文件，权限须为 0600 或更严", false)
	add(&o.gatekeeperCert, "gatekeeper-tls-cert", "本服务出示给 Gatekeeper PDP 的工作负载证书（PEM）。四个 --gatekeeper-tls-* / --gatekeeper-name 要么都给、要么都不给；"+
		"--gatekeeper-url 不是回环地址时必须给，给了之后它必须是 https", false)
	add(&o.gatekeeperKey, "gatekeeper-tls-key", "上面那张证书的私钥（PEM）", false)
	add(&o.gatekeeperCA, "gatekeeper-tls-ca", "签发 PDP 一端证书的 CA（PEM）；系统自带的根证书不被信任", false)
	add(&o.gatekeeperName, "gatekeeper-name", "验证 PDP 一端证书时要对上的名字", false)
	add(&o.rateLimits, "rate-limits", "按 Provider 账户限流的配额文件（JSON：version 与 buckets）。不设则不限流。"+
		"文件里没有秘密，0644 或 0600 都可以；启动时读不成就不启动；文件被换掉之后重读，新文件读不成就沿用上一份", false)
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
	if o.credentials == "" && o.developerTokens == "" && o.oauthClients == "" && o.sfOpenAPIApps == "" {
		missing = append(missing, "--credentials or --developer-tokens or --oauth-clients or --sf-openapi-apps")
	}
	if len(missing) > 0 {
		return o, errors.New("missing required flags: " + strings.Join(missing, ", "))
	}
	if o.oauthTimeout <= 0 {
		return o, errors.New("--oauth-timeout must be greater than zero")
	}
	if o.sfOpenAPITimeout <= 0 {
		return o, errors.New("--sf-openapi-timeout must be greater than zero")
	}
	if o.sfOpenAPIPlainHTTPHost != "" {
		if o.sfOpenAPIApps == "" {
			return o, errors.New("--sf-openapi-plain-http-host needs --sf-openapi-apps")
		}
		if !bareHostName(o.sfOpenAPIPlainHTTPHost) {
			return o, errors.New("--sf-openapi-plain-http-host must be a bare host name: visible ASCII, none of / : @ ? #")
		}
	}
	if o.brokerIdentity == o.gatewayIdentity {
		return o, errors.New("--broker-identity must differ from --gateway-identity: the broker may not ask for credentials")
	}
	if (o.gatekeeperURL == "") != (o.gatekeeperToken == "") {
		return o, errors.New("--gatekeeper-url and --gatekeeper-token-file go together")
	}
	if err := checkGatekeeperTLS(o); err != nil {
		return o, err
	}
	// 没有文件的写入口改的东西重启就没有了；没有写入口的文件谁也改不了。
	if (o.revocations == "") != (o.revokerIdentity == "") {
		return o, errors.New("--revocations and --revoker-identity go together")
	}
	if o.revokerIdentity != "" && (o.revokerIdentity == o.gatewayIdentity || o.revokerIdentity == o.brokerIdentity) {
		return o, errors.New("--revoker-identity must differ from --gateway-identity and --broker-identity: " +
			"who asks for credentials may not be who lifts a revocation")
	}
	return o, nil
}

// bareHostName 报告 host 是不是一个只有主机名的值：非空，全是可见 ASCII，不含 / : @ ? #
// （没有协议、端口、用户信息、路径、查询串和片段）。
func bareHostName(host string) bool {
	if host == "" || strings.ContainsAny(host, "/:@?#") {
		return false
	}
	for i := 0; i < len(host); i++ {
		if host[i] < 0x21 || host[i] > 0x7e {
			return false
		}
	}
	return true
}

// checkGatekeeperTLS 核对到 PDP 的那一跳：客户端证书的四个参数一起给或一起不给；PDP 不在本机回环地址上时
// 必须给，这一跳不能只靠一个共享的令牌；给了就必须走 https。
func checkGatekeeperTLS(o options) error {
	given := 0
	for _, v := range []string{o.gatekeeperCert, o.gatekeeperKey, o.gatekeeperCA, o.gatekeeperName} {
		if v != "" {
			given++
		}
	}
	if given != 0 && given != 4 {
		return errors.New("--gatekeeper-tls-cert, --gatekeeper-tls-key, --gatekeeper-tls-ca and --gatekeeper-name go together")
	}
	if o.gatekeeperURL == "" {
		if given != 0 {
			return errors.New("--gatekeeper-tls-* and --gatekeeper-name need --gatekeeper-url")
		}
		return nil
	}
	address, err := url.Parse(o.gatekeeperURL)
	if err != nil || address.Host == "" {
		return errors.New("--gatekeeper-url is not an absolute URL")
	}
	switch {
	case given == 0 && address.Scheme == "https" && !gatekeeper.Loopback(address.Hostname()):
		return errors.New("--gatekeeper-url is not a loopback address, so --gatekeeper-tls-cert, --gatekeeper-tls-key, " +
			"--gatekeeper-tls-ca and --gatekeeper-name are required: this hop may not rest on a shared token alone")
	case given != 0 && address.Scheme != "https":
		return errors.New("--gatekeeper-url must be https when a client certificate is configured")
	}
	return nil
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
	// 凭证来源：四种文件，给了哪种就装哪种。一个句柄只能在一个文件里：后装的来源启动时查先装的，
	// 先装的在重读时也查后装的（它们互相问，各自不拿锁等对方，见 Holds）。
	var credentials credentialSources
	var bearerTokens, developerTokens, oauthClients, sfOpenAPIApps int
	var bearer *filestore.Credentials
	var developer *filestore.DeveloperTokens
	var oauth *oauthclient.Client
	var sfApps *sfopenapi.Client
	heldElsewhere := func(except string) func(handle string) bool {
		return func(handle string) bool {
			return (except != "bearer" && bearer != nil && bearer.Holds(handle)) ||
				(except != "developer" && developer != nil && developer.Holds(handle)) ||
				(except != "oauth" && oauth != nil && oauth.Holds(handle)) ||
				(except != "sfopenapi" && sfApps != nil && sfApps.Holds(handle))
		}
	}
	if o.credentials != "" {
		bearer, err = filestore.LoadCredentials(o.credentials)
		if err != nil {
			return err
		}
		credentials, bearerTokens = append(credentials, bearer), bearer.Len()
	}
	if o.developerTokens != "" {
		developer, err = filestore.LoadDeveloperTokens(o.developerTokens, heldElsewhere("developer"), logger)
		if err != nil {
			return err
		}
		credentials, developerTokens = append(credentials, developer), developer.Len()
	}
	if o.oauthClients != "" {
		oauth, err = oauthclient.Load(oauthclient.Config{Path: o.oauthClients, Timeout: o.oauthTimeout,
			Reserved: heldElsewhere("oauth"), Logger: logger})
		if err != nil {
			return err
		}
		credentials, oauthClients = append(credentials, oauth), oauth.Len()
	}
	if o.sfOpenAPIApps != "" {
		sfApps, err = sfopenapi.Load(sfopenapi.Config{Path: o.sfOpenAPIApps, Timeout: o.sfOpenAPITimeout,
			PlainHTTPHost: o.sfOpenAPIPlainHTTPHost, Reserved: heldElsewhere("sfopenapi"), Logger: logger})
		if err != nil {
			return err
		}
		credentials, sfOpenAPIApps = append(credentials, sfApps), sfApps.Len()
	}
	tlsConfig, err := workloadtls.ServerConfig(o.tlsCert, o.tlsKey, o.clientCA)
	if err != nil {
		return err
	}

	// 账户的使用授权：默认只看登记表；配置了 Gatekeeper 就每次再问它一遍。
	grantSource := "policy"
	var pdpTLS *tls.Config
	var options []application.Option
	if o.gatekeeperURL != "" {
		token, err := gatekeeper.LoadToken(o.gatekeeperToken)
		if err != nil {
			return err
		}
		if o.gatekeeperCert != "" {
			pdpTLS, err = workloadtls.ClientConfig(o.gatekeeperCert, o.gatekeeperKey, o.gatekeeperCA, o.gatekeeperName)
			if err != nil {
				return fmt.Errorf("gatekeeper: %w", err)
			}
		}
		grants, err := gatekeeper.New(gatekeeper.Config{BaseURL: o.gatekeeperURL, Token: token, TLS: pdpTLS})
		if err != nil {
			return err
		}
		grantSource = "policy+gatekeeper"
		options = append(options, application.WithGrants(grants))
	}
	rateLimits := "disabled"
	rateLimitBuckets := 0
	if o.rateLimits != "" {
		limits, err := filestore.LoadRateLimits(o.rateLimits, logger)
		if err != nil {
			return err
		}
		rateLimits, rateLimitBuckets = "enabled", limits.Len()
		options = append(options, application.WithRateLimiter(limits))
	}

	// 撤销表：给了文件就用文件里的那一张，它也是能改的那一张；没有给就在内存里，没有人能改。
	revocationStore, revokedAccounts, revocationEpoch := "memory", 0, uint64(0)
	inMemory := &memory.Revocations{}
	var revocations ports.Revocations = inMemory
	var ledger *filestore.Revocations
	if o.revocations != "" {
		ledger, err = filestore.LoadRevocations(o.revocations)
		if err != nil {
			return err
		}
		accounts, epoch, err := ledger.Revoked(ctx)
		if err != nil {
			return err
		}
		revocations, inMemory = ledger, nil
		revocationStore, revokedAccounts, revocationEpoch = "file", len(accounts), epoch
		options = append(options, application.WithRevocationLedger(ledger))
	}
	callers := httpapi.Callers{Gateway: o.gatewayIdentity, Broker: o.brokerIdentity, Revoker: o.revokerIdentity}
	service := application.New(policy, credentials, revocations, options...)
	var handler http.Handler = httpapi.New(service, callers, logger)
	var serverLog io.Writer = &serverLogWriter{logger: logger}
	handler, serverLog, err = install(handler, serverLog, seams{listen: o.listen, callers: callers,
		revocationsInMemory: inMemory, revocationsInFile: ledger, logger: logger})
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
		"policy_version", policy.Version, "operations", len(policy.Operations),
		"credentials", bearerTokens, "developer_tokens", developerTokens, "oauth_clients", oauthClients,
		"sf_openapi_apps", sfOpenAPIApps, "sf_openapi_plain_http_host", o.sfOpenAPIPlainHTTPHost,
		"revocations", revocationStore, "revoked_accounts", revokedAccounts, "revocation_epoch", revocationEpoch,
		"gateway_identity", o.gatewayIdentity, "broker_identity", o.brokerIdentity, "revoker_identity", o.revokerIdentity,
		"grants", grantSource, "gatekeeper_mtls", pdpTLS != nil,
		"rate_limits", rateLimits, "rate_limit_buckets", rateLimitBuckets)
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

// credentialSources 依次问各个凭证来源：前一个没有这个账户的凭证，才问后一个。别的错误原样
// 返回，不再往下问。同一个句柄只会在一个来源里，所以先后不影响结果。
type credentialSources []ports.CredentialSource

func (s credentialSources) AuthorizationHeader(ctx context.Context, bindingRef, accountID string) (ports.Secret, error) {
	for _, source := range s {
		credential, err := source.AuthorizationHeader(ctx, bindingRef, accountID)
		if !errors.Is(err, ports.ErrCredentialNotHeld) {
			return credential, err
		}
	}
	return ports.Secret{}, fmt.Errorf("%w: %s", ports.ErrCredentialNotHeld, ports.Handle(bindingRef, accountID))
}

// serverLogWriter 把 net/http 自己写的日志行（被拒绝的 TLS 握手等）并入结构化日志。
type serverLogWriter struct{ logger *slog.Logger }

func (w *serverLogWriter) Write(p []byte) (int, error) {
	w.logger.Warn("http server", "detail", strings.TrimSpace(string(p)))
	return len(p), nil
}
