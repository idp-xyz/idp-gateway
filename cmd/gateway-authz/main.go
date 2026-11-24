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
// --sf-openapi-lease-url、--sf-openapi-lease-cert、--sf-openapi-lease-key、--sf-openapi-lease-ca、
// --sf-openapi-lease-name 五个一起给时，取令牌先问租约协调器；五个都不给时与原来相同。
// 给了协调器之后它不可用就失败关闭，不退回去单独向承运商取票。这五个要和 --sf-openapi-apps 一起给。
// 一个凭证句柄只能出现在其中一个文件里。
//
// 撤销与配额的跨副本协调（docs/adr/ADR-0023.md）：--authz-state-url、--authz-state-cert、
// --authz-state-key、--authz-state-ca、--authz-state-name 五个一起给时，撤销表的读和写走协调器，
// 启动时必须先取到一份快照，否则不启动。五个都不给时仍是本地文件和本地配额桶。这五个要和
// --revocations、--revoker-identity 一起给。同时给了 --rate-limits 时，配额扣费也走协调器；
// 没给 --rate-limits 则不发配额请求。协调器不可用时失败关闭，不用旧快照放行。
//
// 撤销（见 docs/adr/ADR-0012.md）：--revocations 给出保存撤销表的文件，--revoker-identity
// 给出唯一能改它的工作负载身份，两个要一起给。都不给时撤销表在内存里、永远是空的，也没有
// 改它的接口。
//
// --rate-limits 可选。给出时按文件里的配额对每个 Provider 账户限流，超额回答 429 和
// Retry-After，原因码 RATE_LIMITED。不给则不限流。文件里没有秘密。
//
// 登记表文件被原子换掉之后，下一次判定和版本查询用新的一份；新文件读不成或文件不见时继续用上一份，
// 绝不换成空表。--publisher-identity 可选，给出时这个工作负载身份可以 GET /v1/egress/policy-version
// 只读查询当前登记表版本，不能要判定、凭证或改撤销表。它必须与 --gateway-identity、--broker-identity、
// --revoker-identity 都不同。不给则不开放这个接口。
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

	"go.idp.xyz/idp-gateway/internal/egressauthz/adapters/authzstate"
	"go.idp.xyz/idp-gateway/internal/egressauthz/adapters/filestore"
	"go.idp.xyz/idp-gateway/internal/egressauthz/adapters/gatekeeper"
	"go.idp.xyz/idp-gateway/internal/egressauthz/adapters/httpapi"
	"go.idp.xyz/idp-gateway/internal/egressauthz/adapters/memory"
	"go.idp.xyz/idp-gateway/internal/egressauthz/adapters/oauthclient"
	"go.idp.xyz/idp-gateway/internal/egressauthz/adapters/sfopenapi"
	"go.idp.xyz/idp-gateway/internal/egressauthz/application"
	"go.idp.xyz/idp-gateway/internal/egressauthz/ports"
	"go.idp.xyz/idp-gateway/internal/platform/audit"
	"go.idp.xyz/idp-gateway/internal/platform/otlp"
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
	sfOpenAPILeaseURL      string
	sfOpenAPILeaseCert     string
	sfOpenAPILeaseKey      string
	sfOpenAPILeaseCA       string
	sfOpenAPILeaseName     string
	authzStateURL          string
	authzStateCert         string
	authzStateKey          string
	authzStateCA           string
	authzStateName         string
	gatewayIdentity        string
	brokerIdentity         string
	revocations            string
	revokerIdentity        string
	publisherIdentity      string
	gatekeeperURL          string
	gatekeeperToken        string
	gatekeeperCert         string
	gatekeeperKey          string
	gatekeeperCA           string
	gatekeeperName         string
	rateLimits             string
	otlpTracesURL          string
	auditLog               string
	metricsListen          string
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
	add(&o.sfOpenAPILeaseURL, "sf-openapi-lease-url", "顺丰访问令牌租约协调器的 https 地址。与下面四个 --sf-openapi-lease-* 要么一起给、要么都不给；"+
		"要和 --sf-openapi-apps 一起给。给了之后协调器不可用就失败关闭，不退回去单独向承运商取票", false)
	add(&o.sfOpenAPILeaseCert, "sf-openapi-lease-cert", "出示给租约协调器的工作负载证书（PEM）；文件替换后下一次连接用新的", false)
	add(&o.sfOpenAPILeaseKey, "sf-openapi-lease-key", "上面那张证书的私钥（PEM）", false)
	add(&o.sfOpenAPILeaseCA, "sf-openapi-lease-ca", "签发租约协调器证书的 CA（PEM）；系统自带的根证书不被信任", false)
	add(&o.sfOpenAPILeaseName, "sf-openapi-lease-name", "验证租约协调器证书时要对上的名字", false)
	add(&o.authzStateURL, "authz-state-url", "撤销与配额协调器的 https 地址。与下面四个 --authz-state-* 要么一起给、要么都不给；"+
		"要和 --revocations、--revoker-identity 一起给。给了之后每一次判定都向它取新快照，取不到就失败关闭，不用旧快照放行", false)
	add(&o.authzStateCert, "authz-state-cert", "出示给撤销协调器的工作负载证书（PEM）；文件替换后下一次连接用新的", false)
	add(&o.authzStateKey, "authz-state-key", "上面那张证书的私钥（PEM）", false)
	add(&o.authzStateCA, "authz-state-ca", "签发撤销协调器证书的 CA（PEM）；系统自带的根证书不被信任", false)
	add(&o.authzStateName, "authz-state-name", "验证撤销协调器证书时要对上的名字", false)
	add(&o.gatewayIdentity, "gateway-identity", "网关工作负载的身份（证书里的 URI）：可以要判定和凭证", true)
	add(&o.brokerIdentity, "broker-identity", "本地 Broker 工作负载的身份：只能要判定；不设则没有这样的调用方", false)
	add(&o.revocations, "revocations", "撤销文件（JSON：代次和被撤销的账户），权限须为 0600 或更严；启动时读，读不成就不启动；"+
		"之后只由本进程写。要和 --revoker-identity 一起给", false)
	add(&o.revokerIdentity, "revoker-identity", "能改撤销表的工作负载身份：只能撤销、恢复和读出撤销表。要和 --revocations 一起给", false)
	add(&o.publisherIdentity, "publisher-identity", "能只读查询当前登记表版本的工作负载身份：只能 GET /v1/egress/policy-version，"+
		"不能要判定、凭证或改撤销表。不设则不开放这个接口。必须与 --gateway-identity、--broker-identity、--revoker-identity 都不同", false)
	add(&o.gatekeeperURL, "gatekeeper-url", "Gatekeeper PDP 的地址；设了它，登记表放行的请求还要 Gatekeeper 确认账户的使用授权", false)
	add(&o.gatekeeperToken, "gatekeeper-token-file", "访问 Gatekeeper PDP 的 Bearer 令牌文件，权限须为 0600 或更严", false)
	add(&o.gatekeeperCert, "gatekeeper-tls-cert", "本服务出示给 Gatekeeper PDP 的工作负载证书（PEM）。四个 --gatekeeper-tls-* / --gatekeeper-name 要么都给、要么都不给；"+
		"--gatekeeper-url 不是回环地址时必须给，给了之后它必须是 https", false)
	add(&o.gatekeeperKey, "gatekeeper-tls-key", "上面那张证书的私钥（PEM）", false)
	add(&o.gatekeeperCA, "gatekeeper-tls-ca", "签发 PDP 一端证书的 CA（PEM）；系统自带的根证书不被信任", false)
	add(&o.gatekeeperName, "gatekeeper-name", "验证 PDP 一端证书时要对上的名字", false)
	add(&o.rateLimits, "rate-limits", "按 Provider 账户限流的配额文件（JSON：version 与 buckets）。不设则不限流。"+
		"文件里没有秘密，0644 或 0600 都可以；启动时读不成就不启动；文件被换掉之后重读，新文件读不成就沿用上一份", false)
	add(&o.otlpTracesURL, "otlp-traces-url", "OTLP/HTTP JSON 的 traces 地址，例如 http://127.0.0.1:4318/v1/traces；不设则不导出", false)
	add(&o.auditLog, "audit-log", "追加写入的审计 JSONL；权限须为 0600，不设则不写", false)
	add(&o.metricsListen, "metrics-listen", "只提供 GET /metrics 的明文 HTTP 地址，例如 127.0.0.1:19091；不设则没有指标端口，也不把 /metrics 加到 mTLS 监听上", false)
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
	if err := checkSFLease(o); err != nil {
		return o, err
	}
	if err := checkAuthzState(o); err != nil {
		return o, err
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
	if o.publisherIdentity != "" && (o.publisherIdentity == o.gatewayIdentity || o.publisherIdentity == o.brokerIdentity ||
		o.publisherIdentity == o.revokerIdentity) {
		return o, errors.New("--publisher-identity must differ from --gateway-identity, --broker-identity and --revoker-identity: " +
			"who reads the policy version may not ask for a decision, a credential, or a change to the revocation table")
	}
	if o.otlpTracesURL != "" {
		if err := otlp.ValidateEndpoint(o.otlpTracesURL); err != nil {
			return o, fmt.Errorf("--otlp-traces-url: %w", err)
		}
	}
	if strings.ContainsAny(o.auditLog, "\r\n") || strings.ContainsAny(o.metricsListen, "\r\n") {
		return o, errors.New("--audit-log and --metrics-listen must be a single line")
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

// checkSFLease 核对五个租约参数：要么都给，要么都不给，而且要和 --sf-openapi-apps 一起给。
// 地址必须是没有用户信息、查询串和片段的 https。错误文字里不回显这个地址。
func checkSFLease(o options) error {
	given := 0
	for _, v := range []string{o.sfOpenAPILeaseURL, o.sfOpenAPILeaseCert, o.sfOpenAPILeaseKey, o.sfOpenAPILeaseCA, o.sfOpenAPILeaseName} {
		if v != "" {
			given++
		}
	}
	if given == 0 {
		return nil
	}
	if given != 5 {
		return errors.New("--sf-openapi-lease-url, --sf-openapi-lease-cert, --sf-openapi-lease-key, --sf-openapi-lease-ca and --sf-openapi-lease-name go together")
	}
	if o.sfOpenAPIApps == "" {
		return errors.New("--sf-openapi-lease-url needs --sf-openapi-apps")
	}
	address, err := url.Parse(o.sfOpenAPILeaseURL)
	if err != nil || address.Scheme != "https" || address.Host == "" || address.User != nil || address.RawQuery != "" || address.Fragment != "" {
		return errors.New("--sf-openapi-lease-url must be an https URL without user information, a query string, or a fragment")
	}
	return nil
}

// checkAuthzState 核对五个撤销协调参数：要么都给，要么都不给，而且要和撤销文件、撤销者身份一起给。
// 地址必须是没有用户信息、查询串和片段的 https。错误文字里不回显这个地址。
// 调用它时，--revocations 和 --revoker-identity 是否成对还没检查；这里只要求两个都非空。
func checkAuthzState(o options) error {
	given := 0
	for _, v := range []string{o.authzStateURL, o.authzStateCert, o.authzStateKey, o.authzStateCA, o.authzStateName} {
		if v != "" {
			given++
		}
	}
	if given == 0 {
		return nil
	}
	if given != 5 {
		return errors.New("--authz-state-url, --authz-state-cert, --authz-state-key, --authz-state-ca and --authz-state-name go together")
	}
	if o.revocations == "" || o.revokerIdentity == "" {
		return errors.New("--authz-state-url needs --revocations and --revoker-identity")
	}
	address, err := url.Parse(o.authzStateURL)
	if err != nil || address.Scheme != "https" || address.Host == "" || address.User != nil || address.RawQuery != "" || address.Fragment != "" {
		return errors.New("--authz-state-url must be an https URL without user information, a query string, or a fragment")
	}
	return nil
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

	policyFile, err := filestore.LoadPolicyFile(o.policy, logger)
	if err != nil {
		return err
	}
	policy := policyFile.Current()
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
		var lease sfopenapi.LeaseCoordinator
		if o.sfOpenAPILeaseURL != "" {
			leaseTLS, err := workloadtls.ClientConfigWithLogger(o.sfOpenAPILeaseCert, o.sfOpenAPILeaseKey, o.sfOpenAPILeaseCA, o.sfOpenAPILeaseName, logger)
			if err != nil {
				return fmt.Errorf("sf openapi lease: %w", err)
			}
			lease, err = sfopenapi.NewHTTPLeaseClient(o.sfOpenAPILeaseURL, leaseTLS, logger)
			if err != nil {
				return fmt.Errorf("sf openapi lease: %w", err)
			}
		}
		sfApps, err = sfopenapi.Load(sfopenapi.Config{Path: o.sfOpenAPIApps, Timeout: o.sfOpenAPITimeout,
			PlainHTTPHost: o.sfOpenAPIPlainHTTPHost, Reserved: heldElsewhere("sfopenapi"), Logger: logger, Lease: lease})
		if err != nil {
			return err
		}
		credentials, sfOpenAPIApps = append(credentials, sfApps), sfApps.Len()
	}
	tlsConfig, err := workloadtls.ServerConfigWithLogger(o.tlsCert, o.tlsKey, o.clientCA, logger)
	if err != nil {
		return err
	}

	// 账户的使用授权：默认只看登记表；配置了 Gatekeeper 就每次再问它一遍。
	grantSource := "policy"
	var pdpTLS *tls.Config
	var options []application.Option
	options = append(options, application.WithPolicySource(policyFile))
	if o.gatekeeperURL != "" {
		token, err := gatekeeper.LoadToken(o.gatekeeperToken)
		if err != nil {
			return err
		}
		if o.gatekeeperCert != "" {
			pdpTLS, err = workloadtls.ClientConfigWithLogger(o.gatekeeperCert, o.gatekeeperKey, o.gatekeeperCA, o.gatekeeperName, logger)
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
	var stateClient *authzstate.Client
	if o.authzStateURL != "" {
		stateTLS, err := workloadtls.ClientConfigWithLogger(o.authzStateCert, o.authzStateKey, o.authzStateCA, o.authzStateName, logger)
		if err != nil {
			return fmt.Errorf("authz state: %w", err)
		}
		stateClient, err = authzstate.New(o.authzStateURL, stateTLS, logger)
		if err != nil {
			return fmt.Errorf("authz state: %w", err)
		}
	}
	rateLimits := "disabled"
	rateLimitBuckets := 0
	if o.rateLimits != "" {
		limits, err := filestore.LoadRateLimits(o.rateLimits, logger)
		if err != nil {
			return err
		}
		rateLimits, rateLimitBuckets = "enabled", limits.Len()
		var limiter ports.RateLimiter = limits
		if stateClient != nil {
			limiter = authzstate.NewLimiter(stateClient, limits, logger)
		}
		options = append(options, application.WithRateLimiter(limiter))
	}

	// 撤销表：给了文件就用文件里的那一张，它也是能改的那一张；没有给就在内存里，没有人能改。
	// 给了协调器时，读和写都走协调器。启动先取一份快照写回文件；取不到不启动。
	// 验收控制仍拿着这份文件。不传协调参数时，下面的分支与原来相同。
	revocationStore, revokedAccounts, revocationEpoch := "memory", 0, uint64(0)
	inMemory := &memory.Revocations{}
	var revocations ports.Revocations = inMemory
	var ledger *filestore.Revocations
	if o.revocations != "" {
		ledger, err = filestore.LoadRevocations(o.revocations)
		if err != nil {
			return err
		}
		if stateClient != nil {
			if err := authzstate.Mirror(ctx, stateClient, ledger); err != nil {
				return fmt.Errorf("authz state: %w", err)
			}
		}
		accounts, epoch, err := ledger.Revoked(ctx)
		if err != nil {
			return err
		}
		revocations, inMemory = ledger, nil
		revocationStore, revokedAccounts, revocationEpoch = "file", len(accounts), epoch
		var ledgerPort ports.RevocationLedger = ledger
		if stateClient != nil {
			wrapped := authzstate.NewLedger(stateClient, ledger, logger)
			revocations = wrapped
			ledgerPort = wrapped
			revocationStore = "authz-state"
		}
		options = append(options, application.WithRevocationLedger(ledgerPort))
	}
	callers := httpapi.Callers{Gateway: o.gatewayIdentity, Broker: o.brokerIdentity, Revoker: o.revokerIdentity, Publisher: o.publisherIdentity}
	service := application.New(policyFile.Current(), credentials, revocations, options...)
	api := httpapi.New(service, callers, logger)
	traces, sink, metrics, err := openAuthzTelemetry(o, service)
	if err != nil {
		return err
	}
	defer func() {
		if traces != nil {
			_ = traces.Close(context.Background())
		}
		if sink != nil {
			_ = sink.Close()
		}
	}()
	if o.otlpTracesURL != "" || o.auditLog != "" || o.metricsListen != "" {
		api.WithTelemetry(httpapi.Telemetry{Service: "idp-gateway-authz", Traces: traces, Audit: sink, Metrics: metrics})
	}
	var handler http.Handler = api
	var serverLog io.Writer = &serverLogWriter{logger: logger}
	handler, serverLog, err = install(handler, serverLog, seams{listen: o.listen, callers: callers,
		revocationsInMemory: inMemory, revocationsInFile: ledger, logger: logger})
	if err != nil {
		return err
	}

	var metricsLn net.Listener
	if o.metricsListen != "" {
		metricsLn, err = net.Listen("tcp", o.metricsListen)
		if err != nil {
			return fmt.Errorf("--metrics-listen: %w", err)
		}
	}
	listener, err := net.Listen("tcp", o.listen)
	if err != nil {
		if metricsLn != nil {
			_ = metricsLn.Close()
		}
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
		"policy_version", policy.Version, "operations", policyFile.Len(),
		"credentials", bearerTokens, "developer_tokens", developerTokens, "oauth_clients", oauthClients,
		"sf_openapi_apps", sfOpenAPIApps, "sf_openapi_plain_http_host", o.sfOpenAPIPlainHTTPHost,
		"sf_openapi_lease", o.sfOpenAPILeaseURL != "",
		"authz_state", o.authzStateURL != "",
		"authz_state_quota", o.authzStateURL != "" && o.rateLimits != "",
		"revocations", revocationStore, "revoked_accounts", revokedAccounts, "revocation_epoch", revocationEpoch,
		"gateway_identity", o.gatewayIdentity, "broker_identity", o.brokerIdentity, "revoker_identity", o.revokerIdentity,
		"publisher_identity", o.publisherIdentity,
		"grants", grantSource, "gatekeeper_mtls", pdpTLS != nil,
		"rate_limits", rateLimits, "rate_limit_buckets", rateLimitBuckets)
	if o.otlpTracesURL != "" || o.auditLog != "" || o.metricsListen != "" {
		logger.Info("gateway-authz telemetry", "otlp", o.otlpTracesURL, "audit_log", o.auditLog, "metrics_listen", o.metricsListen)
	}
	if ready != nil {
		ready(listener.Addr())
	}

	var metricsSrv *http.Server
	served := make(chan error, 2)
	go func() { served <- server.ServeTLS(listener, "", "") }()
	if metricsLn != nil {
		metricsSrv = &http.Server{
			Handler:           metrics,
			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       10 * time.Second,
			WriteTimeout:      10 * time.Second,
			IdleTimeout:       60 * time.Second,
			MaxHeaderBytes:    64 << 10,
			ErrorLog:          log.New(serverLog, "", 0),
		}
		go func() { served <- metricsSrv.Serve(metricsLn) }()
	}
	select {
	case err := <-served:
		stopCtx, stop := context.WithTimeout(context.Background(), 10*time.Second)
		_ = server.Shutdown(stopCtx)
		if metricsSrv != nil {
			_ = metricsSrv.Shutdown(stopCtx)
		}
		stop()
		if errors.Is(err, http.ErrServerClosed) {
			logger.Info("gateway-authz stopped")
			return nil
		}
		return err
	case <-ctx.Done():
	}
	// 停止接受新连接，等在途的判定答完。导出器在函数返回时刷出剩余 span。
	shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdown); err != nil {
		return fmt.Errorf("shutdown: %w", err)
	}
	if metricsSrv != nil {
		if err := metricsSrv.Shutdown(shutdown); err != nil {
			return fmt.Errorf("metrics shutdown: %w", err)
		}
	}
	logger.Info("gateway-authz stopped")
	return nil
}

// openAuthzTelemetry 按三个可选开关打开导出器、审计文件和指标。任一失败时关掉已经打开的。
func openAuthzTelemetry(o options, service *application.Service) (*otlp.Exporter, *audit.FileSink, *httpapi.AuthzMetrics, error) {
	var traces *otlp.Exporter
	var sink *audit.FileSink
	var err error
	closePartial := func() {
		if traces != nil {
			_ = traces.Close(context.Background())
		}
		if sink != nil {
			_ = sink.Close()
		}
	}
	if o.otlpTracesURL != "" {
		traces, err = otlp.NewExporter(otlp.Config{Endpoint: o.otlpTracesURL, ServiceName: "idp-gateway-authz", ServiceVersion: buildFlavor})
		if err != nil {
			return nil, nil, nil, fmt.Errorf("--otlp-traces-url: %w", err)
		}
	}
	if o.auditLog != "" {
		sink, err = audit.Open(o.auditLog)
		if err != nil {
			closePartial()
			return nil, nil, nil, fmt.Errorf("--audit-log: %w", err)
		}
	}
	var metrics *httpapi.AuthzMetrics
	if o.metricsListen != "" {
		metrics = httpapi.NewAuthzMetrics(func() uint64 {
			return service.RevocationEpoch(context.Background())
		}, func() (uint64, uint64, uint64) {
			if traces == nil {
				return 0, 0, 0
			}
			return traces.Stats()
		})
	}
	return traces, sink, metrics, nil
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
