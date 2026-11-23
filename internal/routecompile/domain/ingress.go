package domain

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
)

// 入口规格的 route_timeout 与契约的 pattern 相同：至少 1 秒，单位只有秒。
var reIngressRouteTimeout = regexp.MustCompile(`^[1-9][0-9]*s$`)

// 入口路由名与契约的 route_id 相同。多个方法时再加小写方法，那个名字可以更长。
var reIngressRouteID = regexp.MustCompile(`^[a-z][a-z0-9-]{2,63}$`)

// 转到后端的请求头只有这三项。调用方的 JWT 留在网关，不进这个名单。
const ingressHeaderFilter = `request.headers.filterKeys(k, k in ["accept", "content-type", "traceparent"])`

// 应答里去掉的头。入口没有判定编号可删。location 防止把调用方带去上游，set-cookie 不透传。
var ingressRemovedResponseHeaders = []string{"location", "set-cookie"}

// IngressSpec 是入口编译的输入。主机名、签发者、受众和后端都在这份文档里，编译器不写死。
type IngressSpec struct {
	TrafficClass string         `json:"traffic_class"`
	Pool         IngressPool    `json:"pool"`
	Backend      IngressBackend `json:"backend"`
	Routes       []IngressRoute `json:"routes"`
}

// IngressPool 是入口监听和调用方 JWT 的那一组。没有承运商，也没有凭证。
type IngressPool struct {
	Name              string       `json:"name"`
	Environment       string       `json:"environment"`
	PublicHostname    string       `json:"public_hostname"`
	ListenPort        int          `json:"listen_port"`
	BindAddress       string       `json:"bind_address"`
	AdminAddr         string       `json:"admin_addr"`
	StatsAddr         string       `json:"stats_addr"`
	ReadinessAddr     string       `json:"readiness_addr"`
	ReadbackPort      int          `json:"readback_port"`
	PublisherIdentity string       `json:"publisher_identity"`
	TLSDir            string       `json:"tls_dir"`
	JWTIssuer         string       `json:"jwt_issuer"`
	JWTAudiences      []string     `json:"jwt_audiences"`
	JWKSFile          string       `json:"jwks_file"`
	Notes             string       `json:"notes,omitempty"`
	Tracing           *TracingSpec `json:"tracing,omitempty"`
}

// IngressBackend 是入口后面的那个服务。upstream_tls 只能是 VERIFY_REQUIRED。
type IngressBackend struct {
	BackendServiceRef string `json:"backend_service_ref"`
	UpstreamHost      string `json:"upstream_host"`
	UpstreamPort      int    `json:"upstream_port"`
	UpstreamTLS       string `json:"upstream_tls"`
	UpstreamSNI       string `json:"upstream_sni,omitempty"`
	RouteTimeout      string `json:"route_timeout"`
}

// IngressRoute 是一条入口路由。公开主机名不在这里，监听用的是池的 public_hostname。
type IngressRoute struct {
	IntentID           string   `json:"intent_id"`
	RouteID            string   `json:"route_id"`
	LogicalPath        string   `json:"logical_path"`
	AllowedMethods     []string `json:"allowed_methods"`
	APIAssetRef        string   `json:"api_asset_ref"`
	AuthzProfile       string   `json:"authz_profile"`
	ApprovalRef        string   `json:"approval_ref"`
	ExpectedGeneration int      `json:"expected_generation"`
	Transport          string   `json:"transport"`
	PolicyBundleRef    string   `json:"policy_bundle_ref"`
}

// IngressDocument 判断原始 JSON 是不是入口规格。
// 只有对象里的 traffic_class 等于字符串 INGRESS 才算。缺这个字段、不是字符串，
// 或者是别的值，都返回 false，调用方继续走出站的 ParseSpec。
func IngressDocument(data []byte) bool {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var doc map[string]any
	if err := dec.Decode(&doc); err != nil {
		return false
	}
	class, ok := doc["traffic_class"].(string)
	return ok && class == ClassIngress
}

// ParseIngressSpec 解码入口规格。未知字段、环境变量引用和敏感键都拒绝。
// 语法错误不是 Refusal。不要把入口文档交给 ParseSpec：它没有 provider，解不进 CompileSpec。
func ParseIngressSpec(data []byte) (IngressSpec, error) {
	if envReference.Match(data) {
		return IngressSpec{}, &Refusal{Issues: []Issue{{Code: "ENV_REFERENCE", Reason: "spec contains an environment variable reference"}}}
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var spec IngressSpec
	if err := dec.Decode(&spec); err != nil {
		if strings.Contains(err.Error(), "unknown field") {
			return IngressSpec{}, &Refusal{Issues: []Issue{{Code: "UNKNOWN_FIELD", Reason: err.Error()}}}
		}
		return IngressSpec{}, fmt.Errorf("ingress compile spec: %w", err)
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return IngressSpec{}, fmt.Errorf("ingress compile spec: extra JSON value")
	}
	if issues := secretIssues(data); len(issues) > 0 {
		return IngressSpec{}, &Refusal{Issues: issues}
	}
	if spec.TrafficClass != ClassIngress {
		return IngressSpec{}, &Refusal{Issues: []Issue{{Code: "TRAFFIC_CLASS", Reason: "traffic_class must be INGRESS"}}}
	}
	return spec, nil
}

// CompileIngress 把入口规格编成网关 YAML 和一份没有承运商操作的策略 JSON。
// 任何一条不满足就整份拒绝，不返回半份配置。
func CompileIngress(spec IngressSpec) (CompiledArtifacts, error) {
	if issues := ingressIssues(spec); len(issues) > 0 {
		return CompiledArtifacts{}, &Refusal{Issues: issues}
	}
	report := Evaluate(nil, spec.intentRaws(), nil, PreflightOptions{})
	if report.IssueCount > 0 {
		return CompiledArtifacts{}, &Refusal{Issues: report.Issues}
	}
	gateway := emitIngressGateway(spec)
	policy := emitIngressPolicy(spec)
	if envReference.Match(gateway) || envReference.Match(policy) {
		return CompiledArtifacts{}, &Refusal{Issues: []Issue{{Code: "ENV_REFERENCE", Reason: "compiled output contains an environment variable reference"}}}
	}
	if bytes.Contains(gateway, []byte("\nsession:")) || bytes.Contains(gateway, []byte("\nsession :")) {
		return CompiledArtifacts{}, &Refusal{Issues: []Issue{{Code: "SESSION_KEY", Reason: "compiled gateway config contains a session key"}}}
	}
	return CompiledArtifacts{
		GatewayYAML:   gateway,
		PolicyJSON:    policy,
		GatewaySHA256: sha256Hex(gateway),
		PolicySHA256:  sha256Hex(policy),
		RouteCount:    ingressRouteCount(spec),
	}, nil
}

func ingressIssues(spec IngressSpec) []Issue {
	var issues []Issue
	add := func(code, reason string) {
		issues = append(issues, Issue{Code: code, Reason: reason})
	}
	raw, err := json.Marshal(spec)
	if err != nil {
		add("SPEC", err.Error())
		return issues
	}
	if envReference.Match(raw) {
		add("ENV_REFERENCE", "spec contains an environment variable reference")
	}
	if spec.TrafficClass != ClassIngress {
		add("TRAFFIC_CLASS", "traffic_class must be INGRESS")
	}
	if !reHostname.MatchString(spec.Pool.PublicHostname) {
		add("PUBLIC_HOSTNAME", "public_hostname is not a DNS name")
	}
	if !reHostname.MatchString(spec.Backend.UpstreamHost) {
		add("UPSTREAM_HOST", "upstream_host is not a DNS name")
	}
	if spec.Backend.UpstreamSNI != "" && !reHostname.MatchString(spec.Backend.UpstreamSNI) {
		add("UPSTREAM_SNI", "upstream_sni is not a DNS name")
	}
	if len(spec.Pool.JWTAudiences) == 0 {
		add("JWT_AUDIENCE", "jwt_audiences must not be empty")
	}
	for _, audience := range spec.Pool.JWTAudiences {
		if audience == "" || strings.ContainsAny(audience, " \n\r\t") {
			add("JWT_AUDIENCE", "jwt audience is empty or contains whitespace")
		}
	}
	if spec.Pool.JWTIssuer == "" || strings.ContainsAny(spec.Pool.JWTIssuer, " \n\r\t") {
		add("JWT_ISSUER", "jwt_issuer is empty or contains whitespace")
	}
	if len(spec.Routes) == 0 {
		add("NO_ROUTES", "at least one route is required")
	}
	if spec.Backend.UpstreamTLS != TLSVerifyRequired {
		add("UPSTREAM_TLS", "upstream_tls must be VERIFY_REQUIRED")
	}
	if !reIngressRouteTimeout.MatchString(spec.Backend.RouteTimeout) {
		add("ROUTE_TIMEOUT", "route_timeout must match ^[1-9][0-9]*s$")
	}
	if spec.Pool.ListenPort < 1 || spec.Pool.ListenPort > 65535 {
		add("LISTEN_PORT", "listen_port is out of range")
	}
	if spec.Pool.ReadbackPort < 1 || spec.Pool.ReadbackPort > 65535 || spec.Pool.ReadbackPort == spec.Pool.ListenPort {
		add("READBACK_PORT", "readback_port must be a distinct TCP port")
	}
	if spec.Backend.UpstreamPort < 1 || spec.Backend.UpstreamPort > 65535 {
		add("UPSTREAM_PORT", "upstream_port is out of range")
	}
	// 示例里的回环地址不是唯一合法值。空的、带空白的、或者三个地址撞在一起的，写出来网关绑不上。
	if spec.Pool.BindAddress == "" || strings.ContainsAny(spec.Pool.BindAddress, " \n\r\t") {
		add("BIND_ADDRESS", "bind_address is empty or contains whitespace")
	}
	admin, stats, ready := spec.Pool.AdminAddr, spec.Pool.StatsAddr, spec.Pool.ReadinessAddr
	if admin == "" || stats == "" || ready == "" ||
		strings.ContainsAny(admin, " \n\r\t") || strings.ContainsAny(stats, " \n\r\t") || strings.ContainsAny(ready, " \n\r\t") ||
		admin == stats || admin == ready || stats == ready {
		add("ADMIN_ADDR", "admin_addr, stats_addr and readiness_addr must be distinct single-line addresses")
	}
	if !strings.HasPrefix(spec.Pool.PublisherIdentity, "spiffe://") || strings.ContainsAny(spec.Pool.PublisherIdentity, " \"\\$'\n\r\t") {
		add("PUBLISHER_IDENTITY", "publisher_identity must be a spiffe id without quotes or references")
	}
	if !relativePath(spec.Pool.TLSDir) || !relativePath(spec.Pool.JWKSFile) {
		add("TLS_PATH", "tls_dir and jwks_file must be relative paths")
	}
	issues = append(issues, tracingIssues(spec.Pool.Tracing, spec.Pool.Environment)...)
	seenName := map[string]struct{}{}
	seenMatch := map[string]struct{}{}
	for _, route := range spec.Routes {
		if len(route.AllowedMethods) == 0 {
			add("ALLOWED_METHODS", "allowed_methods must not be empty")
		}
		if !reIngressRouteID.MatchString(route.RouteID) {
			add("ROUTE_ID", "route_id must match ^[a-z][a-z0-9-]{2,63}$")
		}
		for i, name := range ingressEmittedNames(route) {
			if _, ok := seenName[name]; ok {
				add("DUPLICATE_ROUTE", "route name "+name+" is repeated")
			}
			seenName[name] = struct{}{}
			method := ""
			if i < len(route.AllowedMethods) {
				method = route.AllowedMethods[i]
			}
			key := method + " " + route.LogicalPath
			if _, ok := seenMatch[key]; ok {
				add("DUPLICATE_METHOD_PATH", "method and path "+key+" are repeated")
			}
			seenMatch[key] = struct{}{}
		}
	}
	return issues
}

// intentRaws 按 tests/contracts/test_ingress_compile_spec.py 拼 RouteIntent。
// 公开主机名来自池，不来自路由上的另一个字段。预检用现成的 Evaluate，不另写一套。
func (s IngressSpec) intentRaws() []map[string]any {
	out := make([]map[string]any, len(s.Routes))
	for i, route := range s.Routes {
		methods := make([]any, len(route.AllowedMethods))
		for j, method := range route.AllowedMethods {
			methods[j] = method
		}
		out[i] = map[string]any{
			"intent_id":           route.IntentID,
			"gateway_pool":        s.Pool.Name,
			"traffic_class":       ClassIngress,
			"environment":         s.Pool.Environment,
			"logical_path":        route.LogicalPath,
			"allowed_methods":     methods,
			"public_hostname":     s.Pool.PublicHostname,
			"backend_service_ref": s.Backend.BackendServiceRef,
			"api_asset_ref":       route.APIAssetRef,
			"authz_profile":       route.AuthzProfile,
			"approval_ref":        route.ApprovalRef,
			"expected_generation": route.ExpectedGeneration,
			"transport":           route.Transport,
			"policy_bundle_ref":   route.PolicyBundleRef,
		}
	}
	return out
}

// ingressRouteCount 只数业务路由。回读路由不计入，出站的 RouteCount 同样不计入 read-back。
func ingressRouteCount(spec IngressSpec) int {
	n := 0
	for _, route := range spec.Routes {
		n += len(route.AllowedMethods)
	}
	return n
}

// 一个方法时名字就是 route_id。多个方法时每个方法一条，名字是 route_id 加小写方法。
func ingressEmittedNames(route IngressRoute) []string {
	names := make([]string, len(route.AllowedMethods))
	for i, method := range route.AllowedMethods {
		if len(route.AllowedMethods) == 1 {
			names[i] = route.RouteID
			continue
		}
		names[i] = route.RouteID + "-" + strings.ToLower(method)
	}
	return names
}

func ingressAuthority(backend IngressBackend) string {
	if backend.UpstreamSNI != "" {
		return backend.UpstreamSNI
	}
	return backend.UpstreamHost
}

func emitIngressGateway(spec IngressSpec) []byte {
	var routes []*ynode
	for _, route := range spec.Routes {
		names := ingressEmittedNames(route)
		for i, method := range route.AllowedMethods {
			routes = append(routes, ingressBusinessRoute(spec, names[i], method, route))
		}
	}
	routes = append(routes, readBackRoute(spec.Pool.AdminAddr))
	root := ym(
		yp("config", ym(
			yp("adminAddr", ys(spec.Pool.AdminAddr)),
			yp("statsAddr", ys(spec.Pool.StatsAddr)),
			yp("readinessAddr", ys(spec.Pool.ReadinessAddr)),
			yp("storage", ym(yp("mode", ys("readOnly")))),
		)),
		yp("frontendPolicies", ingressFrontend(spec)),
		yp("gateways", ym(
			yp("read-back", ym(
				yp("port", yi(spec.Pool.ReadbackPort)),
				yp("tls", ym(
					yp("cert", ys(tlsPath(spec.Pool.TLSDir, "gateway-readback.crt"))),
					yp("key", ys(tlsPath(spec.Pool.TLSDir, "gateway-readback.key"))),
					yp("root", ys(tlsPath(spec.Pool.TLSDir, "ca.crt"))),
				)),
			)),
			yp(spec.Pool.Name, ym(
				yp("port", yi(spec.Pool.ListenPort)),
				yp("bindAddress", ys(spec.Pool.BindAddress)),
				yp("protocol", ys("HTTP")),
				yp("jwtAuth", ym(
					yp("mode", ys("strict")),
					yp("issuer", ys(spec.Pool.JWTIssuer)),
					yp("audiences", stringSeq(spec.Pool.JWTAudiences)),
					yp("jwks", ym(yp("file", ys(spec.Pool.JWKSFile)))),
				)),
			)),
		)),
		yp("routes", yq(routes...)),
	)
	var buf bytes.Buffer
	root.write(&buf, 0, false)
	return buf.Bytes()
}

func ingressFrontend(spec IngressSpec) *ynode {
	pairs := []ypair{
		yp("networkAuthorization", ym(
			yp("rules", yq(
				ym(yp("allow", ys("destination.port == "+strconv.Itoa(spec.Pool.ListenPort)))),
				ym(yp("allow", ys("destination.port == "+strconv.Itoa(spec.Pool.ReadbackPort)+" && source.spiffeId == "+strconv.Quote(spec.Pool.PublisherIdentity)))),
			)),
		)),
		yp("accessLog", ym(
			yp("add", ym(
				yp("tenant_ref", ys(fixedTenantRef)),
			)),
		)),
	}
	if spec.Pool.Tracing != nil {
		pairs = append(pairs, yp("tracing", tracingPolicy(spec.Pool.Tracing, false)))
	}
	return ym(pairs...)
}

func ingressBusinessRoute(spec IngressSpec, name, method string, route IngressRoute) *ynode {
	authority := ingressAuthority(spec.Backend)
	return ym(
		yp("name", ys(name)),
		yp("gateways", stringSeq([]string{spec.Pool.Name})),
		yp("hostnames", stringSeq([]string{spec.Pool.PublicHostname})),
		yp("matches", yq(ym(
			yp("path", ym(yp("pathPrefix", ys(route.LogicalPath)))),
			yp("method", ys(method)),
		))),
		yp("policies", ym(
			yp("authorization", ym(yp("rules", yq(ym(yp("allow", ys("request.path == "+strconv.Quote(route.LogicalPath)))))))),
			yp("urlRewrite", ym(
				yp("authority", ym(yp("full", ys(authority)))),
			)),
			yp("responseHeaderModifier", ym(yp("remove", stringSeq(ingressRemovedResponseHeaders)))),
			yp("timeout", ym(yp("requestTimeout", ys(spec.Backend.RouteTimeout)))),
		)),
		yp("backends", yq(ym(
			yp("host", ys(spec.Backend.UpstreamHost+":"+strconv.Itoa(spec.Backend.UpstreamPort))),
			yp("policies", ym(
				yp("backendTLS", certBundle(spec.Pool.TLSDir, authority)),
				yp("transformations", ym(yp("request", ym(yp("replace", ys(ingressHeaderFilter)))))),
			)),
		))),
	)
}

// 入口的策略文件不是承运商登记表。没有 provider_id，没有凭证句柄，也没有账户。
func emitIngressPolicy(spec IngressSpec) []byte {
	doc := ingressPolicyDocument{
		Version:              "ingress",
		DefaultDecision:      "DENY",
		RegisteredOperations: []any{},
		Notes:                spec.Pool.Notes,
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(doc); err != nil {
		panic(err)
	}
	return buf.Bytes()
}

type ingressPolicyDocument struct {
	Version              string `json:"version"`
	DefaultDecision      string `json:"default_decision"`
	RegisteredOperations []any  `json:"registered_operations"`
	Notes                string `json:"notes,omitempty"`
}
