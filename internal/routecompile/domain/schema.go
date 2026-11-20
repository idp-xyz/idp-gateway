package domain

import (
	"encoding/json"
	"regexp"
	"sort"
	"strconv"
)

// 这些正则与 contracts/gateway/route-intent.schema.json 的 pattern 逐字相同。
var (
	reIntentID       = regexp.MustCompile(`^gwi-[a-z0-9-]{3,64}$`)
	reGatewayPool    = regexp.MustCompile(`^[a-z][a-z0-9-]{2,63}$`)
	reProviderID     = regexp.MustCompile(`^[a-z][a-z0-9-]{1,63}$`)
	reOperationID    = regexp.MustCompile(`^[a-z][a-z0-9_.-]{2,127}$`)
	reLogicalPath    = regexp.MustCompile(`^/(?:[A-Za-z0-9._~%-]+/?)*$`)
	reHostname       = regexp.MustCompile(`^(?:[a-z0-9-]+\.)+[a-z]{2,}$`)
	reBackendService = regexp.MustCompile(`^service:[a-z0-9][a-z0-9._/-]{2,127}$`)
	reAITarget       = regexp.MustCompile(`^ai:[a-z0-9][a-z0-9._/-]{2,127}$`)
	rePolicyBundle   = regexp.MustCompile(`^policy:[a-z0-9][a-z0-9._/-]{2,127}$`)
	reCanonicalPath  = regexp.MustCompile(`^(/[A-Za-z0-9_~-][A-Za-z0-9._~-]*)+$`)
	rePoolName       = regexp.MustCompile(`^(ingress|egress|ai)-(dev|test|prod)(?:-[a-z0-9]+)*$`)
)

var allowedMethods = map[string]struct{}{
	"GET": {}, "HEAD": {}, "OPTIONS": {}, "POST": {}, "PUT": {}, "PATCH": {}, "DELETE": {},
}

var knownIntentFields = map[string]struct{}{
	"intent_id": {}, "gateway_pool": {}, "traffic_class": {}, "environment": {},
	"provider_id": {}, "operation_id": {}, "logical_path": {}, "allowed_methods": {},
	"upstream_hostname": {}, "upstream_port": {}, "authz_profile": {}, "approval_ref": {},
	"expected_generation": {}, "contract_ref": {}, "credential_binding_ref": {},
	"redirect_policy": {}, "public_hostname": {}, "backend_service_ref": {},
	"ai_protocol": {}, "ai_target_ref": {}, "transport": {}, "route_priority": {},
	"policy_bundle_ref": {}, "upstream_tls": {}, "upstream_sni": {},
	"provider_account_strategy": {}, "api_asset_ref": {},
}

var (
	environments = map[string]struct{}{"DEV": {}, "TEST": {}, "PROD": {}}
	classes      = map[string]struct{}{ClassIngress: {}, ClassEgress: {}, ClassAI: {}}
	aiProtocols  = map[string]struct{}{"LLM": {}, "MCP": {}, "A2A": {}}
	transports   = map[string]struct{}{"HTTP": {}, "GRPC": {}}
	redirects    = map[string]struct{}{"DENY": {}, "ALLOW_SAME_APPROVED_HOST": {}}
	strategies   = map[string]struct{}{"GATEKEEPER_DECISION_BINDING": {}, "NONE": {}}
)

// schemaErrors 实现 route-intent.schema.json 的全部约束，包括三个 traffic_class 分支
// 的必填、互斥和 const。编译选项只放宽两处：明文沙箱的 upstream_tls，以及一个内部服务名的主机模式。
func schemaErrors(obj map[string]any, opts PreflightOptions) []string {
	c := &checker{obj: obj, opts: opts}
	for key := range obj {
		if _, ok := knownIntentFields[key]; !ok {
			c.msg(key + ": additional property is not allowed")
		}
	}
	c.required("intent_id", "gateway_pool", "traffic_class", "environment", "logical_path", "authz_profile", "approval_ref", "expected_generation")
	c.pattern("intent_id", reIntentID)
	c.pattern("gateway_pool", reGatewayPool)
	c.enum("traffic_class", classes)
	c.enum("environment", environments)
	c.pattern("logical_path", reLogicalPath)
	c.strlen("authz_profile", 3, 100)
	c.strlen("approval_ref", 4, 128)
	c.intRange("expected_generation", 0, -1)

	c.patternIf("provider_id", reProviderID)
	c.patternIf("operation_id", reOperationID)
	c.methods("allowed_methods")
	c.hostname("upstream_hostname")
	c.intRangeIf("upstream_port", 1, 65535)
	c.strlenIf("contract_ref", 0, 160)
	c.strlenIf("credential_binding_ref", 0, 160)
	c.enumIf("redirect_policy", redirects)
	c.hostnameIf("public_hostname")
	c.patternIf("backend_service_ref", reBackendService)
	c.enumIf("ai_protocol", aiProtocols)
	c.patternIf("ai_target_ref", reAITarget)
	c.enumIf("transport", transports)
	c.intRangeIf("route_priority", 0, 10000)
	c.patternIf("policy_bundle_ref", rePolicyBundle)
	c.upstreamTLS()
	c.hostnameIf("upstream_sni")
	c.enumIf("provider_account_strategy", strategies)
	c.strlenIf("api_asset_ref", 4, 160)

	c.branch()
	sort.Strings(c.errs)
	return c.errs
}

type checker struct {
	obj  map[string]any
	opts PreflightOptions
	errs []string
}

func (c *checker) msg(text string) { c.errs = append(c.errs, text) }

func (c *checker) required(keys ...string) {
	for _, key := range keys {
		if _, ok := c.obj[key]; !ok {
			c.msg(key + ": required property is missing")
		}
	}
}

func (c *checker) present(key string) (any, bool) {
	v, ok := c.obj[key]
	return v, ok
}

func (c *checker) pattern(key string, re *regexp.Regexp) {
	v, ok := c.present(key)
	if !ok {
		return
	}
	s, ok := v.(string)
	if !ok {
		c.msg(key + ": must be a string")
		return
	}
	if !re.MatchString(s) {
		c.msg(key + ": does not match pattern " + re.String())
	}
}

func (c *checker) patternIf(key string, re *regexp.Regexp) {
	if _, ok := c.present(key); ok {
		c.pattern(key, re)
	}
}

func (c *checker) enum(key string, allowed map[string]struct{}) {
	v, ok := c.present(key)
	if !ok {
		return
	}
	s, ok := v.(string)
	if !ok {
		c.msg(key + ": must be a string")
		return
	}
	if _, ok := allowed[s]; !ok {
		c.msg(key + ": value is not one of the allowed values")
	}
}

func (c *checker) enumIf(key string, allowed map[string]struct{}) {
	if _, ok := c.present(key); ok {
		c.enum(key, allowed)
	}
}

func (c *checker) strlen(key string, min, max int) {
	v, ok := c.present(key)
	if !ok {
		return
	}
	s, ok := v.(string)
	if !ok {
		c.msg(key + ": must be a string")
		return
	}
	if min > 0 && len(s) < min {
		c.msg(key + ": shorter than " + strconv.Itoa(min))
	}
	if max >= 0 && len(s) > max {
		c.msg(key + ": longer than " + strconv.Itoa(max))
	}
}

func (c *checker) strlenIf(key string, min, max int) {
	if _, ok := c.present(key); ok {
		c.strlen(key, min, max)
	}
}

func (c *checker) intRange(key string, min, max int) {
	v, ok := c.present(key)
	if !ok {
		return
	}
	n, ok := asInt(v)
	if !ok {
		c.msg(key + ": must be an integer")
		return
	}
	if n < min || (max >= 0 && n > max) {
		c.msg(key + ": integer is out of range")
	}
}

func (c *checker) intRangeIf(key string, min, max int) {
	if _, ok := c.present(key); ok {
		c.intRange(key, min, max)
	}
}

func (c *checker) methods(key string) {
	v, ok := c.present(key)
	if !ok {
		return
	}
	items, ok := asStringSlice(v)
	if !ok {
		c.msg(key + ": must be an array of strings")
		return
	}
	if len(items) < 1 {
		c.msg(key + ": must not be empty")
	}
	seen := map[string]struct{}{}
	for _, item := range items {
		if _, ok := allowedMethods[item]; !ok {
			c.msg(key + ": method is not allowed")
		}
		if _, dup := seen[item]; dup {
			c.msg(key + ": items must be unique")
		}
		seen[item] = struct{}{}
	}
}

func (c *checker) hostname(key string) {
	v, ok := c.present(key)
	if !ok {
		return
	}
	s, ok := v.(string)
	if !ok {
		c.msg(key + ": must be a string")
		return
	}
	if reHostname.MatchString(s) {
		return
	}
	if key == "upstream_hostname" && internalHostAllowed(s, stringField(c.obj, "upstream_tls"), c.opts) {
		return
	}
	c.msg(key + ": does not match pattern " + reHostname.String())
}

func (c *checker) hostnameIf(key string) {
	if _, ok := c.present(key); ok {
		c.hostname(key)
	}
}

func (c *checker) upstreamTLS() {
	v, ok := c.present("upstream_tls")
	if !ok {
		return
	}
	s, ok := v.(string)
	if !ok {
		c.msg("upstream_tls: must be a string")
		return
	}
	if s == TLSVerifyRequired {
		return
	}
	host := stringField(c.obj, "upstream_hostname")
	env := stringField(c.obj, "environment")
	if plainHTTPAllowed(host, env, s, c.opts) {
		return
	}
	c.msg("upstream_tls: value is not one of the allowed values")
}

func (c *checker) branch() {
	class := stringField(c.obj, "traffic_class")
	switch class {
	case ClassIngress:
		c.requirePresent("public_hostname", "backend_service_ref", "allowed_methods", "api_asset_ref")
		c.forbid("provider_account_strategy", "credential_binding_ref", "ai_protocol", "ai_target_ref", "provider_id",
			"upstream_hostname", "upstream_port", "upstream_tls", "upstream_sni", "redirect_policy", "operation_id")
	case ClassEgress:
		c.requirePresent("provider_id", "operation_id", "allowed_methods", "upstream_hostname", "upstream_port",
			"upstream_tls", "redirect_policy", "provider_account_strategy", "credential_binding_ref")
		if v, ok := c.obj["provider_account_strategy"]; ok && v != AccountStrategyGatekeeper {
			c.msg("provider_account_strategy: must be GATEKEEPER_DECISION_BINDING")
		}
		if v, ok := c.obj["redirect_policy"]; ok && v != RedirectDeny {
			c.msg("redirect_policy: must be DENY")
		}
		c.forbid("backend_service_ref", "public_hostname", "ai_protocol", "ai_target_ref")
	case ClassAI:
		c.requirePresent("ai_protocol", "ai_target_ref")
		c.forbid("provider_account_strategy", "credential_binding_ref", "backend_service_ref", "public_hostname", "provider_id",
			"upstream_hostname", "upstream_port", "upstream_tls", "upstream_sni", "redirect_policy", "operation_id")
	default:
		if class != "" {
			c.msg("traffic_class: branch is not one of INGRESS, EGRESS, AI")
		}
	}
}

func (c *checker) requirePresent(keys ...string) {
	for _, key := range keys {
		if _, ok := c.obj[key]; !ok {
			c.msg(key + ": required by the " + stringField(c.obj, "traffic_class") + " branch")
		}
	}
}

func (c *checker) forbid(keys ...string) {
	class := stringField(c.obj, "traffic_class")
	for _, key := range keys {
		if _, ok := c.obj[key]; ok {
			c.msg(key + ": not allowed on " + class)
		}
	}
}

func asInt(v any) (int, bool) {
	switch n := v.(type) {
	case json.Number:
		s := string(n)
		if !integerLiteral(s) {
			return 0, false
		}
		i, err := strconv.Atoi(s)
		return i, err == nil
	case int:
		return n, true
	case int64:
		return int(n), true
	case float64:
		if n == float64(int(n)) {
			return int(n), true
		}
		return 0, false
	default:
		return 0, false
	}
}

func integerLiteral(s string) bool {
	if s == "" {
		return false
	}
	i := 0
	if s[0] == '-' {
		if len(s) == 1 {
			return false
		}
		i = 1
	}
	for _, c := range s[i:] {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func asStringSlice(v any) ([]string, bool) {
	switch t := v.(type) {
	case []any:
		out := make([]string, len(t))
		for i, item := range t {
			s, ok := item.(string)
			if !ok {
				return nil, false
			}
			out[i] = s
		}
		return out, true
	case []string:
		return append([]string(nil), t...), true
	default:
		return nil, false
	}
}

func stringField(obj map[string]any, key string) string {
	s, _ := obj[key].(string)
	return s
}

func plainHTTPAllowed(host, env, tls string, opts PreflightOptions) bool {
	if tls != PlainHTTPSandboxException {
		return false
	}
	if opts.AllowPlainHTTPUpstreamHost == "" || host != opts.AllowPlainHTTPUpstreamHost {
		return false
	}
	// 生产环境不允许明文上游。这是唯一的闸门：删掉它，PROD 上的沙箱例外就会编过。
	if env == "PROD" {
		return false
	}
	return true
}

func internalHostAllowed(host, tls string, opts PreflightOptions) bool {
	return opts.AllowInternalBackendHost != "" &&
		host == opts.AllowInternalBackendHost &&
		tls == TLSVerifyRequired &&
		opts.BackendTLSConfigured
}

// IsCanonicalPath 判断路径是否满足出站策略的规范路径。与 internal/egressauthz/domain 的表达式相同。
func IsCanonicalPath(path string) bool {
	return reCanonicalPath.MatchString(path)
}
