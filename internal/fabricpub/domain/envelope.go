package domain

import (
	"bytes"
	"encoding/json"
	"regexp"
	"strings"
)

// 九个敏感键与 routecompile 预检的 sensitiveKeys 相同。真值拒绝，空值不算。
var sensitiveKeys = map[string]struct{}{
	"password": {}, "client_secret": {}, "secret_value": {}, "api_key": {},
	"access_token": {}, "refresh_token": {}, "private_key": {}, "authorization": {}, "bearer_token": {},
}

func rejectSensitive(v any) error {
	switch t := v.(type) {
	case map[string]any:
		for key, child := range t {
			if _, ok := sensitiveKeys[strings.ToLower(key)]; ok && truthy(child) {
				return invalid("sensitive_key")
			}
			if err := rejectSensitive(child); err != nil {
				return err
			}
		}
	case []any:
		for _, child := range t {
			if err := rejectSensitive(child); err != nil {
				return err
			}
		}
	}
	return nil
}

func truthy(v any) bool {
	switch t := v.(type) {
	case nil:
		return false
	case bool:
		return t
	case string:
		return t != ""
	case json.Number:
		return string(t) != "0" && string(t) != "0.0" && string(t) != "-0"
	case []any:
		return len(t) > 0
	case map[string]any:
		return len(t) > 0
	default:
		return true
	}
}

var (
	reIntentID     = regexp.MustCompile(`^gwi-[a-z0-9-]{3,64}$`)
	reGatewayPool  = regexp.MustCompile(`^[a-z][a-z0-9-]{2,63}$`)
	rePoolName     = regexp.MustCompile(`^(ingress|egress|ai)-(dev|test|prod)(?:-[a-z0-9]+)*$`)
	reProviderID   = regexp.MustCompile(`^[a-z][a-z0-9-]{1,63}$`)
	reOperationID  = regexp.MustCompile(`^[a-z][a-z0-9_.-]{2,127}$`)
	reLogicalPath  = regexp.MustCompile(`^/(?:[A-Za-z0-9._~%-]+/?)*$`)
	reCanonical    = regexp.MustCompile(`^(/[A-Za-z0-9_~-][A-Za-z0-9._~-]*)+$`)
	rePublicHost   = regexp.MustCompile(`^(?:[a-z0-9-]+\.)+[a-z]{2,}$`)
	reInternalHost = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)
	reIdempotency  = regexp.MustCompile(`^[A-Za-z0-9._:-]{16,128}$`)
	reCredential   = regexp.MustCompile(`^gatekeeper:[a-z0-9/_-]+$`)
	rePolicyBundle = regexp.MustCompile(`^policy:[a-z0-9][a-z0-9._/-]{2,127}$`)
	reSigner       = regexp.MustCompile(`^signer:[a-z0-9/_-]+$`)
	reScheme       = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9-]* $`)
)

var allowedMethods = map[string]struct{}{
	"GET": {}, "HEAD": {}, "OPTIONS": {}, "POST": {}, "PUT": {}, "PATCH": {}, "DELETE": {},
}

var envelopeFields = map[string]struct{}{
	"idempotency_key": {}, "release_ref": {}, "target_id": {}, "intent": {},
}

var intentFields = map[string]struct{}{
	"intent_id": {}, "gateway_pool": {}, "traffic_class": {}, "environment": {},
	"provider_id": {}, "operation_id": {}, "logical_path": {}, "allowed_methods": {},
	"upstream_hostname": {}, "upstream_port": {}, "authz_profile": {}, "approval_ref": {},
	"expected_generation": {}, "contract_ref": {}, "credential_binding_ref": {},
	"redirect_policy": {}, "transport": {}, "policy_bundle_ref": {}, "upstream_tls": {},
	"upstream_sni": {}, "provider_account_strategy": {}, "route_priority": {},
}

// Intent 是一期出站 RouteIntent 里本进程要核的字段。
type Intent struct {
	IntentID                string
	GatewayPool             string
	TrafficClass            string
	Environment             string
	ProviderID              string
	OperationID             string
	LogicalPath             string
	AllowedMethods          []string
	UpstreamHostname        string
	UpstreamPort            int
	AuthzProfile            string
	ApprovalRef             string
	ExpectedGeneration      int
	ContractRef             string
	CredentialBindingRef    string
	RedirectPolicy          string
	UpstreamTLS             string
	UpstreamSNI             string
	ProviderAccountStrategy string
	Transport               string
	PolicyBundleRef         string
	RoutePriority           int
	HasRoutePriority        bool
}

// Envelope 是规范化之后的 RoutePublicationIntent。Hash 是规范化 JSON 的 SHA-256。
type Envelope struct {
	IdempotencyKey string
	ReleaseRef     string
	TargetID       string
	Intent         Intent
	Canonical      []byte
	Hash           string
}

// ParseEnvelope 严格解析发布信封和内嵌的出站 RouteIntent。
func ParseEnvelope(data []byte) (Envelope, error) {
	doc, err := parseDocument(data)
	if err != nil {
		return Envelope{}, err
	}
	obj, ok := asObject(doc.Value)
	if !ok {
		return Envelope{}, invalid("schema")
	}
	if err := unknownFields(obj, envelopeFields); err != nil {
		return Envelope{}, err
	}
	key, ok := asString(obj["idempotency_key"])
	if !ok || !reIdempotency.MatchString(key) {
		return Envelope{}, invalid("schema")
	}
	release, ok := asString(obj["release_ref"])
	if !ok || len(release) < 4 || len(release) > 160 || !plainText(release) {
		return Envelope{}, invalid("schema")
	}
	target, ok := asString(obj["target_id"])
	if !ok || len(target) < 4 || len(target) > 160 || !plainText(target) {
		return Envelope{}, invalid("schema")
	}
	intentValue, ok := obj["intent"]
	if !ok {
		return Envelope{}, invalid("schema")
	}
	intent, err := parseIntent(intentValue)
	if err != nil {
		return Envelope{}, err
	}
	return Envelope{
		IdempotencyKey: key,
		ReleaseRef:     release,
		TargetID:       target,
		Intent:         intent,
		Canonical:      append([]byte(nil), doc.Canonical...),
		Hash:           doc.Hash,
	}, nil
}

func parseIntent(value any) (Intent, error) {
	obj, ok := asObject(value)
	if !ok {
		return Intent{}, invalid("schema")
	}
	if err := unknownFields(obj, intentFields); err != nil {
		return Intent{}, err
	}
	var in Intent
	var err error
	if in.IntentID, err = needPattern(obj, "intent_id", reIntentID); err != nil {
		return Intent{}, err
	}
	if in.GatewayPool, err = needPattern(obj, "gateway_pool", reGatewayPool); err != nil {
		return Intent{}, err
	}
	if in.TrafficClass, err = needString(obj, "traffic_class"); err != nil {
		return Intent{}, err
	}
	if in.TrafficClass != "EGRESS" {
		return Intent{}, invalid("schema")
	}
	if in.Environment, err = needString(obj, "environment"); err != nil {
		return Intent{}, err
	}
	switch in.Environment {
	case "DEV", "TEST", "PROD":
	default:
		return Intent{}, invalid("schema")
	}
	pool := rePoolName.FindStringSubmatch(in.GatewayPool)
	if pool == nil || strings.ToUpper(pool[1]) != in.TrafficClass || strings.ToUpper(pool[2]) != in.Environment {
		return Intent{}, invalid("schema")
	}
	if in.ProviderID, err = needPattern(obj, "provider_id", reProviderID); err != nil {
		return Intent{}, err
	}
	if in.OperationID, err = needPattern(obj, "operation_id", reOperationID); err != nil {
		return Intent{}, err
	}
	if in.LogicalPath, err = needString(obj, "logical_path"); err != nil {
		return Intent{}, err
	}
	if !reLogicalPath.MatchString(in.LogicalPath) || !reCanonical.MatchString(in.LogicalPath) {
		return Intent{}, invalid("schema")
	}
	methods, ok := obj["allowed_methods"].([]any)
	if !ok || len(methods) != 1 {
		return Intent{}, invalid("schema")
	}
	method, ok := asString(methods[0])
	if !ok {
		return Intent{}, invalid("schema")
	}
	if _, allowed := allowedMethods[method]; !allowed {
		return Intent{}, invalid("schema")
	}
	in.AllowedMethods = []string{method}
	if in.UpstreamHostname, err = needString(obj, "upstream_hostname"); err != nil {
		return Intent{}, err
	}
	if !hostShape(in.UpstreamHostname) {
		return Intent{}, invalid("schema")
	}
	port, ok := asInt(obj["upstream_port"])
	if !ok || port < 1 || port > 65535 {
		return Intent{}, invalid("schema")
	}
	in.UpstreamPort = port
	if in.AuthzProfile, err = needString(obj, "authz_profile"); err != nil || len(in.AuthzProfile) < 3 || len(in.AuthzProfile) > 100 {
		return Intent{}, invalid("schema")
	}
	if in.ApprovalRef, err = needString(obj, "approval_ref"); err != nil || len(in.ApprovalRef) < 4 || len(in.ApprovalRef) > 128 {
		return Intent{}, invalid("schema")
	}
	generation, ok := asInt(obj["expected_generation"])
	if !ok || generation < 0 {
		return Intent{}, invalid("schema")
	}
	in.ExpectedGeneration = generation
	if in.ContractRef, err = needString(obj, "contract_ref"); err != nil || in.ContractRef == "" || len(in.ContractRef) > 160 {
		return Intent{}, invalid("schema")
	}
	if in.CredentialBindingRef, err = needPattern(obj, "credential_binding_ref", reCredential); err != nil || len(in.CredentialBindingRef) > 160 {
		return Intent{}, invalid("schema")
	}
	if in.RedirectPolicy, err = needString(obj, "redirect_policy"); err != nil || in.RedirectPolicy != "DENY" {
		return Intent{}, invalid("schema")
	}
	if in.UpstreamTLS, err = needString(obj, "upstream_tls"); err != nil {
		return Intent{}, err
	}
	switch in.UpstreamTLS {
	case "VERIFY_REQUIRED":
	case "PLAIN_HTTP_SANDBOX_EXCEPTION":
		if in.Environment == "PROD" {
			return Intent{}, invalid("schema")
		}
	default:
		return Intent{}, invalid("schema")
	}
	if raw, ok := obj["upstream_sni"]; ok {
		sni, ok := asString(raw)
		if !ok || !rePublicHost.MatchString(sni) || sni != in.UpstreamHostname {
			return Intent{}, invalid("schema")
		}
		in.UpstreamSNI = sni
	}
	if in.ProviderAccountStrategy, err = needString(obj, "provider_account_strategy"); err != nil || in.ProviderAccountStrategy != "GATEKEEPER_DECISION_BINDING" {
		return Intent{}, invalid("schema")
	}
	if in.Transport, err = needString(obj, "transport"); err != nil || in.Transport != "HTTP" {
		return Intent{}, invalid("schema")
	}
	if in.PolicyBundleRef, err = needPattern(obj, "policy_bundle_ref", rePolicyBundle); err != nil {
		return Intent{}, err
	}
	if raw, ok := obj["route_priority"]; ok {
		priority, ok := asInt(raw)
		if !ok || priority < 0 || priority > 10000 {
			return Intent{}, invalid("schema")
		}
		in.RoutePriority = priority
		in.HasRoutePriority = true
	}
	return in, nil
}

func needString(obj map[string]any, key string) (string, error) {
	value, ok := obj[key]
	if !ok {
		return "", invalid("schema")
	}
	text, ok := asString(value)
	if !ok || !plainText(text) {
		return "", invalid("schema")
	}
	return text, nil
}

func needPattern(obj map[string]any, key string, pattern *regexp.Regexp) (string, error) {
	text, err := needString(obj, key)
	if err != nil || !pattern.MatchString(text) {
		return "", invalid("schema")
	}
	return text, nil
}

func hostShape(host string) bool {
	return rePublicHost.MatchString(host) || reInternalHost.MatchString(host)
}

// CanonicalHash 是测试和幂等比对用的规范化摘要。正文相同则摘要相同，与键的书写顺序无关。
func CanonicalHash(data []byte) (string, error) {
	env, err := ParseEnvelope(data)
	if err != nil {
		return "", err
	}
	return env.Hash, nil
}

// sameCanonical 报告两份正文规范化之后是否相同。供测试使用。
func sameCanonical(a, b []byte) bool {
	left, err := parseDocument(a)
	if err != nil {
		return false
	}
	right, err := parseDocument(b)
	if err != nil {
		return false
	}
	return left.Hash == right.Hash && bytes.Equal(left.Canonical, right.Canonical)
}
