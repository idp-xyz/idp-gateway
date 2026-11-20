package domain

import (
	"encoding/json"
	"errors"
	"sort"
	"strings"
)

var errNotObject = errors.New("provider registry: not a JSON object")

// 保留名和敏感键与 scripts/preflight_intents.py 相同。后缀是第二道检查，不是放行依据。
var (
	reservedSuffixes = []string{".internal", ".local", ".localhost", ".test", ".invalid", ".onion", ".home.arpa"}
	reservedHosts    = map[string]struct{}{
		"localhost": {}, "metadata.google.internal": {}, "169.254.169.254": {}, "metadata.aws.internal": {},
	}
	sensitiveKeys = map[string]struct{}{
		"password": {}, "client_secret": {}, "secret_value": {}, "api_key": {},
		"access_token": {}, "refresh_token": {}, "private_key": {}, "authorization": {}, "bearer_token": {},
	}
)

// Evaluate 对一组意图做静态预检。rawObjects 与 intents 一一对应时，以原始对象为准
// （这样才能看见结构体不认识的字段和敏感键）。registry 为 nil 表示什么都没登记。
func Evaluate(intents []Intent, rawObjects []map[string]any, registry *Registry, opts PreflightOptions) Report {
	items := make([]any, 0, len(rawObjects)+len(intents))
	switch {
	case len(rawObjects) > 0:
		if len(intents) > 0 && len(intents) != len(rawObjects) {
			report := newReport(items, registry)
			report.Issues = []Issue{{Reason: "INTENT_COUNT_MISMATCH"}}
			report.IssueCount = 1
			report.Status = StatusReject
			report.IntentsSHA256 = sha256Hex(canonicalJSON(itemsFromMaps(rawObjects)))
			return report
		}
		for _, obj := range rawObjects {
			items = append(items, obj)
		}
	default:
		for _, intent := range intents {
			items = append(items, intent.asMap())
		}
	}
	return evaluateItems(items, registry, opts)
}

// EvaluateItems 预检一份已经解码的 JSON 文档元素（对象或数组里的每一项）。
// 非对象记为 INTENT_NOT_OBJECT，仍然算进摘要。
func EvaluateItems(items []any, registry *Registry, opts PreflightOptions) Report {
	return evaluateItems(items, registry, opts)
}

func evaluateItems(items []any, registry *Registry, opts PreflightOptions) Report {
	report := newReport(items, registry)
	var issues []Issue
	var dicts []map[string]any
	for _, item := range items {
		obj, ok := item.(map[string]any)
		if !ok {
			issues = append(issues, Issue{IntentID: "UNKNOWN", Reason: "INTENT_NOT_OBJECT"})
			continue
		}
		dicts = append(dicts, obj)
		id := intentID(obj)
		for _, reason := range append(schemaErrors(obj, opts), safetyErrors(obj, registry, opts)...) {
			issues = append(issues, Issue{IntentID: id, Reason: reason})
		}
	}
	issues = append(issues, conflicts(dicts)...)
	issues = append(issues, prefixOverlaps(dicts)...)
	if issues == nil {
		issues = []Issue{}
	}
	report.Issues = issues
	report.IssueCount = len(issues)
	if len(issues) > 0 {
		report.Status = StatusReject
	}
	return report
}

func newReport(items []any, registry *Registry) Report {
	return Report{
		Status:                 StatusPreflightOK,
		IntentsSHA256:          sha256Hex(canonicalJSON(items)),
		ProviderRegistrySHA256: sha256Hex(canonicalJSON(registryDocument(registry))),
		Issues:                 []Issue{},
	}
}

func registryDocument(registry *Registry) any {
	if registry == nil || registry.Document == nil {
		return map[string]any{}
	}
	return registry.Document
}

func itemsFromMaps(raw []map[string]any) []any {
	items := make([]any, len(raw))
	for i, obj := range raw {
		items[i] = obj
	}
	return items
}

func intentID(obj map[string]any) string {
	v, ok := obj["intent_id"]
	if !ok || v == nil {
		return "UNKNOWN"
	}
	s, ok := v.(string)
	if !ok {
		return "UNKNOWN"
	}
	return s
}

func safetyErrors(obj map[string]any, registry *Registry, opts PreflightOptions) []string {
	var issues []string
	path, _ := obj["logical_path"].(string)
	if _, isStr := obj["logical_path"].(string); !isStr || (path != "/" && !IsCanonicalPath(path)) {
		issues = append(issues, "NON_CANONICAL_LOGICAL_PATH")
	}
	poolText, _ := obj["gateway_pool"].(string)
	class, _ := obj["traffic_class"].(string)
	env, _ := obj["environment"].(string)
	if pool := rePoolName.FindStringSubmatch(poolText); pool == nil || strings.ToUpper(pool[1]) != class || strings.ToUpper(pool[2]) != env {
		issues = append(issues, "POOL_CLASS_ENVIRONMENT_MISMATCH")
	}
	if class == ClassEgress {
		issues = append(issues, registryErrors(obj, registry)...)
		rawHost, _ := obj["upstream_hostname"].(string)
		host := strings.TrimRight(strings.ToLower(rawHost), ".")
		if host == "" || reservedHost(host) || reservedSuffix(host) {
			issues = append(issues, "UNAPPROVED_UPSTREAM_DOMAIN")
		}
		if strings.ContainsAny(host, "@%:") {
			issues = append(issues, "UNSAFE_UPSTREAM_HOSTNAME")
		}
		if isIPLiteral(host) {
			issues = append(issues, "IP_LITERAL_UPSTREAM_DENIED")
		}
		if sni, ok := obj["upstream_sni"].(string); ok && sni != "" && sni != rawHost {
			issues = append(issues, "SNI_HOST_MISMATCH_REQUIRES_SIGNED_EXCEPTION")
		}
		redir, _ := obj["redirect_policy"].(string)
		if redir != RedirectDeny {
			issues = append(issues, "REDIRECT_NOT_DENIED")
		}
		tls, _ := obj["upstream_tls"].(string)
		if !plainHTTPAllowed(rawHost, env, tls, opts) && tls != TLSVerifyRequired {
			issues = append(issues, "TLS_VERIFICATION_MISSING")
		}
		if opts.AllowInternalBackendHost != "" && rawHost == opts.AllowInternalBackendHost {
			if tls != TLSVerifyRequired || !opts.BackendTLSConfigured {
				issues = append(issues, "INTERNAL_BACKEND_TLS_REQUIRED")
			}
		}
		ref, _ := obj["credential_binding_ref"].(string)
		if !strings.HasPrefix(ref, "gatekeeper:") {
			issues = append(issues, "NO_GATEKEEPER_CREDENTIAL_REFERENCE")
		}
	}
	if class == ClassIngress {
		if public, ok := obj["public_hostname"].(string); ok && reservedHost(public) {
			issues = append(issues, "UNSAFE_PUBLIC_HOST")
		}
	}
	for key, value := range obj {
		if _, ok := sensitiveKeys[strings.ToLower(key)]; ok && truthy(value) {
			issues = append(issues, "CREDENTIAL_VALUE_IN_INTENT")
		}
	}
	sort.Strings(issues)
	return uniqueStrings(issues)
}

func reservedHost(host string) bool {
	_, ok := reservedHosts[host]
	return ok
}

func reservedSuffix(host string) bool {
	for _, suffix := range reservedSuffixes {
		if strings.HasSuffix(host, suffix) {
			return true
		}
	}
	return false
}

func registryErrors(obj map[string]any, registry *Registry) []string {
	var rows []RegistryRow
	if registry != nil {
		rows = append(rows, registry.RegisteredOperations...)
	}
	provider := stringField(obj, "provider_id")
	env := stringField(obj, "environment")
	rows = filterRows(rows, func(row RegistryRow) bool {
		return row.ProviderID == provider && row.Environment == env
	})
	if len(rows) == 0 {
		return []string{"PROVIDER_NOT_REGISTERED"}
	}
	host := stringField(obj, "upstream_hostname")
	port, portOK := asInt(obj["upstream_port"])
	rows = filterRows(rows, func(row RegistryRow) bool {
		return portOK && row.UpstreamHostname == host && row.Port == port
	})
	if len(rows) == 0 {
		return []string{"UPSTREAM_NOT_REGISTERED_FOR_PROVIDER"}
	}
	operation := stringField(obj, "operation_id")
	path := stringField(obj, "logical_path")
	rows = filterRows(rows, func(row RegistryRow) bool {
		return row.OperationID == operation && IsCanonicalPath(row.PathPrefix) && under(path, row.PathPrefix)
	})
	methods, methodsOK := asStringSlice(obj["allowed_methods"])
	covered := map[string]struct{}{}
	for _, row := range rows {
		covered[row.Method] = struct{}{}
	}
	if len(rows) == 0 || !methodsOK || len(methods) == 0 || !methodsCovered(methods, covered) {
		return []string{"OPERATION_NOT_REGISTERED"}
	}
	wanted := map[string]struct{}{}
	for _, method := range methods {
		wanted[method] = struct{}{}
	}
	for _, row := range rows {
		if _, ok := wanted[row.Method]; ok && row.CredentialBindingRef != stringField(obj, "credential_binding_ref") {
			return []string{"CREDENTIAL_BINDING_NOT_REGISTERED"}
		}
	}
	return nil
}

func methodsCovered(methods []string, covered map[string]struct{}) bool {
	for _, method := range methods {
		if _, ok := covered[method]; !ok {
			return false
		}
	}
	return true
}

func filterRows(rows []RegistryRow, keep func(RegistryRow) bool) []RegistryRow {
	out := make([]RegistryRow, 0, len(rows))
	for _, row := range rows {
		if keep(row) {
			out = append(out, row)
		}
	}
	return out
}

func under(path, prefix string) bool {
	return prefix == "/" || path == prefix || strings.HasPrefix(path, prefix+"/")
}

func conflicts(intents []map[string]any) []Issue {
	var issues []Issue
	index := map[string]string{}
	for _, obj := range intents {
		host := any("*")
		if stringField(obj, "traffic_class") == ClassIngress {
			if v, ok := obj["public_hostname"]; ok {
				host = v
			} else {
				host = nil
			}
		}
		for _, method := range methodSet(obj) {
			key := []any{
				jsonNull(obj, "environment"),
				jsonNull(obj, "gateway_pool"),
				jsonNull(obj, "traffic_class"),
				host,
				jsonNull(obj, "logical_path"),
				method,
			}
			encoded := canonicalKey(key)
			id := intentID(obj)
			prev, seen := index[encoded]
			if !seen {
				index[encoded] = id
				continue
			}
			if prev != id {
				issues = append(issues, Issue{
					Code: "EXACT_ROUTE_CONFLICT", First: prev, Second: id, RouteKey: key,
				})
			}
		}
	}
	return issues
}

func prefixOverlaps(intents []map[string]any) []Issue {
	var issues []Issue
	for i := 0; i < len(intents); i++ {
		for j := i + 1; j < len(intents); j++ {
			a, b := intents[i], intents[j]
			pa, pb := stringField(a, "logical_path"), stringField(b, "logical_path")
			if scopeKey(a) != scopeKey(b) || pa == pb || !(under(pa, pb) || under(pb, pa)) {
				continue
			}
			if !methodsOverlap(a, b) {
				continue
			}
			paPri, aOK := explicitPriority(a)
			pbPri, bOK := explicitPriority(b)
			if aOK && bOK && paPri != pbPri {
				continue
			}
			issues = append(issues, Issue{
				Code: "PREFIX_ROUTE_OVERLAP", First: intentID(a), Second: intentID(b), Paths: []string{pa, pb},
			})
		}
	}
	return issues
}

func scopeKey(obj map[string]any) string {
	host := "*"
	if stringField(obj, "traffic_class") == ClassIngress {
		host = stringField(obj, "public_hostname")
	}
	return stringField(obj, "environment") + "\x00" + stringField(obj, "gateway_pool") + "\x00" + stringField(obj, "traffic_class") + "\x00" + host
}

func methodsOverlap(a, b map[string]any) bool {
	left, right := methodSet(a), methodSet(b)
	for _, method := range left {
		if method == "*" {
			return true
		}
		for _, other := range right {
			if other == "*" || other == method {
				return true
			}
		}
	}
	return false
}

func methodSet(obj map[string]any) []any {
	methods, ok := asStringSlice(obj["allowed_methods"])
	if !ok || len(methods) == 0 {
		return []any{"*"}
	}
	out := make([]any, len(methods))
	for i, method := range methods {
		out[i] = method
	}
	return out
}

func explicitPriority(obj map[string]any) (int, bool) {
	v, ok := obj["route_priority"]
	if !ok || v == nil {
		return 0, false
	}
	switch v.(type) {
	case bool:
		return 0, false
	}
	return asInt(v)
}

func jsonNull(obj map[string]any, key string) any {
	v, ok := obj[key]
	if !ok || v == nil {
		return nil
	}
	if s, ok := v.(string); ok {
		return s
	}
	return nil
}

func canonicalKey(parts []any) string {
	return string(canonicalJSON(parts))
}

func uniqueStrings(in []string) []string {
	if len(in) == 0 {
		return in
	}
	out := in[:1]
	for _, item := range in[1:] {
		if item != out[len(out)-1] {
			out = append(out, item)
		}
	}
	return out
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
	case int:
		return t != 0
	case int64:
		return t != 0
	case float64:
		return t != 0
	case []any:
		return len(t) > 0
	case map[string]any:
		return len(t) > 0
	default:
		return true
	}
}

func (in Intent) asMap() map[string]any {
	obj := map[string]any{
		"intent_id":           in.IntentID,
		"gateway_pool":        in.GatewayPool,
		"traffic_class":       in.TrafficClass,
		"environment":         in.Environment,
		"logical_path":        in.LogicalPath,
		"authz_profile":       in.AuthzProfile,
		"approval_ref":        in.ApprovalRef,
		"expected_generation": in.ExpectedGeneration,
	}
	putString(obj, "provider_id", in.ProviderID)
	putString(obj, "operation_id", in.OperationID)
	if len(in.AllowedMethods) > 0 {
		methods := make([]any, len(in.AllowedMethods))
		for i, method := range in.AllowedMethods {
			methods[i] = method
		}
		obj["allowed_methods"] = methods
	}
	putString(obj, "upstream_hostname", in.UpstreamHostname)
	if in.UpstreamPort != 0 {
		obj["upstream_port"] = in.UpstreamPort
	}
	putString(obj, "contract_ref", in.ContractRef)
	putString(obj, "credential_binding_ref", in.CredentialBindingRef)
	putString(obj, "redirect_policy", in.RedirectPolicy)
	putString(obj, "public_hostname", in.PublicHostname)
	putString(obj, "backend_service_ref", in.BackendServiceRef)
	putString(obj, "ai_protocol", in.AIProtocol)
	putString(obj, "ai_target_ref", in.AITargetRef)
	putString(obj, "transport", in.Transport)
	putString(obj, "policy_bundle_ref", in.PolicyBundleRef)
	putString(obj, "upstream_tls", in.UpstreamTLS)
	putString(obj, "upstream_sni", in.UpstreamSNI)
	putString(obj, "provider_account_strategy", in.ProviderAccountStrategy)
	putString(obj, "api_asset_ref", in.APIAssetRef)
	if in.HasRoutePriority {
		obj["route_priority"] = in.RoutePriority
	}
	return obj
}

func putString(obj map[string]any, key, value string) {
	if value != "" {
		obj[key] = value
	}
}

// ParseRegistry 解码一份登记表。Document 保留全部字段，摘要按整份文档计算。
func ParseRegistry(data []byte) (*Registry, error) {
	var doc any
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.UseNumber()
	if err := dec.Decode(&doc); err != nil {
		return nil, err
	}
	obj, ok := doc.(map[string]any)
	if !ok {
		return nil, errNotObject
	}
	reg := &Registry{Document: doc}
	reg.Version, _ = obj["version"].(string)
	reg.DefaultDecision, _ = obj["default_decision"].(string)
	rows, _ := obj["registered_operations"].([]any)
	for _, item := range rows {
		row, ok := item.(map[string]any)
		if !ok {
			continue
		}
		port, _ := asInt(row["port"])
		reg.RegisteredOperations = append(reg.RegisteredOperations, RegistryRow{
			ProviderID:           stringField(row, "provider_id"),
			Environment:          stringField(row, "environment"),
			UpstreamHostname:     stringField(row, "upstream_hostname"),
			Port:                 port,
			OperationID:          stringField(row, "operation_id"),
			PathPrefix:           stringField(row, "path_prefix"),
			Method:               stringField(row, "method"),
			CredentialBindingRef: stringField(row, "credential_binding_ref"),
		})
	}
	return reg, nil
}
