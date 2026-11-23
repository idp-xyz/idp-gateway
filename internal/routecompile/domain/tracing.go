package domain

import (
	"math"
	"regexp"
	"strconv"
	"strings"
)

// TracingSpec 是可选的 agentgateway frontendPolicies.tracing。
// 不写就不出现在配置里，已有输出保持原样。这里没有密钥，也不接受环境变量引用。
type TracingSpec struct {
	Host           string   `json:"host"`
	Protocol       string   `json:"protocol,omitempty"`
	Path           string   `json:"path,omitempty"`
	ServiceName    string   `json:"service_name"`
	RandomSampling *float64 `json:"random_sampling,omitempty"`
	ClientSampling *float64 `json:"client_sampling,omitempty"`
}

// 主机是小写名字加端口。127.0.0.1 只在非 PROD 放行，别的 IP 字面量不行。
var (
	reTracingEndpoint = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]*:[1-9][0-9]*$`)
	reTracingService  = regexp.MustCompile(`^[a-z][a-z0-9._-]{1,63}$`)
)

func tracingIssues(spec *TracingSpec, environment string) []Issue {
	if spec == nil {
		return nil
	}
	var issues []Issue
	add := func(reason string) {
		issues = append(issues, Issue{Code: "TRACING", Reason: reason})
	}
	if !validTracingHost(spec.Host, environment) {
		add("tracing host must be a lowercase name and port, or 127.0.0.1:<port> outside PROD")
	}
	switch spec.Protocol {
	case "", "http", "grpc":
	default:
		add("tracing protocol must be http or grpc")
	}
	protocol := spec.Protocol
	if protocol == "" {
		protocol = "http"
	}
	switch {
	case protocol == "grpc" && spec.Path != "":
		add("tracing path is only valid for http")
	case protocol == "http" && spec.Path != "" && !validTracingPath(spec.Path):
		add("tracing path must start with / and contain no whitespace, query, or fragment")
	}
	if !reTracingService.MatchString(spec.ServiceName) {
		add("tracing service_name must match ^[a-z][a-z0-9._-]{1,63}$")
	}
	if spec.RandomSampling != nil && !validSampling(*spec.RandomSampling) {
		add("tracing random_sampling must be from 0 to 1")
	}
	if spec.ClientSampling != nil && !validSampling(*spec.ClientSampling) {
		add("tracing client_sampling must be from 0 to 1")
	}
	return issues
}

func validTracingHost(host, environment string) bool {
	if strings.ContainsAny(host, " \t\r\n/@") || strings.Contains(host, "://") {
		return false
	}
	if !reTracingEndpoint.MatchString(host) {
		return false
	}
	name, port, ok := strings.Cut(host, ":")
	if !ok {
		return false
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 || strconv.Itoa(n) != port {
		return false
	}
	if ipv4Literal(name) {
		return name == "127.0.0.1" && environment != "PROD"
	}
	return true
}

func ipv4Literal(host string) bool {
	parts := strings.Split(host, ".")
	if len(parts) != 4 {
		return false
	}
	for _, part := range parts {
		if part == "" {
			return false
		}
		n, err := strconv.Atoi(part)
		if err != nil || n < 0 || n > 255 {
			return false
		}
	}
	return true
}

func validTracingPath(path string) bool {
	return path != "" && path[0] == '/' && !strings.ContainsAny(path, " \t\r\n?#")
}

func validSampling(v float64) bool {
	return !math.IsNaN(v) && !math.IsInf(v, 0) && v >= 0 && v <= 1
}

func formatSampling(v float64) string {
	s := strconv.FormatFloat(v, 'f', -1, 64)
	if !strings.Contains(s, ".") {
		s += ".0"
	}
	return s
}

// tracingPolicy 写成 frontendPolicies.tracing。egress 多一个判定编号。
// 采样用无引号小数：锁定的 1.7.0 接受 1.0 和 0.1，也接受带引号的数字，不接受 100%。
func tracingPolicy(spec *TracingSpec, egress bool) *ynode {
	protocol := spec.Protocol
	if protocol == "" {
		protocol = "http"
	}
	pairs := []ypair{
		yp("host", ys(spec.Host)),
		yp("protocol", ys(protocol)),
	}
	if protocol == "http" {
		path := spec.Path
		if path == "" {
			path = "/v1/traces"
		}
		pairs = append(pairs, yp("path", ys(path)))
	}
	random, client := 1.0, 1.0
	if spec.RandomSampling != nil {
		random = *spec.RandomSampling
	}
	if spec.ClientSampling != nil {
		client = *spec.ClientSampling
	}
	pairs = append(pairs,
		yp("randomSampling", yf(random)),
		yp("clientSampling", yf(client)),
		yp("resources", ym(yp("service.name", ys(strconv.Quote(spec.ServiceName))))),
	)
	attrs := []ypair{}
	if egress {
		attrs = append(attrs, yp("authz_decision_id", ys(fixedAuthzDecision)))
	}
	attrs = append(attrs, yp("tenant_ref", ys(fixedTenantRef)))
	pairs = append(pairs, yp("attributes", ym(attrs...)))
	return ym(pairs...)
}
