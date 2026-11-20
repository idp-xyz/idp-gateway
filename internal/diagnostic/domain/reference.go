package domain

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	ReasonScopeMismatch            = "SCOPE_MISMATCH"
	ReasonApprovalIdentityMissing  = "APPROVAL_IDENTITY_MISSING"
	ReasonInvalidCaptureTimestamps = "INVALID_CAPTURE_TIMESTAMPS"
	ReasonWindowExceeded           = "WINDOW_EXCEEDED"
	ReasonOutsideApprovedWindow    = "OUTSIDE_APPROVED_WINDOW"
	ReasonUnsafeLimit              = "UNSAFE_LIMIT"
	ReasonApprovedBoundScope       = "APPROVED_BOUND_SCOPE"

	IssueDuplicateStage                        = "DUPLICATE_STAGE"
	IssueUnobservedStageHasObservations        = "UNOBSERVED_STAGE_HAS_OBSERVATIONS"
	IssueNotSentOutcomeWithUpstreamExchange    = "NOT_SENT_OUTCOME_WITH_UPSTREAM_EXCHANGE"
	IssueSuccessOutcomeWithoutUpstreamResponse = "SUCCESS_OUTCOME_WITHOUT_UPSTREAM_RESPONSE"

	StageIngress            = "INGRESS"
	StageEgress             = "EGRESS"
	StageUpstreamResponse   = "UPSTREAM_RESPONSE"
	StageDownstreamResponse = "DOWNSTREAM_RESPONSE"

	BodyStatusNotCaptured = "NOT_CAPTURED"

	maxWindow           = 900 * time.Second
	maxBytesPerMessage  = 65536
	maxHeaderValueRunes = 256
)

// StageNames 返回契约 diagnostic-event.schema.json 里 stage 的四个名字，顺序相同。
// 不增加第五个。返回值不是对运行中网关的观察。
func StageNames() []string {
	return []string{StageIngress, StageEgress, StageUpstreamResponse, StageDownstreamResponse}
}

// AllowedHeaders 返回诊断证据可以携带的头名称，小写，已排序。
// 与 diagnostic-event.schema.json 的 sanitized_header_name 是同一组。
func AllowedHeaders() []string {
	names := make([]string, 0, len(allowedHeaders))
	for name := range allowedHeaders {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

var allowedHeaders = map[string]struct{}{
	"content-type":          {},
	"x-request-id":          {},
	"x-correlation-id":      {},
	"x-provider-request-id": {},
	"traceparent":           {},
}

var unobservedStatuses = map[string]struct{}{
	"NOT_SENT":     {},
	"NOT_OBSERVED": {},
}

var observationFields = []string{
	"http_status",
	"grpc_status",
	"sanitized_headers",
	"body_sha256",
	"body_sample_sanitized",
	"bytes_observed",
	"body_total_bytes",
	"body_captured_bytes",
	"content_type",
	"provider_request_id_sanitized",
}

var errBadTime = errors.New("capture timestamp")

// 小数秒可选。时区可以是 Z（调用前已换成数字偏移）、±HH:MM、±HHMM、±HH、±HH:MM:SS。
var timeLayouts = []string{
	time.RFC3339Nano,
	"2006-01-02T15:04:05.999999999Z07:00:00",
	"2006-01-02T15:04:05.999999999Z0700",
	"2006-01-02T15:04:05.999999999Z07",
	"2006-01-02T15:04Z07:00",
	"2006-01-02T15:04Z07:00:00",
	"2006-01-02T15:04Z0700",
	"2006-01-02T15:04Z07",
}

// AuthorizeCapture 在 JSON Schema 之外检查采集授权的范围、申请人和时间窗。
// 它不验证身份签名。
func AuthorizeCapture(grant map[string]any, trustedRoute, trustedTenant, trustedEnvironment string, now time.Time) (bool, string) {
	if len(grant) == 0 ||
		grant["route_ref"] != trustedRoute ||
		grant["tenant_ref"] != trustedTenant ||
		grant["environment"] != trustedEnvironment {
		return false, ReasonScopeMismatch
	}
	// 2026-11-19 仓库所有者决定本项目不区分操作人和审批人，因此去掉 SEGREGATION_OF_DUTIES。
	// approved_by 可以空着，也可以和 requested_by 是同一个人；那不是错误。
	if identity(grant["requested_by"]) == "" {
		return false, ReasonApprovalIdentityMissing
	}
	start, errStart := parseUTC(grant["start_at"])
	end, errEnd := parseUTC(grant["expires_at"])
	if errStart != nil || errEnd != nil {
		return false, ReasonInvalidCaptureTimestamps
	}
	if !end.After(start) || end.Sub(start) > maxWindow {
		return false, ReasonWindowExceeded
	}
	instant := now.UTC()
	if instant.Before(start) || !instant.Before(end) {
		return false, ReasonOutsideApprovedWindow
	}
	limit, ok := strictInt(grant["max_bytes_per_message"])
	if !ok || limit < 0 || limit > maxBytesPerMessage {
		return false, ReasonUnsafeLimit
	}
	return true, ReasonApprovedBoundScope
}

// identity 是参与者引用的可比形式。不是字符串，或去掉空白后为空，就没有指名任何人。
// 授权只拿它判断 requested_by 是否非空，不再拿它比较申请人和审批人。
func identity(value any) string {
	text, ok := value.(string)
	if !ok {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(text))
}

// parseUTC 对应参照里的 _utc：把 Z 换成数字偏移，要求带时区，再归一到 UTC。
// datetime 只保留到微秒，这里同样截断。没有时区或无法解析都是错误。
func parseUTC(value any) (time.Time, error) {
	text, ok := value.(string)
	if !ok || text == "" {
		return time.Time{}, errBadTime
	}
	normalized := strings.ReplaceAll(text, "Z", "+00:00")
	if len(normalized) >= 11 && normalized[10] == ' ' {
		normalized = normalized[:10] + "T" + normalized[11:]
	}
	for _, layout := range timeLayouts {
		parsed, err := time.Parse(layout, normalized)
		if err == nil {
			return parsed.UTC().Truncate(time.Microsecond), nil
		}
	}
	return time.Time{}, errBadTime
}

// strictInt 只接受整数。bool、字符串、浮点（含整数值的浮点）都不是上限。
func strictInt(value any) (int, bool) {
	switch n := value.(type) {
	case int:
		return n, true
	case int32:
		return int(n), true
	case int64:
		if int64(int(n)) != n {
			return 0, false
		}
		return int(n), true
	case json.Number:
		literal := string(n)
		if !integerLiteral(literal) {
			return 0, false
		}
		parsed, err := strconv.Atoi(literal)
		return parsed, err == nil
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

// EventSemanticErrors 检查诊断事件里 JSON Schema 表达不了的一致性。
//
// 应在契约校验之后调用。空列表表示这几条规则没有发现矛盾，不表示这些阶段
// 在运行的网关上真的发生过。阶段名字只有契约里的四个。
func EventSemanticErrors(event map[string]any) []string {
	if event == nil {
		event = map[string]any{}
	}
	stages := eventStages(event)
	var issues []string
	if duplicateStage(stages) {
		issues = append(issues, IssueDuplicateStage)
	}
	for _, stage := range stages {
		if unobserved(stage) && hasObservation(stage) {
			issues = append(issues, IssueUnobservedStageHasObservations)
			break
		}
	}
	byName := stagesByName(stages)
	outcome, _ := event["business_outcome"].(string)
	if outcome == "NOT_SENT" && (observed(byName, StageEgress) || observed(byName, StageUpstreamResponse)) {
		issues = append(issues, IssueNotSentOutcomeWithUpstreamExchange)
	}
	if outcome == "SUCCESS" && !observed(byName, StageUpstreamResponse) {
		issues = append(issues, IssueSuccessOutcomeWithoutUpstreamResponse)
	}
	return uniqueSorted(issues)
}

func eventStages(event map[string]any) []map[string]any {
	raw, ok := event["stages"].([]any)
	if !ok {
		return nil
	}
	stages := make([]map[string]any, 0, len(raw))
	for _, item := range raw {
		stage, ok := item.(map[string]any)
		if ok {
			stages = append(stages, stage)
		}
	}
	return stages
}

func duplicateStage(stages []map[string]any) bool {
	seen := make(map[string]struct{}, len(stages))
	for _, stage := range stages {
		key := stageKey(stage["stage"])
		if _, ok := seen[key]; ok {
			return true
		}
		seen[key] = struct{}{}
	}
	return false
}

func stageKey(value any) string {
	switch n := value.(type) {
	case nil:
		return "nil"
	case string:
		return "s:" + n
	default:
		return fmt.Sprintf("%T:%v", n, n)
	}
}

func unobserved(stage map[string]any) bool {
	status, ok := stage["status"].(string)
	if !ok {
		return false
	}
	_, found := unobservedStatuses[status]
	return found
}

func hasObservation(stage map[string]any) bool {
	for _, field := range observationFields {
		if _, ok := stage[field]; ok {
			return true
		}
	}
	return false
}

func stagesByName(stages []map[string]any) map[string]map[string]any {
	byName := make(map[string]map[string]any, len(stages))
	for _, stage := range stages {
		name, ok := stage["stage"].(string)
		if !ok {
			continue
		}
		byName[name] = stage
	}
	return byName
}

func observed(byName map[string]map[string]any, name string) bool {
	stage, ok := byName[name]
	if !ok {
		return false
	}
	return !unobserved(stage)
}

func uniqueSorted(issues []string) []string {
	if len(issues) == 0 {
		return []string{}
	}
	sort.Strings(issues)
	out := make([]string, 0, len(issues))
	for _, issue := range issues {
		if len(out) == 0 || out[len(out)-1] != issue {
			out = append(out, issue)
		}
	}
	return out
}

// SanitizeHeaders 只保留允许名单里的头，名字按小写留下。
// 名单以外的头（包括 Authorization 和其他自定义头）丢掉。
// 值必须是字符串，并且短于 256 个 Unicode 码位。
// 只是大小写不同的同一个名字，按键的字节序留下后一个。
func SanitizeHeaders(headers map[string]any) map[string]string {
	keys := make([]string, 0, len(headers))
	for key := range headers {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := make(map[string]string)
	for _, key := range keys {
		name := strings.ToLower(key)
		if _, ok := allowedHeaders[name]; !ok {
			continue
		}
		text, ok := headers[key].(string)
		if !ok || utf8.RuneCountInString(text) >= maxHeaderValueRunes {
			continue
		}
		out[name] = text
	}
	return out
}

// Evidence 是可以留下的诊断材料。没有正文字段。
type Evidence struct {
	SanitizedHeaders                map[string]string `json:"sanitized_headers"`
	BodyStatus                      string            `json:"body_status"`
	BodySampleSanitized             *string           `json:"body_sample_sanitized"`
	CaptureGrantPresent             bool              `json:"capture_grant_present"`
	ProductionPayloadCaptureEnabled bool              `json:"production_payload_capture_enabled"`
}

// SanitizedEvidence 返回允许留下的头，以及固定的未采集正文状态。
// body 是调用方手里的正文（[]byte、string、object 或 nil）。它不进入返回值。
// 生产环境的正文采集没有实现；captureGrant 只用来标记这份授权在不在。
func SanitizedEvidence(headers map[string]any, body any, captureGrant map[string]any) Evidence {
	_ = body
	return Evidence{
		SanitizedHeaders:                SanitizeHeaders(headers),
		BodyStatus:                      BodyStatusNotCaptured,
		BodySampleSanitized:             nil,
		CaptureGrantPresent:             len(captureGrant) > 0,
		ProductionPayloadCaptureEnabled: false,
	}
}
