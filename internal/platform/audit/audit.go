// Package audit 是追加写入的 JSONL 审计。文件权限是 0600，Detail 里的敏感键在写入前丢掉。
// 请求路径上用它，Console 以后用 ReadRecent 读同一份文件。只用标准库。
package audit

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"unicode/utf8"
)

// Record 是一行审计。时间由调用方写成 UTC 的 RFC3339Nano。
// 除 Timestamp、Service、EventType 外都可以空着省略。Detail 里的敏感键不会写出去。
type Record struct {
	Timestamp       string            `json:"timestamp"`
	Service         string            `json:"service"`
	EventType       string            `json:"event_type"`
	TraceID         string            `json:"trace_id,omitempty"`
	SpanID          string            `json:"span_id,omitempty"`
	ParentSpanID    string            `json:"parent_span_id,omitempty"`
	DecisionID      string            `json:"decision_id,omitempty"`
	RouteID         string            `json:"route_id,omitempty"`
	ProviderID      string            `json:"provider_id,omitempty"`
	OperationID     string            `json:"operation_id,omitempty"`
	Environment     string            `json:"environment,omitempty"`
	Tenant          string            `json:"tenant,omitempty"`
	Subject         string            `json:"subject,omitempty"`
	Account         string            `json:"account,omitempty"`
	Caller          string            `json:"caller,omitempty"`
	Method          string            `json:"method,omitempty"`
	Path            string            `json:"path,omitempty"`
	Status          int               `json:"status,omitempty"`
	Outcome         string            `json:"outcome,omitempty"`
	Reason          string            `json:"reason,omitempty"`
	FailureOrigin   string            `json:"failure_origin,omitempty"`
	PolicyVersion   string            `json:"policy_version,omitempty"`
	RevocationEpoch uint64            `json:"revocation_epoch,omitempty"`
	DurationMS      int64             `json:"duration_ms,omitempty"`
	Detail          map[string]string `json:"detail,omitempty"`
}

// Filter 的空字段不参与筛选。ReadRecent 只返回每一项都对得上的记录。
type Filter struct {
	TraceID    string
	DecisionID string
	RouteID    string
	Service    string
	EventType  string
	Outcome    string
	Reason     string
}

// FileSink 以 O_APPEND 写一个 0600 的 JSONL 文件。Write 串行，一行一次写完。
type FileSink struct {
	mu   sync.Mutex
	file *os.File
}

// 与 otlp 的属性名规则相同：键里出现这些片段就丢掉，不写出值。
var sensitiveParts = []string{
	"authorization", "token", "secret", "password", "api_key", "apikey",
	"cookie", "private_key", "credential", "aes", "bearer",
}

const maxFieldBytes = 512

// Open 打开或创建审计文件。已存在且组或其他人可读（mode & 077 != 0）时拒绝，不改它的权限。
// 新建的文件和通过检查的文件都会被收成 0600。符号链接拒绝。
func Open(path string) (*FileSink, error) {
	if path == "" || strings.ContainsAny(path, "\r\n") {
		return nil, errors.New("audit: path is empty or contains a line break")
	}
	info, err := os.Lstat(path)
	switch {
	case err == nil:
		if info.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("audit: %s is a symlink", path)
		}
		if !info.Mode().IsRegular() {
			return nil, fmt.Errorf("audit: %s is not a regular file", path)
		}
		if info.Mode().Perm()&0o077 != 0 {
			return nil, fmt.Errorf("audit: %s is readable by others", path)
		}
	case os.IsNotExist(err):
	default:
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return nil, err
	}
	checked, err := file.Stat()
	if err != nil || checked.Mode().Perm()&0o077 != 0 {
		_ = file.Close()
		if err == nil {
			err = fmt.Errorf("audit: %s is readable by others", path)
		}
		return nil, err
	}
	return &FileSink{file: file}, nil
}

// Write 清洗记录后追加一行 JSON 和一个换行。调用方的 Record 不会被改掉。
func (s *FileSink) Write(rec Record) error {
	if s == nil {
		return errors.New("audit: sink is closed")
	}
	rec = sanitizeRecord(rec)
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(rec); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.file == nil {
		return errors.New("audit: sink is closed")
	}
	_, err := s.file.Write(buf.Bytes())
	return err
}

// Close 关闭文件。之后的 Write 失败。
func (s *FileSink) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.file == nil {
		return nil
	}
	err := s.file.Close()
	s.file = nil
	return err
}

// ReadRecent 从文件末尾往前取最多 limit 条符合 filter 的记录，最新的在前。
// limit <= 0 时返回空。坏掉的一行是错误，不跳过。
func ReadRecent(path string, filter Filter, limit int) ([]Record, error) {
	if limit <= 0 {
		return nil, nil
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var matched []Record
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		var rec Record
		if err := json.Unmarshal(line, &rec); err != nil {
			return nil, fmt.Errorf("audit: %s: %w", path, err)
		}
		if filter.matches(rec) {
			matched = append(matched, rec)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if len(matched) > limit {
		matched = matched[len(matched)-limit:]
	}
	for i, j := 0, len(matched)-1; i < j; i, j = i+1, j-1 {
		matched[i], matched[j] = matched[j], matched[i]
	}
	return matched, nil
}

func (f Filter) matches(rec Record) bool {
	checks := [][2]string{
		{f.TraceID, rec.TraceID},
		{f.DecisionID, rec.DecisionID},
		{f.RouteID, rec.RouteID},
		{f.Service, rec.Service},
		{f.EventType, rec.EventType},
		{f.Outcome, rec.Outcome},
		{f.Reason, rec.Reason},
	}
	for _, pair := range checks {
		if pair[0] != "" && pair[0] != pair[1] {
			return false
		}
	}
	return true
}

func sanitizeRecord(rec Record) Record {
	rec.Timestamp = clip(rec.Timestamp)
	rec.Service = clip(rec.Service)
	rec.EventType = clip(rec.EventType)
	rec.TraceID = clip(rec.TraceID)
	rec.SpanID = clip(rec.SpanID)
	rec.ParentSpanID = clip(rec.ParentSpanID)
	rec.DecisionID = clip(rec.DecisionID)
	rec.RouteID = clip(rec.RouteID)
	rec.ProviderID = clip(rec.ProviderID)
	rec.OperationID = clip(rec.OperationID)
	rec.Environment = clip(rec.Environment)
	rec.Tenant = clip(rec.Tenant)
	rec.Subject = clip(rec.Subject)
	rec.Account = clip(rec.Account)
	rec.Caller = clip(rec.Caller)
	rec.Method = clip(rec.Method)
	rec.Path = clip(rec.Path)
	rec.Outcome = clip(rec.Outcome)
	rec.Reason = clip(rec.Reason)
	rec.FailureOrigin = clip(rec.FailureOrigin)
	rec.PolicyVersion = clip(rec.PolicyVersion)
	rec.Detail = sanitizeDetail(rec.Detail)
	return rec
}

func sanitizeDetail(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for key, value := range in {
		if sensitiveKey(key) {
			continue
		}
		key = clip(key)
		if key == "" {
			continue
		}
		out[key] = clip(value)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func sensitiveKey(key string) bool {
	folded := strings.ToLower(key)
	for _, part := range sensitiveParts {
		if strings.Contains(folded, part) {
			return true
		}
	}
	return false
}

func clip(s string) string {
	if strings.ContainsAny(s, "\r\n") {
		s = strings.ReplaceAll(strings.ReplaceAll(s, "\r", ""), "\n", "")
	}
	if len(s) <= maxFieldBytes {
		return s
	}
	s = s[:maxFieldBytes]
	for s != "" && !utf8.ValidString(s) {
		s = s[:len(s)-1]
	}
	return s
}
