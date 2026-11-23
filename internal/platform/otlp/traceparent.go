// Package otlp 是 W3C Trace Context 和 OTLP/HTTP JSON 的导出，只用标准库。
// 它不认识业务上下文：调用方把已经选好的字段交进来，这里只负责格式和发送。
package otlp

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// OTLP SpanKind 与 Status code 的数值，和 opentelemetry proto 一致。
const (
	SpanKindInternal = 1
	SpanKindServer   = 2
	SpanKindClient   = 3

	StatusCodeUnset = 0
	StatusCodeOK    = 1
	StatusCodeError = 2
)

// TraceContext 是一条 W3C traceparent 里的 trace id、span id 和采样位。
type TraceContext struct {
	TraceID string
	SpanID  string
	Sampled bool
}

// 恰好 version 00、32 位小写 trace id、16 位小写 span id、2 位小写 flags。多一位或大写都不收。
var traceparentValue = regexp.MustCompile(`^00-[0-9a-f]{32}-[0-9a-f]{16}-[0-9a-f]{2}$`)

const (
	zeroTraceID = "00000000000000000000000000000000"
	zeroSpanID  = "0000000000000000"
)

// ParseTraceparent 取请求头里第一条合法的 traceparent。没有、或每一条都不合法，返回 false。
// 多条时跳过不合法的，用第一条合法的，不把它们拼起来。
func ParseTraceparent(header http.Header) (TraceContext, bool) {
	if header == nil {
		return TraceContext{}, false
	}
	for _, value := range header.Values("Traceparent") {
		if ctx, ok := ParseTraceparentValue(value); ok {
			return ctx, true
		}
	}
	return TraceContext{}, false
}

// ParseTraceparentValue 校验一条 traceparent 的原文。
// 长度超过 128、含 CR/LF、不是精确的小写格式、trace id 或 span id 全零，都拒绝。
// Sampled 是 flags 的最低位（W3C 的 sampled）。
func ParseTraceparentValue(raw string) (TraceContext, bool) {
	if raw == "" || len(raw) > 128 || strings.ContainsAny(raw, "\r\n") {
		return TraceContext{}, false
	}
	if !traceparentValue.MatchString(raw) {
		return TraceContext{}, false
	}
	parts := strings.Split(raw, "-")
	if parts[1] == zeroTraceID || parts[2] == zeroSpanID {
		return TraceContext{}, false
	}
	flags, err := strconv.ParseUint(parts[3], 16, 8)
	if err != nil {
		return TraceContext{}, false
	}
	return TraceContext{TraceID: parts[1], SpanID: parts[2], Sampled: flags&0x01 == 1}, true
}

// NewTraceID 是 16 个随机字节的小写十六进制，不会是全零。
func NewTraceID() string { return randomHex(16) }

// NewSpanID 是 8 个随机字节的小写十六进制，不会是全零。
func NewSpanID() string { return randomHex(8) }

// FormatTraceparent 按采样位写成 00 或 01。调用方应传入 NewTraceID / NewSpanID 的结果。
func FormatTraceparent(traceID, spanID string, sampled bool) string {
	flags := "00"
	if sampled {
		flags = "01"
	}
	return "00-" + traceID + "-" + spanID + "-" + flags
}

func randomHex(n int) string {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		buf[0] = 1
		if n >= 8 {
			binary.LittleEndian.PutUint64(buf[n-8:], uint64(time.Now().UnixNano()))
		}
	}
	zero := true
	for _, b := range buf {
		if b != 0 {
			zero = false
			break
		}
	}
	if zero {
		buf[0] = 1
	}
	return hex.EncodeToString(buf)
}
