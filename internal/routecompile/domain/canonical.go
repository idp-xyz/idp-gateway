package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strconv"
	"strings"
)

// canonicalJSON 按 Python json.dumps(sort_keys=True, ensure_ascii=False, separators=(',', ':'))
// 的字节来编码，这样意图和登记表的 SHA-256 与 scripts/preflight_intents.py 一致。
func canonicalJSON(v any) []byte {
	var b strings.Builder
	writeCanonical(&b, v)
	return []byte(b.String())
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func writeCanonical(b *strings.Builder, v any) {
	switch t := v.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		if t {
			b.WriteString("true")
		} else {
			b.WriteString("false")
		}
	case string:
		writeCanonicalString(b, t)
	case json.Number:
		b.WriteString(canonicalNumber(string(t)))
	case int:
		b.WriteString(strconv.Itoa(t))
	case int64:
		b.WriteString(strconv.FormatInt(t, 10))
	case float64:
		b.WriteString(strconv.FormatFloat(t, 'f', -1, 64))
	case []any:
		b.WriteByte('[')
		for i, item := range t {
			if i > 0 {
				b.WriteByte(',')
			}
			writeCanonical(b, item)
		}
		b.WriteByte(']')
	case []string:
		b.WriteByte('[')
		for i, item := range t {
			if i > 0 {
				b.WriteByte(',')
			}
			writeCanonicalString(b, item)
		}
		b.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		b.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				b.WriteByte(',')
			}
			writeCanonicalString(b, k)
			b.WriteByte(':')
			writeCanonical(b, t[k])
		}
		b.WriteByte('}')
	default:
		// 编不了的值按 JSON 空对象处理会把摘要算错。这里退回 encoding/json，
		// 调用方只该传入 JSON 解码出来的值。
		raw, err := json.Marshal(t)
		if err != nil {
			b.WriteString("null")
			return
		}
		b.Write(raw)
	}
}

func canonicalNumber(s string) string {
	if s == "" {
		return "0"
	}
	// 没有指数时保留原文：443 仍是 443，1.0 仍是 1.0，与 Python 对这两类字面量的输出一致。
	if !strings.ContainsAny(s, "eE") {
		return s
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return s
	}
	if f == float64(int64(f)) {
		return strconv.FormatInt(int64(f), 10) + ".0"
	}
	return strconv.FormatFloat(f, 'f', -1, 64)
}

func writeCanonicalString(b *strings.Builder, s string) {
	const hexdigits = "0123456789abcdef"
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"', '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if r < 0x20 {
				b.WriteString(`\u00`)
				b.WriteByte(hexdigits[r>>4])
				b.WriteByte(hexdigits[r&0xf])
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
}
