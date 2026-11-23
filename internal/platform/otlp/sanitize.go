package otlp

import (
	"math"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

// 属性名（小写）里出现这些片段就整项丢掉。credential 也在里面：不把凭证句柄或凭证值送出去。
// 值只做长度和换行处理，不靠值的内容判断是不是秘密。
var sensitiveParts = []string{
	"authorization",
	"token",
	"secret",
	"password",
	"api_key",
	"apikey",
	"cookie",
	"private_key",
	"credential",
	"aes",
	"bearer",
}

const maxAttributeBytes = 512

func sensitiveKey(key string) bool {
	folded := strings.ToLower(key)
	for _, part := range sensitiveParts {
		if strings.Contains(folded, part) {
			return true
		}
	}
	return false
}

// clip 去掉 CR/LF，并把字符串截到 512 字节，不截断一个 UTF-8 字符。
func clip(s string) string {
	if strings.ContainsAny(s, "\r\n") {
		s = strings.ReplaceAll(strings.ReplaceAll(s, "\r", ""), "\n", "")
	}
	if len(s) <= maxAttributeBytes {
		return s
	}
	s = s[:maxAttributeBytes]
	for s != "" && !utf8.ValidString(s) {
		s = s[:len(s)-1]
	}
	return s
}

func sanitizeAttributes(in map[string]any) map[string]any {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]any, len(in))
	for key, value := range in {
		if sensitiveKey(key) {
			continue
		}
		key = clip(key)
		if key == "" {
			continue
		}
		encoded, ok := sanitizeValue(value)
		if !ok {
			continue
		}
		out[key] = encoded
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func sanitizeValue(value any) (any, bool) {
	switch v := value.(type) {
	case string:
		return clip(v), true
	case bool:
		return v, true
	case int:
		return int64(v), true
	case int8:
		return int64(v), true
	case int16:
		return int64(v), true
	case int32:
		return int64(v), true
	case int64:
		return v, true
	case uint:
		return narrowUint(uint64(v))
	case uint8:
		return narrowUint(uint64(v))
	case uint16:
		return narrowUint(uint64(v))
	case uint32:
		return narrowUint(uint64(v))
	case uint64:
		return narrowUint(v)
	case float32:
		return finiteFloat(float64(v))
	case float64:
		return finiteFloat(v)
	default:
		return nil, false
	}
}

func narrowUint(v uint64) (any, bool) {
	if v > math.MaxInt64 {
		return nil, false
	}
	return int64(v), true
}

func finiteFloat(v float64) (any, bool) {
	if math.IsNaN(v) || math.IsInf(v, 0) {
		return nil, false
	}
	return strconv.FormatFloat(v, 'f', -1, 64), true
}

func sortedKeys(attrs map[string]any) []string {
	keys := make([]string, 0, len(attrs))
	for key := range attrs {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
