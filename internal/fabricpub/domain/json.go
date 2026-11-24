package domain

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// 与 routecompile 的预检相同：${…}，以及 $ 加大写字母或下划线。
var envReference = regexp.MustCompile(`\$\{|\$[A-Z_]`)

// Document 是一份严格读过的 JSON：重复键、尾随内容和环境变量引用都已经拒绝。
type Document struct {
	Value     any
	Canonical []byte
	Hash      string
}

// parseDocument 用 token 流读一份 JSON。对象里的键按名字排序后编码，数组保持原顺序。
func parseDocument(data []byte) (Document, error) {
	if len(bytes.TrimSpace(data)) == 0 {
		return Document{}, invalid("invalid_json")
	}
	if envReference.Match(data) {
		return Document{}, invalid("env_reference")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	value, err := parseValue(dec)
	if err != nil {
		var inv *Invalid
		if errors.As(err, &inv) {
			return Document{}, err
		}
		return Document{}, invalid("invalid_json")
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return Document{}, invalid("trailing_json")
	}
	if err := rejectSensitive(value); err != nil {
		return Document{}, err
	}
	if err := rejectEnvStrings(value); err != nil {
		return Document{}, err
	}
	canonical := canonicalJSON(value)
	sum := sha256.Sum256(canonical)
	return Document{Value: value, Canonical: canonical, Hash: hex.EncodeToString(sum[:])}, nil
}

func parseValue(dec *json.Decoder) (any, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	switch t := tok.(type) {
	case json.Delim:
		switch t {
		case '{':
			return parseObject(dec)
		case '[':
			return parseArray(dec)
		default:
			return nil, invalid("invalid_json")
		}
	case string, bool, nil, json.Number:
		return t, nil
	default:
		return nil, invalid("invalid_json")
	}
}

func parseObject(dec *json.Decoder) (map[string]any, error) {
	obj := map[string]any{}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		key, ok := tok.(string)
		if !ok {
			return nil, invalid("invalid_json")
		}
		if _, exists := obj[key]; exists {
			return nil, invalid("duplicate_key")
		}
		value, err := parseValue(dec)
		if err != nil {
			return nil, err
		}
		obj[key] = value
	}
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	delim, ok := tok.(json.Delim)
	if !ok || delim != '}' {
		return nil, invalid("invalid_json")
	}
	return obj, nil
}

func parseArray(dec *json.Decoder) ([]any, error) {
	var items []any
	for dec.More() {
		value, err := parseValue(dec)
		if err != nil {
			return nil, err
		}
		items = append(items, value)
	}
	if items == nil {
		items = []any{}
	}
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	delim, ok := tok.(json.Delim)
	if !ok || delim != ']' {
		return nil, invalid("invalid_json")
	}
	return items, nil
}

func rejectEnvStrings(v any) error {
	switch t := v.(type) {
	case string:
		if envReference.MatchString(t) {
			return invalid("env_reference")
		}
	case map[string]any:
		for _, child := range t {
			if err := rejectEnvStrings(child); err != nil {
				return err
			}
		}
	case []any:
		for _, child := range t {
			if err := rejectEnvStrings(child); err != nil {
				return err
			}
		}
	}
	return nil
}

func canonicalJSON(v any) []byte {
	var b strings.Builder
	writeCanonical(&b, v)
	return []byte(b.String())
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
	case []any:
		b.WriteByte('[')
		for i, item := range t {
			if i > 0 {
				b.WriteByte(',')
			}
			writeCanonical(b, item)
		}
		b.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(t))
		for key := range t {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		b.WriteByte('{')
		for i, key := range keys {
			if i > 0 {
				b.WriteByte(',')
			}
			writeCanonicalString(b, key)
			b.WriteByte(':')
			writeCanonical(b, t[key])
		}
		b.WriteByte('}')
	default:
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

func asObject(v any) (map[string]any, bool) {
	obj, ok := v.(map[string]any)
	return obj, ok
}

func asString(v any) (string, bool) {
	s, ok := v.(string)
	return s, ok
}

func asInt(v any) (int, bool) {
	number, ok := v.(json.Number)
	if !ok {
		return 0, false
	}
	text := string(number)
	if !integerLiteral(text) {
		return 0, false
	}
	n, err := strconv.Atoi(text)
	return n, err == nil
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

func plainText(s string) bool {
	return utf8.ValidString(s) && !strings.ContainsFunc(s, unicode.IsControl)
}

func unknownFields(obj map[string]any, allowed map[string]struct{}) error {
	for key := range obj {
		if _, ok := allowed[key]; !ok {
			return invalid("unknown_field")
		}
	}
	return nil
}
