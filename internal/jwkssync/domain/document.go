// Package domain 是 JWKS 同步的纯规则：怎样才算一份合格的公钥集、摘要怎么算才不受键序抖动影响、
// 以及一份曾经成功过的密钥集现在算不算超过了允许的陈旧时间。
//
// 这里不做 I/O，不认识 HTTP，不写日志。私钥参数出现在密钥对象上时直接拒绝：
// 一个配错的端点把私钥漏出来，不能被写成网关要去信任的文件。
package domain

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"time"
)

// privateParameters 是 JWK 里属于私钥或对称密钥材料的成员名。公钥集里出现其中任何一个，
// 整份文档拒绝。只看密钥对象的顶层成员，值是什么都不重要，空值也算出现。
var privateParameters = []string{"d", "p", "q", "dp", "dq", "qi", "oth", "k"}

// Key 是密钥集里的一把公钥，只保留标识。参数在规范形式里，不在这里重复。
type Key struct {
	KID string
	KTY string
}

// Document 是一份通过校验的 JWK Set。
//
// raw 不是身份提供者原样返回的字节，而是规范形式的文件内容：键按 kid 排序，每个密钥对象的
// 成员按名字排序，末尾一个换行。身份提供者把同一套密钥排成不同的顺序时，raw 和 digest 都不变，
// 因此不会引起一次多余的重写。digest 是这些密钥的规范 JSON 数组的 SHA-256，十六进制小写。
type Document struct {
	raw    []byte
	keys   []Key
	kids   []string
	digest string
}

// Canonical 返回要写入磁盘的字节，是一份副本。
func (d Document) Canonical() []byte { return append([]byte(nil), d.raw...) }

// Keys 返回密钥，按 kid 排序，是一份副本。
func (d Document) Keys() []Key { return append([]Key(nil), d.keys...) }

// KIDs 返回 kid，按字节序排序，是一份副本。
func (d Document) KIDs() []string { return append([]string(nil), d.kids...) }

// Digest 返回规范形式的 SHA-256，十六进制小写。
func (d Document) Digest() string { return d.digest }

// EmptySet 是过期之后失败关闭用的空密钥集。它不是一份合格的 Document：Parse 会拒绝它。
func EmptySet() []byte { return []byte("{\"keys\":[]}\n") }

// Parse 严格读一份 JWK Set：恰好一个 JSON 对象，后面不能再有别的值；必须有非空的 keys 数组；
// 每把密钥是对象，且有非空的字符串 kty 和 kid；kid 不能重复；私钥参数一律拒绝。
func Parse(raw []byte) (Document, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var body map[string]any
	if err := dec.Decode(&body); err != nil {
		var typeError *json.UnmarshalTypeError
		if errors.As(err, &typeError) {
			return Document{}, errors.New("jwks: not a JSON object")
		}
		return Document{}, errors.New("jwks: malformed JSON")
	}
	if body == nil {
		return Document{}, errors.New("jwks: not a JSON object")
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return Document{}, errors.New("jwks: trailing data")
	}
	present, exists := body["keys"]
	if !exists {
		return Document{}, errors.New("jwks: keys is required")
	}
	items, ok := present.([]any)
	if !ok {
		return Document{}, errors.New("jwks: keys must be an array")
	}
	if len(items) == 0 {
		return Document{}, errors.New("jwks: keys must contain at least one key")
	}
	parsed := make([]parsedKey, 0, len(items))
	seen := make(map[string]struct{}, len(items))
	for _, item := range items {
		obj, ok := item.(map[string]any)
		if !ok {
			return Document{}, errors.New("jwks: key must be an object")
		}
		for _, name := range privateParameters {
			if _, secret := obj[name]; secret {
				return Document{}, fmt.Errorf("jwks: key contains private parameter %q", name)
			}
		}
		kid, err := requiredString(obj, "kid")
		if err != nil {
			return Document{}, err
		}
		kty, err := requiredString(obj, "kty")
		if err != nil {
			return Document{}, err
		}
		if _, duplicate := seen[kid]; duplicate {
			return Document{}, fmt.Errorf("jwks: duplicate kid %q", kid)
		}
		seen[kid] = struct{}{}
		parsed = append(parsed, parsedKey{kid: kid, kty: kty, obj: obj})
	}
	sort.Slice(parsed, func(i, j int) bool { return parsed[i].kid < parsed[j].kid })
	var array bytes.Buffer
	array.WriteByte('[')
	keys := make([]Key, 0, len(parsed))
	kids := make([]string, 0, len(parsed))
	for i, key := range parsed {
		if i > 0 {
			array.WriteByte(',')
		}
		encoded, err := canonicalValue(key.obj)
		if err != nil {
			return Document{}, err
		}
		array.Write(encoded)
		keys = append(keys, Key{KID: key.kid, KTY: key.kty})
		kids = append(kids, key.kid)
	}
	array.WriteByte(']')
	sum := sha256.Sum256(array.Bytes())
	file := make([]byte, 0, array.Len()+10)
	file = append(file, "{\"keys\":"...)
	file = append(file, array.Bytes()...)
	file = append(file, "}\n"...)
	return Document{raw: file, keys: keys, kids: kids, digest: hex.EncodeToString(sum[:])}, nil
}

type parsedKey struct {
	kid, kty string
	obj      map[string]any
}

func requiredString(obj map[string]any, name string) (string, error) {
	value, ok := obj[name]
	if !ok {
		return "", fmt.Errorf("jwks: key %s must be a non-empty string", name)
	}
	text, ok := value.(string)
	if !ok || text == "" {
		return "", fmt.Errorf("jwks: key %s must be a non-empty string", name)
	}
	return text, nil
}

// canonicalValue 把解码后的 JSON 值写成紧凑、成员名有序、不转义 HTML 的形式。
// 数字保留身份提供者写下的字面量，避免 1 和 1.0 被当成同一个值。
func canonicalValue(v any) ([]byte, error) {
	switch value := v.(type) {
	case nil:
		return []byte("null"), nil
	case bool:
		if value {
			return []byte("true"), nil
		}
		return []byte("false"), nil
	case string:
		return canonicalString(value)
	case json.Number:
		if !validNumber(string(value)) {
			return nil, errors.New("jwks: malformed JSON")
		}
		return []byte(value), nil
	case map[string]any:
		names := make([]string, 0, len(value))
		for name := range value {
			names = append(names, name)
		}
		sort.Strings(names)
		var buf bytes.Buffer
		buf.WriteByte('{')
		for i, name := range names {
			if i > 0 {
				buf.WriteByte(',')
			}
			key, err := canonicalString(name)
			if err != nil {
				return nil, err
			}
			buf.Write(key)
			buf.WriteByte(':')
			encoded, err := canonicalValue(value[name])
			if err != nil {
				return nil, err
			}
			buf.Write(encoded)
		}
		buf.WriteByte('}')
		return buf.Bytes(), nil
	case []any:
		var buf bytes.Buffer
		buf.WriteByte('[')
		for i, item := range value {
			if i > 0 {
				buf.WriteByte(',')
			}
			encoded, err := canonicalValue(item)
			if err != nil {
				return nil, err
			}
			buf.Write(encoded)
		}
		buf.WriteByte(']')
		return buf.Bytes(), nil
	default:
		return nil, errors.New("jwks: malformed JSON")
	}
}

func canonicalString(s string) ([]byte, error) {
	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(s); err != nil {
		return nil, errors.New("jwks: malformed JSON")
	}
	out := buf.Bytes()
	if len(out) == 0 || out[len(out)-1] != '\n' {
		return nil, errors.New("jwks: malformed JSON")
	}
	return out[:len(out)-1], nil
}

func validNumber(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c >= '0' && c <= '9', c == '-', c == '+', c == '.', c == 'e', c == 'E':
		default:
			return false
		}
	}
	return true
}

// StaleStatus 判断上一次成功取到密钥的时刻，到 now 为止，有没有超过 maxStale。
// maxStale 不大于 0，或者还没有成功过（lastSuccess 是零值）时，不算过期。
// 恰好等于 maxStale 也不算：必须严格超过。now 早于 lastSuccess 时年龄为负，不算过期。
func StaleStatus(lastSuccess, now time.Time, maxStale time.Duration) (stale bool, age time.Duration) {
	if !lastSuccess.IsZero() {
		age = now.Sub(lastSuccess)
	}
	stale = maxStale > 0 && !lastSuccess.IsZero() && age > maxStale
	return stale, age
}
