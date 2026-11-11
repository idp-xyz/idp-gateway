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
	"strconv"
	"strings"
	"unicode/utf16"
)

const (
	// settingsSection 是 /config_dump 里装启动设置的那一段。
	settingsSection = "config"
	// certificatePlaceholder 替换 /config_dump 里的证书正文。
	certificatePlaceholder = "<certificate>"
	certificateHeader      = "-----BEGIN CERTIFICATE-----"
)

// PublishedDigest 是网关的 /config_dump 里由发布的文件决定的那部分的摘要（ADR-0010 第 6 条）：
//
//   - 去掉顶层的 config 段。那是启动时定下的设置，里面有随运行环境变的值，由 StartupSettings 另外比；
//   - 证书正文换成占位。证书不在快照里，换证书不经过发布；
//   - 剩下的写成规范形式，取 SHA-256。
//
// 同一份快照由同一个版本的网关加载，在哪里加载、对象里的键以什么顺序输出，摘要都相同。
//
// 规范形式与 Python 的 json.dumps(sort_keys=True, separators=(',', ':')) 逐字节相同，
// tests/integration 下的用例就是那样算的：键按码点排序，没有多余的空白，字符串里 ASCII 可见字符
// 以外的一律写成 \uXXXX，整数照原样，带小数点或指数的数按 float64 的最短写法。
// 输入里有不成对的代理字符时两边不同，这里把它当成 U+FFFD。
func PublishedDigest(dump []byte) (string, error) {
	document, err := decodeObject(dump)
	if err != nil {
		return "", err
	}
	delete(document, settingsSection)
	var canonical bytes.Buffer
	if err := writeCanonical(&canonical, withoutCertificates(document)); err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical.Bytes())
	return hex.EncodeToString(sum[:]), nil
}

// Settings 是 /config_dump 的 config 段：网关启动时定下的设置。换配置文件不会让它们变，
// 要重启网关（tests/integration/compose 的 SH-06）。每一项的值是它的规范形式。
type Settings map[string]string

// StartupSettings 取出 /config_dump 的 config 段。没有这一段时返回空的 Settings。
func StartupSettings(dump []byte) (Settings, error) {
	document, err := decodeObject(dump)
	if err != nil {
		return nil, err
	}
	section, ok := document[settingsSection]
	if !ok {
		return Settings{}, nil
	}
	fields, ok := section.(map[string]any)
	if !ok {
		return nil, errors.New("gatewayconfig: the config section of the dump is not an object")
	}
	settings := make(Settings, len(fields))
	for name, value := range fields {
		var canonical bytes.Buffer
		if err := writeCanonical(&canonical, value); err != nil {
			return nil, err
		}
		settings[name] = canonical.String()
	}
	return settings, nil
}

// environmentDependent 是 config 段里随运行环境变、与快照无关的项。同一份快照在两个地方加载，
// 这几项可以不同：
//
//   - dns：解析器的配置取自容器的环境（compose 套件的 SH-01 和 Kubernetes 套件的 K8-01 都见到了）；
//   - numWorkerThreads：随 CPU 个数和限额变（Kubernetes 套件的上一版见到过）。
//
// 快照自己改了这两项时，这里看不出来。
var environmentDependent = map[string]bool{"dns": true, "numWorkerThreads": true}

// Differing 返回两份启动设置里不同的项，按名字排序；随运行环境变的项不算。
// 只在一边出现的项也算不同。
func (s Settings) Differing(other Settings) []string {
	var names []string
	for name, value := range s {
		if theirs, ok := other[name]; (!ok || theirs != value) && !environmentDependent[name] {
			names = append(names, name)
		}
	}
	for name := range other {
		if _, ok := s[name]; !ok && !environmentDependent[name] {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names
}

// decodeObject 把一份 JSON 文档解成对象。数字保留原文，后面写规范形式时再定写法。
func decodeObject(raw []byte) (map[string]any, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var document any
	if err := decoder.Decode(&document); err != nil {
		return nil, fmt.Errorf("gatewayconfig: the dump is not JSON: %w", err)
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("gatewayconfig: the dump has content after the JSON document")
	}
	object, ok := document.(map[string]any)
	if !ok {
		return nil, errors.New("gatewayconfig: the dump is not a JSON object")
	}
	return object, nil
}

// withoutCertificates 把证书正文换成占位。只看值，不看键。
func withoutCertificates(node any) any {
	switch value := node.(type) {
	case map[string]any:
		replaced := make(map[string]any, len(value))
		for key, child := range value {
			replaced[key] = withoutCertificates(child)
		}
		return replaced
	case []any:
		replaced := make([]any, len(value))
		for i, child := range value {
			replaced[i] = withoutCertificates(child)
		}
		return replaced
	case string:
		if strings.HasPrefix(strings.TrimLeft(value, " \t\r\n"), certificateHeader) {
			return certificatePlaceholder
		}
	}
	return node
}

func writeCanonical(out *bytes.Buffer, node any) error {
	switch value := node.(type) {
	case nil:
		out.WriteString("null")
	case bool:
		out.WriteString(strconv.FormatBool(value))
	case json.Number:
		number, err := canonicalNumber(value.String())
		if err != nil {
			return err
		}
		out.WriteString(number)
	case string:
		writeCanonicalString(out, value)
	case []any:
		out.WriteByte('[')
		for i, child := range value {
			if i > 0 {
				out.WriteByte(',')
			}
			if err := writeCanonical(out, child); err != nil {
				return err
			}
		}
		out.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(value))
		for key := range value {
			keys = append(keys, key)
		}
		sort.Strings(keys) // 按 UTF-8 字节排序，与按码点排序是同一个顺序
		out.WriteByte('{')
		for i, key := range keys {
			if i > 0 {
				out.WriteByte(',')
			}
			writeCanonicalString(out, key)
			out.WriteByte(':')
			if err := writeCanonical(out, value[key]); err != nil {
				return err
			}
		}
		out.WriteByte('}')
	default:
		return fmt.Errorf("gatewayconfig: unexpected %T in a decoded JSON document", node)
	}
	return nil
}

// canonicalNumber 把 JSON 里一个数的原文换成规范写法。整数照原样（多大都不丢精度）；
// 带小数点或指数的按 float64 解释，写成能原样读回来的最短形式。
func canonicalNumber(literal string) (string, error) {
	if !strings.ContainsAny(literal, ".eE") {
		if literal == "-0" {
			return "0", nil
		}
		return literal, nil
	}
	value, err := strconv.ParseFloat(literal, 64)
	if err != nil {
		return "", fmt.Errorf("gatewayconfig: number %s in the dump: %w", literal, err)
	}
	scientific := strconv.FormatFloat(value, 'e', -1, 64) // d.ddde±XX
	exponent, err := strconv.Atoi(scientific[strings.IndexByte(scientific, 'e')+1:])
	if err != nil {
		return "", fmt.Errorf("gatewayconfig: number %s in the dump: %w", literal, err)
	}
	if exponent < -4 || exponent >= 16 {
		return scientific, nil
	}
	fixed := strconv.FormatFloat(value, 'f', -1, 64)
	if !strings.Contains(fixed, ".") {
		fixed += ".0"
	}
	return fixed, nil
}

func writeCanonicalString(out *bytes.Buffer, text string) {
	out.WriteByte('"')
	for _, r := range text {
		switch {
		case r == '"':
			out.WriteString(`\"`)
		case r == '\\':
			out.WriteString(`\\`)
		case r == '\n':
			out.WriteString(`\n`)
		case r == '\r':
			out.WriteString(`\r`)
		case r == '\t':
			out.WriteString(`\t`)
		case r == '\b':
			out.WriteString(`\b`)
		case r == '\f':
			out.WriteString(`\f`)
		case r >= 0x20 && r <= 0x7e:
			out.WriteRune(r)
		case r < 0x10000:
			fmt.Fprintf(out, `\u%04x`, r)
		default:
			high, low := utf16.EncodeRune(r)
			fmt.Fprintf(out, `\u%04x\u%04x`, high, low)
		}
	}
	out.WriteByte('"')
}
