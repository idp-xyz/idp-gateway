package application

import (
	"fmt"
	"strconv"
	"strings"
)

// parseYAML 只覆盖承运商配置和编译器写出的那种子集：缩进、整行注释、单双引号、
// 普通标量，以及同一行上的方括号列表。测试用它比较解析后的结构。
func parseYAML(src []byte) (any, error) {
	lines, err := yamlLines(string(src))
	if err != nil {
		return nil, err
	}
	if len(lines) == 0 {
		return nil, fmt.Errorf("empty yaml")
	}
	value, rest, err := parseNode(lines)
	if err != nil {
		return nil, err
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("yaml line %d: trailing %q", rest[0].n, rest[0].text)
	}
	return value, nil
}

type yline struct {
	n      int
	indent int
	text   string
}

func yamlLines(src string) ([]yline, error) {
	var out []yline
	for n, raw := range strings.Split(strings.ReplaceAll(src, "\r\n", "\n"), "\n") {
		stripped, err := stripYAMLComment(raw)
		if err != nil {
			return nil, fmt.Errorf("yaml line %d: %w", n+1, err)
		}
		if strings.TrimSpace(stripped) == "" {
			continue
		}
		indent := 0
		for indent < len(stripped) && stripped[indent] == ' ' {
			indent++
		}
		if indent < len(stripped) && stripped[indent] == '\t' {
			return nil, fmt.Errorf("yaml line %d: tab indent", n+1)
		}
		out = append(out, yline{n: n + 1, indent: indent, text: strings.TrimRight(stripped[indent:], " ")})
	}
	return out, nil
}

func stripYAMLComment(line string) (string, error) {
	var b strings.Builder
	quote := byte(0)
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch quote {
		case '\'':
			b.WriteByte(c)
			if c != '\'' {
				continue
			}
			if i+1 < len(line) && line[i+1] == '\'' {
				b.WriteByte('\'')
				i++
				continue
			}
			quote = 0
		case '"':
			b.WriteByte(c)
			if c == '\\' && i+1 < len(line) {
				i++
				b.WriteByte(line[i])
				continue
			}
			if c == '"' {
				quote = 0
			}
		default:
			if c == '#' && (i == 0 || line[i-1] == ' ') {
				return b.String(), nil
			}
			if c == '\'' || c == '"' {
				quote = c
			}
			b.WriteByte(c)
		}
	}
	if quote != 0 {
		return "", fmt.Errorf("unterminated quote")
	}
	return b.String(), nil
}

func parseNode(lines []yline) (any, []yline, error) {
	if strings.HasPrefix(lines[0].text, "-") {
		return parseSeq(lines, lines[0].indent)
	}
	return parseMap(lines, lines[0].indent)
}

func parseMap(lines []yline, indent int) (any, []yline, error) {
	obj := map[string]any{}
	for len(lines) > 0 && lines[0].indent == indent && !dash(lines[0].text) {
		key, raw, err := splitKV(lines[0].text)
		if err != nil {
			return nil, nil, fmt.Errorf("yaml line %d: %w", lines[0].n, err)
		}
		lineNo := lines[0].n
		lines = lines[1:]
		if _, exists := obj[key]; exists {
			return nil, nil, fmt.Errorf("yaml line %d: duplicate key %s", lineNo, key)
		}
		switch {
		case raw != "":
			value, err := parseScalar(raw)
			if err != nil {
				return nil, nil, fmt.Errorf("yaml line %d: %w", lineNo, err)
			}
			obj[key] = value
		case len(lines) > 0 && lines[0].indent == indent && dash(lines[0].text):
			seq, rest, err := parseSeq(lines, indent)
			if err != nil {
				return nil, nil, err
			}
			obj[key] = seq
			lines = rest
		case len(lines) > 0 && lines[0].indent > indent:
			child, rest, err := parseNode(lines)
			if err != nil {
				return nil, nil, err
			}
			obj[key] = child
			lines = rest
		default:
			obj[key] = nil
		}
	}
	return obj, lines, nil
}

func parseSeq(lines []yline, indent int) (any, []yline, error) {
	var items []any
	for len(lines) > 0 && lines[0].indent == indent && dash(lines[0].text) {
		body := strings.TrimSpace(strings.TrimPrefix(lines[0].text, "-"))
		lineNo := lines[0].n
		lines = lines[1:]
		var nested []yline
		for len(lines) > 0 && lines[0].indent > indent {
			nested = append(nested, lines[0])
			lines = lines[1:]
		}
		switch {
		case body == "" && len(nested) == 0:
			items = append(items, nil)
		case body == "":
			child, rest, err := parseNode(nested)
			if err != nil {
				return nil, nil, err
			}
			if len(rest) != 0 {
				return nil, nil, fmt.Errorf("yaml line %d: sequence item did not consume %q", rest[0].n, rest[0].text)
			}
			items = append(items, child)
		case isKV(body):
			// 头一个键与后续同级键（例如 method）共用 indent+2，更深的行仍属于它的值。
			block := append([]yline{{n: lineNo, indent: indent + 2, text: body}}, nested...)
			child, rest, err := parseMap(block, indent+2)
			if err != nil {
				return nil, nil, err
			}
			if len(rest) != 0 {
				return nil, nil, fmt.Errorf("yaml line %d: sequence item did not consume %q", rest[0].n, rest[0].text)
			}
			items = append(items, child)
		default:
			if len(nested) != 0 {
				return nil, nil, fmt.Errorf("yaml line %d: scalar sequence item has nested lines", lineNo)
			}
			value, err := parseScalar(body)
			if err != nil {
				return nil, nil, fmt.Errorf("yaml line %d: %w", lineNo, err)
			}
			items = append(items, value)
		}
	}
	return items, lines, nil
}

func dash(text string) bool {
	return text == "-" || strings.HasPrefix(text, "- ")
}

func isKV(text string) bool {
	_, _, err := splitKV(text)
	return err == nil
}

func splitKV(text string) (string, string, error) {
	inSingle, inDouble := false, false
	for i := 0; i < len(text); i++ {
		c := text[i]
		switch {
		case inSingle:
			if c == '\'' {
				if i+1 < len(text) && text[i+1] == '\'' {
					i++
					continue
				}
				inSingle = false
			}
		case inDouble:
			if c == '\\' && i+1 < len(text) {
				i++
				continue
			}
			if c == '"' {
				inDouble = false
			}
		case c == '\'':
			inSingle = true
		case c == '"':
			inDouble = true
		case c == ':':
			key := strings.TrimSpace(text[:i])
			if key == "" || strings.ContainsAny(key, " \t") {
				continue
			}
			return key, strings.TrimSpace(text[i+1:]), nil
		}
	}
	return "", "", fmt.Errorf("not a key: %q", text)
}

func parseScalar(raw string) (any, error) {
	switch {
	case strings.HasPrefix(raw, "'"):
		return unquoteSingle(raw)
	case strings.HasPrefix(raw, "\""):
		return unquoteDouble(raw)
	case strings.HasPrefix(raw, "[") && strings.HasSuffix(raw, "]"):
		return parseFlow(raw)
	}
	switch raw {
	case "null", "Null", "NULL", "~":
		return nil, nil
	case "true", "True", "TRUE", "yes", "Yes", "YES", "on", "On", "ON":
		return true, nil
	case "false", "False", "FALSE", "no", "No", "NO", "off", "Off", "OFF":
		return false, nil
	}
	if integerText(raw) {
		n, err := strconv.Atoi(raw)
		if err != nil {
			return nil, err
		}
		return n, nil
	}
	return raw, nil
}

func parseFlow(raw string) (any, error) {
	inner := strings.TrimSpace(raw[1 : len(raw)-1])
	if inner == "" {
		return []any{}, nil
	}
	parts, err := splitCommas(inner)
	if err != nil {
		return nil, err
	}
	items := make([]any, len(parts))
	for i, part := range parts {
		item, err := parseScalar(strings.TrimSpace(part))
		if err != nil {
			return nil, err
		}
		items[i] = item
	}
	return items, nil
}

func splitCommas(s string) ([]string, error) {
	var parts []string
	start := 0
	inSingle, inDouble := false, false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case inSingle:
			if c == '\'' {
				if i+1 < len(s) && s[i+1] == '\'' {
					i++
					continue
				}
				inSingle = false
			}
		case inDouble:
			if c == '\\' && i+1 < len(s) {
				i++
				continue
			}
			if c == '"' {
				inDouble = false
			}
		case c == '\'':
			inSingle = true
		case c == '"':
			inDouble = true
		case c == ',':
			parts = append(parts, s[start:i])
			start = i + 1
		}
	}
	if inSingle || inDouble {
		return nil, fmt.Errorf("unterminated quote in flow sequence")
	}
	parts = append(parts, s[start:])
	return parts, nil
}

func unquoteSingle(raw string) (string, error) {
	if len(raw) < 2 || raw[0] != '\'' || raw[len(raw)-1] != '\'' {
		return "", fmt.Errorf("bad single quote %q", raw)
	}
	body := raw[1 : len(raw)-1]
	if strings.Contains(body, "\n") {
		return "", fmt.Errorf("newline in scalar")
	}
	return strings.ReplaceAll(body, "''", "'"), nil
}

func unquoteDouble(raw string) (string, error) {
	quoted, err := strconv.Unquote(raw)
	if err != nil {
		return "", err
	}
	return quoted, nil
}

func integerText(s string) bool {
	if s == "" || s == "-" {
		return false
	}
	i := 0
	if s[0] == '-' {
		i = 1
	}
	if len(s)-i > 1 && s[i] == '0' {
		return false
	}
	for _, r := range s[i:] {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
