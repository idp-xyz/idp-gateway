package sbom

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Requires 读 go.mod，按出现顺序列出 require 的模块路径。
// replace、exclude、retract 不算。注释里的 require 不算。
func Requires(goMod []byte) ([]string, error) {
	if !utf8.Valid(goMod) {
		return nil, errors.New("sbom: go.mod is not UTF-8")
	}
	tokens, err := tokenize(string(goMod))
	if err != nil {
		return nil, err
	}
	var paths []string
	for i := 0; i < len(tokens); i++ {
		if tokens[i].kind != tokenWord || tokens[i].val != "require" {
			continue
		}
		if i+1 >= len(tokens) {
			return nil, errors.New("sbom: require has no module")
		}
		if tokens[i+1].kind == tokenParenL {
			for i = i + 2; i < len(tokens) && tokens[i].kind != tokenParenR; {
				path, next, err := requireSpec(tokens, i)
				if err != nil {
					return nil, err
				}
				paths = append(paths, path)
				i = next
			}
			if i >= len(tokens) || tokens[i].kind != tokenParenR {
				return nil, errors.New("sbom: require block is not closed")
			}
			continue
		}
		path, next, err := requireSpec(tokens, i+1)
		if err != nil {
			return nil, err
		}
		paths = append(paths, path)
		i = next - 1
	}
	return paths, nil
}

func isModuleToken(kind tokenKind) bool {
	return kind == tokenWord || kind == tokenString
}

func requireSpec(tokens []token, i int) (string, int, error) {
	if i+1 >= len(tokens) || !isModuleToken(tokens[i].kind) || !isModuleToken(tokens[i+1].kind) {
		return "", 0, errors.New("sbom: require spec is incomplete")
	}
	if tokens[i].val == "" || tokens[i+1].val == "" {
		return "", 0, errors.New("sbom: require spec is incomplete")
	}
	return tokens[i].val, i + 2, nil
}

type tokenKind int

const (
	tokenWord tokenKind = iota
	tokenString
	tokenParenL
	tokenParenR
)

type token struct {
	kind tokenKind
	val  string
}

func tokenize(src string) ([]token, error) {
	var out []token
	i := 0
	for i < len(src) {
		switch src[i] {
		case ' ', '\t', '\r', '\n', ';':
			i++
		case '/':
			if i+1 < len(src) && src[i+1] == '/' {
				i += 2
				for i < len(src) && src[i] != '\n' {
					i++
				}
				continue
			}
			if i+1 < len(src) && src[i+1] == '*' {
				end := strings.Index(src[i+2:], "*/")
				if end < 0 {
					return nil, errors.New("sbom: block comment is not closed")
				}
				i += 2 + end + 2
				continue
			}
			word, next, err := scanWord(src, i)
			if err != nil {
				return nil, err
			}
			out = append(out, token{kind: tokenWord, val: word})
			i = next
		case '(':
			out = append(out, token{kind: tokenParenL})
			i++
		case ')':
			out = append(out, token{kind: tokenParenR})
			i++
		case '"', '`':
			word, next, err := scanQuoted(src, i)
			if err != nil {
				return nil, err
			}
			out = append(out, token{kind: tokenString, val: word})
			i = next
		default:
			word, next, err := scanWord(src, i)
			if err != nil {
				return nil, err
			}
			out = append(out, token{kind: tokenWord, val: word})
			i = next
		}
	}
	return out, nil
}

func scanWord(src string, i int) (string, int, error) {
	j := i
	for j < len(src) && !breaksWord(src, j) {
		j++
	}
	if j == i {
		return "", 0, fmt.Errorf("sbom: bad token at byte %d", i)
	}
	return src[i:j], j, nil
}

func breaksWord(src string, j int) bool {
	switch src[j] {
	case ' ', '\t', '\r', '\n', ';', '(', ')', '"', '`':
		return true
	case '/':
		return j+1 < len(src) && (src[j+1] == '/' || src[j+1] == '*')
	default:
		return false
	}
}

func scanQuoted(src string, i int) (string, int, error) {
	if src[i] == '`' {
		end := strings.IndexByte(src[i+1:], '`')
		if end < 0 {
			return "", 0, errors.New("sbom: string is not closed")
		}
		raw := src[i : i+1+end+1]
		val, err := strconv.Unquote(raw)
		if err != nil {
			return "", 0, errors.New("sbom: string is not closed")
		}
		return val, i + 1 + end + 1, nil
	}
	j := i + 1
	for j < len(src) {
		if src[j] == '\\' {
			if j+1 >= len(src) {
				return "", 0, errors.New("sbom: string is not closed")
			}
			j += 2
			continue
		}
		if src[j] == '"' {
			val, err := strconv.Unquote(src[i : j+1])
			if err != nil {
				return "", 0, errors.New("sbom: bad string")
			}
			return val, j + 1, nil
		}
		if src[j] == '\n' {
			return "", 0, errors.New("sbom: string is not closed")
		}
		j++
	}
	return "", 0, errors.New("sbom: string is not closed")
}
