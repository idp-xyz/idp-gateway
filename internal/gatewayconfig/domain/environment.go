package domain

import (
	"strings"
	"unicode/utf8"
)

const (
	// schemaComment 是上游在做替换之前先拿掉的那一处写法（给编辑器看的注释）。这里照做。
	schemaComment = "# yaml-language-server: $schema"
	// maxReferences 是 EnvironmentReferences 至多返回几处。
	maxReferences = 5
	// maxReferenceLength 是返回的每一处至多多少字节，超出的截断。
	maxReferenceLength = 48
)

// EnvironmentReferences 找出快照正文里网关会拿环境变量换掉的写法。
//
// 锁定版本的网关在解析配置文件之前，先把整份正文过一遍 shell 式的替换：$名字、${名字}、
// ${名字:-默认值} 换成加载它的那个进程的环境变量的值，没有这个变量时整份文件加载失败；$$ 是字面的
// 一个 $；反斜杠不起转义的作用（tests/integration/compose 的 SH-08）。
//
// 带这种写法的文件，内容定不下它在网关上是什么：换一个环境就是另一份配置，还能把 SESSION_KEY
// 这样的值带进运行配置里。所以快照里不许有，发布器遇到就拒绝。
//
// 这里的判断比网关的宽，宁可多拒绝：$ 后面跟着 {、下划线、ASCII 字母或数字、或任何非 ASCII
// 字符的，都算。返回找到的写法：去重，按出现的先后，至多 maxReferences 处。
func (s Snapshot) EnvironmentReferences() []string {
	text := strings.ReplaceAll(string(s.content), schemaComment, "#")
	var found []string
	seen := map[string]bool{}
	for i := 0; i+1 < len(text) && len(found) < maxReferences; i++ {
		if text[i] != '$' {
			continue
		}
		if text[i+1] == '$' {
			i++ // $$ 是字面的 $，后面跟着的不再是名字
			continue
		}
		if text[i+1] != '{' && !nameByte(text[i+1]) {
			continue // 后面不是名字的 $ 原样留着：正则里结尾的 $ 就是这样
		}
		if reference := referenceAt(text[i:]); !seen[reference] {
			seen[reference] = true
			found = append(found, reference)
		}
	}
	return found
}

// nameByte 报告 b 是否可能是变量名的一部分。非 ASCII 的字节一律算：上游按 Unicode 的字母和数字判断，
// 这里不去和它对齐。
func nameByte(b byte) bool {
	return b == '_' || b >= 0x80 || b >= '0' && b <= '9' || b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z'
}

// referenceAt 取出 text 开头的那一处写法，给人看用。text 以 $ 开头，后面至少还有一个字节。
func referenceAt(text string) string {
	end := 1
	if text[1] == '{' {
		end = len(text)
		if stop := strings.IndexAny(text, "}\n"); stop >= 0 {
			end = stop
			if text[stop] == '}' {
				end++
			}
		}
	} else {
		for end < len(text) && nameByte(text[end]) {
			end++
		}
	}
	if end <= maxReferenceLength {
		return text[:end]
	}
	end = maxReferenceLength
	for end > 0 && !utf8.RuneStart(text[end]) {
		end-- // 不把一个字符切成两半
	}
	return text[:end] + "…"
}
