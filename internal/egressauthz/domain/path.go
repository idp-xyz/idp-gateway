package domain

import "regexp"

// CanonicalPathPattern 描述规范路径：/段/段...，每段由非保留字符组成且不以点开头。
// 于是路径里没有百分号（也就没有编码或二次编码的点、斜杠、NUL），没有空段、"."、".."，
// 没有结尾斜杠，没有 ";参数"。
//
// 不规范的路径直接拒绝，不做规范化：判定方不能去猜网关或 Provider 会怎样解码它。
// 网关路由上的 authorization 规则用的是同一个表达式，两处必须逐字相同。
const CanonicalPathPattern = `^(/[A-Za-z0-9_~-][A-Za-z0-9._~-]*)+$`

var canonicalPath = regexp.MustCompile(CanonicalPathPattern)

// IsCanonicalPath 判断路径是否规范。
func IsCanonicalPath(path string) bool {
	return canonicalPath.MatchString(path)
}
