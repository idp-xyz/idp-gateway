package domain

import "slices"

// Operation 是操作表里的一行：网关路由上的一个方法加路径，对到承运商的一个 msgType。
// 表是写死的，msgType 从不取自请求或启动参数。
type Operation struct {
	ID      string
	Method  string
	Path    string
	MsgType string
}

// operations 是第一步的三个操作（docs/adr/ADR-0014.md 第 3 条）。面单以后再做。
var operations = []Operation{
	{ID: "orders.create", Method: "POST", Path: "/sfintl/v1/orders", MsgType: "IECS_CREATE_ORDER"},
	{ID: "orders.cancel", Method: "POST", Path: "/sfintl/v1/order-cancellations", MsgType: "IECS_CANCEL_ORDER"},
	{ID: "agent-numbers.query", Method: "POST", Path: "/sfintl/v1/agent-number-queries", MsgType: "IECS_QUERY_AGENTNO"},
}

// Operations 返回操作表的一份拷贝。
func Operations() []Operation { return slices.Clone(operations) }

// FindOperation 按方法和路径的完全相等查表：没有前缀匹配，没有大小写折叠，没有结尾斜杠的宽容。
func FindOperation(method, path string) (Operation, bool) {
	for _, operation := range operations {
		if operation.Method == method && operation.Path == path {
			return operation, true
		}
	}
	return Operation{}, false
}

// languages 是承运商接受的 lang 头的取值。
var languages = []string{"en", "zh-CN", "zh-HK"}

// ValidLanguage 报告 lang 是不是承运商接受的取值之一。
func ValidLanguage(lang string) bool { return slices.Contains(languages, lang) }
