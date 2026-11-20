package domain

import "testing"

func TestOperationTable(t *testing.T) {
	want := []Operation{
		{"orders.create", "POST", "/sfintl/v1/orders", "IECS_CREATE_ORDER"},
		{"orders.cancel", "POST", "/sfintl/v1/order-cancellations", "IECS_CANCEL_ORDER"},
		{"agent-numbers.query", "POST", "/sfintl/v1/agent-number-queries", "IECS_QUERY_AGENTNO"},
	}
	if got := Operations(); len(got) != len(want) {
		t.Fatalf("表里有 %d 行", len(got))
	}
	for _, expected := range want {
		got, ok := FindOperation(expected.Method, expected.Path)
		if !ok || got != expected {
			t.Errorf("%s %s：%+v %v", expected.Method, expected.Path, got, ok)
		}
	}
}

func TestOperationLookupIsExact(t *testing.T) {
	for _, c := range []struct{ method, path string }{
		{"GET", "/sfintl/v1/orders"},
		{"PUT", "/sfintl/v1/orders"},
		{"DELETE", "/sfintl/v1/orders"},
		{"post", "/sfintl/v1/orders"},
		{"Post", "/sfintl/v1/orders"},
		{"", "/sfintl/v1/orders"},
		{"POST", ""},
		{"POST", "/"},
		{"POST", "/sfintl/v1/orders/"},
		{"POST", "/sfintl/v1/orders/1"},
		{"POST", "/sfintl/v1/order"},
		{"POST", "/sfintl/v1/Orders"},
		{"POST", "/SFINTL/v1/orders"},
		{"POST", "//sfintl/v1/orders"},
		{"POST", "/sfintl/v1//orders"},
		{"POST", "/sfintl/v1/orders?x=1"},
		{"POST", "/sfintl/v1/orders "},
		{"POST", " /sfintl/v1/orders"},
		{"POST", "sfintl/v1/orders"},
		{"POST", "/sfintl/v2/orders"},
		{"POST", "/providers/sfintl/v1/orders"},
		{"POST", "/sfintl/v1/order-cancellations/"},
		{"POST", "/sfintl/v1/agent-number-queries/"},
		{"POST", "/openapi/api/dispatch"},
	} {
		if got, ok := FindOperation(c.method, c.path); ok {
			t.Errorf("%s %q 找到了 %+v", c.method, c.path, got)
		}
	}
}

func TestOperationsReturnsACopy(t *testing.T) {
	first := Operations()
	first[0].MsgType = "CHANGED"
	first[0].Path = "/changed"
	if got, ok := FindOperation("POST", "/sfintl/v1/orders"); !ok || got.MsgType != "IECS_CREATE_ORDER" {
		t.Errorf("改拷贝改动了操作表：%+v %v", got, ok)
	}
	if again := Operations(); again[0].MsgType != "IECS_CREATE_ORDER" {
		t.Error("改拷贝改动了操作表")
	}
}

func TestOperationIDsAndMessageTypesAreUnique(t *testing.T) {
	ids, msgTypes, routes := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, operation := range Operations() {
		route := operation.Method + " " + operation.Path
		if ids[operation.ID] || msgTypes[operation.MsgType] || routes[route] {
			t.Errorf("%+v 重复了", operation)
		}
		ids[operation.ID], msgTypes[operation.MsgType], routes[route] = true, true, true
		if operation.MsgType == "" || operation.ID == "" || !VisibleASCII(operation.MsgType) {
			t.Errorf("%+v 有空字段", operation)
		}
	}
}

func TestValidLanguage(t *testing.T) {
	for lang, want := range map[string]bool{
		"en": true, "zh-CN": true, "zh-HK": true,
		"": false, "fr": false, "EN": false, "zh-cn": false, "zh-TW": false, "zh": false, "en ": false, "en-US": false,
	} {
		if got := ValidLanguage(lang); got != want {
			t.Errorf("%q: %v", lang, got)
		}
	}
}
