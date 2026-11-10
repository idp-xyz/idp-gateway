package domain

import (
	"strings"
	"testing"
)

const trackingPrefix = "/providers/mockcarrier/v1/tracking"

// examplePolicy 与 contracts/gateway/policies/egress-policy.example.json 的登记行相同；
// 从文件读出来的那一份由 filestore 包的测试覆盖。
func examplePolicy() Policy {
	return Policy{
		Version: "test",
		Operations: []Operation{{
			RouteID:              "r-mockcarrier-track-test",
			ProviderID:           "mockcarrier",
			OperationID:          "tracking.get",
			Environment:          "TEST",
			Method:               "GET",
			PathPrefix:           trackingPrefix,
			CredentialBindingRef: "gatekeeper:mockcarrier-test",
			AllowedTenants:       []string{"tenant-blue", "tenant-green"},
			AllowedServiceIDs:    []string{"parcel-service", "cargo-service"},
			AccountsByTenant: map[string][]string{
				"tenant-blue":  {"account-blue"},
				"tenant-green": {"account-green"},
			},
		}},
	}
}

func blue() *Principal {
	return &Principal{ServiceID: "parcel-service", TenantID: "tenant-blue", Environment: "TEST"}
}

func trackingRequest() Request {
	return Request{ProviderID: "mockcarrier", OperationID: "tracking.get", Environment: "TEST", Method: "GET",
		Path: trackingPrefix + "/123", AccountID: "account-blue"}
}

func TestEvaluate(t *testing.T) {
	cases := []struct {
		name      string
		principal func() *Principal
		request   func(*Request)
		policy    func(*Policy)
		want      Reason
	}{
		{name: "登记过的调用放行", want: ReasonActiveAccountGrant},
		{name: "别的租户的账户", principal: func() *Principal {
			return &Principal{ServiceID: "parcel-service", TenantID: "tenant-green", Environment: "TEST"}
		}, want: ReasonAccountNotGranted},
		{name: "自己租户的账户", principal: func() *Principal {
			return &Principal{ServiceID: "parcel-service", TenantID: "tenant-green", Environment: "TEST"}
		}, request: func(r *Request) { r.AccountID = "account-green" }, want: ReasonActiveAccountGrant},
		{name: "没有身份", principal: func() *Principal { return nil }, want: ReasonUnauthenticated},
		{name: "身份缺服务", principal: func() *Principal { return &Principal{TenantID: "tenant-blue", Environment: "TEST"} },
			want: ReasonUnauthenticated},
		{name: "身份缺租户", principal: func() *Principal { return &Principal{ServiceID: "parcel-service", Environment: "TEST"} },
			want: ReasonUnauthenticated},
		{name: "身份缺环境", principal: func() *Principal { return &Principal{ServiceID: "parcel-service", TenantID: "tenant-blue"} },
			want: ReasonUnauthenticated},
		{name: "未登记的操作", request: func(r *Request) { r.OperationID = "label.create" }, want: ReasonNoMatchingOperation},
		{name: "未登记的方法", request: func(r *Request) { r.Method = "POST" }, want: ReasonNoMatchingOperation},
		{name: "不在允许之列的方法", request: func(r *Request) { r.Method = "CONNECT" }, want: ReasonMethodNotAllowed},
		{name: "小写方法", request: func(r *Request) { r.Method = "get" }, want: ReasonMethodNotAllowed},
		{name: "Token 的环境与网关池不同", request: func(r *Request) { r.Environment = "PROD" }, want: ReasonEnvironmentMismatch},
		{name: "未获授的服务", principal: func() *Principal {
			return &Principal{ServiceID: "unknown-service", TenantID: "tenant-blue", Environment: "TEST"}
		}, want: ReasonServiceNotGranted},
		{name: "未获授的租户", principal: func() *Principal {
			return &Principal{ServiceID: "parcel-service", TenantID: "tenant-red", Environment: "TEST"}
		}, want: ReasonTenantNotGranted},
		{name: "没有指明账户", request: func(r *Request) { r.AccountID = "" }, want: ReasonAccountNotGranted},
		{name: "登记表把空串写成了账户", request: func(r *Request) { r.AccountID = "" },
			policy: func(p *Policy) { p.Operations[0].AccountsByTenant["tenant-blue"] = []string{""} }, want: ReasonAccountNotGranted},
		{name: "别的 Provider", request: func(r *Request) { r.ProviderID = "othercarrier" }, want: ReasonNoMatchingOperation},
		{name: "编码的斜杠", request: func(r *Request) { r.Path = trackingPrefix + "%2fadmin" }, want: ReasonPathNotCanonical},
		{name: "编码的点段", request: func(r *Request) { r.Path = trackingPrefix + "/%2e%2e/" }, want: ReasonPathNotCanonical},
		{name: "点段", request: func(r *Request) { r.Path = trackingPrefix + "/../private" }, want: ReasonPathNotCanonical},
		{name: "只是字符串前缀相同", request: func(r *Request) { r.Path = trackingPrefix + "-admin" }, want: ReasonNoMatchingOperation},
		{name: "前缀之上的路径", request: func(r *Request) { r.Path = "/providers/mockcarrier" }, want: ReasonNoMatchingOperation},
		{name: "没有凭证绑定", policy: func(p *Policy) { p.Operations[0].CredentialBindingRef = "" }, want: ReasonCredentialBindingMissing},
		{name: "空登记表", policy: func(p *Policy) { p.Operations = nil }, want: ReasonNoMatchingOperation},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			policy, principal, request := examplePolicy(), blue(), trackingRequest()
			if tc.principal != nil {
				principal = tc.principal()
			}
			if tc.request != nil {
				tc.request(&request)
			}
			if tc.policy != nil {
				tc.policy(&policy)
			}
			got := policy.Evaluate(principal, request)
			if got.Reason != tc.want {
				t.Fatalf("原因码 = %s，期望 %s", got.Reason, tc.want)
			}
			allowed := tc.want == ReasonActiveAccountGrant
			if got.Allowed != allowed {
				t.Fatalf("Allowed = %v，期望 %v", got.Allowed, allowed)
			}
			if allowed != (got.CredentialBindingRef != "") {
				t.Fatalf("凭证绑定 %q 与放行结果 %v 不一致：拒绝时不得带出绑定", got.CredentialBindingRef, allowed)
			}
		})
	}
}

func TestCanonicalPathsAreAllowed(t *testing.T) {
	for _, path := range []string{trackingPrefix, trackingPrefix + "/TRK-1", trackingPrefix + "/a.b_c~d-e", trackingPrefix + "/1/events"} {
		request := trackingRequest()
		request.Path = path
		if got := examplePolicy().Evaluate(blue(), request); !got.Allowed {
			t.Errorf("%q 被拒绝：%s", path, got.Reason)
		}
	}
}

// 这些路径都是评审与黑盒运行中出现过的绕过尝试。它们必须因为"不规范"被拒绝，
// 而不是碰巧没有匹配上哪一行。
func TestNonCanonicalPathsAreDenied(t *testing.T) {
	cases := map[string]string{
		"二次编码的点段":     trackingPrefix + "/%252e%252e/admin",
		"二次编码的斜杠":     trackingPrefix + "/%252e%252e%252fadmin",
		"编码的 NUL":     trackingPrefix + "/TRK-1%00",
		"原始 NUL":      trackingPrefix + "/TRK-1\x00",
		"路径参数":        trackingPrefix + "/TRK-1;x=1",
		"单点段":         trackingPrefix + "/./TRK-1",
		"隐藏段":         trackingPrefix + "/.git",
		"结尾斜杠":        trackingPrefix + "/TRK-1/",
		"连续斜杠":        trackingPrefix + "//admin",
		"路径里带查询串":     trackingPrefix + "/TRK-1?admin=1",
		"片段":          trackingPrefix + "/TRK-1#x",
		"空格":          trackingPrefix + "/TRK 1",
		"制表符":         trackingPrefix + "/TRK\t1",
		"换行后跟伪造的头":    trackingPrefix + "/TRK-1\nX-Injected: 1",
		"结尾换行":        trackingPrefix + "/TRK-1\n",
		"形似点的非 ASCII": trackingPrefix + "/\uff0e\uff0e/admin",
		"编码的空格":       trackingPrefix + "/TRK%201",
		"at 符号":       trackingPrefix + "/user@evil.example",
		"反斜杠":         trackingPrefix + `\..\admin`,
		"空路径":         "",
		"只有斜杠":        "/",
		"不以斜杠开头":      strings.TrimPrefix(trackingPrefix, "/") + "/TRK-1",
	}
	for name, path := range cases {
		t.Run(name, func(t *testing.T) {
			request := trackingRequest()
			request.Path = path
			got := examplePolicy().Evaluate(blue(), request)
			if got.Allowed || got.Reason != ReasonPathNotCanonical || got.CredentialBindingRef != "" {
				t.Fatalf("%q: %+v，期望以 %s 拒绝", path, got, ReasonPathNotCanonical)
			}
		})
	}
}

// 没有写出规范路径前缀或标识不全的登记行不授权任何请求。
func TestIncompleteRowAuthorisesNothing(t *testing.T) {
	mutations := map[string]func(*Operation){
		"前缀为空":        func(op *Operation) { op.PathPrefix = "" },
		"前缀是根":        func(op *Operation) { op.PathPrefix = "/" },
		"前缀不规范":       func(op *Operation) { op.PathPrefix = "/providers/../providers/mockcarrier/v1/tracking" },
		"没有 Provider": func(op *Operation) { op.ProviderID = "" },
		"没有操作":        func(op *Operation) { op.OperationID = "" },
		"没有环境":        func(op *Operation) { op.Environment = "" },
		"没有方法":        func(op *Operation) { op.Method = "" },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			policy := examplePolicy()
			mutate(&policy.Operations[0])
			for _, path := range []string{trackingPrefix + "/123", "/anything/else", "/"} {
				// 请求一侧也照着残缺的行来写，确认空值对空值不算匹配。
				for _, request := range []Request{trackingRequest(), {Method: "GET", Path: path, AccountID: "account-blue", Environment: "TEST"}} {
					request.Path = path
					if got := policy.Evaluate(blue(), request); got.Allowed || got.CredentialBindingRef != "" {
						t.Fatalf("%q 被放行：%+v", path, got)
					}
				}
			}
			if account, ok := policy.SoleAccount("tenant-blue", policy.Operations[0].ProviderID, policy.Operations[0].OperationID, policy.Operations[0].Environment); ok {
				t.Fatalf("残缺的行给出了默认账户 %q", account)
			}
		})
	}
}

func TestSoleAccount(t *testing.T) {
	policy := examplePolicy()
	if account, ok := policy.SoleAccount("tenant-blue", "mockcarrier", "tracking.get", "TEST"); !ok || account != "account-blue" {
		t.Fatalf("得到 %q, %v", account, ok)
	}
	for name, args := range map[string][4]string{
		"没有获授的租户":     {"tenant-red", "mockcarrier", "tracking.get", "TEST"},
		"别的操作":        {"tenant-blue", "mockcarrier", "labels.create", "TEST"},
		"别的 Provider": {"tenant-blue", "othercarrier", "tracking.get", "TEST"},
		"别的环境":        {"tenant-blue", "mockcarrier", "tracking.get", "PROD"},
		"空租户":         {"", "mockcarrier", "tracking.get", "TEST"},
	} {
		if account, ok := policy.SoleAccount(args[0], args[1], args[2], args[3]); ok {
			t.Errorf("%s: 给出了默认账户 %q", name, account)
		}
	}

	// 有两个获授账户时不替调用方选。
	policy.Operations[0].AccountsByTenant["tenant-blue"] = []string{"account-blue", "account-blue-2"}
	if account, ok := policy.SoleAccount("tenant-blue", "mockcarrier", "tracking.get", "TEST"); ok {
		t.Fatalf("两个账户时给出了默认账户 %q", account)
	}
	// 同一个账户在两行里出现仍然是一个。
	policy = examplePolicy()
	policy.Operations = append(policy.Operations, policy.Operations[0])
	if account, ok := policy.SoleAccount("tenant-blue", "mockcarrier", "tracking.get", "TEST"); !ok || account != "account-blue" {
		t.Fatalf("重复的行: %q, %v", account, ok)
	}
}
