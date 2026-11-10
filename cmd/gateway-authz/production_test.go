//go:build !acceptance

package main

import (
	"net/http"
	"testing"
)

// 产品构建不读这些环境变量。设上它们，是为了说明即使有人设了也不起作用。
func flavorEnv(t *testing.T) {
	t.Setenv("GATEWAY_AUTHZ_ACCEPTANCE_ADMIN_SECRET", "a-secret-of-sufficient-length")
	t.Setenv("GATEWAY_AUTHZ_ACCEPTANCE_OPERATOR_IDENTITY", operatorID)
	t.Setenv("GATEWAY_AUTHZ_ACCEPTANCE_SLOW_SECONDS", "0.3")
}

// 验收用的控制接口不在产品构建里：同样的证书、同样的口令，得到的是 404，状态也没有变。
func TestProductionBuildHasNoTestControls(t *testing.T) {
	if buildFlavor != "production" {
		t.Fatalf("buildFlavor = %q", buildFlavor)
	}
	h := newHarness(t).start()
	admin := [][2]string{{"X-Poc-Admin", "a-secret-of-sufficient-length"}}
	for _, path := range []string{"/admin/log", "/admin/reset", "/admin/mode?value=error500", "/admin/mode?value=allow_without_credential",
		"/admin/revoke?account=account-blue"} {
		for _, method := range []string{http.MethodGet, http.MethodPost} {
			if a := h.must(call{peer: "operator", method: method, path: path, headers: admin}); a.status != http.StatusNotFound {
				t.Errorf("%s %s: %d %s", method, path, a.status, a.body)
			}
		}
	}
	a := h.must(call{peer: "gateway", path: extAuthzPath, headers: trusted("tenant-blue")})
	if a.status != http.StatusOK || a.header.Get("Authorization") != "Bearer "+blueToken {
		t.Fatalf("对控制接口的调用改变了服务的行为：%d %s", a.status, a.body)
	}
}
