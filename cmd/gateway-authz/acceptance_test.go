//go:build acceptance

package main

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

const adminSecret = "a-secret-of-sufficient-length"

func flavorEnv(t *testing.T) {
	t.Setenv(envAdminSecret, adminSecret)
	t.Setenv(envOperator, operatorID)
	t.Setenv(envSlowSeconds, "0.3")
}

func (h *harness) admin(path string) answer {
	h.t.Helper()
	a := h.must(call{peer: "operator", method: http.MethodPost, path: path, headers: [][2]string{{adminHeader, adminSecret}}})
	if a.status != http.StatusOK {
		h.t.Fatalf("%s: %d %s", path, a.status, a.body)
	}
	return a
}

func (h *harness) gateway() answer {
	h.t.Helper()
	return h.must(call{peer: "gateway", path: extAuthzPath, headers: trusted("tenant-blue")})
}

func TestControlsRequireTheOperatorAndTheSecret(t *testing.T) {
	if buildFlavor != "acceptance" {
		t.Fatalf("buildFlavor = %q", buildFlavor)
	}
	h := newHarness(t).start()
	secret := [][2]string{{adminHeader, adminSecret}}
	for name, c := range map[string]call{
		"操作者，没有口令":    {peer: "operator", path: "/admin/log"},
		"操作者，口令不对":    {peer: "operator", path: "/admin/log", headers: [][2]string{{adminHeader, adminSecret + "x"}}},
		"网关，口令正确":     {peer: "gateway", path: "/admin/log", headers: secret},
		"业务应用，口令正确":   {peer: "business", path: "/admin/mode?value=error500", headers: secret},
		"Broker，口令正确": {peer: "broker", path: "/admin/revoke?account=account-blue", headers: secret},
	} {
		if a := h.must(c); a.status != http.StatusNotFound {
			t.Errorf("%s: %d %s", name, a.status, a.body)
		}
	}
	if a := h.gateway(); a.status != http.StatusOK {
		t.Fatalf("被拒绝的控制调用改变了服务的行为：%d", a.status)
	}
	// 空的记录必须是 []，套件按列表读它。
	h.admin("/admin/reset")
	if a := h.admin("/admin/log"); a.body != `{"log":[],"tls_handshakes_refused":[]}` {
		t.Fatalf("清空后的记录：%s", a.body)
	}
	if a := h.must(call{peer: "operator", path: "/admin/nothing", headers: secret}); a.status != http.StatusNotFound {
		t.Errorf("未知的控制操作：%d", a.status)
	}
	if a := h.must(call{peer: "operator", path: "/admin/mode?value=open", headers: secret}); a.status != http.StatusBadRequest {
		t.Errorf("未知的模式：%d", a.status)
	}
}

func TestLogRecordsWhatWasReceived(t *testing.T) {
	h := newHarness(t).start()
	h.must(call{peer: "gateway", path: extAuthzPath + "?probe=1", headers: append(trusted("tenant-blue"), [2]string{"X-Provider-Account", "account-blue"})})
	h.must(call{peer: "business", path: extAuthzPath, headers: trusted("tenant-blue")})
	h.must(call{peer: "broker", method: http.MethodPost, path: decisionPath, body: decisionBody})
	h.must(call{peer: "gateway", path: "/healthz"})

	state := h.admin("/admin/log").json(t)
	log := state["log"].([]any)
	if len(log) != 3 {
		t.Fatalf("记录了 %d 条，期望 3 条（healthz 和控制调用不记）：%v", len(log), log)
	}
	first := log[0].(map[string]any)
	if first["seq"] != float64(1) || first["method"] != "GET" || first["raw_target"] != extAuthzPath+"?probe=1" ||
		first["peer_identity"] != gatewayID || first["tls_version"] != "TLSv1.3" || first["proto"] != "HTTP/1.1" {
		t.Errorf("第一条：%v", first)
	}
	seen := map[string][]string{}
	for _, pair := range first["headers"].([]any) {
		kv := pair.([]any)
		name := strings.ToLower(kv[0].(string))
		seen[name] = append(seen[name], kv[1].(string))
	}
	for name, want := range map[string]string{"x-idp-verified-tenant": "tenant-blue", "x-provider-account": "account-blue",
		"x-idp-path": tracking + "/TRK-1", "host": strings.TrimPrefix(h.url, "https://")} {
		if len(seen[name]) != 1 || seen[name][0] != want {
			t.Errorf("头 %s：%v", name, seen[name])
		}
	}
	// 身份不对的调用被拒绝，但留在记录里。
	if second := log[1].(map[string]any); second["peer_identity"] != businessID {
		t.Errorf("第二条：%v", second)
	}
	if third := log[2].(map[string]any); third["raw_target"] != decisionPath || third["peer_identity"] != brokerID ||
		third["body_len"] != float64(len(decisionBody)) {
		t.Errorf("第三条：%v", third)
	}
}

func TestFaultModes(t *testing.T) {
	h := newHarness(t).start()

	h.admin("/admin/mode?value=error500")
	if a := h.gateway(); a.status != http.StatusInternalServerError || a.carriesCredential() {
		t.Errorf("error500: %d %s", a.status, a.body)
	}
	if a := h.must(call{peer: "broker", method: http.MethodPost, path: decisionPath, body: decisionBody}); a.status != http.StatusInternalServerError {
		t.Errorf("error500，判定接口：%d", a.status)
	}
	// 故障不改变对身份的检查。
	if a := h.must(call{peer: "business", path: extAuthzPath, headers: trusted("tenant-blue")}); a.status != http.StatusUnauthorized {
		t.Errorf("error500 下身份不对的调用：%d", a.status)
	}

	h.admin("/admin/mode?value=slow")
	started := time.Now()
	if a := h.gateway(); a.status != http.StatusOK || time.Since(started) < 300*time.Millisecond {
		t.Errorf("slow: %d，用时 %s", a.status, time.Since(started))
	}

	h.admin("/admin/mode?value=allow_without_credential")
	a := h.gateway()
	if a.status != http.StatusOK || a.json(t)["result"] != "ALLOW" {
		t.Fatalf("allow_without_credential: %d %s", a.status, a.body)
	}
	if a.carriesCredential() || len(a.header.Values("Authorization")) != 0 || len(a.header.Values("X-Idp-Decision-Id")) != 0 {
		t.Errorf("allow_without_credential 仍带出了凭证头：%v", a.header)
	}
	// 拒绝在这个模式下仍是拒绝。
	denied := h.must(call{peer: "gateway", path: extAuthzPath, headers: append(trusted("tenant-blue"), [2]string{"X-Provider-Account", "account-green"})})
	if denied.status != http.StatusForbidden {
		t.Errorf("allow_without_credential 下的拒绝：%d", denied.status)
	}

	h.admin("/admin/reset")
	if a := h.gateway(); a.status != http.StatusOK || a.header.Get("Authorization") != "Bearer "+blueToken {
		t.Errorf("reset 之后：%d", a.status)
	}
}

func TestRevokeAndRestore(t *testing.T) {
	h := newHarness(t).start()
	state := h.admin("/admin/revoke?account=account-blue").json(t)
	if state["revocation_epoch"] != float64(1) || len(state["revoked"].([]any)) != 1 {
		t.Fatalf("撤销后：%v", state)
	}
	if a := h.gateway(); a.status != http.StatusForbidden || a.json(t)["reason_code"] != "ACCOUNT_REVOKED" || a.carriesCredential() {
		t.Errorf("撤销后蓝租户：%d %s", a.status, a.body)
	}
	if a := h.must(call{peer: "gateway", path: extAuthzPath, headers: trusted("tenant-green")}); a.status != http.StatusOK {
		t.Errorf("撤销蓝账户影响了绿租户：%d", a.status)
	}
	h.admin("/admin/restore?account=account-blue")
	if a := h.gateway(); a.status != http.StatusOK {
		t.Errorf("恢复后：%d", a.status)
	}
	h.admin("/admin/revoke?account=account-blue")
	h.admin("/admin/reset")
	if a := h.gateway(); a.status != http.StatusOK {
		t.Errorf("reset 没有清掉撤销：%d", a.status)
	}
}

func TestRefusedHandshakesAreCounted(t *testing.T) {
	h := newHarness(t).start()
	for _, peer := range []string{"", "rogue-gateway"} {
		if _, err := h.do(call{peer: peer, path: extAuthzPath, headers: trusted("tenant-blue")}); err == nil {
			t.Fatalf("证书 %q 得到了响应", peer)
		}
	}
	var state map[string]any
	deadline := time.Now().Add(3 * time.Second)
	for {
		state = h.admin("/admin/log").json(t)
		if len(state["tls_handshakes_refused"].([]any)) == 2 || time.Now().After(deadline) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	refused := state["tls_handshakes_refused"].([]any)
	if len(refused) != 2 || len(state["log"].([]any)) != 0 {
		t.Fatalf("被拒绝的握手 %v，记录 %v", refused, state["log"])
	}
	for _, reason := range refused {
		if !strings.Contains(reason.(string), "tls:") {
			t.Errorf("原因 %q 不像一次 TLS 握手失败", reason)
		}
	}
}

func TestAcceptanceBuildRefusesAnUnsafeStart(t *testing.T) {
	h := newHarness(t)
	try := func(listen string) error {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return run(ctx, h.args(listen), io.Discard, nil)
	}
	cases := map[string]func(){
		"没有口令":         func() { t.Setenv(envAdminSecret, "") },
		"口令太短":         func() { t.Setenv(envAdminSecret, "short") },
		"没有操作者身份":      func() { t.Setenv(envOperator, "") },
		"操作者就是网关":      func() { t.Setenv(envOperator, gatewayID) },
		"操作者就是 Broker": func() { t.Setenv(envOperator, brokerID) },
		"没有慢速时长":       func() { t.Setenv(envSlowSeconds, "") },
		"慢速时长不是数":      func() { t.Setenv(envSlowSeconds, "soon") },
	}
	for name, breakIt := range cases {
		flavorEnv(t)
		breakIt()
		if err := try("127.0.0.1:0"); err == nil || !strings.Contains(err.Error(), "acceptance build") {
			t.Errorf("%s: %v", name, err)
		}
	}
	flavorEnv(t)
	for _, listen := range []string{"0.0.0.0:0", ":0", "[::]:0", "localhost:0", "192.0.2.1:0"} {
		if err := try(listen); err == nil || !strings.Contains(err.Error(), "loopback") {
			t.Errorf("监听 %s: %v", listen, err)
		}
	}
}
