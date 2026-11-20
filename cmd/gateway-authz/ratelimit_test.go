package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func rateLimitFile(t *testing.T, max int) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "limits.json")
	content := fmt.Sprintf(`{"version":"v1","buckets":[{"id":"per-account","key_dimensions":["provider","provider_account"],"max_requests":%d,"window_seconds":60}]}`, max)
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func (h *harness) ext(tenant string, extra ...[2]string) answer {
	h.t.Helper()
	return h.must(call{peer: "gateway", path: extAuthzPath, headers: append(trusted(tenant), extra...)})
}

func TestRateLimitPerAccount(t *testing.T) {
	h := newHarness(t)
	h.extra = []string{"--rate-limits", rateLimitFile(t, 2)}
	h.start()
	logs := h.logs.String()
	if !strings.Contains(logs, `"rate_limits":"enabled"`) || !strings.Contains(logs, `"rate_limit_buckets":1`) {
		t.Fatalf("启动日志没有说明配额：%s", logs)
	}
	for i := 1; i <= 2; i++ {
		a := h.ext("tenant-blue")
		if a.status != http.StatusOK || a.header.Get("Authorization") != "Bearer "+blueToken {
			t.Fatalf("第 %d 次：%d %s", i, a.status, a.body)
		}
	}
	limited := h.ext("tenant-blue")
	body := limited.json(t)
	retry, err := strconv.Atoi(limited.header.Get("Retry-After"))
	if limited.status != http.StatusTooManyRequests || err != nil || retry < 1 || retry > 60 {
		t.Fatalf("429：%d retry=%q body=%s", limited.status, limited.header.Get("Retry-After"), limited.body)
	}
	if body["result"] != "DENY" || body["reason_code"] != "RATE_LIMITED" || limited.header.Get("Authorization") != "" || limited.carriesCredential() {
		t.Fatalf("429 的正文或凭证：%v %v", body, limited.header)
	}
	if !strings.Contains(h.logs.String(), `"reason":"RATE_LIMITED"`) || !strings.Contains(h.logs.String(), `"status":429`) {
		t.Fatalf("日志里没有 429：%s", h.logs)
	}
	if a := h.ext("tenant-green"); a.status != http.StatusOK || a.header.Get("Authorization") != "Bearer "+greenToken {
		t.Fatalf("绿账户被蓝账户拖累：%d %s", a.status, a.body)
	}
	// 绿账户过了之后，蓝账户仍然被限。
	if a := h.ext("tenant-blue"); a.status != http.StatusTooManyRequests {
		t.Fatalf("绿账户把蓝账户的桶重置了：%d", a.status)
	}
}

func TestUngrantedRequestDoesNotConsumeTheAccountQuota(t *testing.T) {
	h := newHarness(t)
	h.extra = []string{"--rate-limits", rateLimitFile(t, 1)}
	h.start()
	denied := h.ext("tenant-blue", [2]string{"X-Provider-Account", "account-green"})
	if denied.status != http.StatusForbidden || denied.json(t)["reason_code"] != "ACCOUNT_NOT_GRANTED" || denied.carriesCredential() {
		t.Fatalf("未获授：%d %s", denied.status, denied.body)
	}
	if a := h.ext("tenant-blue"); a.status != http.StatusOK || a.header.Get("Authorization") != "Bearer "+blueToken {
		t.Fatalf("未获授的申请扣了蓝账户的额度：%d %s", a.status, a.body)
	}
	if a := h.ext("tenant-blue"); a.status != http.StatusTooManyRequests {
		t.Fatalf("额度不是 1：%d %s", a.status, a.body)
	}
}

func TestDecisionAPIReportsRateLimitAsDeny(t *testing.T) {
	h := newHarness(t)
	h.extra = []string{"--rate-limits", rateLimitFile(t, 1)}
	h.start()
	first := h.must(call{peer: "broker", method: http.MethodPost, path: decisionPath, body: decisionBody})
	if first.status != http.StatusOK || first.json(t)["result"] != "ALLOW" || first.carriesCredential() {
		t.Fatalf("第一次：%d %s", first.status, first.body)
	}
	second := h.must(call{peer: "broker", method: http.MethodPost, path: decisionPath, body: decisionBody})
	body := second.json(t)
	if second.status != http.StatusOK || body["result"] != "DENY" || body["reason_code"] != "RATE_LIMITED" || second.carriesCredential() {
		t.Fatalf("判定接口：%d %s", second.status, second.body)
	}
	if _, has := body["credential_handle"]; has || second.header.Get("Authorization") != "" {
		t.Fatalf("判定接口带了凭证：%v", body)
	}
}

func TestWithoutRateLimitsThereIsNoCap(t *testing.T) {
	h := newHarness(t).start()
	for range 20 {
		if a := h.ext("tenant-blue"); a.status != http.StatusOK {
			t.Fatalf("没有配额文件也被限了：%d", a.status)
		}
	}
	logs := h.logs.String()
	if !strings.Contains(logs, `"rate_limits":"disabled"`) || !strings.Contains(logs, `"rate_limit_buckets":0`) {
		t.Fatalf("启动日志：%s", logs)
	}
}

func TestRateLimitFileRefusesToStart(t *testing.T) {
	h := newHarness(t)
	dir := t.TempDir()
	write := func(name, content string) string {
		t.Helper()
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		return path
	}
	cases := map[string]struct {
		path string
		says string
	}{
		"文件不存在":               {filepath.Join(dir, "missing.json"), "rate limits"},
		"不是 JSON":             {write("bad.json", `{`), "rate limits"},
		"缺少 provider_account": {write("no-account.json", `{"version":"v1","buckets":[{"id":"a","key_dimensions":["tenant"],"max_requests":1,"window_seconds":1}]}`), "provider_account"},
		"不认识的字段":              {write("unknown.json", `{"version":"v1","buckets":[],"notes":"x"}`), "unknown field"},
	}
	for name, tc := range cases {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		err := run(ctx, append(h.args("127.0.0.1:0"), "--rate-limits", tc.path), io.Discard, nil)
		cancel()
		if err == nil || !strings.Contains(err.Error(), tc.says) {
			t.Errorf("%s: %v", name, err)
		}
	}
}
