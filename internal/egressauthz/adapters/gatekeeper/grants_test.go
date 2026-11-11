package gatekeeper

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"go.idp.xyz/idp-gateway/internal/egressauthz/ports"
)

const pdpToken = "pdp-token-for-tests"

// pdp 起一个只会按 answer 作答的 PDP，并记下收到的最后一个请求。
type pdp struct {
	server *httptest.Server
	calls  atomic.Int32
	last   struct {
		method, path, authorization, contentType string
		body                                     map[string]any
	}
}

func newPDP(t *testing.T, answer http.HandlerFunc) *pdp {
	t.Helper()
	p := &pdp{}
	p.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.calls.Add(1)
		raw, _ := io.ReadAll(r.Body)
		p.last.method, p.last.path = r.Method, r.URL.Path
		p.last.authorization, p.last.contentType = r.Header.Get("Authorization"), r.Header.Get("Content-Type")
		p.last.body = nil
		_ = json.Unmarshal(raw, &p.last.body)
		answer(w, r)
	}))
	t.Cleanup(p.server.Close)
	return p
}

func (p *pdp) grants(t *testing.T) *Grants {
	t.Helper()
	g, err := New(Config{BaseURL: p.server.URL, Token: ports.NewSecret(pdpToken), Timeout: 200 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func says(status int, body string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}
}

func TestAsksThePDPInItsOwnTerms(t *testing.T) {
	p := newPDP(t, says(http.StatusOK, `{"decision":true,"reason":"rebac:use"}`))
	granted, err := p.grants(t).MayUse(context.Background(), "client-1", "tenant-1", "account-blue")
	if err != nil || !granted {
		t.Fatalf("%v, %v", granted, err)
	}
	if p.last.method != http.MethodPost || p.last.path != "/authz/check" || p.last.contentType != "application/json" {
		t.Fatalf("%s %s %s", p.last.method, p.last.path, p.last.contentType)
	}
	if p.last.authorization != "Bearer "+pdpToken {
		t.Fatal("没有带上 PDP 令牌")
	}
	want := map[string]any{
		"subject":  map[string]any{"id": "client-1"},
		"action":   "provider_account.use",
		"resource": map[string]any{"type": "provider_account", "id": "account-blue"},
		"context": map[string]any{
			"tenant_id": "tenant-1",
			"contextual_tuples": []any{
				map[string]any{"user": "user:client-1", "relation": "member", "object": "org:tenant-1"},
			},
		},
	}
	got, _ := json.Marshal(p.last.body)
	expected, _ := json.Marshal(want)
	if string(got) != string(expected) {
		t.Fatalf("请求体\n  是   %s\n  期望 %s", got, expected)
	}
}

// 应答按 indeterminate 和 decision 两个字段读。reason 的措辞只在一处起作用：模型里没有这个动作。
func TestHowThePDPsAnswerIsRead(t *testing.T) {
	cases := map[string]struct {
		answer  http.HandlerFunc
		granted bool
		failed  bool
	}{
		"放行": {says(200, `{"decision":true,"reason":"rebac:use"}`), true, false},

		// 拒绝：读得出来、不带 indeterminate 的 decision=false，不管 reason 怎么写。
		"没有授权":                    {says(200, `{"decision":false,"reason":"rebac denied"}`), false, false},
		"功能权限不够":                  {says(200, `{"decision":false,"reason":"rbac denied"}`), false, false},
		"拒绝，措辞没见过":                {says(200, `{"decision":false,"reason":"something new"}`), false, false},
		"拒绝但没有原因":                 {says(200, `{"decision":false}`), false, false},
		"indeterminate 写明是 false": {says(200, `{"decision":false,"reason":"rebac denied","indeterminate":false}`), false, false},
		// 更早的 Gatekeeper 没有 indeterminate：它查询失败时的应答在这里就是拒绝。
		"查询失败但没有标记": {says(200, `{"decision":false,"reason":"rebac lookup failed"}`), false, false},

		// 没有结论：PDP 自己标了没能求出判定。
		"授权引擎查不了":            {says(200, `{"decision":false,"indeterminate":true,"reason":"rebac lookup failed"}`), false, true},
		"权限来源查不了":            {says(200, `{"decision":false,"indeterminate":true,"reason":"rbac lookup failed"}`), false, true},
		"没有结论，措辞没见过":         {says(200, `{"decision":false,"indeterminate":true,"reason":"something new"}`), false, true},
		"没有结论但没有原因":          {says(200, `{"decision":false,"indeterminate":true}`), false, true},
		"标着没有结论却写着放行":        {says(200, `{"decision":true,"indeterminate":true,"reason":"rebac:use"}`), false, true},
		"indeterminate 不是布尔": {says(200, `{"decision":false,"indeterminate":"true","reason":"rebac denied"}`), false, true},
		"模型里没有这个动作":          {says(200, `{"decision":false,"reason":"unknown action"}`), false, true},
		"模型里没有这个动作，后面还有说明":   {says(200, `{"decision":false,"reason":"unknown action: provider_account.use"}`), false, true},

		// 没有结论：读不出判定，或者答的不是 200。
		"答案里没有 decision":   {says(200, `{"reason":"rebac:use"}`), false, true},
		"decision 不是布尔":    {says(200, `{"decision":"true"}`), false, true},
		"不是 JSON":          {says(200, `<html>ok</html>`), false, true},
		"空的 200":           {says(200, ``), false, true},
		"令牌不被接受":           {says(401, `{"error":"unauthorized"}`), false, true},
		"PDP 没有启用":         {says(501, `{"error":"pdp not configured"}`), false, true},
		"400 也带着 decision": {says(400, `{"decision":false,"reason":"bad request"}`), false, true},
		"500 里写着放行":        {says(500, `{"decision":true}`), false, true},
		"重定向": {func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/elsewhere", http.StatusTemporaryRedirect)
		}, false, true},
		"答得太慢": {func(w http.ResponseWriter, _ *http.Request) {
			time.Sleep(600 * time.Millisecond)
			_, _ = io.WriteString(w, `{"decision":true}`)
		}, false, true},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			p := newPDP(t, tc.answer)
			granted, err := p.grants(t).MayUse(context.Background(), "client-1", "tenant-1", "account-blue")
			if granted != tc.granted || (err != nil) != tc.failed {
				t.Fatalf("granted=%v err=%v", granted, err)
			}
			if err != nil && strings.Contains(err.Error(), pdpToken) {
				t.Fatalf("错误信息里有令牌：%v", err)
			}
		})
	}
}

func TestDoesNotFollowRedirects(t *testing.T) {
	p := newPDP(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/elsewhere" {
			_, _ = io.WriteString(w, `{"decision":true}`)
			return
		}
		http.Redirect(w, r, "/elsewhere", http.StatusTemporaryRedirect)
	})
	if granted, err := p.grants(t).MayUse(context.Background(), "client-1", "tenant-1", "account-blue"); granted || err == nil {
		t.Fatalf("granted=%v err=%v", granted, err)
	}
	if p.calls.Load() != 1 {
		t.Fatalf("PDP 被问了 %d 次：令牌跟着重定向走了", p.calls.Load())
	}
}

func TestUnreachablePDPIsAnErrorNotADenial(t *testing.T) {
	p := newPDP(t, says(200, `{"decision":true}`))
	g := p.grants(t)
	p.server.Close()
	if granted, err := g.MayUse(context.Background(), "client-1", "tenant-1", "account-blue"); granted || err == nil {
		t.Fatalf("granted=%v err=%v", granted, err)
	}
}

func TestCancelledRequestIsAnError(t *testing.T) {
	p := newPDP(t, says(200, `{"decision":true}`))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if granted, err := p.grants(t).MayUse(ctx, "client-1", "tenant-1", "account-blue"); granted || err == nil {
		t.Fatalf("granted=%v err=%v", granted, err)
	}
}

// 会被授权引擎当作语法的标识不发出去。
func TestIdentifiersThatAreNotPlainNamesAreNeverSent(t *testing.T) {
	p := newPDP(t, says(200, `{"decision":true,"reason":"rebac:use"}`))
	g := p.grants(t)
	plain := [3]string{"client-1", "tenant-1", "account-blue"}
	for _, bad := range []string{"", "*", "team:ops#member", "user:client-1", "a b", "a\nb", "org:tenant-1", "-leading", strings.Repeat("a", 129), "naïve"} {
		for position := range plain {
			ids := plain
			ids[position] = bad
			granted, err := g.MayUse(context.Background(), ids[0], ids[1], ids[2])
			if granted || err != nil {
				t.Errorf("%q 在第 %d 个位置：granted=%v err=%v", bad, position, granted, err)
			}
		}
	}
	if p.calls.Load() != 0 {
		t.Fatalf("PDP 被问了 %d 次", p.calls.Load())
	}
	for _, good := range []string{"c9a4cda5-eb63-4584-8704-9acbf2ff86f7", "parcel-service", "acct_1.v2~x", strings.Repeat("a", 128)} {
		if granted, err := g.MayUse(context.Background(), good, good, good); !granted || err != nil {
			t.Errorf("%q: granted=%v err=%v", good, granted, err)
		}
	}
}

func TestRefusesUnsafeConfiguration(t *testing.T) {
	token := ports.NewSecret(pdpToken)
	for name, cfg := range map[string]Config{
		"不是 URL":      {BaseURL: "gatekeeper", Token: token},
		"空地址":         {BaseURL: "", Token: token},
		"非回环的明文 http": {BaseURL: "http://gk.example.com", Token: token},
		"非回环的明文 IP":   {BaseURL: "http://10.0.0.8:3000", Token: token},
		"别的协议":        {BaseURL: "ftp://127.0.0.1", Token: token},
		"地址里带着口令":     {BaseURL: "https://user:pass@gk.example.com", Token: token},
		"地址里带着查询":     {BaseURL: "https://gk.example.com/?x=1", Token: token},
		"没有令牌":        {BaseURL: "https://gk.example.com"},
	} {
		if _, err := New(cfg); err == nil {
			t.Errorf("%s: 被接受了", name)
		} else if strings.Contains(err.Error(), pdpToken) || strings.Contains(err.Error(), "user:pass") {
			t.Errorf("%s: 错误信息里有秘密：%v", name, err)
		}
	}
	for _, good := range []string{"https://gk.example.com", "https://gk.example.com/", "https://gk.example.com/pdp", "http://127.0.0.1:27622", "http://localhost:3000", "http://[::1]:3000"} {
		g, err := New(Config{BaseURL: good, Token: token})
		if err != nil {
			t.Errorf("%s: %v", good, err)
			continue
		}
		if !strings.HasSuffix(g.endpoint, "/authz/check") || strings.Contains(g.endpoint, "//authz") {
			t.Errorf("%s: 询问地址是 %s", good, g.endpoint)
		}
	}
}

func TestLoadToken(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string, mode os.FileMode) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(content), mode); err != nil {
			t.Fatal(err)
		}
		return path
	}
	token, err := LoadToken(write("ok", pdpToken+"\n", 0o600))
	if err != nil || token.Reveal() != pdpToken {
		t.Fatalf("%v", err)
	}
	for name, path := range map[string]string{
		"别人可读":  write("open", pdpToken, 0o640),
		"空文件":   write("empty", "\n", 0o600),
		"中间有空白": write("spaced", "a b", 0o600),
		"两行":    write("two", "a\nb\n", 0o600),
		"不存在":   filepath.Join(dir, "missing"),
	} {
		if _, err := LoadToken(path); err == nil {
			t.Errorf("%s: 被接受了", name)
		} else if strings.Contains(err.Error(), pdpToken) {
			t.Errorf("%s: 错误信息里有令牌", name)
		}
	}
}
