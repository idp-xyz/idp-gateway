package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.idp.xyz/idp-gateway/internal/platform/workloadtls"
	"go.idp.xyz/idp-gateway/internal/platform/workloadtls/tlstest"
)

const (
	authzName    = "authz.idp.test"
	revokerID    = "spiffe://idp.test/egress/revoker"
	otherID      = "spiffe://idp.test/gateway-control/publisher"
	bodySentinel = "SENTINEL-FROM-THE-ANSWER-BODY"
)

// seenRequest 是假 gateway-authz 收到的一个请求。
type seenRequest struct {
	method, path, body, contentType, identity string
}

// fakeAuthz 是一个要客户端证书的假 gateway-authz。它认的撤销者是 revokerID，别的身份得 401；
// 其余的由 answer 决定。
type fakeAuthz struct {
	t        *testing.T
	ca       *tlstest.CA
	server   *httptest.Server
	revoker  tlstest.Leaf
	other    tlstest.Leaf
	mu       sync.Mutex
	requests []seenRequest
	answer   func(w http.ResponseWriter, r *http.Request, body string)
}

func newFakeAuthz(t *testing.T, answer func(w http.ResponseWriter, r *http.Request, body string)) *fakeAuthz {
	t.Helper()
	ca := tlstest.NewCA(t, "workload CA")
	f := &fakeAuthz{t: t, ca: ca, answer: answer}
	f.revoker = ca.Issue("revoker", []string{revokerID})
	f.other = ca.Issue("publisher", []string{otherID})
	f.server = f.start(ca, authzName)
	return f
}

func (f *fakeAuthz) start(ca *tlstest.CA, name string) *httptest.Server {
	leaf := ca.Issue("authz-"+strings.ReplaceAll(name, ".", "-"), nil, name)
	config, err := workloadtls.ServerConfig(leaf.CertFile, leaf.KeyFile, ca.File())
	if err != nil {
		f.t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		f.requests = append(f.requests, seenRequest{r.Method, r.URL.Path, string(raw), r.Header.Get("Content-Type"), workloadtls.PeerIdentity(r.TLS)})
		f.mu.Unlock()
		if workloadtls.PeerIdentity(r.TLS) != revokerID {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		f.answer(w, r, string(raw))
	}))
	server.TLS = config
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.StartTLS()
	f.t.Cleanup(server.Close)
	return server
}

func (f *fakeAuthz) seen() []seenRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]seenRequest(nil), f.requests...)
}

func (f *fakeAuthz) address() string { return f.server.Listener.Addr().String() }

// common 是各条命令共有的参数，用撤销者的证书。
func (f *fakeAuthz) common(extra ...string) []string {
	return append([]string{"--authz", f.address(), "--authz-name", authzName,
		"--tls-cert", f.revoker.CertFile, "--tls-key", f.revoker.KeyFile, "--tls-ca", f.ca.File()}, extra...)
}

type revocationResult struct {
	code           int
	stdout, stderr string
	report         map[string]any
}

func runRevocationCommand(t *testing.T, ctx context.Context, args ...string) revocationResult {
	t.Helper()
	var stdout, stderr bytes.Buffer
	r := revocationResult{code: run(ctx, args, &stdout, &stderr, nil)}
	r.stdout, r.stderr = stdout.String(), stderr.String()
	if r.stdout != "" {
		if strings.Count(r.stdout, "\n") != 1 || !strings.HasSuffix(r.stdout, "\n") {
			t.Fatalf("标准输出不是一行：%q", r.stdout)
		}
		if err := json.Unmarshal(stdout.Bytes(), &r.report); err != nil {
			t.Fatalf("标准输出不是 JSON：%q", r.stdout)
		}
	}
	return r
}

func (f *fakeAuthz) run(args ...string) revocationResult {
	f.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return runRevocationCommand(f.t, ctx, args...)
}

func writeJSON(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, body)
}

// changeBody 是 RevocationChange 的正文。
func changeBody(account string, revoked, changed bool, epoch int, errorName string) string {
	b, _ := json.Marshal(map[string]any{"account_id": account, "revoked": revoked, "changed": changed, "revocation_epoch": epoch})
	if errorName == "" {
		return string(b)
	}
	return strings.TrimSuffix(string(b), "}") + `,"error":"` + errorName + `"}`
}

func answers(status int, body string) func(http.ResponseWriter, *http.Request, string) {
	return func(w http.ResponseWriter, _ *http.Request, _ string) { writeJSON(w, status, body) }
}

func field[T any](t *testing.T, report map[string]any, name string) T {
	t.Helper()
	value, ok := report[name].(T)
	if !ok {
		t.Fatalf("JSON 里没有 %q，或类型不对：%v", name, report)
	}
	return value
}

func TestRevokeSendsOneRevocationAndReportsTheState(t *testing.T) {
	f := newFakeAuthz(t, answers(200, changeBody("account-blue", true, true, 7, "")))
	r := f.run(append([]string{"revoke", "--account", "account-blue", "--reason", "credential reported leaked"}, f.common()...)...)
	if r.code != 0 {
		t.Fatalf("退出码 %d：%s", r.code, r.stderr)
	}
	if field[string](t, r.report, "command") != "revoke" || field[string](t, r.report, "outcome") != "REVOKED" ||
		field[string](t, r.report, "account") != "account-blue" || !field[bool](t, r.report, "revoked") ||
		!field[bool](t, r.report, "changed") || field[float64](t, r.report, "revocation_epoch") != 7 {
		t.Errorf("输出不对：%s", r.stdout)
	}
	if !strings.Contains(r.stderr, "REVOKED") || !strings.Contains(r.stderr, "account-blue") || strings.Count(r.stderr, "\n") != 1 {
		t.Errorf("标准错误应当是一句话：%q", r.stderr)
	}
	seen := f.seen()
	if len(seen) != 1 {
		t.Fatalf("应当只发一次请求，发了 %d 次", len(seen))
	}
	got := seen[0]
	if got.method != "POST" || got.path != "/v1/egress/revocations" || got.identity != revokerID || got.contentType != "application/json" {
		t.Errorf("请求不对：%+v", got)
	}
	var sent map[string]any
	if err := json.Unmarshal([]byte(got.body), &sent); err != nil {
		t.Fatal(err)
	}
	if len(sent) != 3 || sent["account_id"] != "account-blue" || sent["revoked"] != true || sent["reason"] != "credential reported leaked" {
		t.Errorf("请求正文不对：%s", got.body)
	}
}

func TestRevokingWhatIsRevokedAlreadyIsNotAnError(t *testing.T) {
	f := newFakeAuthz(t, answers(200, changeBody("account-blue", true, false, 7, "")))
	r := f.run(append([]string{"revoke", "--account", "account-blue", "--reason", "again"}, f.common()...)...)
	if r.code != 0 || field[string](t, r.report, "outcome") != "REVOKED" || field[bool](t, r.report, "changed") || field[float64](t, r.report, "revocation_epoch") != 7 {
		t.Errorf("退出码 %d，输出 %s", r.code, r.stdout)
	}
	if !strings.Contains(r.stderr, "already") || !strings.Contains(r.stderr, "nothing changed") {
		t.Errorf("标准错误没有说本来就是撤销的：%q", r.stderr)
	}
}

func TestRestoreSendsNoReasonAndReportsTheState(t *testing.T) {
	for _, c := range []struct {
		name    string
		changed bool
	}{{"取消了", true}, {"本来就没有撤销", false}} {
		t.Run(c.name, func(t *testing.T) {
			f := newFakeAuthz(t, answers(200, changeBody("account-blue", false, c.changed, 8, "")))
			r := f.run(append([]string{"restore", "--account", "account-blue"}, f.common()...)...)
			if r.code != 0 || field[string](t, r.report, "command") != "restore" || field[string](t, r.report, "outcome") != "LIFTED" ||
				field[bool](t, r.report, "revoked") || field[bool](t, r.report, "changed") != c.changed || field[float64](t, r.report, "revocation_epoch") != 8 {
				t.Errorf("退出码 %d，输出 %s", r.code, r.stdout)
			}
			if strings.Contains(r.stdout, "RESTORED") || strings.Contains(r.stderr, "RESTORED") {
				t.Error("RESTORED 是 publish 的一个结局（退出码 4），这里不用")
			}
			seen := f.seen()
			if len(seen) != 1 || seen[0].method != "POST" || seen[0].body != `{"account_id":"account-blue","revoked":false}` {
				t.Errorf("请求不对：%+v", seen)
			}
		})
	}
}

func TestRevocationsReadsTheWholeTable(t *testing.T) {
	table := `{"revocation_epoch":9,"revoked_accounts":[{"account_id":"account-blue","revoked_at":"2026-11-19T10:00:00Z","revoked_by":"` + revokerID + `","reason":"leaked"}]}`
	f := newFakeAuthz(t, answers(200, table))
	r := f.run(append([]string{"revocations"}, f.common()...)...)
	if r.code != 0 || field[string](t, r.report, "command") != "revocations" || field[string](t, r.report, "outcome") != "LISTED" || field[float64](t, r.report, "revocation_epoch") != 9 {
		t.Fatalf("退出码 %d，输出 %s", r.code, r.stdout)
	}
	rows := field[[]any](t, r.report, "revoked_accounts")
	row, _ := rows[0].(map[string]any)
	if len(rows) != 1 || row["account_id"] != "account-blue" || row["revoked_by"] != revokerID || row["reason"] != "leaked" || row["revoked_at"] != "2026-11-19T10:00:00Z" {
		t.Errorf("表不对：%s", r.stdout)
	}
	if seen := f.seen(); len(seen) != 1 || seen[0].method != "GET" || seen[0].body != "" {
		t.Errorf("请求不对：%+v", seen)
	}

	empty := newFakeAuthz(t, answers(200, `{"revocation_epoch":2,"revoked_accounts":[]}`))
	r = empty.run(append([]string{"revocations"}, empty.common()...)...)
	if r.code != 0 || !strings.Contains(r.stdout, `"revoked_accounts":[]`) {
		t.Errorf("空表应当写成 []：退出码 %d，%s", r.code, r.stdout)
	}
}

func TestEveryOutcomeHasItsOwnNameAndExitCode(t *testing.T) {
	revoke := []string{"revoke", "--account", "account-blue", "--reason", "leaked"}
	restore := []string{"restore", "--account", "account-blue"}
	list := []string{"revocations"}
	secret := `{"error":"` + bodySentinel + `"}`
	for _, c := range []struct {
		name    string
		command []string
		status  int
		body    string
		outcome string
		code    int
		says    []string // 标准错误里要有
		state   bool     // 输出里要有服务端说的状态
	}{
		{"撤销，不是撤销者", revoke, 401, secret, "NOT_REVOKER", 3, []string{"Nothing changed"}, false},
		{"撤销，没有配置撤销者", revoke, 404, secret, "NO_REVOKER_CONFIGURED", 3, []string{"Nothing changed"}, false},
		{"撤销，不认识的账户", revoke, 422, changeBody("account-blue", false, false, 3, "unknown_account"), "UNKNOWN_ACCOUNT", 3, []string{"mistyped", "Nothing changed"}, false},
		{"撤销，请求不合格式", revoke, 400, secret, "REQUEST_REFUSED", 3, []string{"Nothing changed"}, false},
		{"撤销，生效了但没有写下去", revoke, 500, changeBody("account-blue", true, true, 8, "revocation_in_effect_but_not_written"), "REVOKED_NOT_WRITTEN", 7,
			[]string{"refused now", "will not be refused after gateway-authz restarts", "run the same command again", "revocations file"}, true},
		{"恢复，不是撤销者", restore, 401, secret, "NOT_REVOKER", 3, nil, false},
		{"恢复，不认识的账户", restore, 422, changeBody("account-blue", false, false, 3, "unknown_account"), "UNKNOWN_ACCOUNT", 3, nil, false},
		{"恢复，没有写下去所以没有恢复", restore, 500, changeBody("account-blue", true, false, 8, "revocations_not_changed"), "LIFT_NOT_WRITTEN", 3,
			[]string{"NOT lifted", "still revoked"}, true},
		{"读表，不是撤销者", list, 401, secret, "NOT_REVOKER", 3, nil, false},
		{"读表，没有配置撤销者", list, 404, secret, "NO_REVOKER_CONFIGURED", 3, nil, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newFakeAuthz(t, answers(c.status, c.body))
			r := f.run(append(append([]string{}, c.command...), f.common()...)...)
			if r.code != c.code || field[string](t, r.report, "outcome") != c.outcome || field[float64](t, r.report, "http_status") != float64(c.status) {
				t.Fatalf("退出码 %d，输出 %s；要的是 %d %s", r.code, r.stdout, c.code, c.outcome)
			}
			for _, says := range c.says {
				if !strings.Contains(r.stderr, says) {
					t.Errorf("标准错误里没有 %q：%q", says, r.stderr)
				}
			}
			if _, has := r.report["revocation_epoch"]; has != c.state {
				t.Errorf("输出里有没有服务端说的状态：%v，要的是 %v：%s", has, c.state, r.stdout)
			}
			if strings.Contains(r.stdout+r.stderr, bodySentinel) || strings.Contains(r.stdout+r.stderr, "unknown_account") {
				t.Errorf("应答正文被原样带了出来：%q %q", r.stdout, r.stderr)
			}
			if strings.Count(r.stderr, "\n") != 1 {
				t.Errorf("标准错误应当是一句话：%q", r.stderr)
			}
		})
	}
}

func TestNotTheRevokersCertificateIsRefusedAndChangesNothing(t *testing.T) {
	f := newFakeAuthz(t, answers(200, changeBody("account-blue", true, true, 7, "")))
	args := []string{"revoke", "--account", "account-blue", "--reason", "x", "--authz", f.address(), "--authz-name", authzName,
		"--tls-cert", f.other.CertFile, "--tls-key", f.other.KeyFile, "--tls-ca", f.ca.File()}
	r := f.run(args...)
	if r.code != 3 || field[string](t, r.report, "outcome") != "NOT_REVOKER" {
		t.Errorf("退出码 %d，输出 %s", r.code, r.stdout)
	}
	if seen := f.seen(); len(seen) != 1 || seen[0].identity != otherID {
		t.Errorf("%+v", seen)
	}
}

// 不知道：请求可能已经到了。每一种都是退出码 5，标准错误说再跑一次是安全的、读到表之前不要当作已经撤销。
func TestWhenThereIsNoUsableAnswerTheOutcomeIsUnknown(t *testing.T) {
	revoke := []string{"revoke", "--account", "account-blue", "--reason", "leaked"}
	for _, c := range []struct {
		name   string
		answer func(http.ResponseWriter, *http.Request, string)
		status int
	}{
		{"别的状态码：403", answers(403, bodySentinel), 403},
		{"别的状态码：502", answers(502, bodySentinel), 502},
		{"别的状态码：204", func(w http.ResponseWriter, _ *http.Request, _ string) { w.WriteHeader(204) }, 204},
		{"500，但不是认识的那两种", answers(500, `{"error":"`+bodySentinel+`"}`), 500},
		{"500，正文看不懂", answers(500, bodySentinel), 500},
		{"500，撤销接口的另一个错误名", answers(500, changeBody("account-blue", true, true, 8, "revocations_not_changed")), 500},
		{"200，正文看不懂", answers(200, bodySentinel), 200},
		{"200，正文是别的账户的", answers(200, changeBody("account-green", true, true, 8, "")), 200},
		{"200，说的是没有撤销", answers(200, changeBody("account-blue", false, true, 8, "")), 200},
		{"200，缺代次", answers(200, `{"account_id":"account-blue","revoked":true,"changed":true}`), 200},
		{"200，正文后面还有东西", answers(200, changeBody("account-blue", true, true, 8, "")+` `+bodySentinel), 200},
		{"200，正文是空的", answers(200, ``), 200},
		{"重定向", func(w http.ResponseWriter, r *http.Request, _ string) {
			http.Redirect(w, r, "/elsewhere", http.StatusTemporaryRedirect)
		}, 307},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newFakeAuthz(t, c.answer)
			r := f.run(append(append([]string{}, revoke...), f.common()...)...)
			if r.code != 5 || field[string](t, r.report, "outcome") != "UNKNOWN" || field[float64](t, r.report, "http_status") != float64(c.status) {
				t.Fatalf("退出码 %d，输出 %s", r.code, r.stdout)
			}
			for _, says := range []string{"may or may not be", "Running the same command again is safe", "gateway-control revocations", "do not take it as revoked", "Nothing was retried"} {
				if !strings.Contains(r.stderr, says) {
					t.Errorf("标准错误里没有 %q：%q", says, r.stderr)
				}
			}
			if strings.Contains(r.stdout+r.stderr, bodySentinel) {
				t.Errorf("应答正文被原样带了出来：%q %q", r.stdout, r.stderr)
			}
			if _, has := r.report["revoked"]; has {
				t.Errorf("没有看懂应答，输出里不该有服务端的状态：%s", r.stdout)
			}
			if seen := f.seen(); len(seen) != 1 {
				t.Errorf("不自动重试：应当只有一次请求，有 %d 次（含重定向）", len(seen))
			}
		})
	}
}

func TestUnknownOutcomeSaysWhatToDoForEachCommand(t *testing.T) {
	f := newFakeAuthz(t, answers(502, ""))
	restore := f.run(append([]string{"restore", "--account", "account-blue"}, f.common()...)...)
	if restore.code != 5 || !strings.Contains(restore.stderr, "may or may not be lifted") || !strings.Contains(restore.stderr, "Running the same command again is safe") {
		t.Errorf("%d %q", restore.code, restore.stderr)
	}
	list := f.run(append([]string{"revocations"}, f.common()...)...)
	if list.code != 5 || !strings.Contains(list.stderr, "table was not read") {
		t.Errorf("%d %q", list.code, list.stderr)
	}
}

func TestNoAnswerAtAllIsUnknownToo(t *testing.T) {
	revoke := []string{"revoke", "--account", "account-blue", "--reason", "leaked"}
	check := func(t *testing.T, r revocationResult) {
		t.Helper()
		if r.code != 5 || field[string](t, r.report, "outcome") != "UNKNOWN" {
			t.Fatalf("退出码 %d，输出 %s，标准错误 %s", r.code, r.stdout, r.stderr)
		}
		if _, has := r.report["http_status"]; has {
			t.Errorf("没有应答，不该有状态码：%s", r.stdout)
		}
		if !strings.Contains(r.stderr, "may or may not") || !strings.Contains(r.stderr, "do not take it as revoked") {
			t.Errorf("标准错误：%q", r.stderr)
		}
	}
	t.Run("连不上", func(t *testing.T) {
		f := newFakeAuthz(t, answers(200, ""))
		args := f.common()
		f.server.Close()
		check(t, f.run(append(append([]string{}, revoke...), args...)...))
	})
	t.Run("握手之后连接断了", func(t *testing.T) {
		f := newFakeAuthz(t, func(w http.ResponseWriter, _ *http.Request, _ string) {
			conn, _, _ := w.(http.Hijacker).Hijack()
			_ = conn.Close()
		})
		check(t, f.run(append(append([]string{}, revoke...), f.common()...)...))
		if seen := f.seen(); len(seen) != 1 {
			t.Errorf("不自动重试：请求有 %d 次", len(seen))
		}
	})
	t.Run("应答到一半断了", func(t *testing.T) {
		f := newFakeAuthz(t, func(w http.ResponseWriter, _ *http.Request, _ string) {
			w.Header().Set("Content-Length", "500")
			w.WriteHeader(200)
			_, _ = io.WriteString(w, `{"account_id":`)
			conn, _, _ := w.(http.Hijacker).Hijack()
			_ = conn.Close()
		})
		check(t, f.run(append(append([]string{}, revoke...), f.common()...)...))
	})
	t.Run("超时", func(t *testing.T) {
		release := make(chan struct{})
		f := newFakeAuthz(t, func(w http.ResponseWriter, _ *http.Request, _ string) {
			select {
			case <-release:
			case <-time.After(10 * time.Second):
			}
		})
		t.Cleanup(func() { close(release) })
		started := time.Now()
		r := f.run(append(append([]string{}, revoke...), f.common("--timeout", "300ms")...)...)
		check(t, r)
		if took := time.Since(started); took > 5*time.Second {
			t.Errorf("--timeout 300ms 却等了 %s", took)
		}
		if !strings.Contains(r.stderr, "no answer") || !strings.Contains(r.stderr, "within 300ms") {
			t.Errorf("标准错误没有说是超时：%q", r.stderr)
		}
		if seen := f.seen(); len(seen) != 1 {
			t.Errorf("不自动重试：请求有 %d 次", len(seen))
		}
	})
	t.Run("对端不说 HTTP", func(t *testing.T) {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		go func() {
			for {
				conn, err := listener.Accept()
				if err != nil {
					return
				}
				_, _ = io.WriteString(conn, "not a TLS server\r\n")
				_ = conn.Close()
			}
		}()
		f := newFakeAuthz(t, answers(200, ""))
		args := []string{"--authz", listener.Addr().String(), "--authz-name", authzName,
			"--tls-cert", f.revoker.CertFile, "--tls-key", f.revoker.KeyFile, "--tls-ca", f.ca.File()}
		check(t, f.run(append(append([]string{}, revoke...), args...)...))
	})
	t.Run("服务端的证书不是信任的 CA 签的", func(t *testing.T) {
		f := newFakeAuthz(t, answers(200, changeBody("account-blue", true, true, 1, "")))
		// 这个服务端不要客户端证书：握手能不能完成，只看客户端认不认它的证书。
		rogue := tlstest.NewCA(t, "rogue CA")
		leaf := rogue.Issue("rogue-authz", nil, authzName)
		var reached int32
		impostor := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			atomic.AddInt32(&reached, 1)
			writeJSON(w, 200, changeBody("account-blue", true, true, 1, ""))
		}))
		impostor.TLS = &tls.Config{Certificates: []tls.Certificate{leaf.Certificate}}
		impostor.Config.ErrorLog = log.New(io.Discard, "", 0)
		impostor.StartTLS()
		t.Cleanup(impostor.Close)
		args := []string{"--authz", impostor.Listener.Addr().String(), "--authz-name", authzName,
			"--tls-cert", f.revoker.CertFile, "--tls-key", f.revoker.KeyFile, "--tls-ca", f.ca.File()}
		check(t, f.run(append(append([]string{}, revoke...), args...)...))
		if atomic.LoadInt32(&reached) != 0 {
			t.Error("握手没有完成，不该有请求")
		}
	})
	t.Run("服务端的证书是给别的名字的", func(t *testing.T) {
		f := newFakeAuthz(t, answers(200, changeBody("account-blue", true, true, 1, "")))
		args := []string{"--authz", f.address(), "--authz-name", "someone-else.idp.test",
			"--tls-cert", f.revoker.CertFile, "--tls-key", f.revoker.KeyFile, "--tls-ca", f.ca.File()}
		check(t, f.run(append(append([]string{}, revoke...), args...)...))
		if len(f.seen()) != 0 {
			t.Error("名字对不上，握手不该完成，更不该有请求")
		}
	})
	t.Run("服务端不信任撤销者的证书", func(t *testing.T) {
		f := newFakeAuthz(t, answers(200, changeBody("account-blue", true, true, 1, "")))
		rogue := tlstest.NewCA(t, "rogue CA")
		leaf := rogue.Issue("rogue-revoker", []string{revokerID})
		args := []string{"--authz", f.address(), "--authz-name", authzName, "--tls-cert", leaf.CertFile, "--tls-key", leaf.KeyFile, "--tls-ca", f.ca.File()}
		check(t, f.run(append(append([]string{}, revoke...), args...)...))
		if len(f.seen()) != 0 {
			t.Error("握手没有完成，不该有请求")
		}
	})
	t.Run("被叫停", func(t *testing.T) {
		started := make(chan struct{})
		f := newFakeAuthz(t, func(w http.ResponseWriter, r *http.Request, _ string) {
			close(started)
			<-r.Context().Done()
		})
		ctx, cancel := context.WithCancel(context.Background())
		go func() { <-started; cancel() }()
		r := runRevocationCommand(t, ctx, append(append([]string{}, revoke...), f.common()...)...)
		check(t, r)
		if !strings.Contains(r.stderr, "interrupted") {
			t.Errorf("%q", r.stderr)
		}
	})
}

func TestRedirectsAreNotFollowed(t *testing.T) {
	elsewhere := newFakeAuthz(t, answers(200, changeBody("account-blue", true, true, 1, "")))
	f := newFakeAuthz(t, func(w http.ResponseWriter, r *http.Request, _ string) {
		http.Redirect(w, r, "https://"+elsewhere.address()+"/v1/egress/revocations", http.StatusTemporaryRedirect)
	})
	r := f.run(append([]string{"revoke", "--account", "account-blue", "--reason", "x"}, f.common()...)...)
	if r.code != 5 || field[float64](t, r.report, "http_status") != 307 {
		t.Errorf("退出码 %d，输出 %s", r.code, r.stdout)
	}
	if n := len(elsewhere.seen()); n != 0 {
		t.Errorf("重定向的那一头收到了 %d 个请求", n)
	}
}

func TestUsageOfTheRevocationCommands(t *testing.T) {
	f := newFakeAuthz(t, answers(200, changeBody("account-blue", true, true, 1, "")))
	without := func(args []string, flag string) []string {
		var kept []string
		for i := 0; i < len(args); i++ {
			if args[i] == flag {
				i++
				continue
			}
			kept = append(kept, args[i])
		}
		return kept
	}
	revoke := append([]string{"revoke", "--account", "account-blue", "--reason", "leaked"}, f.common()...)
	restore := append([]string{"restore", "--account", "account-blue"}, f.common()...)
	list := append([]string{"revocations"}, f.common()...)
	for _, c := range []struct {
		name string
		args []string
		says string
	}{
		{"revoke 没有参数", []string{"revoke"}, "missing required flags: --account, --authz, --authz-name, --reason, --tls-ca, --tls-cert, --tls-key"},
		{"restore 没有参数", []string{"restore"}, "missing required flags: --account, --authz, --authz-name, --tls-ca, --tls-cert, --tls-key"},
		{"revocations 没有参数", []string{"revocations"}, "missing required flags: --authz, --authz-name, --tls-ca, --tls-cert, --tls-key"},
		{"revoke 缺 --reason", without(revoke, "--reason"), "missing required flags: --reason"},
		{"revoke 的原因是空的", append(without(revoke, "--reason"), "--reason", ""), "missing required flags: --reason"},
		{"revoke 的原因只有空白", append(without(revoke, "--reason"), "--reason", " \t "), "--reason must not be blank"},
		{"revoke 缺 --account", without(revoke, "--account"), "missing required flags: --account"},
		{"restore 缺 --account", without(restore, "--account"), "missing required flags: --account"},
		{"缺 --authz", without(list, "--authz"), "missing required flags: --authz"},
		{"缺 --authz-name", without(list, "--authz-name"), "missing required flags: --authz-name"},
		{"缺 --tls-cert", without(list, "--tls-cert"), "missing required flags: --tls-cert"},
		{"缺 --tls-key", without(list, "--tls-key"), "missing required flags: --tls-key"},
		{"缺 --tls-ca", without(list, "--tls-ca"), "missing required flags: --tls-ca"},
		{"--authz 没有端口", append(without(list, "--authz"), "--authz", "127.0.0.1"), "--authz must be host:port"},
		{"--authz 没有主机", append(without(list, "--authz"), "--authz", ":8443"), "--authz must be host:port"},
		{"--timeout 为零", append(list[:len(list):len(list)], "--timeout", "0s"), "--timeout must be positive"},
		{"--timeout 是负的", append(list[:len(list):len(list)], "--timeout", "-1s"), "--timeout must be positive"},
		{"--timeout 不是时长", append(list[:len(list):len(list)], "--timeout", "soon"), "invalid value"},
		{"多余的参数", append(list[:len(list):len(list)], "now"), `unexpected argument "now"`},
		{"revocations 不要 --account", append(list[:len(list):len(list)], "--account", "account-blue"), "flag provided but not defined: -account"},
		{"restore 不要 --reason", append(restore[:len(restore):len(restore)], "--reason", "x"), "flag provided but not defined: -reason"},
		{"不认识的参数", append(list[:len(list):len(list)], "--retries", "3"), "flag provided but not defined: -retries"},
		{"不认识的子命令", []string{"remove"}, "usage: gateway-control publish|restart|reconcile|place|keep [flags]"},
		{"不认识的子命令也提到三条新命令", []string{"remove"}, "gateway-control revoke|restore|revocations [flags]"},
	} {
		t.Run(c.name, func(t *testing.T) {
			before := len(f.seen())
			r := f.run(c.args...)
			if r.code != 2 || r.stdout != "" || !strings.Contains(r.stderr, c.says) {
				t.Errorf("退出码 %d，标准输出 %q，标准错误 %q；要的是 2 和 %q", r.code, r.stdout, r.stderr, c.says)
			}
			if len(f.seen()) != before {
				t.Error("用法错误的时候什么都不该发出去")
			}
		})
	}
}

func TestHelpListsTheOutcomesAndExitCodes(t *testing.T) {
	for _, command := range []string{"revoke", "restore", "revocations"} {
		r := runRevocationCommand(t, context.Background(), command, "--help")
		if r.code != 2 || r.stdout != "" {
			t.Errorf("%s --help：退出码 %d，标准输出 %q", command, r.code, r.stdout)
		}
		for _, want := range []string{"-authz", "-authz-name", "-tls-cert", "-tls-key", "-tls-ca", "-timeout", "REVOKED, LIFTED, LISTED (0)",
			"NOT_REVOKER (3)", "NO_REVOKER_CONFIGURED (3)", "UNKNOWN_ACCOUNT (3)", "REQUEST_REFUSED (3)", "LIFT_NOT_WRITTEN (3)", "UNKNOWN (5)", "REVOKED_NOT_WRITTEN (7)"} {
			if !strings.Contains(r.stderr, want) {
				t.Errorf("%s --help 里没有 %q", command, want)
			}
		}
	}
}

func TestACertificateFileThatCannotBeReadSendsNothing(t *testing.T) {
	f := newFakeAuthz(t, answers(200, changeBody("account-blue", true, true, 1, "")))
	missing := f.revoker.CertFile + ".missing"
	r := f.run("revoke", "--account", "account-blue", "--reason", "x", "--authz", f.address(), "--authz-name", authzName,
		"--tls-cert", missing, "--tls-key", f.revoker.KeyFile, "--tls-ca", f.ca.File())
	if r.code != 1 || r.stdout != "" || !strings.Contains(r.stderr, "client certificate") || len(f.seen()) != 0 {
		t.Errorf("退出码 %d，标准输出 %q，标准错误 %q", r.code, r.stdout, r.stderr)
	}
}

// 证书、私钥的内容不出现在任何输出里：成功、各种结局、连不上、握手失败、读不了证书，都一样。
func TestNoCertificateOrKeyContentIsPrinted(t *testing.T) {
	f := newFakeAuthz(t, answers(200, changeBody("account-blue", true, true, 7, "")))
	rogue := tlstest.NewCA(t, "rogue CA")
	rogueServer := f.start(rogue, authzName)

	var bodies []string
	for _, file := range []string{f.revoker.CertFile, f.revoker.KeyFile, f.ca.File(), f.other.CertFile, f.other.KeyFile} {
		raw, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		block, _ := pem.Decode(raw)
		if block == nil {
			t.Fatal("不是 PEM")
		}
		// 一段够长、不会碰巧出现的：PEM 正文的第一行，和 DER 的十六进制。
		bodies = append(bodies, strings.SplitN(string(raw), "\n", 3)[1], string(block.Bytes[len(block.Bytes)-24:]))
	}
	revoke := []string{"revoke", "--account", "account-blue", "--reason", "leaked"}
	runs := [][]string{
		append(append([]string{}, revoke...), f.common()...),
		append([]string{"revocations"}, f.common()...),
		append(append([]string{}, revoke...), "--authz", rogueServer.Listener.Addr().String(), "--authz-name", authzName,
			"--tls-cert", f.revoker.CertFile, "--tls-key", f.revoker.KeyFile, "--tls-ca", f.ca.File()),
		append(append([]string{}, revoke...), "--authz", f.address(), "--authz-name", "wrong.idp.test",
			"--tls-cert", f.revoker.CertFile, "--tls-key", f.revoker.KeyFile, "--tls-ca", f.ca.File()),
		// 把私钥文件当证书：读得出，但配不上
		append(append([]string{}, revoke...), "--authz", f.address(), "--authz-name", authzName,
			"--tls-cert", f.revoker.KeyFile, "--tls-key", f.revoker.KeyFile, "--tls-ca", f.ca.File()),
		append(append([]string{}, revoke...), "--authz", f.address(), "--authz-name", authzName,
			"--tls-cert", f.revoker.CertFile, "--tls-key", f.revoker.KeyFile, "--tls-ca", f.revoker.KeyFile),
	}
	for _, args := range runs {
		r := f.run(args...)
		if r.stdout == "" && r.stderr == "" {
			t.Fatal("没有任何输出")
		}
		for _, body := range bodies {
			if strings.Contains(r.stdout+r.stderr, body) || strings.Contains(r.stdout+r.stderr, "BEGIN") {
				t.Errorf("输出里有证书或私钥的内容（%q）：%q %q", body, r.stdout, r.stderr)
			}
		}
	}
}

func TestExitCodesOfTheRevocationOutcomesDoNotClashWithTheOldOnes(t *testing.T) {
	for _, code := range []int{exitRestored, exitRestartPending} {
		if code == exitRevokedNotWritten {
			t.Errorf("REVOKED_NOT_WRITTEN 的退出码 %d 与 publish 的一个结局相同", code)
		}
	}
	if exitRevokedNotWritten == exitActive || exitRevokedNotWritten == exitError || exitRevokedNotWritten == exitUsage || exitRevokedNotWritten == exitNotDone || exitRevokedNotWritten == exitUnknown {
		t.Errorf("退出码 %d 与已有的相同", exitRevokedNotWritten)
	}
	if defaultAuthzTimeout < time.Second || defaultAuthzTimeout > 30*time.Second {
		t.Errorf("默认时限 %s 应当是几秒", defaultAuthzTimeout)
	}
}
