package main

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func banBody(operation string, banned, changed bool, epoch int, errorName string) string {
	body, _ := json.Marshal(map[string]any{"operation_id": operation, "banned": banned, "changed": changed, "revocation_epoch": epoch})
	if errorName == "" {
		return string(body)
	}
	return strings.TrimSuffix(string(body), "}") + `,"error":"` + errorName + `"}`
}

func TestBanSendsOneRequestAndReportsTheState(t *testing.T) {
	f := newFakeAuthz(t, answers(200, banBody("tracking.get", true, true, 4, "")))
	r := f.run(append([]string{"ban", "--operation", "tracking.get", "--reason", "abuse"}, f.common()...)...)
	if r.code != 0 || field[string](t, r.report, "command") != "ban" || field[string](t, r.report, "outcome") != "BANNED" ||
		field[string](t, r.report, "operation") != "tracking.get" || !field[bool](t, r.report, "banned") ||
		!field[bool](t, r.report, "changed") || field[float64](t, r.report, "revocation_epoch") != 4 {
		t.Fatalf("退出码 %d，输出 %s，标准错误 %s", r.code, r.stdout, r.stderr)
	}
	if _, hasAccount := r.report["account"]; hasAccount {
		t.Fatalf("封禁的输出不该带账户：%s", r.stdout)
	}
	if _, hasRevoked := r.report["revoked"]; hasRevoked {
		t.Fatalf("封禁的输出不该带 revoked：%s", r.stdout)
	}
	if strings.Count(r.stdout, "\n") != 1 || strings.Count(r.stderr, "\n") != 1 || !strings.Contains(r.stderr, "BANNED") {
		t.Fatalf("应当各是一行：%q %q", r.stdout, r.stderr)
	}
	seen := f.seen()
	if len(seen) != 1 || seen[0].method != "POST" || seen[0].path != "/v1/egress/operation-bans" || seen[0].identity != revokerID {
		t.Fatalf("请求：%+v", seen)
	}
	var sent map[string]any
	if err := json.Unmarshal([]byte(seen[0].body), &sent); err != nil {
		t.Fatal(err)
	}
	if len(sent) != 3 || sent["operation_id"] != "tracking.get" || sent["banned"] != true || sent["reason"] != "abuse" {
		t.Fatalf("请求正文：%s", seen[0].body)
	}
}

func TestUnbanSendsNoReason(t *testing.T) {
	f := newFakeAuthz(t, answers(200, banBody("tracking.get", false, true, 5, "")))
	r := f.run(append([]string{"unban", "--operation", "tracking.get"}, f.common()...)...)
	if r.code != 0 || field[string](t, r.report, "command") != "unban" || field[string](t, r.report, "outcome") != "LIFTED" ||
		field[bool](t, r.report, "banned") || !field[bool](t, r.report, "changed") {
		t.Fatalf("退出码 %d，输出 %s", r.code, r.stdout)
	}
	seen := f.seen()
	if len(seen) != 1 || seen[0].body != `{"operation_id":"tracking.get","banned":false}` {
		t.Fatalf("请求：%+v", seen)
	}
}

func TestBanOutcomes(t *testing.T) {
	ban := []string{"ban", "--operation", "tracking.get", "--reason", "abuse"}
	unban := []string{"unban", "--operation", "tracking.get"}
	for _, c := range []struct {
		name    string
		command []string
		status  int
		body    string
		outcome string
		code    int
	}{
		{"不认识的操作", ban, 422, banBody("tracking.get", false, false, 1, "unknown_operation"), "UNKNOWN_OPERATION", 3},
		{"生效了但没有写下去", ban, 500, banBody("tracking.get", true, true, 2, "revocation_in_effect_but_not_written"), "BANNED_NOT_WRITTEN", 7},
		{"解除没有写下去", unban, 500, banBody("tracking.get", true, false, 2, "revocations_not_changed"), "LIFT_NOT_WRITTEN", 3},
		{"重复封禁", ban, 200, banBody("tracking.get", true, false, 2, ""), "BANNED", 0},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newFakeAuthz(t, answers(c.status, c.body))
			r := f.run(append(append([]string{}, c.command...), f.common()...)...)
			if r.code != c.code || field[string](t, r.report, "outcome") != c.outcome {
				t.Fatalf("退出码 %d，输出 %s；要的是 %d %s", r.code, r.stdout, c.code, c.outcome)
			}
			if strings.Contains(r.stdout+r.stderr, "unknown_operation") || strings.Contains(r.stdout+r.stderr, bodySentinel) {
				t.Fatalf("应答正文被带了出来：%q %q", r.stdout, r.stderr)
			}
		})
	}
}

func TestBanUsage(t *testing.T) {
	f := newFakeAuthz(t, answers(http.StatusOK, banBody("tracking.get", true, true, 1, "")))
	for _, c := range []struct {
		args []string
		says string
	}{
		{[]string{"ban"}, "missing required flags: --authz, --authz-name, --operation, --reason, --tls-ca, --tls-cert, --tls-key"},
		{[]string{"unban"}, "missing required flags: --authz, --authz-name, --operation, --tls-ca, --tls-cert, --tls-key"},
		{append([]string{"ban", "--operation", "tracking.get", "--reason", " \t "}, f.common()...), "--reason must not be blank"},
		{append([]string{"ban", "--operation", "tracking.get"}, f.common()...), "missing required flags: --reason"},
		{append([]string{"unban", "--operation", "tracking.get", "--reason", "x"}, f.common()...), "flag provided but not defined: -reason"},
	} {
		before := len(f.seen())
		r := f.run(c.args...)
		if r.code != 2 || r.stdout != "" || !strings.Contains(r.stderr, c.says) {
			t.Errorf("退出码 %d，标准输出 %q，标准错误 %q；要的是 %q", r.code, r.stdout, r.stderr, c.says)
		}
		if len(f.seen()) != before {
			t.Error("用法错误的时候什么都不该发出去")
		}
	}
	help := f.run("ban", "--help")
	if help.code != 2 {
		t.Fatalf("ban --help：%d", help.code)
	}
	for _, want := range []string{"-operation", "-reason", "-authz", "-tls-cert", "-tls-key", "-tls-ca", "BANNED, LIFTED (0)", "UNKNOWN_OPERATION (3)", "BANNED_NOT_WRITTEN (7)"} {
		if !strings.Contains(help.stderr, want) {
			t.Errorf("ban --help 里没有 %q", want)
		}
	}
}
