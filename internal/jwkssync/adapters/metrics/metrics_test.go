package metrics

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"go.idp.xyz/idp-gateway/internal/jwkssync/application"
)

func Test指标的文本和处理器(t *testing.T) {
	m := New()
	text := string(m.Text())
	if !strings.Contains(text, "idp_gateway_jwks_last_success_timestamp_seconds 0\n") ||
		!strings.Contains(text, "idp_gateway_jwks_key_count 0\n") ||
		!strings.Contains(text, "idp_gateway_jwks_stale 0\n") ||
		!strings.Contains(text, "idp_gateway_jwks_sync_failures_total 0\n") {
		t.Fatalf("初值不对：\n%s", text)
	}
	for _, name := range []string{
		"idp_gateway_jwks_last_success_timestamp_seconds",
		"idp_gateway_jwks_key_count",
		"idp_gateway_jwks_stale",
		"idp_gateway_jwks_sync_failures_total",
	} {
		if !strings.Contains(text, "# HELP "+name+" ") || !strings.Contains(text, "# TYPE "+name+" ") {
			t.Fatalf("%s 缺少 HELP 或 TYPE：\n%s", name, text)
		}
	}
	at := time.Date(2026, 11, 20, 1, 2, 3, 4_000_000, time.UTC)
	m.Observe(application.Result{Outcome: application.OutcomeUpdated, KeyCount: 2, LastSuccess: at})
	want := strconv.FormatFloat(float64(at.UnixMilli())/1000, 'f', 3, 64)
	text = string(m.Text())
	if !strings.Contains(text, "idp_gateway_jwks_last_success_timestamp_seconds "+want+"\n") ||
		!strings.Contains(text, "idp_gateway_jwks_key_count 2\n") ||
		!strings.Contains(text, "idp_gateway_jwks_stale 0\n") ||
		!strings.Contains(text, "idp_gateway_jwks_sync_failures_total 0\n") {
		t.Fatalf("成功之后：\n%s", text)
	}
	m.Observe(application.Result{Outcome: application.OutcomeFetchFailed, KeyCount: 2, LastSuccess: at, Error: "jwks fetch: HTTP 503"})
	m.Observe(application.Result{Outcome: application.OutcomeStaleExpired, KeyCount: 0, Stale: true, LastSuccess: at, Cleared: true})
	text = string(m.Text())
	if !strings.Contains(text, "idp_gateway_jwks_key_count 0\n") ||
		!strings.Contains(text, "idp_gateway_jwks_stale 1\n") ||
		!strings.Contains(text, "idp_gateway_jwks_sync_failures_total 2\n") ||
		!strings.Contains(text, "idp_gateway_jwks_last_success_timestamp_seconds "+want+"\n") {
		t.Fatalf("失败之后：\n%s", text)
	}

	server := httptest.NewServer(m.Handler())
	defer server.Close()
	response, err := http.Get(server.URL + Path)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode != http.StatusOK || response.Header.Get("Content-Type") != ContentType || !strings.Contains(string(body), "idp_gateway_jwks_stale 1\n") {
		t.Fatalf("GET：%d %s %q", response.StatusCode, response.Header.Get("Content-Type"), body)
	}
	head, err := http.Head(server.URL + Path)
	if err != nil || head.StatusCode != http.StatusOK {
		t.Fatalf("HEAD：%v %v", err, head)
	}
	head.Body.Close()
	post, err := http.Post(server.URL+Path, "text/plain", nil)
	if err != nil || post.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("POST：%v %v", err, post)
	}
	post.Body.Close()
	other, err := http.Get(server.URL + "/other")
	if err != nil || other.StatusCode != http.StatusNotFound {
		t.Fatalf("别的路径：%v %v", err, other)
	}
	other.Body.Close()
}
