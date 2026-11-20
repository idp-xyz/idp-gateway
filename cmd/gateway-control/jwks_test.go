package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const kid1 = `{"keys":[{"kty":"RSA","kid":"kid-1","e":"AQAB","n":"n1"}]}`
const kid2 = `{"keys":[{"kty":"RSA","kid":"kid-2","e":"AQAB","n":"n2"}]}`

type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

func runSync(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	return run(ctx, args, stdout, stderr, nil)
}

func jwksLines(text string) []map[string]any {
	var out []map[string]any
	for _, line := range strings.Split(text, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var decoded map[string]any
		if err := json.Unmarshal([]byte(line), &decoded); err != nil {
			return nil
		}
		out = append(out, decoded)
	}
	return out
}

func waitJWKSText(t *testing.T, buf *lockedBuffer, contains string) {
	t.Helper()
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(buf.String(), contains) {
			return
		}
		time.Sleep(15 * time.Millisecond)
	}
	t.Fatalf("等不到 %q，输出是 %s", contains, buf.String())
}

func Test同步参数(t *testing.T) {
	dir := t.TempDir()
	output := filepath.Join(dir, "jwks.json")
	good := []string{"--url", "http://127.0.0.1:9/.well-known/jwks.json", "--output", output}
	if _, err := parseJWKS(good, io.Discard); err != nil {
		t.Fatal(err)
	}
	parsed, err := parseJWKS(append(append([]string{}, good...), "--mode", "0600", "--interval", "2s", "--timeout", "1s", "--max-stale", "0s"), io.Discard)
	if err != nil || parsed.mode != 0o600 || parsed.interval != 2*time.Second || parsed.maxStale != 0 || parsed.timeout != time.Second {
		t.Fatalf("%+v %v", parsed, err)
	}
	cases := []struct{ name, args, want string }{
		{"没有地址", "--output " + output, "missing required flags: --url"},
		{"没有文件", "--url http://127.0.0.1/jwks.json", "missing required flags: --output"},
		{"间隔不是正数", "--interval 0s", "--interval must be positive"},
		{"超时不是正数", "--timeout 0s", "--timeout must be positive"},
		{"期限是负的", "--max-stale -1s", "--max-stale must not be negative"},
		{"权限不对", "--mode 0755", "--mode must be 0600 or 0644"},
		{"权限没写前导零", "--mode 644", "--mode must be 0600 or 0644"},
		{"明文主机不是裸名字", "--plain-http-host http://idp.test", "bare host"},
		{"非回环明文", "--url http://example.com/jwks.json --output " + output, "must be https"},
		{"地址带用户信息", "--url http://user:secret@127.0.0.1/jwks.json --output " + output, "user information"},
		{"证书只给了一半", "--tls-cert /no/such.crt", "--tls-cert and --tls-key"},
		{"只跑一轮还要指标", "--once --metrics-listen 127.0.0.1:9", "--metrics-listen is not used with --once"},
		{"指标地址只有端口", "--metrics-listen :9617", "host:port"},
		{"指标地址是空的", "--metrics-listen \"\"", "host:port"},
		{"多了参数", "extra", "unexpected argument"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			base := append([]string{}, good...)
			if strings.Contains(c.args, "--url ") || strings.Contains(c.args, "--output ") {
				base = nil
			}
			fields := strings.Fields(c.args)
			// --metrics-listen "" 用 Fields 会丢掉空字符串，这里单独拼。
			if c.args == `--metrics-listen ""` {
				fields = []string{"--metrics-listen", ""}
			}
			var stderr bytes.Buffer
			code := runSync(context.Background(), append(append([]string{"sync-jwks"}, base...), fields...), io.Discard, &stderr)
			if code != exitUsage || !strings.Contains(stderr.String(), c.want) || strings.Contains(stderr.String(), "secret") {
				t.Fatalf("退出码 %d，输出 %q，想包含 %q", code, stderr.String(), c.want)
			}
		})
	}
	var help bytes.Buffer
	if code := runSync(context.Background(), []string{"sync-jwks", "--help"}, io.Discard, &help); code != exitUsage || !strings.Contains(help.String(), "UPDATED") {
		t.Fatalf("--help：%d %q", code, help.String())
	}
	var usage bytes.Buffer
	if code := runSync(context.Background(), []string{"no-such"}, io.Discard, &usage); code != exitUsage ||
		!strings.Contains(usage.String(), "usage: gateway-control publish|restart|reconcile|place|keep [flags]") ||
		!strings.Contains(usage.String(), "sync-jwks") {
		t.Fatalf("用法：%d %q", code, usage.String())
	}
	taken, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer taken.Close()
	var stderr bytes.Buffer
	code := runSync(context.Background(), append([]string{"sync-jwks"}, append(good, "--metrics-listen", taken.Addr().String())...), io.Discard, &stderr)
	if code != exitError || !strings.Contains(stderr.String(), "metrics") {
		t.Fatalf("指标地址被占：%d %q", code, stderr.String())
	}
}

func Test只同步一次成功和失败(t *testing.T) {
	var status atomic.Int32
	status.Store(http.StatusOK)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if code := status.Load(); code != http.StatusOK {
			w.WriteHeader(int(code))
			_, _ = w.Write([]byte(`{"error":"unavailable"}`))
			return
		}
		_, _ = w.Write([]byte(kid1))
	}))
	defer server.Close()
	path := filepath.Join(t.TempDir(), "jwks.json")
	args := []string{"sync-jwks", "--url", server.URL + "/.well-known/jwks.json", "--output", path, "--once", "--mode", "0600"}
	var stdout, stderr bytes.Buffer
	if code := runSync(context.Background(), args, &stdout, &stderr); code != exitActive {
		t.Fatalf("成功应为 0：%d %s %s", code, stdout.String(), stderr.String())
	}
	lines := jwksLines(stdout.String())
	if len(lines) != 1 || lines[0]["outcome"] != "UPDATED" || lines[0]["key_count"] != float64(1) {
		t.Fatalf("成功的行：%s", stdout.String())
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("文件权限：%v %v", info, err)
	}
	past := time.Now().Add(-2 * time.Hour)
	if err := os.Chtimes(path, past, past); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	if code := runSync(context.Background(), args, &stdout, &stderr); code != exitActive || !strings.Contains(stdout.String(), `"outcome":"UNCHANGED"`) {
		t.Fatalf("同一套密钥：%d %s", code, stdout.String())
	}
	info, err = os.Stat(path)
	if err != nil || !info.ModTime().Before(time.Now().Add(-time.Hour)) {
		t.Fatalf("不该重写文件，修改时间 %v", info.ModTime())
	}
	status.Store(http.StatusServiceUnavailable)
	kept, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	if code := runSync(context.Background(), args, &stdout, &stderr); code != exitError || !strings.Contains(stdout.String(), `"outcome":"FETCH_FAILED"`) {
		t.Fatalf("503：%d %s", code, stdout.String())
	}
	got, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(got, kept) || bytes.Contains(got, []byte("unavailable")) {
		t.Fatalf("503 改了文件：%q", got)
	}
	missing := filepath.Join(t.TempDir(), "no-ca.pem")
	var bad bytes.Buffer
	code := runSync(context.Background(), append(args, "--tls-ca", missing), io.Discard, &bad)
	if code != exitError || strings.Contains(bad.String(), "{") && strings.Contains(bad.String(), "outcome") {
		t.Fatalf("证书文件不存在应在写出 JSON 之前失败：%d %q", code, bad.String())
	}
}

func Test常驻时密钥轮换只写变化(t *testing.T) {
	var mu sync.Mutex
	body := []byte(kid1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		_, _ = w.Write(body)
	}))
	defer server.Close()
	path := filepath.Join(t.TempDir(), "jwks.json")
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	stdout := &lockedBuffer{}
	done := make(chan int, 1)
	go func() {
		done <- runSync(ctx, []string{"sync-jwks", "--url", server.URL + "/jwks.json", "--output", path, "--interval", "40ms", "--timeout", "1s"}, stdout, io.Discard)
	}()
	waitJWKSText(t, stdout, `"kid-1"`)
	time.Sleep(200 * time.Millisecond)
	if lines := jwksLines(stdout.String()); len(lines) != 1 || lines[0]["outcome"] != "UPDATED" {
		t.Fatalf("安稳时应只有一行：%s", stdout.String())
	}
	mu.Lock()
	body = []byte(kid2)
	mu.Unlock()
	waitJWKSText(t, stdout, `"kid-2"`)
	cancel()
	select {
	case code := <-done:
		if code != exitActive {
			t.Fatalf("被叫停应退出 0，得到 %d，输出 %s", code, stdout.String())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("被叫停之后没有退出")
	}
	lines := jwksLines(stdout.String())
	if len(lines) != 2 || lines[1]["outcome"] != "UPDATED" {
		t.Fatalf("轮换应再写一行：%s", stdout.String())
	}
	file, err := os.ReadFile(path)
	if err != nil || !bytes.Contains(file, []byte("kid-2")) || bytes.Contains(file, []byte("kid-1")) {
		t.Fatalf("文件是 %q（%v）", file, err)
	}
}

func Test过期腾空(t *testing.T) {
	var n atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if n.Add(1) == 1 {
			_, _ = w.Write([]byte(kid1))
			return
		}
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"error":"unavailable"}`))
	}))
	defer server.Close()
	path := filepath.Join(t.TempDir(), "jwks.json")
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	stdout := &lockedBuffer{}
	done := make(chan int, 1)
	go func() {
		done <- runSync(ctx, []string{
			"sync-jwks", "--url", server.URL + "/jwks.json", "--output", path,
			"--interval", "40ms", "--timeout", "1s", "--max-stale", "400ms", "--empty-on-stale",
		}, stdout, io.Discard)
	}()
	waitJWKSText(t, stdout, "STALE_EXPIRED")
	cancel()
	select {
	case code := <-done:
		if code != exitActive {
			t.Fatalf("退出码 %d，输出 %s", code, stdout.String())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("没有退出")
	}
	lines := jwksLines(stdout.String())
	var sawFailed, sawExpired bool
	for _, line := range lines {
		switch line["outcome"] {
		case "FETCH_FAILED":
			sawFailed = true
			if line["cleared"] == true {
				t.Fatalf("期限内不该腾空：%v", line)
			}
		case "STALE_EXPIRED":
			sawExpired = true
			if line["cleared"] != true || line["stale"] != true {
				t.Fatalf("过期应腾空：%v", line)
			}
		}
	}
	if !sawFailed || !sawExpired {
		t.Fatalf("应先失败再过期：%s", stdout.String())
	}
	file, err := os.ReadFile(path)
	if err != nil || string(file) != "{\"keys\":[]}\n" {
		t.Fatalf("文件是 %q（%v）", file, err)
	}
}

func Test指标(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(kid1))
	}))
	defer server.Close()
	address := freeAddress(t)
	path := filepath.Join(t.TempDir(), "jwks.json")
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	stdout := &lockedBuffer{}
	done := make(chan int, 1)
	go func() {
		done <- runSync(ctx, []string{
			"sync-jwks", "--url", server.URL + "/jwks.json", "--output", path,
			"--interval", "50ms", "--metrics-listen", address,
		}, stdout, io.Discard)
	}()
	waitJWKSText(t, stdout, "UPDATED")
	var body string
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		response, err := http.Get("http://" + address + "/metrics")
		if err == nil {
			raw, _ := io.ReadAll(response.Body)
			response.Body.Close()
			body = string(raw)
			if response.StatusCode == http.StatusOK && strings.Contains(body, "idp_gateway_jwks_key_count 1\n") {
				break
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !strings.Contains(body, "idp_gateway_jwks_key_count 1\n") ||
		!strings.Contains(body, "idp_gateway_jwks_stale 0\n") ||
		!strings.Contains(body, "idp_gateway_jwks_sync_failures_total 0\n") ||
		!strings.Contains(body, "# TYPE idp_gateway_jwks_last_success_timestamp_seconds gauge\n") ||
		strings.Contains(body, "idp_gateway_jwks_last_success_timestamp_seconds 0\n") {
		t.Fatalf("指标：\n%s", body)
	}
	other, err := http.Get("http://" + address + "/other")
	if err != nil || other.StatusCode != http.StatusNotFound {
		t.Fatalf("别的路径：%v %v", err, other)
	}
	if other != nil {
		other.Body.Close()
	}
	cancel()
	select {
	case code := <-done:
		if code != exitActive {
			t.Fatalf("退出码 %d", code)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("没有退出")
	}
}
