package sfopenapi

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"
)

// madeUpSecret 只出现在归类测试构造的那个地址里。归类的结果里不该有它，也不该有这段地址。
const madeUpSecret = "made-up-secret-for-the-cause"

func TestExchangeCause(t *testing.T) {
	secretURL := "https://carrier.example.test/openapi/api/token?appKey=k&appSecret=" + madeUpSecret
	// 标准库就是这样包的：*url.Error 的 Op 是 Get，里面是 *net.OpError，再里面是 *os.SyscallError。
	wrap := func(err error) error { return &url.Error{Op: "Get", URL: secretURL, Err: err} }
	op := func(name string, err error) error { return wrap(&net.OpError{Op: name, Net: "tcp", Err: err}) }
	sys := func(call string, err error) error { return &os.SyscallError{Syscall: call, Err: err} }
	dns := func(notFound, timeout bool, unwrap error) error {
		return op("dial", &net.DNSError{IsNotFound: notFound, IsTimeout: timeout, UnwrapErr: unwrap,
			Name: "carrier.example.test", Err: "lookup failed"})
	}

	cases := []struct {
		name string
		err  error
		want string
	}{
		{"dns_not_found", dns(true, false, nil), "dns_not_found"},
		{"dns_not_found，同时也是超时", dns(true, true, context.DeadlineExceeded), "dns_not_found"},
		{"dns_timeout，外层是 dial", dns(false, true, context.DeadlineExceeded), "dns_timeout"},
		{"dns_other，链上有截止时间", dns(false, false, context.DeadlineExceeded), "dns_other"},
		{"dns_other", dns(false, false, nil), "dns_other"},

		{"refused", op("dial", sys("connect", syscall.ECONNREFUSED)), "refused"},
		{"reset", op("read", sys("read", syscall.ECONNRESET)), "reset"},
		{"no_route，ENETUNREACH", op("dial", sys("connect", syscall.ENETUNREACH)), "no_route"},
		{"no_route，EHOSTUNREACH", op("dial", sys("connect", syscall.EHOSTUNREACH)), "no_route"},

		{"closed，对端先关", wrap(io.EOF), "closed"},
		{"closed，正文没读完", io.ErrUnexpectedEOF, "closed"},
		{"closed，读的时候 EOF", op("read", io.EOF), "closed"},

		{"dial_timeout，截止时间", op("dial", context.DeadlineExceeded), "dial_timeout"},
		{"dial_timeout，i/o timeout", op("dial", os.ErrDeadlineExceeded), "dial_timeout"},
		{"dial_timeout，ETIMEDOUT", op("dial", sys("connect", syscall.ETIMEDOUT)), "dial_timeout"},
		{"response_timeout，EAGAIN", op("read", sys("read", syscall.EAGAIN)), "response_timeout"},
		{"response_timeout，等应答", wrap(context.DeadlineExceeded), "response_timeout"},
		{"response_timeout，读的时候超时", op("read", os.ErrDeadlineExceeded), "response_timeout"},
		{"response_timeout，正文上的截止时间", context.DeadlineExceeded, "response_timeout"},

		{"tls，证书", wrap(&tls.CertificateVerificationError{Err: x509.UnknownAuthorityError{}}), "tls"},
		{"tls，裸的 UnknownAuthority", wrap(x509.UnknownAuthorityError{}), "tls"},
		{"tls，HostnameError", wrap(x509.HostnameError{}), "tls"},
		{"tls，CertificateInvalidError", wrap(x509.CertificateInvalidError{}), "tls"},
		{"tls，SystemRootsError", wrap(x509.SystemRootsError{}), "tls"},
		{"tls，ConstraintViolationError", wrap(x509.ConstraintViolationError{}), "tls"},
		{"tls，InsecureAlgorithmError", wrap(x509.InsecureAlgorithmError(0)), "tls"},
		{"tls，RecordHeaderError", wrap(tls.RecordHeaderError{Msg: "first record does not look like a TLS handshake"}), "tls"},
		{"tls，AlertError", wrap(fmt.Errorf("%w%.0w", errors.New("handshake"), tls.AlertError(40))), "tls"},
		{"tls，ECHRejectionError", wrap(&tls.ECHRejectionError{}), "tls"},

		{"other", wrap(errors.New(madeUpSecret)), "other"},
		{"other，net.ErrClosed", wrap(net.ErrClosed), "other"},
		{"other，context 取消", wrap(context.Canceled), "other"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := exchangeCause(tc.err)
			if strings.Contains(got, madeUpSecret) || strings.Contains(got, "appSecret") || strings.Contains(got, "://") ||
				strings.Contains(got, "carrier.example.test") {
				t.Fatal("归类带回了地址或密钥")
			}
			if got != tc.want {
				t.Fatalf("%q，期望 %q", got, tc.want)
			}
		})
	}
}

// 传输层失败走真的客户端和回环。类别与改之前相同；失败日志多一个 cause，除此没有别的字段；
// 日志和错误里没有应用密钥、appSecret、令牌端点的地址和查询串，也没有错误原文。
func TestTransportFailuresLogACauseAndNothingElse(t *testing.T) {
	t.Run("refused", func(t *testing.T) {
		closed := httptest.NewServer(http.NotFoundHandler())
		address := closed.URL
		closed.Close()
		f := newFixture(t, two(address+tokenPath))
		assertTransport(t, f, "unreachable", "refused", address, strings.TrimPrefix(address, "http://"), "connection refused", "dial tcp", "Get ")
	})
	t.Run("closed", func(t *testing.T) {
		// 不读就关，内核有时把还没读走的请求当成 RST（ECONNRESET），有时当成 EOF。先把请求读完再关，
		// 对端就是在应答之前正常关掉连接，类别才稳定是 closed。
		endpoint := serveTCP(t, func(c net.Conn) {
			readHeaders(c)
			c.Close()
		})
		f := newFixture(t, two(endpoint))
		assertTransport(t, f, "unreachable", "closed", endpoint, hostOf(endpoint), "EOF", "Get ")
	})
	t.Run("reset", func(t *testing.T) {
		endpoint := serveTCP(t, func(c net.Conn) {
			tcp, ok := c.(*net.TCPConn)
			if !ok {
				c.Close()
				return
			}
			tcp.SetLinger(0)
			tcp.Close()
		})
		f := newFixture(t, two(endpoint))
		assertTransport(t, f, "unreachable", "reset", endpoint, hostOf(endpoint), "connection reset", "Get ")
	})
	t.Run("response_timeout", func(t *testing.T) {
		ep := newEndpoint(t)
		release := make(chan struct{})
		t.Cleanup(func() { close(release) })
		ep.set(func(http.ResponseWriter, *http.Request) { <-release })
		f := newFixture(t, two(ep.tokenURL()), withTimeout(100*time.Millisecond))
		begun := time.Now()
		assertTransport(t, f, "timeout", "response_timeout", ep.URL, "deadline", "Get ")
		if time.Since(begun) > 2*time.Second {
			t.Errorf("等了 %v", time.Since(begun))
		}
	})
	t.Run("读正文时对端关了", func(t *testing.T) {
		endpoint := serveTCP(t, func(c net.Conn) {
			defer c.Close()
			readHeaders(c)
			io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 20\r\nConnection: close\r\n\r\nshort")
		})
		f := newFixture(t, two(endpoint))
		assertTransport(t, f, "unreachable", "closed", endpoint, hostOf(endpoint), "unexpected EOF", "Get ")
	})
	t.Run("读正文超时", func(t *testing.T) {
		ep := newEndpoint(t)
		release := make(chan struct{})
		t.Cleanup(func() { close(release) })
		ep.set(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.(http.Flusher).Flush()
			<-release
		})
		f := newFixture(t, two(ep.tokenURL()), withTimeout(100*time.Millisecond))
		begun := time.Now()
		assertTransport(t, f, "timeout", "response_timeout", ep.URL, "deadline", "Get ")
		if time.Since(begun) > 2*time.Second {
			t.Errorf("等了 %v", time.Since(begun))
		}
	})
	t.Run("tls", func(t *testing.T) {
		server := httptest.NewTLSServer(http.NotFoundHandler())
		server.Config.ErrorLog = log.New(io.Discard, "", 0)
		t.Cleanup(server.Close)
		f := newFixture(t, two(server.URL+tokenPath))
		assertTransport(t, f, "unreachable", "tls", server.URL, "x509", "certificate")
	})
}

func TestAFetchThatIsNotATransportFailureLogsNoCause(t *testing.T) {
	t.Run("成功", func(t *testing.T) {
		ep := newEndpoint(t)
		f := newFixture(t, two(ep.tokenURL()))
		if _, err := f.get(blueHandle); err != nil {
			t.Fatal(err)
		}
		noSecrets(t, f.logs.String(), "成功", ep.URL)
		if strings.Contains(f.logs.String(), "not obtained") || strings.Contains(f.logs.String(), `"cause"`) {
			t.Fatalf("成功的日志里有 cause 或错误信息")
		}
		line := oneObject(t, f.logs.String(), "sf openapi token fetched")
		assertLine(t, line, "INFO", "sf openapi token fetched", "ok", "")
		if line["expires_in"] != float64(7200) {
			t.Errorf("expires_in %v", line["expires_in"])
		}
	})
	for _, tc := range []struct {
		name, result, body string
		status             int
	}{
		{"bad_answer", "bad_answer", `<html>` + bodyMarker + ` ` + blueSecret + `</html>`, http.StatusOK},
		{"status 500", "status 500", `{"apiErrorMsg":"` + bodyMarker + ` appSecret=` + blueSecret + `"}`, http.StatusInternalServerError},
		{"code 500", "code 500", `{"apiResultCode":500,"apiErrorMsg":"` + bodyMarker + ` ` + blueSecret + `","apiResultData":null}`, http.StatusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ep := newEndpoint(t)
			f := newFixture(t, two(ep.tokenURL()))
			ep.set(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				io.WriteString(w, tc.body)
			})
			_, err := f.get(blueHandle)
			if err == nil || err.Error() != failed(blueHandle, tc.result) {
				t.Fatalf("%v", err)
			}
			noSecrets(t, err.Error()+f.logs.String(), tc.name, ep.URL)
			if strings.Contains(f.logs.String(), "not obtained") || strings.Contains(f.logs.String(), `"cause"`) {
				t.Fatalf("日志里有 cause 或错误信息")
			}
			line := oneObject(t, f.logs.String(), "sf openapi token not fetched")
			assertLine(t, line, "WARN", "sf openapi token not fetched", tc.result, "")
		})
	}
}

// 令牌端点的地址里有控制字符时，请求造不出来。这不是传输失败的某一种，cause 用 other；
// 构造失败的错误里带着完整地址，不能把它传出去。
func TestARequestThatCannotBeBuiltIsOther(t *testing.T) {
	f := newFixture(t, two("http://127.0.0.1"+tokenPath))
	f.c.entries[blueHandle].tokenEndpoint = "http://127.0.0.1/\n"
	_, err := f.get(blueHandle)
	if err == nil || err.Error() != failed(blueHandle, "unreachable") {
		if err != nil && (strings.Contains(err.Error(), blueSecret) || strings.Contains(err.Error(), "appSecret")) {
			t.Fatal("错误信息里有密钥或地址")
		}
		t.Fatalf("%v", err)
	}
	noSecrets(t, err.Error()+f.logs.String(), "造不出请求")
	if strings.Contains(f.logs.String(), "not obtained") || strings.Contains(f.logs.String(), "invalid") {
		t.Fatal("错误原文进了日志")
	}
	line := oneObject(t, f.logs.String(), "sf openapi token not fetched")
	assertLine(t, line, "WARN", "sf openapi token not fetched", "unreachable", "other")
}

func assertTransport(t *testing.T, f *fixture, result, cause string, also ...string) {
	t.Helper()
	_, err := f.get(blueHandle)
	if err == nil || err.Error() != failed(blueHandle, result) {
		if err != nil && (strings.Contains(err.Error(), blueSecret) || strings.Contains(err.Error(), "appSecret") || strings.Contains(err.Error(), "://")) {
			t.Fatal("错误信息里有密钥或地址")
		}
		t.Fatalf("%v", err)
	}
	noSecrets(t, err.Error()+f.logs.String(), cause, also...)
	if strings.Contains(f.logs.String(), "not obtained") {
		t.Fatal("错误信息进了日志")
	}
	line := oneObject(t, f.logs.String(), "sf openapi token not fetched")
	assertLine(t, line, "WARN", "sf openapi token not fetched", result, cause)
}

func assertLine(t *testing.T, line map[string]any, level, msg, result, cause string) {
	t.Helper()
	if line["level"] != level || line["msg"] != msg || line["handle"] != blueHandle || line["result"] != result {
		t.Errorf("日志 level=%v msg=%v handle=%v result=%v", line["level"], line["msg"], line["handle"], line["result"])
	}
	if cause == "" {
		if _, ok := line["cause"]; ok {
			t.Errorf("不该有 cause")
		}
	} else if got, _ := line["cause"].(string); got != cause {
		if strings.Contains(got, blueSecret) || strings.Contains(got, madeUpSecret) || strings.Contains(got, "appSecret") || strings.Contains(got, "://") {
			t.Errorf("cause 带回了密钥或地址")
		} else {
			t.Errorf("cause %q，期望 %q", got, cause)
		}
	}
	allowed := map[string]bool{"time": true, "level": true, "msg": true, "handle": true, "result": true, "elapsed_ms": true}
	if cause != "" {
		allowed["cause"] = true
	}
	if msg == "sf openapi token fetched" {
		allowed["expires_in"] = true
	}
	for name := range line {
		if !allowed[name] {
			t.Errorf("多了字段 %s", name)
		}
	}
}

func oneObject(t *testing.T, logs, msg string) map[string]any {
	t.Helper()
	var found map[string]any
	n := 0
	for _, line := range strings.Split(strings.TrimSpace(logs), "\n") {
		if line == "" || !strings.Contains(line, `"msg":"`+msg+`"`) {
			continue
		}
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatal("日志不是 JSON")
		}
		if rec["msg"] != msg {
			continue
		}
		n++
		found = rec
	}
	if n != 1 {
		t.Fatalf("msg %s 的日志有 %d 行", msg, n)
	}
	return found
}

func serveTCP(t *testing.T, fn func(net.Conn)) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			fn(c)
		}
	}()
	return "http://" + ln.Addr().String() + tokenPath
}

func readHeaders(c net.Conn) {
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 1024)
	var got []byte
	for !bytes.Contains(got, []byte("\r\n\r\n")) {
		n, err := c.Read(buf)
		got = append(got, buf[:n]...)
		if err != nil || len(got) > 64<<10 {
			return
		}
	}
}

func hostOf(endpoint string) string {
	u, err := url.Parse(endpoint)
	if err != nil {
		return ""
	}
	return u.Host
}
