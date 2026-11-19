package revokerclient

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"go.idp.xyz/idp-gateway/internal/platform/workloadtls"
	"go.idp.xyz/idp-gateway/internal/platform/workloadtls/tlstest"
)

const serverName = "authz.idp.test"

func startServer(t *testing.T, handler http.HandlerFunc) (*Client, *int32) {
	t.Helper()
	ca := tlstest.NewCA(t, "workload CA")
	serverLeaf := ca.Issue("authz", nil, serverName)
	clientLeaf := ca.Issue("revoker", []string{"spiffe://idp.test/egress/revoker"})
	serverTLS, err := workloadtls.ServerConfig(serverLeaf.CertFile, serverLeaf.KeyFile, ca.File())
	if err != nil {
		t.Fatal(err)
	}
	var requests int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requests, 1)
		handler(w, r)
	}))
	server.TLS = serverTLS
	server.StartTLS()
	t.Cleanup(server.Close)
	clientTLS, err := workloadtls.ClientConfig(clientLeaf.CertFile, clientLeaf.KeyFile, ca.File(), serverName)
	if err != nil {
		t.Fatal(err)
	}
	client, err := New(Config{Address: server.Listener.Addr().String(), TLS: clientTLS, Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	return client, &requests
}

func TestNewRefusesWhatItCannotUseSafely(t *testing.T) {
	ca := tlstest.NewCA(t, "workload CA")
	leaf := ca.Issue("revoker", []string{"spiffe://idp.test/egress/revoker"})
	good, err := workloadtls.ClientConfig(leaf.CertFile, leaf.KeyFile, ca.File(), serverName)
	if err != nil {
		t.Fatal(err)
	}
	for name, config := range map[string]Config{
		"没有 TLS 配置": {Address: "127.0.0.1:1", Timeout: time.Second},
		"没有地址":      {TLS: good, Timeout: time.Second},
		"地址没有端口":    {Address: "127.0.0.1", TLS: good, Timeout: time.Second},
		"时限为零":      {Address: "127.0.0.1:1", TLS: good},
		"没有名字":      {Address: "127.0.0.1:1", TLS: withoutName(good), Timeout: time.Second},
		"没有客户端证书":   {Address: "127.0.0.1:1", TLS: withoutCertificate(good), Timeout: time.Second},
		"没有 CA":     {Address: "127.0.0.1:1", TLS: withoutRoots(good), Timeout: time.Second},
	} {
		if _, err := New(config); err == nil {
			t.Errorf("%s：应当报错", name)
		}
	}
	client, err := New(Config{Address: "127.0.0.1:1", TLS: good, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	transport := client.http.Transport.(*http.Transport)
	if transport.Proxy != nil || !transport.DisableKeepAlives {
		t.Error("不用环境里的代理，每次一条新连接")
	}
	if err := client.http.CheckRedirect(nil, nil); err != http.ErrUseLastResponse {
		t.Error("不跟随重定向")
	}
}

func TestARevocationWithoutAReasonIsNotSent(t *testing.T) {
	client, requests := startServer(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) })
	for _, reason := range []string{"", " ", "\t\n"} {
		if _, err := client.Revoke(context.Background(), "account-blue", reason); err == nil {
			t.Errorf("原因 %q：应当报错", reason)
		}
	}
	if _, err := client.Revoke(context.Background(), "", "why"); err == nil {
		t.Error("没有账户：应当报错")
	}
	if _, err := client.Restore(context.Background(), ""); err == nil {
		t.Error("没有账户：应当报错")
	}
	if n := atomic.LoadInt32(requests); n != 0 {
		t.Errorf("发出去了 %d 个请求", n)
	}
}

func TestASingleRequestIsSentWhateverTheAnswer(t *testing.T) {
	for _, status := range []int{200, 401, 404, 422, 400, 500, 502, 503} {
		client, requests := startServer(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(status) })
		if _, err := client.Revoke(context.Background(), "account-blue", "why"); err != nil {
			t.Fatal(err)
		}
		if n := atomic.LoadInt32(requests); n != 1 {
			t.Errorf("状态 %d：发了 %d 个请求", status, n)
		}
	}
}

func withoutName(c *tls.Config) *tls.Config {
	c = c.Clone()
	c.ServerName = ""
	return c
}

func withoutCertificate(c *tls.Config) *tls.Config {
	c = c.Clone()
	c.Certificates = nil
	return c
}

func withoutRoots(c *tls.Config) *tls.Config {
	c = c.Clone()
	c.RootCAs = nil
	return c
}
