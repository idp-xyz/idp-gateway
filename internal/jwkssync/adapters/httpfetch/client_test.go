package httpfetch

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const validBody = `{"keys":[{"kty":"RSA","kid":"kid-1","e":"AQAB","n":"n1"}]}`

func Test非回环明文在没有例外时拒绝(t *testing.T) {
	refused := []string{
		"http://example.com/jwks.json",
		"http://localhost/jwks.json",
		"http://localhost:80/.well-known/jwks.json",
		"http://127.0.0.1.example/jwks.json",
		"http://127.1/jwks.json",
		"http://[::ffff:127.0.0.1]/jwks.json",
		"http://10.0.0.8/jwks.json",
	}
	for _, raw := range refused {
		t.Run(raw, func(t *testing.T) {
			if _, err := ParseURL(raw, ""); err == nil || !strings.Contains(err.Error(), "must be https") {
				t.Fatalf("应拒绝明文非回环地址，得到 %v", err)
			}
		})
	}
	// 例外是另一个主机时，这个名字仍然不行。
	if _, err := ParseURL("http://example.com/jwks.json", "idp.test"); err == nil {
		t.Fatal("例外主机对不上时不该放行")
	}
}

func Test地址的其余规矩(t *testing.T) {
	accepted := []string{
		"https://idp.example/jwks.json",
		"https://idp.example:8443/.well-known/jwks.json",
		"http://127.0.0.1/jwks.json",
		"http://127.0.0.1:9/.well-known/jwks.json",
		"http://127.255.255.255/jwks.json",
		"http://[::1]/jwks.json",
		"http://[::1]:9/jwks.json",
	}
	for _, raw := range accepted {
		if _, err := ParseURL(raw, ""); err != nil {
			t.Fatalf("%s：%v", raw, err)
		}
	}
	if _, err := ParseURL("http://idp.test/jwks.json", "IDP.test"); err != nil {
		t.Fatalf("例外主机应忽略大小写：%v", err)
	}
	secret := "s3cret-token"
	if _, err := ParseURL("https://user:"+secret+"@idp.example/jwks.json", ""); err == nil || strings.Contains(err.Error(), secret) {
		t.Fatalf("用户信息应被拒绝且不出现在错误里：%v", err)
	}
	if _, err := ParseURL("http://user:"+secret+"@127.0.0.1/jwks.json", ""); err == nil || strings.Contains(err.Error(), secret) {
		t.Fatalf("回环地址上的用户信息也应拒绝：%v", err)
	}
	for _, raw := range []string{
		"https://idp.example/jwks.json?x=1",
		"https://idp.example/jwks.json#frag",
		"https://idp.example/jwks.json?",
	} {
		if _, err := ParseURL(raw, ""); err == nil || !strings.Contains(err.Error(), "query") && !strings.Contains(err.Error(), "fragment") {
			t.Fatalf("%s 应拒绝查询串或片段：%v", raw, err)
		}
	}
	if _, err := ParseURL("ftp://idp.example/jwks.json", ""); err == nil {
		t.Fatal("ftp 不该通过")
	}
	if _, err := ParseURL("", ""); err == nil {
		t.Fatal("空地址不该通过")
	}
	for _, host := range []string{"a/b", "a:80", "a@b", "a?b", "a#b", "a b", "http://idp.test", "[::1]"} {
		if _, err := ParseURL("https://idp.example/jwks.json", host); err == nil || !strings.Contains(err.Error(), "bare host") {
			t.Fatalf("例外主机 %q 应被拒绝：%v", host, err)
		}
	}
}

func Test传输不走代理也不跟随重定向(t *testing.T) {
	client, err := New(Config{URL: "http://127.0.0.1:9/jwks.json", Timeout: time.Second, MaxBodyBytes: 128})
	if err != nil {
		t.Fatal(err)
	}
	transport, ok := client.http.Transport.(*http.Transport)
	if !ok || transport.Proxy != nil {
		t.Fatal("应显式不使用代理")
	}
	if err := client.http.CheckRedirect(nil, nil); !errors.Is(err, http.ErrUseLastResponse) {
		t.Fatalf("重定向应停住：%v", err)
	}
	if transport.TLSClientConfig == nil || transport.TLSClientConfig.MinVersion != tls.VersionTLS12 {
		t.Fatal("至少要 TLS 1.2")
	}
}

func Test取回成功以及失败的状态不是密钥集(t *testing.T) {
	var followed atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/jwks.json":
			_, _ = w.Write([]byte(validBody))
		case "/redirect":
			http.Redirect(w, r, "/gone", http.StatusFound)
		case "/gone":
			followed.Add(1)
			_, _ = w.Write([]byte(validBody))
		case "/unavailable":
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"keys":[{"kty":"RSA","kid":"should-not-leak"}]}`))
		case "/created":
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(validBody))
		case "/big":
			_, _ = w.Write([]byte(strings.Repeat("x", 64)))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	client := newClient(t, server.URL+"/jwks.json", 128)
	body, err := client.Fetch(context.Background())
	if err != nil || string(body) != validBody {
		t.Fatalf("200：%v %q", err, body)
	}
	_, err = newClient(t, server.URL+"/unavailable", 128).Fetch(context.Background())
	if err == nil || !strings.Contains(err.Error(), "HTTP 503") || strings.Contains(err.Error(), "should-not-leak") {
		t.Fatalf("503 应是错误且不带正文：%v", err)
	}
	_, err = newClient(t, server.URL+"/created", 128).Fetch(context.Background())
	if err == nil || !strings.Contains(err.Error(), "HTTP 201") {
		t.Fatalf("201 不是成功：%v", err)
	}
	_, err = newClient(t, server.URL+"/redirect", 128).Fetch(context.Background())
	if err == nil || !strings.Contains(err.Error(), "HTTP 302") || followed.Load() != 0 {
		t.Fatalf("不应跟随重定向：%v，跟了 %d 次", err, followed.Load())
	}
	_, err = newClient(t, server.URL+"/big", 8).Fetch(context.Background())
	if err == nil || !strings.Contains(err.Error(), "exceeds 8") {
		t.Fatalf("超限：%v", err)
	}
}

func Test取回超时(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer server.Close()
	client := newClient(t, server.URL+"/jwks.json", 128)
	client.http.Timeout = 150 * time.Millisecond
	started := time.Now()
	_, err := client.Fetch(context.Background())
	if err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("超时：%v", err)
	}
	if time.Since(started) > 2*time.Second {
		t.Fatalf("超时用了 %s", time.Since(started))
	}
}

func Test明文例外主机的请求会发出去(t *testing.T) {
	var seen atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen.Add(1)
		if r.Host != "idp.test" {
			t.Errorf("Host 是 %s", r.Host)
		}
		_, _ = w.Write([]byte(validBody))
	}))
	defer server.Close()
	client, err := New(Config{URL: "http://idp.test/jwks.json", PlainHTTPHost: "idp.test", Timeout: time.Second, MaxBodyBytes: 128})
	if err != nil {
		t.Fatal(err)
	}
	dialer := &net.Dialer{}
	client.http.Transport = &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if addr != "idp.test:80" {
				t.Errorf("拨了 %s", addr)
			}
			return dialer.DialContext(ctx, network, server.Listener.Addr().String())
		},
	}
	body, err := client.Fetch(context.Background())
	if err != nil || string(body) != validBody || seen.Load() != 1 {
		t.Fatalf("例外主机：%v %q 次数 %d", err, body, seen.Load())
	}
}

func Test用测试CA做TLS(t *testing.T) {
	caCert, caKey, pool := newCA(t)
	serverLeaf := leaf(t, caCert, caKey, true)
	clientLeaf := leaf(t, caCert, caKey, false)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			http.Error(w, "no client cert", http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(validBody))
	}))
	server.TLS = &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{serverLeaf},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pool,
	}
	server.StartTLS()
	defer server.Close()

	good := &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool, Certificates: []tls.Certificate{clientLeaf}}
	body, err := mustClient(t, server.URL+"/jwks.json", good).Fetch(context.Background())
	if err != nil || string(body) != validBody {
		t.Fatalf("可信的 CA 和客户端证书：%v %q", err, body)
	}
	wrong, _ := x509.SystemCertPool()
	if wrong == nil {
		wrong = x509.NewCertPool()
	}
	_, err = mustClient(t, server.URL+"/jwks.json", &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: x509.NewCertPool(), Certificates: []tls.Certificate{clientLeaf}}).Fetch(context.Background())
	if err == nil {
		t.Fatal("不信任的 CA 不该取到密钥")
	}
	_, err = mustClient(t, server.URL+"/jwks.json", &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool}).Fetch(context.Background())
	if err == nil {
		t.Fatal("没有客户端证书不该取到密钥")
	}
	_ = wrong
}

func newClient(t *testing.T, raw string, limit int64) *Client {
	t.Helper()
	client, err := New(Config{URL: raw, Timeout: time.Second, MaxBodyBytes: limit})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func mustClient(t *testing.T, raw string, tlsConfig *tls.Config) *Client {
	t.Helper()
	client, err := New(Config{URL: raw, Timeout: 2 * time.Second, MaxBodyBytes: DefaultMaxBodyBytes, TLS: tlsConfig})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func newCA(t *testing.T) (*x509.Certificate, crypto.Signer, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "jwks-test-ca"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return cert, key, pool
}

func leaf(t *testing.T, ca *x509.Certificate, caKey crypto.Signer, server bool) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "jwks"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature,
	}
	if server {
		template.SerialNumber = big.NewInt(3)
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		template.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
	} else {
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca, key.Public(), caKey)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}
