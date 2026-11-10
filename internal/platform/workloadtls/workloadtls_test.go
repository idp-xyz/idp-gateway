package workloadtls_test

import (
	"crypto/tls"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"go.idp.xyz/idp-gateway/internal/platform/workloadtls"
	"go.idp.xyz/idp-gateway/internal/platform/workloadtls/tlstest"
)

const (
	serverName = "authz.idp.test"
	gatewayID  = "spiffe://idp.test/egress/agentgateway"
)

// startServer 起一个要求客户端证书的服务，响应体是它从证书里读到的对端身份。
func startServer(t *testing.T, ca *tlstest.CA) string {
	t.Helper()
	server := ca.Issue("server", []string{"spiffe://idp.test/egress/authz"}, serverName)
	config, err := workloadtls.ServerConfig(server.CertFile, server.KeyFile, ca.File())
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{
		TLSConfig:   config,
		ReadTimeout: 5 * time.Second,
		ErrorLog:    log.New(io.Discard, "", 0), // 被拒绝的握手是这些测试的预期结果
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.WriteString(w, "peer="+workloadtls.PeerIdentity(r.TLS))
		}),
	}
	go func() { _ = srv.ServeTLS(listener, "", "") }()
	t.Cleanup(func() { _ = srv.Close() })
	return "https://" + listener.Addr().String() + "/"
}

func get(t *testing.T, url string, config *tls.Config) (string, error) {
	t.Helper()
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: config}}
	defer client.CloseIdleConnections()
	response, err := client.Get(url)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	return string(body), err
}

func TestPeerIdentityComesFromTheVerifiedClientCertificate(t *testing.T) {
	ca := tlstest.NewCA(t, "workload CA")
	url := startServer(t, ca)

	gateway := ca.Issue("gateway", []string{gatewayID})
	if body, err := get(t, url, tlstest.ClientConfig(ca, serverName, &gateway)); err != nil || body != "peer="+gatewayID {
		t.Fatalf("网关证书：%q, %v", body, err)
	}

	// 身份必须无歧义：没有 URI、或有两个 URI 的证书握手能过（它确实是这个 CA 签的），
	// 但读不出身份。
	anonymous := ca.Issue("anonymous", nil)
	if body, err := get(t, url, tlstest.ClientConfig(ca, serverName, &anonymous)); err != nil || body != "peer=" {
		t.Fatalf("没有 URI 的证书：%q, %v", body, err)
	}
	twoNames := ca.Issue("two-names", []string{gatewayID, "spiffe://idp.test/apps/parcel-service"})
	if body, err := get(t, url, tlstest.ClientConfig(ca, serverName, &twoNames)); err != nil || body != "peer=" {
		t.Fatalf("两个 URI 的证书：%q, %v", body, err)
	}
}

func TestHandshakeIsRefusedWithoutACertificateFromTheWorkloadCA(t *testing.T) {
	ca := tlstest.NewCA(t, "workload CA")
	url := startServer(t, ca)

	if body, err := get(t, url, tlstest.ClientConfig(ca, serverName, nil)); err == nil {
		t.Fatalf("没有客户端证书却得到了响应：%q", body)
	}
	// 另一个 CA 签的证书，身份写得和网关一模一样。
	rogue := tlstest.NewCA(t, "a CA outside the trust domain")
	impostor := rogue.Issue("gateway", []string{gatewayID})
	if body, err := get(t, url, tlstest.ClientConfig(ca, serverName, &impostor)); err == nil {
		t.Fatalf("别的 CA 签的证书得到了响应：%q", body)
	}
	// 对照：客户端一侧同样在验证。信任另一个 CA 的客户端不接受这个服务端。
	gateway := ca.Issue("gateway", []string{gatewayID})
	if body, err := get(t, url, tlstest.ClientConfig(rogue, serverName, &gateway)); err == nil {
		t.Fatalf("客户端接受了不受信任的服务端：%q", body)
	}
	// 对照：同一张证书在名字不对时也不被接受。
	if body, err := get(t, url, tlstest.ClientConfig(ca, "other.idp.test", &gateway)); err == nil {
		t.Fatalf("客户端接受了名字不符的服务端：%q", body)
	}
}

func TestPeerIdentityWithoutTLS(t *testing.T) {
	if got := workloadtls.PeerIdentity(nil); got != "" {
		t.Fatal(got)
	}
	// 只有 PeerCertificates、没有 VerifiedChains 的状态说明证书没有被验证过。
	ca := tlstest.NewCA(t, "workload CA")
	leaf := ca.Issue("gateway", []string{gatewayID})
	state := tlstest.PeerState(leaf)
	if got := workloadtls.PeerIdentity(state); got != gatewayID {
		t.Fatal(got)
	}
	state.VerifiedChains = nil
	if got := workloadtls.PeerIdentity(state); got != "" {
		t.Fatalf("未经验证的证书读出了身份 %q", got)
	}
}

func TestServerConfigRejectsUnusableFiles(t *testing.T) {
	ca := tlstest.NewCA(t, "workload CA")
	server := ca.Issue("server", nil, serverName)
	empty := filepath.Join(t.TempDir(), "empty.pem")
	if err := os.WriteFile(empty, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, args := range map[string][3]string{
		"证书文件不存在":    {"missing.crt", server.KeyFile, ca.File()},
		"证书与私钥不配对":   {ca.Issue("other", nil, serverName).CertFile, server.KeyFile, ca.File()},
		"CA 文件不存在":   {server.CertFile, server.KeyFile, "missing-ca.crt"},
		"CA 文件里没有证书": {server.CertFile, server.KeyFile, empty},
	} {
		if _, err := workloadtls.ServerConfig(args[0], args[1], args[2]); err == nil {
			t.Errorf("%s: 被接受了", name)
		}
	}
	config, err := workloadtls.ServerConfig(server.CertFile, server.KeyFile, ca.File())
	if err != nil {
		t.Fatal(err)
	}
	if config.ClientAuth != tls.RequireAndVerifyClientCert || config.MinVersion < tls.VersionTLS12 {
		t.Fatalf("%+v", config)
	}
}
