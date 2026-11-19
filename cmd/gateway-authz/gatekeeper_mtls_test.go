package main

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"go.idp.xyz/idp-gateway/internal/platform/workloadtls"
	"go.idp.xyz/idp-gateway/internal/platform/workloadtls/tlstest"
)

const (
	pdpHostName  = "gatekeeper.idp.test"
	authzOwnName = "spiffe://idp.test/egress/gateway-authz"
	pdpSecret    = "pdp-token-mtls"
)

// requireClientCertificate 起一个要求并验证客户端证书的 PDP，记下到达处理器的请求数和对端身份。
func requireClientCertificate(t *testing.T, serverCA, clientCA *tlstest.CA) (server *httptest.Server, reached *atomic.Int32, peer *atomic.Value) {
	t.Helper()
	reached, peer = new(atomic.Int32), new(atomic.Value)
	leaf := serverCA.Issue("pdp", nil, pdpHostName)
	server = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached.Add(1)
		peer.Store(workloadtls.PeerIdentity(r.TLS))
		if r.Header.Get("Authorization") != "Bearer "+pdpSecret {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = io.WriteString(w, `{"decision":true,"reason":"rebac:use"}`)
	}))
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{leaf.Certificate},
		ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: clientCA.Pool()}
	server.StartTLS()
	t.Cleanup(server.Close)
	return server, reached, peer
}

func tokenFileFor(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "pdp-token")
	if err := os.WriteFile(path, []byte(pdpSecret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// gateway-authz 向 PDP 出示自己的证书：对得上才问得到；问不到就是没有结论（503），不是策略拒绝。
func TestPresentsWorkloadCertificateToGatekeeper(t *testing.T) {
	rogue := tlstest.NewCA(t, "a CA the PDP does not trust")
	for name, tc := range map[string]struct {
		leaf    func(h *harness) tlstest.Leaf
		name    string
		pdpCA   func(h *harness) *tlstest.CA // 签发 PDP 证书的 CA；nil 表示 h.ca
		trusted func(h *harness) string      // --gatekeeper-tls-ca；nil 表示 h.ca
		allowed bool
	}{
		"证书、CA、名字都对":     {leaf: func(h *harness) tlstest.Leaf { return h.ca.Issue("own", []string{authzOwnName}) }, name: pdpHostName, allowed: true},
		"出示的证书是别的 CA 签的": {leaf: func(*harness) tlstest.Leaf { return rogue.Issue("own", []string{authzOwnName}) }, name: pdpHostName},
		"PDP 的名字对不上":     {leaf: func(h *harness) tlstest.Leaf { return h.ca.Issue("own", []string{authzOwnName}) }, name: "elsewhere.idp.test"},
		"PDP 的证书不是信任的 CA 签的": {leaf: func(h *harness) tlstest.Leaf { return h.ca.Issue("own", []string{authzOwnName}) }, name: pdpHostName,
			trusted: func(*harness) string { return rogue.File() }},
	} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t)
			pdp, reached, peer := requireClientCertificate(t, h.ca, h.ca)
			leaf := tc.leaf(h)
			trusted := h.ca.File()
			if tc.trusted != nil {
				trusted = tc.trusted(h)
			}
			h.extra = []string{"--gatekeeper-url", pdp.URL, "--gatekeeper-token-file", tokenFileFor(t),
				"--gatekeeper-tls-cert", leaf.CertFile, "--gatekeeper-tls-key", leaf.KeyFile,
				"--gatekeeper-tls-ca", trusted, "--gatekeeper-name", tc.name}
			h.start()
			answer := h.blue()
			body := answer.json(t)
			if tc.allowed {
				if answer.status != http.StatusOK || reached.Load() != 1 {
					t.Fatalf("%d %s，PDP 收到 %d 个请求", answer.status, answer.body, reached.Load())
				}
				if got, _ := peer.Load().(string); got != authzOwnName {
					t.Fatalf("PDP 看到的对端身份是 %q", got)
				}
			} else if answer.status != http.StatusServiceUnavailable || body["result"] != "INDETERMINATE" ||
				body["reason_code"] != "GRANT_STATE_UNAVAILABLE" || answer.carriesCredential() || reached.Load() != 0 {
				t.Fatalf("应当没有结论：%d %s，PDP 收到 %d 个请求", answer.status, answer.body, reached.Load())
			}
			logs := h.logs.String()
			for _, secret := range []string{pdpSecret, "PRIVATE KEY", "BEGIN CERTIFICATE"} {
				if strings.Contains(logs, secret) || strings.Contains(answer.body, secret) {
					t.Errorf("日志或应答里有 %q", secret)
				}
			}
			if !strings.Contains(logs, `"gatekeeper_mtls":true`) {
				t.Error("启动日志没有说明这一跳用了客户端证书")
			}
		})
	}
}

// 到 PDP 的那一跳的启动参数：四个一起给或一起不给；非回环地址必须给；给了就必须是 https。
func TestGatekeeperTLSFlags(t *testing.T) {
	h := newHarness(t)
	cert, key, ca := h.peers["gateway"].CertFile, h.peers["gateway"].KeyFile, h.ca.File()
	token := tokenFileFor(t)
	withTLS := []string{"--gatekeeper-tls-cert", cert, "--gatekeeper-tls-key", key, "--gatekeeper-tls-ca", ca, "--gatekeeper-name", pdpHostName}
	ask := func(address string, more ...string) error {
		args := append(h.args("127.0.0.1:0"), "--gatekeeper-url", address, "--gatekeeper-token-file", token)
		_, err := parse(append(args, more...), io.Discard)
		return err
	}
	for name, tc := range map[string]struct {
		address string
		more    []string
		says    string // 空串：应当通过
	}{
		"回环地址不给证书（原有的用法）":         {"http://127.0.0.1:27622", nil, ""},
		"回环地址 https 不给证书":         {"https://localhost:27622", nil, ""},
		"回环地址给证书":                 {"https://127.0.0.1:27623", withTLS, ""},
		"非回环地址给证书":                {"https://gk.idp.test", withTLS, ""},
		"非回环地址不给证书":               {"https://gk.idp.test", nil, "not a loopback address"},
		"非回环的 IP 不给证书":            {"https://10.0.0.8:3000", nil, "not a loopback address"},
		"缺证书":                     {"https://gk.idp.test", withTLS[2:], "go together"},
		"缺私钥":                     {"https://gk.idp.test", append(append([]string{}, withTLS[:2]...), withTLS[4:]...), "go together"},
		"缺 CA":                    {"https://gk.idp.test", append(append([]string{}, withTLS[:4]...), withTLS[6:]...), "go together"},
		"缺名字":                     {"https://gk.idp.test", withTLS[:6], "go together"},
		"只给了名字":                   {"https://gk.idp.test", withTLS[6:], "go together"},
		"给了证书却是回环的 http":          {"http://127.0.0.1:27623", withTLS, "must be https"},
		"给了证书却是 localhost 的 http": {"http://localhost:27623", withTLS, "must be https"},
		"给了证书却是非回环的 http":         {"http://gk.idp.test", withTLS, "must be https"},
	} {
		err := ask(tc.address, tc.more...)
		switch {
		case tc.says == "" && err != nil:
			t.Errorf("%s: 被拒绝：%v", name, err)
		case tc.says != "" && err == nil:
			t.Errorf("%s: 被接受了", name)
		case tc.says != "" && !strings.Contains(err.Error(), tc.says):
			t.Errorf("%s: 错误是 %q，期望提到 %q", name, err, tc.says)
		}
	}
	// 没有 --gatekeeper-url 时这些参数没有地方可用。
	if _, err := parse(append(h.args("127.0.0.1:0"), withTLS...), io.Discard); err == nil || !strings.Contains(err.Error(), "need --gatekeeper-url") {
		t.Errorf("没有 PDP 地址却给了证书：%v", err)
	}

	// 启动时读不了证书、私钥或 CA：不启动，错误里没有证书或私钥的内容。
	dir := t.TempDir()
	garbage := filepath.Join(dir, "garbage.pem")
	if err := os.WriteFile(garbage, []byte("-----BEGIN PRIVATE KEY-----\nc2VjcmV0LWtleS1ib2R5\n-----END PRIVATE KEY-----\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, bad := range map[string][]string{
		"证书文件不存在": {"--gatekeeper-tls-cert", filepath.Join(dir, "missing.crt"), "--gatekeeper-tls-key", key, "--gatekeeper-tls-ca", ca, "--gatekeeper-name", pdpHostName},
		"私钥读不懂":   {"--gatekeeper-tls-cert", cert, "--gatekeeper-tls-key", garbage, "--gatekeeper-tls-ca", ca, "--gatekeeper-name", pdpHostName},
		"CA 读不懂":  {"--gatekeeper-tls-cert", cert, "--gatekeeper-tls-key", key, "--gatekeeper-tls-ca", garbage, "--gatekeeper-name", pdpHostName},
	} {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		args := append(h.args("127.0.0.1:0"), "--gatekeeper-url", "https://127.0.0.1:27623", "--gatekeeper-token-file", token)
		err := run(ctx, append(args, bad...), io.Discard, nil)
		cancel()
		if err == nil {
			t.Errorf("%s: 启动了", name)
		} else if strings.Contains(err.Error(), "c2VjcmV0") || strings.Contains(err.Error(), pdpSecret) {
			t.Errorf("%s: 错误信息里有秘密：%v", name, err)
		}
	}
}
