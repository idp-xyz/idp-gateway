package readback

import (
	"context"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"go.idp.xyz/idp-gateway/internal/platform/workloadtls"
	"go.idp.xyz/idp-gateway/internal/platform/workloadtls/tlstest"
)

const (
	readBackName = "readback.gateway.idp.test"
	publisherID  = "spiffe://idp.test/gateway-control/publisher"
	// 下面两段是锁定的 agentgateway 1.7.0 镜像的 /api/runtime 原文：加载成功时的，和加载失败之后的
	//（后一段里原文的反引号在这里写成了单引号）。
	runtimeLoaded = `{"user":null,"build":{"version":"1.7.0","gitRevision":"26f5aebe99a36a037fe54f8080a608aca5547e15","rustVersion":"1.99.0","buildProfile":"release","buildTarget":"x86_64-unknown-linux-gnu"},"ui":{"gatewayMode":"standalone","configStoreMode":"readOnly"},"configReload":{"synchronized":true,"lastError":null}}`
	runtimeFailed = `{"user":null,"build":{"version":"1.7.0","gitRevision":"26f5aebe99a36a037fe54f8080a608aca5547e15","rustVersion":"1.99.0","buildProfile":"release","buildTarget":"x86_64-unknown-linux-gnu"},"ui":{"gatewayMode":"standalone","configStoreMode":"readOnly"},"configReload":{"synchronized":false,"lastError":"routes[2]: unknown field 'notAFieldOfARoute' at line 45 column 3"}}`
	// 同一份原文由 tests/integration/compose 的 published_digest 算出的摘要（见 domain 包的测试）。
	realDumpDigest = "d963105500f5d47848eae32fb9fee12652d5522e8d2ea2368f2247f3d85c4121"
)

// gateway 是一个假的回读口：要客户端证书，按表回答。
type gateway struct {
	mu       sync.Mutex
	answers  map[string]answer
	requests []string
}

// answer 是假回读口对一个路径的回答。status 是 302 时，body 是它要重定向去的地方。
type answer struct {
	status int
	body   string
}

func (g *gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	g.mu.Lock()
	g.requests = append(g.requests, r.Method+" "+r.URL.Path+" host="+r.Host+" peer="+workloadtls.PeerIdentity(r.TLS))
	reply, ok := g.answers[r.URL.Path]
	g.mu.Unlock()
	if !ok {
		http.NotFound(w, r)
		return
	}
	if reply.status == http.StatusFound {
		w.Header().Set("Location", reply.body)
		w.WriteHeader(reply.status)
		return
	}
	w.WriteHeader(reply.status)
	_, _ = io.WriteString(w, reply.body)
}

func realDump(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile("../../domain/testdata/config_dump.json")
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// start 起一个假的回读口，返回它、它的地址和一个拿着发布器证书的客户端。
func start(t *testing.T, answers map[string]answer) (*gateway, *tlstest.CA, *Client) {
	t.Helper()
	ca := tlstest.NewCA(t, "workload CA")
	server := ca.Issue("gateway-readback", nil, readBackName)
	config, err := workloadtls.ServerConfig(server.CertFile, server.KeyFile, ca.File())
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	fake := &gateway{answers: answers}
	srv := &http.Server{Handler: fake, TLSConfig: config, ReadTimeout: 5 * time.Second, ErrorLog: log.New(io.Discard, "", 0)}
	go func() { _ = srv.ServeTLS(listener, "", "") }()
	t.Cleanup(func() { _ = srv.Close() })
	return fake, ca, client(t, ca, listener.Addr().String(), readBackName)
}

func client(t *testing.T, ca *tlstest.CA, address, serverName string) *Client {
	t.Helper()
	publisher := ca.Issue("publisher", []string{publisherID})
	config, err := workloadtls.ClientConfig(publisher.CertFile, publisher.KeyFile, ca.File(), serverName)
	if err != nil {
		t.Fatal(err)
	}
	c, err := New(Config{Address: address, TLS: config, Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestObserveReadsWhatARealGatewayAnswers(t *testing.T) {
	fake, _, c := start(t, map[string]answer{dumpPath: {200, realDump(t)}, runtimePath: {200, runtimeLoaded}})
	observed, err := c.Observe(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if observed.Digest != realDumpDigest || !observed.Synchronized || observed.LastError != "" || observed.StorageMode != "readOnly" {
		t.Fatalf("%+v", observed)
	}
	if observed.Version != "1.7.0" || observed.Revision != "26f5aebe99a36a037fe54f8080a608aca5547e15" || observed.Settings["terminationMaxDeadline"] != `"45s"` {
		t.Fatalf("%+v", observed)
	}
	// 两个 GET，带着回读口的名字，出示的是发布器的证书。
	want := []string{
		"GET /config_dump host=" + readBackName + " peer=" + publisherID,
		"GET /api/runtime host=" + readBackName + " peer=" + publisherID,
	}
	if len(fake.requests) != 2 || fake.requests[0] != want[0] || fake.requests[1] != want[1] {
		t.Fatalf("发出的请求是 %v", fake.requests)
	}

	fake.mu.Lock()
	fake.answers[runtimePath] = answer{200, runtimeFailed}
	fake.mu.Unlock()
	observed, err = c.Observe(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if observed.Synchronized || observed.LastError != "routes[2]: unknown field 'notAFieldOfARoute' at line 45 column 3" || observed.Digest != realDumpDigest {
		t.Fatalf("%+v", observed)
	}
}

func TestObserveFailsWhenTheGatewayDoesNotAnswerAsExpected(t *testing.T) {
	dump := realDump(t)
	for name, answers := range map[string]map[string]answer{
		"回读口上没有 /config_dump":  {runtimePath: {200, runtimeLoaded}},
		"回读口上没有 /api/runtime":  {dumpPath: {200, dump}},
		"/config_dump 被拒绝":     {dumpPath: {403, "denied"}, runtimePath: {200, runtimeLoaded}},
		"/config_dump 不是 JSON": {dumpPath: {200, "<html>"}, runtimePath: {200, runtimeLoaded}},
		"/config_dump 是数组":     {dumpPath: {200, "[]"}, runtimePath: {200, runtimeLoaded}},
		"/api/runtime 不是 JSON": {dumpPath: {200, dump}, runtimePath: {200, "ok"}},
		"/api/runtime 是 5xx":   {dumpPath: {200, dump}, runtimePath: {503, runtimeLoaded}},
		"没有 configReload":      {dumpPath: {200, dump}, runtimePath: {200, `{"build":{"version":"1.7.0"},"ui":{"configStoreMode":"readOnly"}}`}},
		"没有 synchronized":      {dumpPath: {200, dump}, runtimePath: {200, `{"build":{},"ui":{},"configReload":{"lastError":null}}`}},
		"没有 ui":                {dumpPath: {200, dump}, runtimePath: {200, `{"build":{},"configReload":{"synchronized":true}}`}},
		"没有 build":             {dumpPath: {200, dump}, runtimePath: {200, `{"ui":{},"configReload":{"synchronized":true}}`}},
		// 跟着重定向走的话，会从别处读到一份看起来完好的运行配置。
		"重定向到别处": {dumpPath: {302, "/elsewhere"}, "/elsewhere": {200, dump}, runtimePath: {200, runtimeLoaded}},
	} {
		_, _, c := start(t, answers)
		if observed, err := c.Observe(context.Background()); err == nil {
			t.Errorf("%s：读到了 %+v", name, observed)
		}
	}
}

func TestObserveRefusesAnOversizedAnswer(t *testing.T) {
	_, _, c := start(t, map[string]answer{dumpPath: {200, realDump(t)}, runtimePath: {200, runtimeLoaded}})
	c.limit = 1024
	if _, err := c.Observe(context.Background()); err == nil || !strings.Contains(err.Error(), "more than 1024 bytes") {
		t.Fatalf("得到 %v", err)
	}
	c.limit = int64(len(realDump(t))) // 正好这么大的不算超
	if _, err := c.Observe(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestObserveVerifiesTheGatewayAndHonoursTheContext(t *testing.T) {
	answers := map[string]answer{dumpPath: {200, realDump(t)}, runtimePath: {200, runtimeLoaded}}
	fake, ca, good := start(t, answers)

	// 回读口的证书不是给这个名字的。
	if _, err := client(t, ca, good.address, "other.idp.test").Observe(context.Background()); err == nil {
		t.Fatal("名字不符的回读口被接受了")
	}
	// 回读口的证书不是这个 CA 签的。
	rogue := tlstest.NewCA(t, "a CA outside the trust domain")
	if _, err := client(t, rogue, good.address, readBackName).Observe(context.Background()); err == nil {
		t.Fatal("别的 CA 签的回读口被接受了（或者别的 CA 签的发布器证书被回读口接受了）")
	}
	if len(fake.requests) != 0 {
		t.Fatalf("握手不该完成，却有请求到了：%v", fake.requests)
	}
	// 已经取消的 ctx。
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := good.Observe(cancelled); err == nil {
		t.Fatal("ctx 已取消，却读到了")
	}
	// 那里没有人在听。
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	_ = listener.Close()
	if _, err := client(t, ca, address, readBackName).Observe(context.Background()); err == nil {
		t.Fatal("没有人在听，却读到了")
	}
	// 对照：同一个客户端此刻读得到。
	if _, err := good.Observe(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestNewRefusesAnIncompleteConfiguration(t *testing.T) {
	ca := tlstest.NewCA(t, "workload CA")
	publisher := ca.Issue("publisher", []string{publisherID})
	complete, err := workloadtls.ClientConfig(publisher.CertFile, publisher.KeyFile, ca.File(), readBackName)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := New(Config{Address: "127.0.0.1:8443", TLS: complete}); err != nil {
		t.Fatal(err)
	}
	withoutName, withoutCertificate, withoutCA := complete.Clone(), complete.Clone(), complete.Clone()
	withoutName.ServerName, withoutCertificate.Certificates, withoutCA.RootCAs = "", nil, nil
	for name, config := range map[string]Config{
		"地址没有端口":    {Address: "127.0.0.1", TLS: complete},
		"没有 TLS 配置": {Address: "127.0.0.1:8443"},
		"没有要验证的名字":  {Address: "127.0.0.1:8443", TLS: withoutName},
		"没有客户端证书":   {Address: "127.0.0.1:8443", TLS: withoutCertificate},
		"没有 CA":     {Address: "127.0.0.1:8443", TLS: withoutCA},
	} {
		if _, err := New(config); err == nil {
			t.Errorf("%s：被接受了", name)
		}
	}
}
