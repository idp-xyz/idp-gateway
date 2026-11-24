package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"go.idp.xyz/idp-gateway/internal/fabricpub/domain"
	"go.idp.xyz/idp-gateway/internal/fabricpub/ports"
	gapplication "go.idp.xyz/idp-gateway/internal/gatewayconfig/application"
	gdomain "go.idp.xyz/idp-gateway/internal/gatewayconfig/domain"
	gports "go.idp.xyz/idp-gateway/internal/gatewayconfig/ports"
	"go.idp.xyz/idp-gateway/internal/platform/workloadtls/tlstest"
)

func TestParseRejectsIncompleteArguments(t *testing.T) {
	_, err := parse(nil, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "missing required flags") || !strings.Contains(err.Error(), "--fabric-identity") {
		t.Fatal(err)
	}
	_, err = parse([]string{"--listen", "127.0.0.1:0", "--staging-image", "repo@sha256:aa", "--staging-binary", "/bin/true"}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "missing required") {
		t.Fatal(err)
	}
	args := requiredArgs(t)
	args = append(args, "--staging-image", "repo@sha256:"+strings.Repeat("ab", 32), "--staging-binary", "/bin/true", "--staging-lock-file", "lock.json")
	if _, err := parse(args, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatal(err)
	}
	image := append(requiredArgs(t), "--staging-image", "repo@sha256:"+strings.Repeat("ab", 32))
	if _, err := parse(image, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "--staging-tls-dir") {
		t.Fatal(err)
	}
	binary := append(requiredArgs(t), "--staging-binary", "/bin/true")
	if _, err := parse(binary, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "--staging-lock-file") {
		t.Fatal(err)
	}
	neither := requiredArgs(t)
	if _, err := parse(neither, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "choose one") {
		t.Fatal(err)
	}
}

func TestCompileAdapterAcceptsProviderSpec(t *testing.T) {
	raw, err := os.ReadFile("../../deploy/providers/wanbexpress/compile-spec.json")
	if err != nil {
		t.Fatal(err)
	}
	base, err := domain.ParsePoolBase(raw)
	if err != nil {
		t.Fatal(err)
	}
	route := base.Routes[0]
	body := map[string]any{
		"idempotency_key": "pub-wanbexpress-whoami-0001",
		"release_ref":     "fabric-release:wanbexpress/0001",
		"target_id":       "fabric-target:egress-test",
		"intent": map[string]any{
			"intent_id": route.IntentID, "gateway_pool": base.Pool.Name, "traffic_class": "EGRESS",
			"environment": base.Pool.Environment, "provider_id": base.Provider.ProviderID,
			"operation_id": route.OperationID, "logical_path": route.LogicalPath, "allowed_methods": []any{route.Method},
			"upstream_hostname": base.Provider.UpstreamHost, "upstream_port": base.Provider.UpstreamPort,
			"authz_profile": route.AuthzProfile, "approval_ref": route.ApprovalRef, "expected_generation": 0,
			"contract_ref": "consumer-api-wanbexpress-v1", "credential_binding_ref": base.Provider.CredentialBindingRef,
			"redirect_policy": "DENY", "upstream_tls": route.UpstreamTLS,
			"provider_account_strategy": "GATEKEEPER_DECISION_BINDING", "transport": "HTTP",
			"policy_bundle_ref": route.PolicyBundleRef,
		},
	}
	if base.Provider.UpstreamHost == base.Provider.RewriteAuthority {
		body["intent"].(map[string]any)["upstream_sni"] = base.Provider.UpstreamHost
	}
	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	env, err := domain.ParseEnvelope(encoded)
	if err != nil {
		t.Fatal(err)
	}
	merged, _, err := domain.Merge(base, nil, env, env.TargetID, base.Provider.PolicyVersion+"-g0-abcdef12")
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := (compileAdapter{validator: okValidator{}, tlsDir: t.TempDir()}).ValidateAndCompile(context.Background(), merged)
	if err != nil {
		t.Fatal(err)
	}
	if len(bundle.GatewayYAML) == 0 || len(bundle.PolicyJSON) == 0 || !strings.Contains(bundle.PolicyVersion, "-g0-") {
		t.Fatalf("bundle version %s yaml %d", bundle.PolicyVersion, len(bundle.GatewayYAML))
	}
	if _, err := (compileAdapter{validator: refuseValidator{}}).ValidateAndCompile(context.Background(), merged); !errors.Is(err, ports.ErrRefused) {
		t.Fatal(err)
	}
}

func TestPoolPublisherMapsBusyAndRefusal(t *testing.T) {
	publisher, err := gapplication.New(okStaging{}, busyDelivery{}, downReadback{}, gapplication.Timing{Settle: time.Millisecond, Timeout: 20 * time.Millisecond, Interval: time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	reconciler, err := gapplication.NewReconciler(busyDelivery{}, downReadback{}, gapplication.Timing{Settle: time.Millisecond, Timeout: 20 * time.Millisecond, Interval: time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	adapter := &poolPublisher{staging: refuseStaging{}, publisher: publisher, reconciler: reconciler}
	if _, err := adapter.Stage(context.Background(), []byte("gateway: true\n")); !errors.Is(err, ports.ErrRefused) {
		t.Fatal(err)
	}
	out, err := adapter.Publish(context.Background(), []byte("gateway: true\n"), "note")
	if !errors.Is(err, ports.ErrBusy) || !out.Busy {
		t.Fatal(err, out)
	}
	if _, err := adapter.Reconcile(context.Background()); !errors.Is(err, ports.ErrBusy) {
		t.Fatal(err)
	}
}

func TestBinaryStagingRejectsAProcessThatExits(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "agentgateway")
	if err := os.WriteFile(script, []byte("#!/bin/sh\necho cannot-load >&2\nexit 1\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	sum, err := fileSHA256(script)
	if err != nil {
		t.Fatal(err)
	}
	lock := filepath.Join(dir, "lock.json")
	if err := os.WriteFile(lock, []byte(`{"sha256":{"test":"`+sum+`"}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	ca := tlstest.NewCA(t, "ca")
	leaf := ca.Issue("publisher", []string{"spiffe://idp.test/egress/publisher"})
	staging, err := newBinaryStaging(script, lock, "127.0.0.1:1", "", tlstest.ClientConfig(ca, "gateway.idp.test", &leaf))
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := gdomain.NewSnapshot([]byte("gateway: true\n"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = staging.Load(context.Background(), snapshot)
	var rejected *gports.RejectedError
	if !errors.As(err, &rejected) || !strings.Contains(rejected.Reason, "cannot-load") {
		t.Fatal(err)
	}
	bad := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(bad, []byte(`{"sha256":{"test":"`+hex.EncodeToString(bytes.Repeat([]byte{1}, 32))+`"}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	staging.lockFile = bad
	if _, err := staging.Load(context.Background(), snapshot); err == nil || errors.As(err, &rejected) {
		t.Fatal(err)
	}
}

// TestBinaryStagingReapsWhenPortsAreFree 用锁定的二进制在空闲端口上做一次真的离线加载。
// 池若在另一个网络命名空间里，这些端口在本机就是空的；这里模拟的是那种情况。
// 返回之后进程必须已经被收割，端口也必须放开。和正在听同一组端口的网关同处一个网络命名空间时，
// 不能靠改 gateways 端口来躲开冲突，那种加载走 --staging-image。
func TestBinaryStagingReapsWhenPortsAreFree(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("binary staging reaps a Linux process")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(home, ".local", "opt", "agentgateway", "1.7.0", "agentgateway")
	lockPath := filepath.Join("..", "..", "deploy", "agentgateway", "agentgateway.lock.json")
	if _, err := os.Stat(binary); err != nil {
		t.Skip("locked agentgateway binary is not installed")
	}
	if err := matchLock(binary, lockPath); err != nil {
		t.Skip(err)
	}
	listen, readback, admin, stats, ready := freePort(t), freePort(t), freePort(t), freePort(t), freePort(t)
	raw, err := os.ReadFile("../../deploy/providers/wanbexpress/compile-spec.json")
	if err != nil {
		t.Fatal(err)
	}
	base, err := domain.ParsePoolBase(raw)
	if err != nil {
		t.Fatal(err)
	}
	base.Pool.ListenPort = listen
	base.Pool.ReadbackPort = readback
	base.Pool.AdminAddr = fmt.Sprintf("127.0.0.1:%d", admin)
	base.Pool.StatsAddr = fmt.Sprintf("127.0.0.1:%d", stats)
	base.Pool.ReadinessAddr = fmt.Sprintf("127.0.0.1:%d", ready)
	base.Pool.ExtAuthz.Host = "127.0.0.1:9"
	var spec bytes.Buffer
	enc := json.NewEncoder(&spec)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(base); err != nil {
		t.Fatal(err)
	}
	bundle, err := (compileAdapter{validator: okValidator{}, tlsDir: t.TempDir()}).ValidateAndCompile(context.Background(), spec.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	tlsDir := filepath.Join(root, "tls")
	if err := os.Mkdir(tlsDir, 0o700); err != nil {
		t.Fatal(err)
	}
	ca := tlstest.NewCA(t, "ca")
	readbackLeaf := ca.Issue("gateway-readback", nil, "readback.idp.test")
	gatewayLeaf := ca.Issue("gateway", []string{"spiffe://idp.test/egress/agentgateway"})
	publisher := ca.Issue("publisher", []string{"spiffe://idp.test/gateway-control/publisher"})
	copyFile(t, filepath.Join(tlsDir, "ca.crt"), ca.File())
	copyFile(t, filepath.Join(tlsDir, "gateway-readback.crt"), readbackLeaf.CertFile)
	copyFile(t, filepath.Join(tlsDir, "gateway-readback.key"), readbackLeaf.KeyFile)
	copyFile(t, filepath.Join(tlsDir, "gateway.crt"), gatewayLeaf.CertFile)
	copyFile(t, filepath.Join(tlsDir, "gateway.key"), gatewayLeaf.KeyFile)
	if err := os.WriteFile(filepath.Join(tlsDir, "jwks.json"), testJWKS(t), 0o644); err != nil {
		t.Fatal(err)
	}
	staging, err := newBinaryStaging(binary, lockPath, fmt.Sprintf("127.0.0.1:%d", readback), tlsDir, tlstest.ClientConfig(ca, "readback.idp.test", &publisher))
	if err != nil {
		t.Fatal(err)
	}
	staging.timeout = 15 * time.Second
	snapshot, err := gdomain.NewSnapshot(bundle.GatewayYAML)
	if err != nil {
		t.Fatal(err)
	}
	parent := os.Getpid()
	observed, err := staging.Load(context.Background(), snapshot)
	if zombies := childZombies(parent); len(zombies) != 0 {
		t.Fatalf("zombies left behind: %v", zombies)
	}
	if err != nil {
		t.Fatal(err)
	}
	if observed.Digest == "" || !observed.Synchronized || observed.StorageMode != gdomain.StorageReadOnly {
		t.Fatalf("observation %+v", observed)
	}
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", readback))
	if err != nil {
		t.Fatalf("read-back port %d still taken after Load: %v", readback, err)
	}
	ln.Close()
}

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}
	return port
}

func copyFile(t *testing.T, dst, src string) {
	t.Helper()
	body, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, body, 0o600); err != nil {
		t.Fatal(err)
	}
}

func testJWKS(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	coord := func(n []byte) string { return base64.RawURLEncoding.EncodeToString(n) }
	body, err := json.Marshal(map[string]any{"keys": []map[string]string{{
		"kty": "EC", "crv": "P-256", "kid": "suite", "alg": "ES256", "use": "sig",
		"x": coord(key.X.FillBytes(make([]byte, 32))),
		"y": coord(key.Y.FillBytes(make([]byte, 32))),
	}}})
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func childZombies(parent int) []string {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return []string{"proc: " + err.Error()}
	}
	want := strconv.Itoa(parent)
	var found []string
	for _, entry := range entries {
		if _, err := strconv.Atoi(entry.Name()); err != nil {
			continue
		}
		stat, err := os.ReadFile(filepath.Join("/proc", entry.Name(), "stat"))
		if err != nil {
			continue
		}
		text := string(stat)
		end := strings.LastIndex(text, ")")
		if end < 0 || end+2 >= len(text) {
			continue
		}
		fields := strings.Fields(text[end+2:])
		if len(fields) >= 2 && fields[0] == "Z" && fields[1] == want {
			found = append(found, entry.Name())
		}
	}
	return found
}

type okValidator struct{}

func (okValidator) Validate(context.Context, []byte, string, string) error { return nil }

type refuseValidator struct{}

func (refuseValidator) Validate(context.Context, []byte, string, string) error {
	return ports.ErrRefused
}

type refuseStaging struct{}

func (refuseStaging) Load(context.Context, gdomain.Snapshot) (gdomain.Observation, error) {
	return gdomain.Observation{}, &gports.RejectedError{Reason: "no"}
}

type okStaging struct{}

func (okStaging) Load(context.Context, gdomain.Snapshot) (gdomain.Observation, error) {
	return gdomain.Observation{Digest: "abc", Synchronized: true, StorageMode: gdomain.StorageReadOnly}, nil
}

type busyDelivery struct{}

func (busyDelivery) Hold(context.Context) (func(), error) { return nil, gports.ErrBusy }
func (busyDelivery) Current(context.Context) (gdomain.Snapshot, bool, error) {
	return gdomain.Snapshot{}, false, nil
}
func (busyDelivery) Put(context.Context, gdomain.Snapshot) error { return nil }
func (busyDelivery) Confirmed(context.Context) (gdomain.Confirmation, bool, error) {
	return gdomain.Confirmation{}, false, nil
}
func (busyDelivery) Confirm(context.Context, gdomain.Confirmation) error { return nil }

type downReadback struct{}

func (downReadback) Observe(context.Context) (gdomain.Observation, error) {
	return gdomain.Observation{}, errors.New("down")
}

func TestRunAssemblesOnLoopback(t *testing.T) {
	ca := tlstest.NewCA(t, "ca")
	serverLeaf := ca.Issue("fabric", []string{"spiffe://idp.test/gateway-fabric"}, "fabric.idp.test")
	fabric := ca.Issue("caller", []string{"spiffe://idp.test/fabric/publisher"})
	other := ca.Issue("other", []string{"spiffe://idp.test/other"})
	publisher := ca.Issue("publisher", []string{"spiffe://idp.test/gateway-control/publisher"})
	root := t.TempDir()
	stateDir := filepath.Join(root, "state")
	configDir := filepath.Join(root, "config")
	tlsDir := filepath.Join(root, "tls")
	for _, dir := range []string{stateDir, configDir, tlsDir} {
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(root, "agentgateway")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	sum, err := fileSHA256(script)
	if err != nil {
		t.Fatal(err)
	}
	lock := filepath.Join(root, "lock.json")
	if err := os.WriteFile(lock, []byte(`{"sha256":{"test":"`+sum+`"}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "policy.json"), []byte(`{"version":"old"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	spec := "../../deploy/providers/wanbexpress/compile-spec.json"
	baseRaw, err := os.ReadFile(spec)
	if err != nil {
		t.Fatal(err)
	}
	base, err := domain.ParsePoolBase(baseRaw)
	if err != nil {
		t.Fatal(err)
	}
	binding := `{
	  "binding_id": "bind-wanbexpress", "provider_id": "wanbexpress", "environment": "TEST",
	  "auth_scheme": "API_KEY", "account_resolution": "GATEKEEPER_AUTHORIZED_ACCOUNT",
	  "gateway_workload_id": "spiffe://idp.test/egress/gateway",
	  "authorized_credential_ref": "gatekeeper:wanbexpress-test", "approval_ref": "APPROVAL-SANDBOX-001"
	}`
	bindingPath := filepath.Join(root, "bindings.json")
	if err := os.WriteFile(bindingPath, []byte(binding), 0o644); err != nil {
		t.Fatal(err)
	}
	route := base.Routes[0]
	body, err := json.Marshal(map[string]any{
		"idempotency_key": "pub-wanbexpress-whoami-0001",
		"release_ref":     "fabric-release:wanbexpress/0001",
		"target_id":       "fabric-target:egress-test",
		"intent": map[string]any{
			"intent_id": route.IntentID, "gateway_pool": base.Pool.Name, "traffic_class": "EGRESS",
			"environment": base.Pool.Environment, "provider_id": base.Provider.ProviderID,
			"operation_id": route.OperationID, "logical_path": route.LogicalPath, "allowed_methods": []any{route.Method},
			"upstream_hostname": base.Provider.UpstreamHost, "upstream_port": base.Provider.UpstreamPort,
			"authz_profile": route.AuthzProfile, "approval_ref": route.ApprovalRef, "expected_generation": 0,
			"contract_ref": "consumer-api-wanbexpress-v1", "credential_binding_ref": base.Provider.CredentialBindingRef,
			"redirect_policy": "DENY", "upstream_tls": route.UpstreamTLS, "upstream_sni": base.Provider.UpstreamHost,
			"provider_account_strategy": "GATEKEEPER_DECISION_BINDING", "transport": "HTTP",
			"policy_bundle_ref": route.PolicyBundleRef,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	args := []string{
		"--listen", "127.0.0.1:0",
		"--tls-cert", serverLeaf.CertFile, "--tls-key", serverLeaf.KeyFile, "--client-ca", ca.File(),
		"--fabric-identity", "spiffe://idp.test/fabric/publisher",
		"--target-id", "fabric-target:egress-test", "--pool-base", spec, "--bindings", bindingPath,
		"--state-dir", stateDir, "--agentgateway", script, "--lock-file", lock, "--compile-tls-dir", tlsDir,
		"--config-dir", configDir, "--read-back", "127.0.0.1:9", "--read-back-name", "gateway.idp.test",
		"--publisher-cert", publisher.CertFile, "--publisher-key", publisher.KeyFile, "--publisher-ca", ca.File(),
		"--authz-policy-file", filepath.Join(root, "policy.json"), "--authz", "127.0.0.1:1", "--authz-name", "authz.idp.test",
		"--staging-binary", script, "--staging-lock-file", lock, "--staging-listen", "127.0.0.1:1",
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	addrCh := make(chan net.Addr, 1)
	errCh := make(chan error, 1)
	go func() { errCh <- run(ctx, args, io.Discard, func(addr net.Addr) { addrCh <- addr }) }()
	var addr net.Addr
	select {
	case addr = <-addrCh:
	case err := <-errCh:
		t.Fatal(err)
	case <-time.After(10 * time.Second):
		t.Fatal("服务没有启动")
	}
	client := func(leaf *tlstest.Leaf) *http.Client {
		return &http.Client{Transport: &http.Transport{TLSClientConfig: tlstest.ClientConfig(ca, "fabric.idp.test", leaf)}}
	}
	foreign, err := client(&other).Post("https://"+addr.String()+"/v1/route-intents", "application/json", strings.NewReader(string(body)))
	if err != nil {
		t.Fatal(err)
	}
	foreignBody, _ := io.ReadAll(foreign.Body)
	foreign.Body.Close()
	if foreign.StatusCode != http.StatusUnauthorized || strings.Contains(string(foreignBody), "wanbexpress") {
		t.Fatalf("错误身份 %d %s", foreign.StatusCode, foreignBody)
	}
	accepted, err := client(&fabric).Post("https://"+addr.String()+"/v1/route-intents", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	acceptedBody, _ := io.ReadAll(accepted.Body)
	accepted.Body.Close()
	if accepted.StatusCode != http.StatusAccepted {
		t.Fatalf("受理 %d %s", accepted.StatusCode, acceptedBody)
	}
	deadline := time.Now().Add(10 * time.Second)
	var statusBody []byte
	for time.Now().Before(deadline) {
		resp, err := client(&fabric).Get("https://" + addr.String() + "/v1/route-intents/" + route.IntentID + "/status")
		if err != nil {
			t.Fatal(err)
		}
		statusBody, _ = io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode == http.StatusOK && strings.Contains(string(statusBody), `"state":"REJECTED"`) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !strings.Contains(string(statusBody), `"state":"REJECTED"`) {
		t.Fatalf("没有走到 REJECTED：%s", statusBody)
	}
	policy, err := os.ReadFile(filepath.Join(root, "policy.json"))
	if err != nil || string(policy) != `{"version":"old"}` {
		t.Fatalf("策略文件被改了：%s %v", policy, err)
	}
	replay, err := client(&fabric).Post("https://"+addr.String()+"/v1/route-intents", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	replayBody, _ := io.ReadAll(replay.Body)
	replay.Body.Close()
	if replay.StatusCode != http.StatusAccepted || !strings.Contains(string(replayBody), `"state":"DRAFT"`) {
		t.Fatalf("重放 %d %s", replay.StatusCode, replayBody)
	}
	cancel()
	select {
	case <-errCh:
	case <-time.After(5 * time.Second):
		t.Fatal("服务没有退出")
	}
}

func requiredArgs(t *testing.T) []string {
	t.Helper()
	dir := t.TempDir()
	return []string{
		"--listen", "127.0.0.1:0",
		"--tls-cert", filepath.Join(dir, "c.pem"), "--tls-key", filepath.Join(dir, "k.pem"),
		"--client-ca", filepath.Join(dir, "ca.pem"), "--fabric-identity", "spiffe://idp.test/fabric/publisher",
		"--target-id", "fabric-target:egress-test", "--pool-base", filepath.Join(dir, "pool.json"),
		"--bindings", filepath.Join(dir, "bindings.json"), "--state-dir", dir,
		"--agentgateway", "/bin/true", "--lock-file", filepath.Join(dir, "lock.json"),
		"--compile-tls-dir", dir, "--config-dir", dir, "--read-back", "127.0.0.1:9",
		"--read-back-name", "gateway.idp.test", "--publisher-cert", filepath.Join(dir, "p.pem"),
		"--publisher-key", filepath.Join(dir, "p.key"), "--publisher-ca", filepath.Join(dir, "pca.pem"),
		"--authz-policy-file", filepath.Join(dir, "policy.json"), "--authz", "127.0.0.1:9",
		"--authz-name", "authz.idp.test",
	}
}
