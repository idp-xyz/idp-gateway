package sfopenapi

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.idp.xyz/idp-gateway/internal/platform/workloadtls"
	"go.idp.xyz/idp-gateway/internal/platform/workloadtls/tlstest"
)

const coordName = "coord.idp.test"
const coordIdentity = "spiffe://idp.test/egress/gateway-authz"

func TestLeaseKeyIsAFingerprintWithoutTheSecret(t *testing.T) {
	base := cacheKey{handle: "handle", tokenEndpoint: "https://carrier.example/token", appKey: "app", keyVersion: "v1",
		secretDigest: sha256.Sum256([]byte("app-secret-one"))}
	otherVersion := base
	otherVersion.keyVersion = "v2"
	otherSecret := base
	otherSecret.secretDigest = sha256.Sum256([]byte("app-secret-two"))
	swapped := cacheKey{handle: "handlehttps", tokenEndpoint: "://carrier.example/token", appKey: "app", keyVersion: "v1",
		secretDigest: base.secretDigest}
	keys := []string{leaseKey(base), leaseKey(otherVersion), leaseKey(otherSecret), leaseKey(swapped)}
	seen := map[string]bool{}
	for _, key := range keys {
		if len(key) != 64 || key != strings.ToLower(key) {
			t.Fatalf("key %q", key)
		}
		if seen[key] {
			t.Fatalf("collision %s", key)
		}
		seen[key] = true
		if strings.Contains(key, "secret") || strings.Contains(key, "app-secret") {
			t.Fatalf("fingerprint contains the secret: %s", key)
		}
	}
	if err := validHolderIDCheck(); err != nil {
		t.Fatal(err)
	}
}

func validHolderIDCheck() error {
	if !validHolderID("holder-1") || validHolderID("") || validHolderID("has space") || validHolderID(strings.Repeat("a", 129)) {
		return fmt.Errorf("holder id rule")
	}
	return nil
}

type downLease struct{}

func (downLease) Acquire(context.Context, AcquireRequest) (AcquireResult, error) {
	return AcquireResult{}, &leaseCallError{cause: "unreachable"}
}
func (downLease) Commit(context.Context, CommitRequest) error {
	return &leaseCallError{cause: "unreachable"}
}
func (downLease) Release(context.Context, ReleaseRequest) error { return nil }

func TestCoordinatorDownDoesNotCallTheCarrier(t *testing.T) {
	ep := newEndpoint(t)
	f := newFixture(t, fileOf(entryJSON(blueHandle, blueApp(ep.tokenURL()))), func(cfg *Config) {
		cfg.Lease = downLease{}
		cfg.HolderID = "holder-down"
	})
	_, err := f.get(blueHandle)
	if err == nil || err.Error() != failed(blueHandle, "lease_unavailable") || ep.count() != 0 {
		t.Fatalf("err=%v calls=%d logs=%s", err, ep.count(), f.logs.String())
	}
	if !strings.Contains(f.logs.String(), `"result":"lease_unavailable"`) || !strings.Contains(f.logs.String(), `"cause":"unreachable"`) {
		t.Fatalf("log: %s", f.logs.String())
	}
	noSecrets(t, f.logs.String()+" "+err.Error(), "fail closed")
}

type countingLease struct {
	LeaseCoordinator
	acquires atomic.Int32
}

func (c *countingLease) Acquire(ctx context.Context, req AcquireRequest) (AcquireResult, error) {
	c.acquires.Add(1)
	return c.LeaseCoordinator.Acquire(ctx, req)
}

func TestTwoInstancesShareOneCarrierCallAndSurviveRestart(t *testing.T) {
	ep := newEndpoint(t)
	var current atomic.Value
	ep.set(func(w http.ResponseWriter, r *http.Request) {
		token := fmt.Sprintf("harsh-token-%d", ep.count())
		current.Store(token)
		io.WriteString(w, answer("7200", token))
	})
	proc, lease := startCoordinator(t)
	counted := &countingLease{LeaseCoordinator: lease}
	content := fileOf(entryJSON(blueHandle, blueApp(ep.tokenURL())))
	f1 := newFixture(t, content, withLease(counted, "holder-instance-1"), withRealClock())
	f2 := newFixture(t, content, withLease(counted, "holder-instance-2"), withRealClock())

	var wg sync.WaitGroup
	headers := make(chan string, 16)
	errs := make(chan error, 16)
	start := make(chan struct{})
	for range 8 {
		for _, f := range []*fixture{f1, f2} {
			wg.Add(1)
			go func(f *fixture) {
				defer wg.Done()
				<-start
				got, err := f.get(blueHandle)
				if err != nil {
					errs <- err
					return
				}
				headers <- got
			}(f)
		}
	}
	close(start)
	wg.Wait()
	close(errs)
	close(headers)
	var first string
	n := 0
	for err := range errs {
		t.Errorf("request: %v", err)
	}
	for got := range headers {
		n++
		if first == "" {
			first = got
		} else if got != first {
			t.Errorf("token diverged: %q vs %q", first, got)
		}
	}
	if n != 16 || ep.count() != 1 {
		t.Fatalf("responses %d carrier calls %d", n, ep.count())
	}
	token, _ := current.Load().(string)
	if token == "" || !strings.Contains(first, token) {
		t.Fatalf("header %q token %q", first, token)
	}
	afterBurst := counted.acquires.Load()
	if _, err := f1.get(blueHandle); err != nil || ep.count() != 1 || counted.acquires.Load() != afterBurst {
		t.Fatalf("warm cache called out: calls %d acquires %d->%d", ep.count(), afterBurst, counted.acquires.Load())
	}

	f3 := newFixture(t, content, withLease(counted, "holder-instance-3"), withRealClock())
	got, err := f3.get(blueHandle)
	if err != nil || got != first || ep.count() != 1 {
		t.Fatalf("restarted instance %q %v calls %d", got, err, ep.count())
	}

	rotated := blueApp(ep.tokenURL())
	rotated.KeyVersion = "v2"
	write(t, f1.path, fileOf(entryJSON(blueHandle, rotated)), 0o600)
	got, err = f1.get(blueHandle)
	if err != nil || ep.count() != 2 || got == first {
		t.Fatalf("key version %q %v calls %d", got, err, ep.count())
	}
	next, _ := current.Load().(string)
	if next == token || !strings.Contains(got, next) {
		t.Fatalf("new token %q header %q", next, got)
	}
	raw, err := os.ReadFile(proc.leaseFile)
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw) + f1.logs.String() + f2.logs.String() + f3.logs.String() + proc.logs.String()
	if strings.Contains(f1.logs.String()+f2.logs.String()+f3.logs.String()+proc.logs.String(), token) ||
		strings.Contains(f1.logs.String()+proc.logs.String(), next) ||
		strings.Contains(text, blueSecret) || strings.Contains(text, blueAES) {
		t.Fatal("secret or token leaked into logs or the lease file mixed with the app secret")
	}
	if strings.Contains(string(raw), blueSecret) || strings.Contains(string(raw), blueAES) || !strings.Contains(string(raw), next) {
		t.Fatalf("lease file shape: %s", raw)
	}
	info, err := os.Stat(proc.leaseFile)
	if err != nil || info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("lease mode %v", info.Mode())
	}
}

func TestStoppedCoordinatorFailsClosed(t *testing.T) {
	ep := newEndpoint(t)
	ep.setExpireIn("7200")
	proc, lease := startCoordinator(t)
	clk := &fakeClock{now: time.Now()}
	content := fileOf(entryJSON(blueHandle, blueApp(ep.tokenURL())))
	f1 := newFixture(t, content, withLease(lease, "holder-expire-1"), func(cfg *Config) { cfg.Now = clk.Now })
	f2 := newFixture(t, content, withLease(lease, "holder-expire-2"), func(cfg *Config) { cfg.Now = clk.Now })
	first, err := f1.get(blueHandle)
	if err != nil || ep.count() != 1 {
		t.Fatalf("prime %v calls %d", err, ep.count())
	}
	second, err := f2.get(blueHandle)
	if err != nil || second != first || ep.count() != 1 {
		t.Fatalf("share %q %v calls %d", second, err, ep.count())
	}
	clk.Advance(3 * time.Hour)
	proc.stop()
	for _, f := range []*fixture{f1, f2} {
		_, err := f.get(blueHandle)
		if err == nil || err.Error() != failed(blueHandle, "lease_unavailable") {
			t.Fatalf("fail closed: %v", err)
		}
	}
	if ep.count() != 1 {
		t.Fatalf("carrier was called %d times after the coordinator stopped", ep.count())
	}
	blob := f1.logs.String() + f2.logs.String() + proc.logs.String()
	noSecrets(t, blob, "stopped coordinator")
	if strings.Contains(blob, "harsh") {
		t.Fatalf("token in logs: %s", blob)
	}
}

func withLease(lease LeaseCoordinator, holder string) func(*Config) {
	return func(cfg *Config) {
		cfg.Lease = lease
		cfg.HolderID = holder
	}
}

func withRealClock() func(*Config) {
	return func(cfg *Config) { cfg.Now = time.Now }
}

var (
	binOnce sync.Once
	binPath string
	binErr  error
)

func coordinatorBinary(t *testing.T) string {
	t.Helper()
	binOnce.Do(func() {
		dir, err := os.MkdirTemp("", "sf-coord-bin-")
		if err != nil {
			binErr = err
			return
		}
		binPath = filepath.Join(dir, "sf-token-coordinator")
		envCmd := exec.Command("go", "env", "GOMOD")
		envCmd.Env = append(os.Environ(), "PATH=/usr/local/go/bin:"+os.Getenv("PATH"))
		gomod, err := envCmd.Output()
		if err != nil {
			binErr = err
			return
		}
		cmd := exec.Command("go", "build", "-o", binPath, "go.idp.xyz/idp-gateway/cmd/sf-token-coordinator")
		cmd.Dir = filepath.Dir(strings.TrimSpace(string(gomod)))
		cmd.Env = append(os.Environ(), "PATH=/usr/local/go/bin:"+os.Getenv("PATH"))
		out, err := cmd.CombinedOutput()
		if err != nil {
			binErr = fmt.Errorf("%w\n%s", err, out)
		}
	})
	if binErr != nil {
		t.Fatal(binErr)
	}
	return binPath
}

type coordProc struct {
	cmd       *exec.Cmd
	done      chan error
	logs      *lockedBuffer
	leaseFile string
	stopOnce  sync.Once
}

func (p *coordProc) stop() {
	p.stopOnce.Do(func() {
		if p.cmd != nil && p.cmd.Process != nil {
			_ = p.cmd.Process.Kill()
		}
		<-p.done
	})
}

func startCoordinator(t *testing.T) (*coordProc, *HTTPLeaseClient) {
	t.Helper()
	ca := tlstest.NewCA(t, "lease CA")
	server := ca.Issue("coordinator", []string{"spiffe://idp.test/sf-lease"}, coordName)
	client := ca.Issue("authz", []string{coordIdentity})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	leaseFile := filepath.Join(t.TempDir(), "leases.json")
	logs := &lockedBuffer{}
	cmd := exec.Command(coordinatorBinary(t),
		"--listen", addr,
		"--tls-cert", server.CertFile,
		"--tls-key", server.KeyFile,
		"--client-ca", ca.File(),
		"--authz-identity", coordIdentity,
		"--lease-file", leaseFile,
	)
	cmd.Stdout = logs
	cmd.Stderr = logs
	cmd.Env = os.Environ()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	proc := &coordProc{cmd: cmd, done: make(chan error, 1), logs: logs, leaseFile: leaseFile}
	go func() { proc.done <- cmd.Wait() }()
	t.Cleanup(proc.stop)

	tlsConfig, err := workloadtls.ClientConfigWithLogger(client.CertFile, client.KeyFile, ca.File(), coordName, nil)
	if err != nil {
		t.Fatal(err)
	}
	lease, err := NewHTTPLeaseClient("https://"+addr, tlsConfig, nil)
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	var last error
	for time.Now().Before(deadline) {
		req, err := http.NewRequest(http.MethodGet, "https://"+addr+"/healthz", nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := (&http.Client{Timeout: time.Second, Transport: &http.Transport{TLSClientConfig: tlsConfig}}).Do(req)
		if err == nil {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK && strings.Contains(string(raw), `"ok":true`) {
				return proc, lease
			}
			last = fmt.Errorf("health %d %s", resp.StatusCode, raw)
		} else {
			last = err
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("coordinator not healthy: %v\n%s", last, logs.String())
	return nil, nil
}
