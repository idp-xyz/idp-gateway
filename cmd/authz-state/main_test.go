package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"go.idp.xyz/idp-gateway/internal/egressauthz/adapters/authzstate"
	"go.idp.xyz/idp-gateway/internal/egressauthz/adapters/filestore"
	"go.idp.xyz/idp-gateway/internal/egressauthz/domain"
	"go.idp.xyz/idp-gateway/internal/platform/workloadtls"
	"go.idp.xyz/idp-gateway/internal/platform/workloadtls/tlstest"
)

func TestParseRequiresEveryFlag(t *testing.T) {
	if _, err := parse(nil, io.Discard); err == nil || !strings.Contains(err.Error(), "missing required flags") {
		t.Fatal(err)
	}
	if _, err := parse([]string{"--listen", "127.0.0.1:1", "extra"}, io.Discard); err == nil || !strings.Contains(err.Error(), "unexpected") {
		t.Fatal(err)
	}
}

func TestTwoClientsShareRevokeQuotaAndRejectParameterMismatch(t *testing.T) {
	ca := tlstest.NewCA(t, "state CA")
	const serverName = "state.idp.test"
	const authzID = "spiffe://idp.test/egress/gateway-authz"
	server := ca.Issue("state", []string{"spiffe://idp.test/authz-state"}, serverName)
	clientLeaf := ca.Issue("authz", []string{authzID})
	dir := t.TempDir()
	stateFile := filepath.Join(dir, "state.json")
	var logs lockedBuffer
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	addrCh := make(chan string, 1)
	done := make(chan error, 1)
	go func() {
		done <- run(ctx, []string{
			"--listen", "127.0.0.1:0",
			"--tls-cert", server.CertFile,
			"--tls-key", server.KeyFile,
			"--client-ca", ca.File(),
			"--authz-identity", authzID,
			"--state-file", stateFile,
		}, &logs, func(addr net.Addr) { addrCh <- addr.String() })
	}()
	var addr string
	select {
	case addr = <-addrCh:
	case err := <-done:
		t.Fatal(err)
	case <-time.After(5 * time.Second):
		t.Fatal("did not listen")
	}
	tlsConfig, err := workloadtls.ClientConfigWithLogger(clientLeaf.CertFile, clientLeaf.KeyFile, ca.File(), serverName, nil)
	if err != nil {
		t.Fatal(err)
	}
	waitHealthy(t, "https://"+addr, tlsConfig)
	clientA := mustClient(t, "https://"+addr, tlsConfig)
	clientB := mustClient(t, "https://"+addr, tlsConfig)
	localA := emptyRevocations(t)
	localB := emptyRevocations(t)
	if err := authzstate.Mirror(context.Background(), clientA, localA); err != nil {
		t.Fatal(err)
	}
	ledgerA := authzstate.NewLedger(clientA, localA, nil)
	ledgerB := authzstate.NewLedger(clientB, localB, nil)
	change, err := ledgerA.Revoke(context.Background(), "account-blue", "spiffe://idp.test/revoker", "key leaked")
	if err != nil || !change.Changed || !change.Revoked || change.Epoch != 1 {
		t.Fatalf("revoke %+v %v", change, err)
	}
	revoked, _, epoch, err := ledgerB.View(context.Background(), "account-blue", "tracking.get")
	if err != nil || !revoked || epoch != 1 {
		t.Fatalf("second client: revoked=%v epoch=%d err=%v", revoked, epoch, err)
	}
	info, err := os.Stat(stateFile)
	if err != nil || info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("state file mode %v %v", info, err)
	}
	limitsA, _ := quotaFile(t, 1)
	limitsB, pathB := quotaFile(t, 1)
	limA := authzstate.NewLimiter(clientA, limitsA, nil)
	limB := authzstate.NewLimiter(clientB, limitsB, nil)
	subject := domain.RateLimitSubject{AccountID: "preimage-quota-ZZ", ProviderID: "carrier"}
	ok, _, err := limA.Allow(context.Background(), subject)
	if err != nil || !ok {
		t.Fatalf("first allow %v %v", ok, err)
	}
	ok, retry, err := limB.Allow(context.Background(), subject)
	if err != nil || ok || retry < 1 {
		t.Fatalf("second allow %v retry %d err %v", ok, retry, err)
	}
	writeQuota(t, pathB, 10)
	ok, _, err = limB.Allow(context.Background(), subject)
	if err == nil || ok || !strings.Contains(err.Error(), "parameter_mismatch") {
		t.Fatalf("mismatch allowed=%v err=%v", ok, err)
	}
	if strings.Contains(logs.String()+err.Error(), "preimage-quota-ZZ") {
		t.Fatalf("preimage leaked: %s %v", logs.String(), err)
	}
	if strings.Contains(logs.String(), "\x00") {
		t.Fatal("log contains NUL")
	}
}

func mustClient(t *testing.T, raw string, tlsConfig *tls.Config) *authzstate.Client {
	t.Helper()
	client, err := authzstate.New(raw, tlsConfig, nil)
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func waitHealthy(t *testing.T, base string, tlsConfig *tls.Config) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	var last error
	for time.Now().Before(deadline) {
		req, err := http.NewRequest(http.MethodGet, base+"/healthz", nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := (&http.Client{Timeout: time.Second, Transport: &http.Transport{TLSClientConfig: tlsConfig}}).Do(req)
		if err == nil {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK && strings.Contains(string(raw), `"ok":true`) {
				return
			}
			last = errString(resp.StatusCode, raw)
		} else {
			last = err
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal(last)
}

type statusErr struct {
	status int
	body   string
}

func (e statusErr) Error() string { return e.body }

func errString(status int, raw []byte) error {
	return statusErr{status: status, body: string(raw)}
}

func emptyRevocations(t *testing.T) *filestore.Revocations {
	t.Helper()
	path := filepath.Join(t.TempDir(), "revocations.json")
	if err := os.WriteFile(path, []byte("{\"epoch\":0,\"revoked_accounts\":{}}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ledger, err := filestore.LoadRevocations(path)
	if err != nil {
		t.Fatal(err)
	}
	return ledger
}

func quotaFile(t *testing.T, max int) (*filestore.RateLimits, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "limits.json")
	writeQuota(t, path, max)
	limits, err := filestore.LoadRateLimits(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	return limits, path
}

func writeQuota(t *testing.T, path string, max int) {
	t.Helper()
	body := "{\"version\":\"v1\",\"buckets\":[{\"id\":\"per-account\",\"key_dimensions\":[\"provider_account\"],\"max_requests\":" + itoa(max) + ",\"window_seconds\":3600}]}\n"
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [16]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}
