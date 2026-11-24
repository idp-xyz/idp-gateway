package authzstate

import (
	"context"
	"crypto/tls"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go.idp.xyz/idp-gateway/internal/egressauthz/adapters/filestore"
	"go.idp.xyz/idp-gateway/internal/egressauthz/domain"
	"go.idp.xyz/idp-gateway/internal/platform/workloadtls"
	"go.idp.xyz/idp-gateway/internal/platform/workloadtls/tlstest"
)

func TestCoordinatorDownFailsClosed(t *testing.T) {
	ca := tlstest.NewCA(t, "state CA")
	clientLeaf := ca.Issue("authz", []string{"spiffe://idp.test/egress/gateway-authz"})
	tlsConfig, err := workloadtls.ClientConfigWithLogger(clientLeaf.CertFile, clientLeaf.KeyFile, ca.File(), "state.idp.test", nil)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	client, err := New("https://"+addr, tlsConfig, nil)
	if err != nil {
		t.Fatal(err)
	}
	local := loadEmptyRevocations(t)
	ledger := NewLedger(client, local, nil)
	if _, _, _, err := ledger.View(context.Background(), "account-blue", "tracking.get"); err == nil || strings.Contains(err.Error(), "account-blue") {
		t.Fatalf("View: %v", err)
	}
	limits := loadLimits(t, 1)
	limiter := NewLimiter(client, limits, nil)
	allowed, _, err := limiter.Allow(context.Background(), domain.RateLimitSubject{AccountID: "preimage-quota-ZZ"})
	if err == nil || allowed || strings.Contains(err.Error(), "preimage-quota-ZZ") {
		t.Fatalf("Allow: allowed=%v err=%v", allowed, err)
	}
	empty := loadLimits(t, 0)
	if allowed, _, err := NewLimiter(client, empty, nil).Allow(context.Background(), domain.RateLimitSubject{AccountID: "preimage-quota-ZZ"}); err != nil || !allowed {
		t.Fatalf("no rule should allow without RPC: %v %v", allowed, err)
	}
}

func loadEmptyRevocations(t *testing.T) *filestore.Revocations {
	t.Helper()
	path := filepath.Join(t.TempDir(), "revocations.json")
	if err := os.WriteFile(path, []byte(`{"epoch":0,"revoked_accounts":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	ledger, err := filestore.LoadRevocations(path)
	if err != nil {
		t.Fatal(err)
	}
	return ledger
}

func loadLimits(t *testing.T, max int) *filestore.RateLimits {
	t.Helper()
	body := `{"version":"v1","buckets":[]}`
	if max > 0 {
		body = `{"version":"v1","buckets":[{"id":"per-account","key_dimensions":["provider_account"],"max_requests":1,"window_seconds":3600}]}`
	}
	path := filepath.Join(t.TempDir(), "limits.json")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	limits, err := filestore.LoadRateLimits(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	return limits
}

func TestURLRejectsUserInfoQueryAndFragment(t *testing.T) {
	for _, raw := range []string{
		"http://state.idp.test",
		"https://user:pass@state.idp.test",
		"https://state.idp.test?q=1",
		"https://state.idp.test#x",
	} {
		if _, err := New(raw, &tls.Config{}, nil); err == nil {
			t.Fatal(raw)
		}
	}
	if _, err := New("https://state.idp.test", nil, nil); err == nil {
		t.Fatal("nil tls")
	}
}
