package policyapplier

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"go.idp.xyz/idp-gateway/internal/fabricpub/ports"
	"go.idp.xyz/idp-gateway/internal/platform/workloadtls/tlstest"
)

func TestApplyConfirmsVersionAndRestoresOnTimeout(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.json")
	if err := os.WriteFile(path, []byte(`{"version":"old"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	ca := tlstest.NewCA(t, "ca")
	serverLeaf := ca.Issue("authz", []string{"spiffe://idp.test/egress/authz"}, "authz.idp.test")
	publisher := ca.Issue("publisher", []string{"spiffe://idp.test/egress/publisher"})
	version := "old"
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/egress/policy-version" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"policy_version":"` + version + `"}`))
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{serverLeaf.Certificate}, MinVersion: tls.VersionTLS12}
	srv.StartTLS()
	t.Cleanup(srv.Close)

	client := &http.Client{Transport: &http.Transport{TLSClientConfig: tlstest.ClientConfig(ca, "authz.idp.test", &publisher)}}
	ok, err := New(Config{Path: path, AuthzURL: srv.URL, ServerName: "authz.idp.test", HTTP: client, Timeout: time.Second, Interval: 10 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	version = "policy-9"
	prev, err := ok.Apply(context.Background(), []byte(`{"version":"policy-9"}`), "policy-9")
	if err != nil {
		t.Fatal(err)
	}
	if string(prev) != `{"version":"old"}` {
		t.Fatalf("previous %s", prev)
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != `{"version":"policy-9"}` {
		t.Fatalf("file %s %v", got, err)
	}

	version = "old"
	slow, err := New(Config{Path: path, AuthzURL: srv.URL, ServerName: "authz.idp.test", HTTP: client, Timeout: 40 * time.Millisecond, Interval: 10 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := slow.Apply(context.Background(), []byte(`{"version":"policy-10"}`), "policy-10"); err == nil {
		t.Fatal("版本对不上时应失败")
	}
	got, err = os.ReadFile(path)
	if err != nil || string(got) != `{"version":"policy-9"}` {
		t.Fatalf("失败后应还原，文件是 %s", got)
	}
}

func TestRestoreFailureIsPartial(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.json")
	if err := os.WriteFile(path, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	applier, err := New(Config{
		Path: path, AuthzURL: "https://authz.idp.test:443", ServerName: "authz.idp.test",
		HTTP: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			if err := os.Chmod(dir, 0o555); err != nil {
				t.Error(err)
			}
			return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody, Header: make(http.Header)}, nil
		})},
		Timeout: 30 * time.Millisecond, Interval: 5 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })
	_, err = applier.Apply(context.Background(), []byte("new-policy-body"), "wanted")
	if err == nil || !os.IsPermission(err) && !errorIsPartial(err) {
		t.Fatal(err)
	}
	if !errorIsPartial(err) {
		t.Fatal(err)
	}
}

func errorIsPartial(err error) bool {
	return err != nil && (os.IsPermission(err) || len(err.Error()) > 0) && (func() bool {
		return err != nil && (err.Error() == ports.ErrPartial.Error() || contains(err.Error(), ports.ErrPartial.Error()))
	})()
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(sub) == 0 || (func() bool {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	})())
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
