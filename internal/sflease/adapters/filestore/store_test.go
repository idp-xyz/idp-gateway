package filestore

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"go.idp.xyz/idp-gateway/internal/sflease/domain"
)

const (
	leaseKey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	token    = "persisted-access-token"
)

func TestCreatesAPrivateFileAndRoundTrips(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "leases.json")
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode().Perm() != 0o600 || info.Mode()&os.ModeSymlink != 0 {
		t.Fatalf("created mode %v %v", info.Mode(), err)
	}
	loaded, err := store.Load()
	if err != nil || len(loaded) != 0 {
		t.Fatalf("%v %d", err, len(loaded))
	}
	raw, err := os.ReadFile(path)
	if err != nil || string(raw) != "{\"version\":1,\"leases\":{}}\n" {
		t.Fatalf("empty file %s %v", raw, err)
	}
	expires := time.Now().Add(time.Hour).UTC()
	err = store.Save(map[string]domain.LeaseRecord{
		leaseKey: {LeaseKey: leaseKey, Token: domain.NewSecret(token), ExpiresAt: expires, Lifetime: time.Hour},
	})
	if err != nil {
		t.Fatal(err)
	}
	info, err = os.Lstat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("saved mode %v", info.Mode())
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.Contains(entry.Name(), ".tmp") {
			t.Fatalf("temp file left behind: %s", entry.Name())
		}
	}
	again, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	got, err := again.Load()
	if err != nil || len(got) != 1 || got[leaseKey].Token.Reveal() != token || !got[leaseKey].ExpiresAt.Equal(expires) || got[leaseKey].Lifetime != time.Hour {
		t.Fatalf("%v %+v", err, got[leaseKey])
	}
	onDisk, err := os.ReadFile(path)
	if err != nil || !strings.Contains(string(onDisk), token) {
		t.Fatal("the file is where the token lives")
	}
}

func TestRejectsSymlinkLooseModeAndBadJSONWithoutLeakingTheToken(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "real.json")
	if err := os.WriteFile(target, []byte("{\"version\":1,\"leases\":{}}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.json")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(link); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("symlink: %v", err)
	}

	loose := filepath.Join(dir, "loose.json")
	body := []byte(`{"version":1,"leases":{"` + leaseKey + `":{"token":"` + token + `","expires_at":"2030-01-01T00:00:00Z","lifetime_ns":3600000000000}}}`)
	if err := os.WriteFile(loose, body, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(loose, 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := Open(loose)
	if err == nil || !strings.Contains(err.Error(), "mode") || strings.Contains(err.Error(), token) {
		t.Fatalf("loose: %v", err)
	}

	broken := filepath.Join(dir, "broken.json")
	junk := []byte(`{"version":1,"leases":{"token":"` + token + `"`)
	if err := os.WriteFile(broken, junk, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = Open(broken)
	if err == nil || !strings.Contains(err.Error(), "not valid JSON") || strings.Contains(err.Error(), token) {
		t.Fatalf("broken: %v", err)
	}

	missingParent := filepath.Join(dir, "no-such-dir", "leases.json")
	if _, err := Open(missingParent); err == nil {
		t.Fatal("missing parent was created")
	}
}

func TestExpiredEntriesAreDropped(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "leases.json")
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	past := time.Now().Add(-time.Minute)
	future := time.Now().Add(time.Hour)
	err = store.Save(map[string]domain.LeaseRecord{
		leaseKey:                 {LeaseKey: leaseKey, Token: domain.NewSecret(token), ExpiresAt: past, Lifetime: time.Minute},
		strings.Repeat("ab", 32): {LeaseKey: strings.Repeat("ab", 32), Token: domain.NewSecret("still-valid-token"), ExpiresAt: future, Lifetime: time.Hour},
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := store.Load()
	if err != nil || len(got) != 1 || got[strings.Repeat("ab", 32)].Token.Reveal() != "still-valid-token" {
		t.Fatalf("%v %d", err, len(got))
	}
	raw, err := os.ReadFile(path)
	if err != nil || strings.Contains(string(raw), token) {
		t.Fatalf("expired token was written: %s", raw)
	}
}
