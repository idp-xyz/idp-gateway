package binaryvalidator

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"go.idp.xyz/idp-gateway/internal/routecompile/ports"
)

func TestLockMismatchDoesNotRunTheBinary(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "agentgateway")
	if err := os.WriteFile(bin, []byte("not-a-real-gateway"), 0o755); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte("not-a-real-gateway"))
	lock := filepath.Join(dir, "lock.json")
	body := `{"version":"1.7.0","sha256":{"probe":"deadbeef"}}`
	if err := os.WriteFile(lock, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	err := (Validator{Binary: bin, LockFile: lock}).Validate(context.Background(), []byte("config: {}\n"), "", "")
	if !errors.Is(err, ports.ErrRefused) || err == nil {
		t.Fatal(err)
	}
	matched := filepath.Join(dir, "lock-ok.json")
	okBody := `{"sha256":{"probe":"` + hex.EncodeToString(sum[:]) + `"}}`
	if err := os.WriteFile(matched, []byte(okBody), 0o644); err != nil {
		t.Fatal(err)
	}
	err = (Validator{Binary: bin, LockFile: matched}).Validate(context.Background(), []byte("config: {}\n"), "", "")
	if errors.Is(err, ports.ErrRefused) {
		t.Fatal("hash matched, but the failure was reported as a lock refusal")
	}
	if err == nil {
		t.Fatal("a fake binary should not validate")
	}
}
