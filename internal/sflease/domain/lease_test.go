package domain

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"
)

func TestSecretStaysRedacted(t *testing.T) {
	secret := NewSecret("sf-access-token-raw")
	if secret.Reveal() != "sf-access-token-raw" || secret.IsZero() {
		t.Fatal("Reveal")
	}
	if NewSecret("").IsZero() != true {
		t.Fatal("zero")
	}
	for name, text := range map[string]string{
		"string": secret.String(), "go": secret.GoString(),
		"%v": fmt.Sprintf("%v", secret), "%#v": fmt.Sprintf("%#v", secret),
		"%s": fmt.Sprintf("%s", secret), "%x": fmt.Sprintf("%x", secret), "%q": fmt.Sprintf("%q", secret),
	} {
		if text != "[REDACTED]" {
			t.Errorf("%s: %q", name, text)
		}
	}
	text, err := secret.MarshalText()
	if err != nil || string(text) != "[REDACTED]" {
		t.Fatalf("MarshalText %s %v", text, err)
	}
	encoded, err := json.Marshal(secret)
	if err != nil || string(encoded) != `"[REDACTED]"` {
		t.Fatalf("MarshalJSON %s %v", encoded, err)
	}
	var buf strings.Builder
	slog.New(slog.NewJSONHandler(&buf, nil)).Info("lease", "token", secret, slog.Any("again", secret))
	slog.New(slog.NewTextHandler(&buf, nil)).Info("lease", "token", secret)
	if strings.Contains(buf.String(), "sf-access-token-raw") || !strings.Contains(buf.String(), "[REDACTED]") {
		t.Fatalf("slog leaked: %s", buf.String())
	}
}

func TestValidators(t *testing.T) {
	goodKey := strings.Repeat("ab", 32)
	if err := ValidateLeaseKey(goodKey); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"", "abc", strings.Repeat("a", 63), strings.Repeat("A", 64), strings.Repeat("g", 64), "../" + strings.Repeat("a", 61), "ab cd" + strings.Repeat("0", 59)} {
		if err := ValidateLeaseKey(bad); err == nil {
			t.Errorf("lease key accepted %q", bad)
		} else if bad != "" && strings.Contains(err.Error(), bad) {
			t.Errorf("lease key error echoes the input: %v", err)
		}
	}
	if err := ValidateHolderID("holder-1"); err != nil {
		t.Fatal(err)
	}
	if err := ValidateHolderID(strings.Repeat("a", 128)); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"", "has space", "line\nbreak", "tab\t", strings.Repeat("a", 129), "非ascii"} {
		if err := ValidateHolderID(bad); err == nil {
			t.Errorf("holder accepted %q", bad)
		}
	}
	if err := ValidateToken("token-without-semicolon"); err != nil {
		t.Fatal(err)
	}
	if err := ValidateToken(strings.Repeat("a", 4096)); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"", "has space", "a;b", "line\n", strings.Repeat("a", 4097)} {
		if err := ValidateToken(bad); err == nil {
			t.Errorf("token accepted")
		} else if strings.Contains(err.Error(), "a;b") || strings.Contains(err.Error(), "has space") {
			t.Errorf("token error echoes the input: %v", err)
		}
	}
}

func TestUsable(t *testing.T) {
	now := time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)
	rec := LeaseRecord{ExpiresAt: now.Add(time.Hour), Lifetime: time.Hour}
	if !rec.Usable(now, 10*time.Minute) {
		t.Fatal("should be usable")
	}
	if rec.Usable(now, time.Hour) {
		t.Fatal("equal to the lead is not usable")
	}
	if rec.Usable(now.Add(time.Hour), 0) {
		t.Fatal("expired")
	}
	if (LeaseRecord{}).Usable(now, 0) {
		t.Fatal("zero record")
	}
}
