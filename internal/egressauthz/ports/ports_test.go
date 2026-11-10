package ports

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"testing"
)

// 凭证值不能经由格式化、日志或 JSON 泄露出去。
func TestSecretDoesNotLeak(t *testing.T) {
	const value = "Bearer provider-token-0123456789"
	secret := NewSecret(value)
	holder := struct {
		Credential Secret
		Pointer    *Secret
	}{secret, &secret}

	var logged bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logged, nil))
	logger.Info("x", "credential", secret, "holder", holder, slog.Any("pointer", &secret))
	text := slog.New(slog.NewTextHandler(&logged, nil))
	text.Info("x", "credential", secret, "holder", holder)

	encoded, err := json.Marshal(map[string]any{"credential": secret, "holder": holder})
	if err != nil {
		t.Fatal(err)
	}
	outputs := map[string]string{
		"%v":      fmt.Sprintf("%v", secret),
		"%+v":     fmt.Sprintf("%+v", holder),
		"%#v":     fmt.Sprintf("%#v", holder),
		"%s":      fmt.Sprintf("%s", secret),
		"%q":      fmt.Sprintf("%q", secret),
		"%v 指针":   fmt.Sprintf("%v", &secret),
		"错误包装":    fmt.Errorf("credential %v rejected", secret).Error(),
		"slog":    logged.String(),
		"json":    string(encoded),
		"Println": fmt.Sprintln(secret, holder),
	}
	for how, out := range outputs {
		if strings.Contains(out, "provider-token") {
			t.Errorf("%s 泄露了凭证：%s", how, out)
		}
	}
	if secret.Reveal() != value {
		t.Fatal("Reveal 应返回原值")
	}
	if !(Secret{}).IsZero() || secret.IsZero() {
		t.Fatal("IsZero 判断错误")
	}
}

func TestHandle(t *testing.T) {
	if got := Handle("gatekeeper:mockcarrier-test", "account-blue"); got != "gatekeeper:mockcarrier-test/account-blue" {
		t.Fatal(got)
	}
}
