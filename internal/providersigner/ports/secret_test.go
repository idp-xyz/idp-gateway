package ports

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"testing"
)

// 凭证值不能经由格式化、日志或 JSON 泄露出去。
func TestSecretDoesNotLeak(t *testing.T) {
	const value = "idpgw-test-secret-value-0001"
	secret := NewSecret(value)
	request := CarrierRequest{MsgType: "IECS_CREATE_ORDER", Lang: "en", AppKey: secret, Token: NewSecret(value + "-token")}
	holder := struct {
		Credential Secret
		Pointer    *Secret
		Request    CarrierRequest
	}{secret, &secret, request}

	var text, structured strings.Builder
	slog.New(slog.NewTextHandler(&text, nil)).Info("secret", "value", secret, "pointer", &secret, "holder", holder, "request", request)
	slog.New(slog.NewJSONHandler(&structured, nil)).Info("secret", "value", secret, "pointer", &secret, "holder", holder, "request", request)
	outputs := []string{text.String(), structured.String(), secret.String(), secret.GoString()}
	// %p 不在其内：fmt 对 %p 不走 Formatter，go vet 也会拒绝把非指针值交给 %p。
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d", "%t", "%10.3v"} {
		outputs = append(outputs, fmt.Sprintf(verb, secret), fmt.Sprintf(verb, &secret), fmt.Sprintf(verb, holder), fmt.Sprintf(verb, request))
	}
	for _, v := range []any{secret, &secret, holder, request} {
		encoded, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		outputs = append(outputs, string(encoded))
	}
	marshaled, err := secret.MarshalText()
	if err != nil {
		t.Fatal(err)
	}
	outputs = append(outputs, string(marshaled))

	for _, output := range outputs {
		if strings.Contains(output, "idpgw-test-secret-value") {
			t.Fatalf("凭证出现在输出里：%q", output)
		}
	}
	if !strings.Contains(structured.String(), redacted) || !strings.Contains(text.String(), redacted) {
		t.Error("日志里没有占位符")
	}
	if secret.Reveal() != value {
		t.Fatal("Reveal 应返回原值")
	}
}
