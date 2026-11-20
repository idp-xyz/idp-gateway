package domain

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
)

func TestParseCredential(t *testing.T) {
	v := loadVectors(t)
	good := CredentialScheme + v.AppKey + ";" + v.Token + ";" + v.EncodingAESKey
	badKey := v.EncodingAESKey

	credential, err := ParseCredential(good)
	if err != nil {
		t.Fatal(err)
	}
	if credential.AppKey() != v.AppKey || credential.Token() != v.Token {
		t.Errorf("取出的 appKey 或令牌不对")
	}
	// 取出的密钥是能用的那一把。
	ciphertext, err := Encrypt(credential.Key(), credential.AppKey(), []byte("{}"), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if plain, err := Decrypt(vectorKey(t, v), v.AppKey, ciphertext); err != nil || string(plain) != "{}" {
		t.Errorf("取出的密钥和向量里的不是同一把：%q %v", plain, err)
	}

	for _, c := range []struct {
		name  string
		value string
	}{
		{"empty", ""},
		{"scheme only", "Sf-OpenApi"},
		{"scheme and a space only", "Sf-OpenApi "},
		{"missing scheme", v.AppKey + ";" + v.Token + ";" + badKey},
		{"another scheme", "Bearer " + v.AppKey + ";" + v.Token + ";" + badKey},
		{"scheme in lower case", "sf-openapi " + v.AppKey + ";" + v.Token + ";" + badKey},
		{"scheme in another case", "Sf-Openapi " + v.AppKey + ";" + v.Token + ";" + badKey},
		{"scheme in upper case", "SF-OPENAPI " + v.AppKey + ";" + v.Token + ";" + badKey},
		{"no space after the scheme", "Sf-OpenApi" + v.AppKey + ";" + v.Token + ";" + badKey},
		{"two spaces after the scheme", "Sf-OpenApi  " + v.AppKey + ";" + v.Token + ";" + badKey},
		{"a tab instead of the space", "Sf-OpenApi\t" + v.AppKey + ";" + v.Token + ";" + badKey},
		{"leading space", " " + good},
		{"two parts", "Sf-OpenApi " + v.AppKey + ";" + v.Token},
		{"one part", "Sf-OpenApi " + v.AppKey},
		{"four parts", good + ";extra"},
		{"trailing semicolon", good + ";"},
		{"empty appKey", "Sf-OpenApi ;" + v.Token + ";" + badKey},
		{"empty token", "Sf-OpenApi " + v.AppKey + ";;" + badKey},
		{"empty key", "Sf-OpenApi " + v.AppKey + ";" + v.Token + ";"},
		{"all parts empty", "Sf-OpenApi ;;"},
		{"a space inside the appKey", "Sf-OpenApi app key;" + v.Token + ";" + badKey},
		{"a space inside the token", "Sf-OpenApi " + v.AppKey + ";to ken;" + badKey},
		{"a space inside the key", "Sf-OpenApi " + v.AppKey + ";" + v.Token + ";" + badKey[:20] + " " + badKey[21:]},
		{"a space after a semicolon", "Sf-OpenApi " + v.AppKey + "; " + v.Token + ";" + badKey},
		{"a control character in the appKey", "Sf-OpenApi app\x01key;" + v.Token + ";" + badKey},
		{"a newline in the token", "Sf-OpenApi " + v.AppKey + ";to\nken;" + badKey},
		{"a carriage return at the end", good + "\r"},
		{"a DEL character", "Sf-OpenApi " + v.AppKey + ";tok\x7fen;" + badKey},
		{"a non-ASCII character in the appKey", "Sf-OpenApi appé;" + v.Token + ";" + badKey},
		{"a non-ASCII character in the token", "Sf-OpenApi " + v.AppKey + ";tokén;" + badKey},
		{"a non-ASCII character in the key", "Sf-OpenApi " + v.AppKey + ";" + v.Token + ";" + badKey[:20] + "é" + badKey[22:]},
		{"key of 42 characters", "Sf-OpenApi " + v.AppKey + ";" + v.Token + ";" + badKey[:42]},
		{"key of 44 characters", "Sf-OpenApi " + v.AppKey + ";" + v.Token + ";" + badKey + "A"},
		{"key with a character outside the alphabet", "Sf-OpenApi " + v.AppKey + ";" + v.Token + ";" + badKey[:20] + "!" + badKey[21:]},
		{"key with a url-safe character", "Sf-OpenApi " + v.AppKey + ";" + v.Token + ";" + badKey[:20] + "-" + badKey[21:]},
	} {
		t.Run(c.name, func(t *testing.T) {
			credential, err := ParseCredential(c.value)
			if !errors.Is(err, ErrCredentialMalformed) {
				t.Fatalf("错误是 %v", err)
			}
			if credential.AppKey() != "" || credential.Token() != "" || credential.key.valid {
				t.Error("被拒绝了，却返回了部分内容")
			}
			if err.Error() != ErrCredentialMalformed.Error() || strings.Contains(err.Error(), v.AppKey) || strings.Contains(err.Error(), v.Token) {
				t.Errorf("错误文字不固定或带着头里的内容：%q", err)
			}
		})
	}

	// 分号以外的标点是合规矩的：可见 ASCII 都行。
	punctuated := CredentialScheme + "app~key!#$%&'()*+,-./:<=>?@[\\]^_`{|}~;tok:en/with=punct;" + v.EncodingAESKey
	if c, err := ParseCredential(punctuated); err != nil || c.AppKey() != "app~key!#$%&'()*+,-./:<=>?@[\\]^_`{|}~" || c.Token() != "tok:en/with=punct" {
		t.Errorf("标点：%q %v", c.AppKey(), err)
	}
}

func TestVisibleASCII(t *testing.T) {
	for s, want := range map[string]bool{
		"": true, "a": true, "~": true, "!": true, " ": false, "\x7f": false, "\x1f": false, "é": false, "a b": false, "\t": false, "\xff": false,
	} {
		if got := VisibleASCII(s); got != want {
			t.Errorf("%q: %v", s, got)
		}
	}
}

// 装着秘密的类型，在每一种常见的输出途径里都只有占位符。
func TestSecretsAreNeverPrinted(t *testing.T) {
	v := loadVectors(t)
	credential, err := ParseCredential(CredentialScheme + v.AppKey + ";" + v.Token + ";" + v.EncodingAESKey)
	if err != nil {
		t.Fatal(err)
	}
	key := vectorKey(t, v)
	forbidden := []string{v.AppKey, v.Token, v.EncodingAESKey, "idpgw", "auth_idpgw"}

	holder := struct {
		Credential Credential
		Key        Key
		Pointer    *Credential
	}{credential, key, &credential}

	var text, structured strings.Builder
	jsonLogger := slog.New(slog.NewJSONHandler(&structured, nil))
	textLogger := slog.New(slog.NewTextHandler(&text, nil))
	for _, logger := range []*slog.Logger{jsonLogger, textLogger} {
		logger.Info("holder", "credential", credential, "key", key, "pointer", &credential, "holder", holder)
	}
	outputs := []string{text.String(), structured.String()}
	// %p 不在其内：fmt 对 %p 不走 Formatter，go vet 也会拒绝把非指针值交给 %p。
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d", "%t", "%10.3v"} {
		outputs = append(outputs, fmt.Sprintf(verb, credential), fmt.Sprintf(verb, key), fmt.Sprintf(verb, &credential), fmt.Sprintf(verb, holder))
	}
	for _, value := range []any{credential, key, &credential, holder} {
		encoded, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		outputs = append(outputs, string(encoded))
		pretty, err := json.MarshalIndent(value, "", " ")
		if err != nil {
			t.Fatal(err)
		}
		outputs = append(outputs, string(pretty))
	}
	text2, _ := credential.MarshalText()
	outputs = append(outputs, string(text2), credential.String(), credential.GoString(), key.String(), key.GoString())

	for _, output := range outputs {
		for _, secret := range forbidden {
			if strings.Contains(output, secret) {
				t.Fatalf("输出 %q 里有 %q", output, secret)
			}
		}
	}
	if !strings.Contains(structured.String(), placeholder) {
		t.Errorf("日志里没有占位符：%s", structured.String())
	}
}
