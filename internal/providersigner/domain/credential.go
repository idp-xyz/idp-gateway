package domain

import (
	"errors"
	"strings"
)

// CredentialScheme 是 Authorization 头里承运商凭证的前缀：区分大小写，后面恰好一个空格。
const CredentialScheme = "Sf-OpenApi "

// ErrCredentialMalformed 的文字是固定的，不带头里的任何一段。
var ErrCredentialMalformed = errors.New("credential is malformed")

// Credential 是从一次请求的 Authorization 头里取出的三样：appKey、访问令牌、AES 密钥。
// 适配器不存任何秘密，每个请求都从头里重新取。它是秘密：输出里只有占位符。
type Credential struct {
	redacted
	appKey string
	token  string
	key    Key
}

// AppKey 是承运商分给这个客户的标识。
func (c Credential) AppKey() string { return c.appKey }

// Token 是访问令牌。
func (c Credential) Token() string { return c.token }

// Key 是解析好的 AES 密钥。
func (c Credential) Key() Key { return c.key }

// ParseCredential 解析 Authorization 头的值：`Sf-OpenApi <appKey>;<accessToken>;<encodingAesKey>`。
// 三段都不能为空，只含可见 ASCII（0x21 到 0x7e），第三段还必须是合法的 AES 密钥。
// 失败时不说明是哪一段不对，错误里没有头里的任何内容。
func ParseCredential(value string) (Credential, error) {
	rest, ok := strings.CutPrefix(value, CredentialScheme)
	if !ok {
		return Credential{}, ErrCredentialMalformed
	}
	parts := strings.Split(rest, ";")
	if len(parts) != 3 {
		return Credential{}, ErrCredentialMalformed
	}
	for _, part := range parts {
		if part == "" || !VisibleASCII(part) {
			return Credential{}, ErrCredentialMalformed
		}
	}
	key, err := ParseKey(parts[2])
	if err != nil {
		return Credential{}, ErrCredentialMalformed
	}
	return Credential{appKey: parts[0], token: parts[1], key: key}, nil
}

// VisibleASCII 报告 s 里是否只有 0x21 到 0x7e 的字符（空串也算）。
func VisibleASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x21 || s[i] > 0x7e {
			return false
		}
	}
	return true
}
