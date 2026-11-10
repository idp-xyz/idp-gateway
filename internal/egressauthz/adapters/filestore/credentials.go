package filestore

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"go.idp.xyz/idp-gateway/internal/egressauthz/ports"
)

// Credentials 是从文件读入的 Bearer 令牌，按凭证句柄（凭证绑定/账户）索引。
type Credentials struct {
	tokens map[string]ports.Secret
}

// LoadCredentials 读凭证文件：一个 JSON 对象，键是凭证句柄，值是该账户的 Bearer 令牌。
//
// 文件对属主以外可读时拒绝加载。令牌里出现空白或控制字符时也拒绝：它会被原样写进
// HTTP 头。
func LoadCredentials(path string) (*Credentials, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("credentials: %w", err)
	}
	if mode := info.Mode().Perm(); mode&0o077 != 0 {
		return nil, fmt.Errorf("credentials %s: mode %04o is readable by others; want 0600 or stricter", path, mode)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("credentials: %w", err)
	}
	var tokens map[string]string
	if err := json.Unmarshal(raw, &tokens); err != nil {
		// 解码错误可能带出文件内容的片段，这里只报告位置之外的事实。
		return nil, fmt.Errorf("credentials %s: not a JSON object of handle to token", path)
	}
	store := &Credentials{tokens: make(map[string]ports.Secret, len(tokens))}
	for handle, token := range tokens {
		if handle == "" || !visibleASCII(token) {
			return nil, fmt.Errorf("credentials %s: entry %q is empty or its token contains characters that cannot go into a header", path, handle)
		}
		store.tokens[handle] = ports.NewSecret("Bearer " + token)
	}
	return store, nil
}

// AuthorizationHeader 实现 ports.CredentialSource。
func (c *Credentials) AuthorizationHeader(_ context.Context, bindingRef, accountID string) (ports.Secret, error) {
	credential, ok := c.tokens[ports.Handle(bindingRef, accountID)]
	if !ok {
		return ports.Secret{}, fmt.Errorf("%w: %s", ports.ErrCredentialNotHeld, ports.Handle(bindingRef, accountID))
	}
	return credential, nil
}

// Len 返回持有的凭证数量，供启动日志使用。
func (c *Credentials) Len() int { return len(c.tokens) }

func visibleASCII(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] <= 0x20 || s[i] >= 0x7f {
			return false
		}
	}
	return true
}
