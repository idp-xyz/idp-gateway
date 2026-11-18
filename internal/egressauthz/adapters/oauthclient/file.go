package oauthclient

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"net/url"
	"os"
	"strings"

	"go.idp.xyz/idp-gateway/internal/egressauthz/ports"
)

// entry 是文件里一个凭证句柄的一条记录，校验过。
type entry struct {
	handle        string
	tokenEndpoint string
	clientID      string
	clientSecret  ports.Secret
	keyVersion    string
	scope         string
	audience      string
	// secretDigest 是客户端密钥的 SHA-256，只在内存里，作缓存键的一项；它不写进日志和错误。
	secretDigest [sha256.Size]byte
}

// cacheKey 是令牌缓存的键。ADR-0011 第 4 条（G04 第 4 节）要求缓存键至少包含 Provider、账户、环境、
// 客户端、scope 或 audience、密钥版本；凭证句柄里已经有凭证绑定和账户，Provider 与环境在绑定里。
// 它是可比较的值：键里任何一项变了，旧的那一条就不再用。
type cacheKey struct {
	handle        string
	tokenEndpoint string
	clientID      string
	scope         string
	audience      string
	keyVersion    string
	// secretDigest：运维换了密钥却忘了改 key_version 时，用旧密钥取来的令牌不会一直用到过期。
	secretDigest [sha256.Size]byte
}

func (e *entry) key() cacheKey {
	return cacheKey{e.handle, e.tokenEndpoint, e.clientID, e.scope, e.audience, e.keyVersion, e.secretDigest}
}

var errShape = errors.New(`not a JSON object of handle to {"token_endpoint", "client_id", "client_secret", "key_version"}`)

// read 读一遍文件。返回的 FileInfo 属于实际读到的那个文件，不是读之前按名字看到的那个。
// 返回的错误里没有文件的内容。
func (c *Client) read() (map[string]*entry, os.FileInfo, error) {
	file, err := os.Open(c.path)
	if err != nil {
		return nil, nil, fmt.Errorf("oauth clients: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, nil, fmt.Errorf("oauth clients: %w", err)
	}
	if mode := info.Mode().Perm(); mode&0o077 != 0 {
		return nil, nil, fmt.Errorf("oauth clients %s: mode %04o is readable by others; want 0600 or stricter", c.path, mode)
	}
	raw, err := io.ReadAll(file)
	if err != nil {
		return nil, nil, fmt.Errorf("oauth clients: %w", err)
	}
	entries, err := parse(raw, c.reserved)
	if err != nil {
		return nil, nil, fmt.Errorf("oauth clients %s: %w", c.path, err)
	}
	return entries, info, nil
}

func parse(raw []byte, reserved func(handle string) bool) (map[string]*entry, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	// 逐项读，是为了看得见同一个句柄写了两次：解码成 map 时后一个会悄悄盖住前一个。
	// 解码错误可能带出文件内容的片段（密钥就在里面），所以只报告固定的一句话。
	if opening, err := decoder.Token(); err != nil || opening != json.Delim('{') {
		return nil, errShape
	}
	entries := map[string]*entry{}
	for decoder.More() {
		key, err := decoder.Token()
		if err != nil {
			return nil, errShape
		}
		handle, ok := key.(string)
		if !ok {
			return nil, errShape
		}
		var fields struct {
			TokenEndpoint *string `json:"token_endpoint"`
			ClientID      *string `json:"client_id"`
			ClientSecret  *string `json:"client_secret"`
			KeyVersion    *string `json:"key_version"`
			Scope         *string `json:"scope"`
			Audience      *string `json:"audience"`
		}
		if err := decoder.Decode(&fields); err != nil {
			return nil, errShape
		}
		if handle == "" {
			return nil, errors.New("an entry has an empty handle")
		}
		if _, twice := entries[handle]; twice {
			return nil, fmt.Errorf("entry %q appears twice", handle)
		}
		if fields.TokenEndpoint == nil || fields.ClientID == nil || fields.ClientSecret == nil || fields.KeyVersion == nil {
			return nil, fmt.Errorf("entry %q: token_endpoint, client_id, client_secret and key_version are all required", handle)
		}
		if err := checkEndpoint(*fields.TokenEndpoint); err != nil {
			return nil, fmt.Errorf("entry %q: token_endpoint: %w", handle, err)
		}
		for name, value := range map[string]*string{"client_id": fields.ClientID, "client_secret": fields.ClientSecret, "key_version": fields.KeyVersion} {
			if !visibleASCII(*value) {
				return nil, fmt.Errorf("entry %q: %s is empty or contains characters other than visible ASCII", handle, name)
			}
		}
		e := &entry{handle: handle, tokenEndpoint: *fields.TokenEndpoint, clientID: *fields.ClientID,
			clientSecret: ports.NewSecret(*fields.ClientSecret), keyVersion: *fields.KeyVersion,
			secretDigest: sha256.Sum256([]byte(*fields.ClientSecret))}
		if fields.Scope != nil {
			if *fields.Scope != "" && !validScope(*fields.Scope) {
				return nil, fmt.Errorf("entry %q: scope must be one or more tokens of visible ASCII without double quote or backslash, separated by single spaces", handle)
			}
			e.scope = *fields.Scope
		}
		if fields.Audience != nil {
			if *fields.Audience != "" && !visibleASCII(*fields.Audience) {
				return nil, fmt.Errorf("entry %q: audience contains characters other than visible ASCII", handle)
			}
			e.audience = *fields.Audience
		}
		if reserved != nil && reserved(handle) {
			return nil, fmt.Errorf("entry %q is also held by another credential source; a handle may be in one source only", handle)
		}
		entries[handle] = e
	}
	if closing, err := decoder.Token(); err != nil || closing != json.Delim('}') {
		return nil, errShape
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, errors.New("unexpected data after the object")
	}
	return entries, nil
}

// checkEndpoint 查令牌端点的地址：https；只有主机是回环地址的字面量（127.0.0.0/8 或 ::1）时才允许 http；
// 不带用户信息、查询串和片段。错误信息里没有地址本身：它可能带着用户信息。
func checkEndpoint(raw string) error {
	if !visibleASCII(raw) {
		return errors.New("is empty or contains characters other than visible ASCII")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.Hostname() == "" {
		return errors.New("is not an absolute URL with a host")
	}
	if u.User != nil {
		return errors.New("must not carry user information")
	}
	if u.RawQuery != "" || u.ForceQuery || strings.Contains(raw, "?") {
		return errors.New("must not carry a query string")
	}
	if u.Fragment != "" || strings.Contains(raw, "#") {
		return errors.New("must not carry a fragment")
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		if loopbackLiteral(u.Hostname()) {
			return nil
		}
		return errors.New("must be https (plain http is accepted only when the host is a loopback address literal)")
	default:
		return errors.New("must be https")
	}
}

// loopbackLiteral 报告 host 是不是回环地址的字面量。"localhost" 不算：它要靠解析，解析结果不是文件的作者定的。
func loopbackLiteral(host string) bool {
	ip, err := netip.ParseAddr(host)
	if err != nil || ip.Zone() != "" || ip.Is4In6() {
		return false
	}
	return ip.IsLoopback()
}

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

// validScope 报告 s 是不是 RFC 6749 第 3.3 节的 scope：一个或多个记号，用单个空格隔开；记号由
// 可见 ASCII 组成，不含双引号和反斜杠（NQCHAR）。开头、结尾有空格或连着两个空格都不行。
func validScope(s string) bool {
	if s == "" {
		return false
	}
	for _, token := range strings.Split(s, " ") {
		if token == "" {
			return false
		}
		for i := 0; i < len(token); i++ {
			if c := token[i]; c < 0x21 || c > 0x7e || c == '"' || c == '\\' {
				return false
			}
		}
	}
	return true
}
