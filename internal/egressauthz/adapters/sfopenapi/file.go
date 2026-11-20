package sfopenapi

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
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

const (
	// aesKeyChars 是 encoding_aes_key 的字符数：32 字节的密钥做标准 base64 是 44 个字符，去掉末尾的一个 "="。
	aesKeyChars = 43
	// aesKeyBytes 是 encoding_aes_key 解开之后的字节数（AES-256）。
	aesKeyBytes = 32
)

// entry 是文件里一个凭证句柄的一条记录，校验过。
type entry struct {
	handle        string
	tokenEndpoint string
	appKey        string
	appSecret     ports.Secret
	aesKey        ports.Secret
	keyVersion    string
	// secretDigest 是应用密钥的 SHA-256，只在内存里，作缓存键的一项；它不写进日志和错误。
	secretDigest [sha256.Size]byte
}

// cacheKey 是访问令牌缓存的键：句柄、令牌端点、appKey、密钥版本和应用密钥的摘要。
// 它是可比较的值：键里任何一项变了，旧的那一条就不再用。
//
// AES 密钥不在键里：它不参与取令牌，只改交出的认证头；单独换它不需要新令牌，下一次交出的值就带新的密钥。
type cacheKey struct {
	handle        string
	tokenEndpoint string
	appKey        string
	keyVersion    string
	// secretDigest：运维换了应用密钥却忘了改 key_version 时，用旧密钥取来的令牌不会一直用到过期。
	secretDigest [sha256.Size]byte
}

func (e *entry) key() cacheKey {
	return cacheKey{e.handle, e.tokenEndpoint, e.appKey, e.keyVersion, e.secretDigest}
}

var errShape = errors.New(`not a JSON object of handle to {"token_endpoint", "app_key", "app_secret", "encoding_aes_key", "key_version"}`)

// read 读一遍文件。返回的 FileInfo 属于实际读到的那个文件，不是读之前按名字看到的那个。
// 返回的错误里没有文件的内容。
func (c *Client) read() (map[string]*entry, os.FileInfo, error) {
	file, err := os.Open(c.path)
	if err != nil {
		return nil, nil, fmt.Errorf("sf openapi apps: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, nil, fmt.Errorf("sf openapi apps: %w", err)
	}
	if mode := info.Mode().Perm(); mode&0o077 != 0 {
		return nil, nil, fmt.Errorf("sf openapi apps %s: mode %04o is readable by others; want 0600 or stricter", c.path, mode)
	}
	raw, err := io.ReadAll(file)
	if err != nil {
		return nil, nil, fmt.Errorf("sf openapi apps: %w", err)
	}
	entries, err := parse(raw, c.reserved, c.plainHTTPHost)
	if err != nil {
		return nil, nil, fmt.Errorf("sf openapi apps %s: %w", c.path, err)
	}
	return entries, info, nil
}

func parse(raw []byte, reserved func(handle string) bool, plainHTTPHost string) (map[string]*entry, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	// 逐项读，是为了看得见同一个句柄写了两次：解码成 map 时后一个会悄悄盖住前一个。
	// 解码错误可能带出文件内容的片段（密钥就在里面），所以只报告固定的一句话。
	if opening, err := decoder.Token(); err != nil || opening != json.Delim('{') {
		return nil, errShape
	}
	entries := map[string]*entry{}
	// byAppKey 记着每个 appKey 在哪个句柄下：承运商取了新令牌就让旧令牌失效，同一个 appKey 在两个句柄下，
	// 两个缓存条目会互相作废对方的令牌。
	byAppKey := map[string]string{}
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
			TokenEndpoint  *string `json:"token_endpoint"`
			AppKey         *string `json:"app_key"`
			AppSecret      *string `json:"app_secret"`
			EncodingAesKey *string `json:"encoding_aes_key"`
			KeyVersion     *string `json:"key_version"`
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
		if fields.TokenEndpoint == nil || fields.AppKey == nil || fields.AppSecret == nil || fields.EncodingAesKey == nil || fields.KeyVersion == nil {
			return nil, fmt.Errorf("entry %q: token_endpoint, app_key, app_secret, encoding_aes_key and key_version are all required", handle)
		}
		if err := checkEndpoint(*fields.TokenEndpoint, plainHTTPHost); err != nil {
			return nil, fmt.Errorf("entry %q: token_endpoint: %w", handle, err)
		}
		for _, field := range []struct{ name, value string }{
			{"app_key", *fields.AppKey}, {"app_secret", *fields.AppSecret}, {"key_version", *fields.KeyVersion},
		} {
			if !visibleASCII(field.value) {
				return nil, fmt.Errorf("entry %q: %s is empty or contains characters other than visible ASCII", handle, field.name)
			}
		}
		if strings.Contains(*fields.AppKey, ";") {
			return nil, fmt.Errorf("entry %q: app_key must not contain a semicolon: it goes into a header value that is split at semicolons", handle)
		}
		if !validAESKey(*fields.EncodingAesKey) {
			return nil, fmt.Errorf("entry %q: encoding_aes_key must be %d characters of standard base64 that give %d bytes once one \"=\" is appended",
				handle, aesKeyChars, aesKeyBytes)
		}
		if reserved != nil && reserved(handle) {
			return nil, fmt.Errorf("entry %q is also held by another credential source; a handle may be in one source only", handle)
		}
		if other, taken := byAppKey[*fields.AppKey]; taken {
			return nil, fmt.Errorf("entries %q and %q use the same app_key; the carrier voids the previous token whenever a new one is fetched, so one app_key may be under one handle only",
				other, handle)
		}
		byAppKey[*fields.AppKey] = handle
		entries[handle] = &entry{handle: handle, tokenEndpoint: *fields.TokenEndpoint, appKey: *fields.AppKey,
			appSecret: ports.NewSecret(*fields.AppSecret), aesKey: ports.NewSecret(*fields.EncodingAesKey),
			keyVersion: *fields.KeyVersion, secretDigest: sha256.Sum256([]byte(*fields.AppSecret))}
	}
	if closing, err := decoder.Token(); err != nil || closing != json.Delim('}') {
		return nil, errShape
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, errors.New("unexpected data after the object")
	}
	return entries, nil
}

// validAESKey 报告 s 是不是 encoding_aes_key：43 个字符，末尾补一个 "=" 之后按标准 base64 解得出 32 字节。
// 标准字母表里没有分号和空白，所以它放进 "appKey;令牌;AES密钥" 里不会被切开。
func validAESKey(s string) bool {
	if len(s) != aesKeyChars {
		return false
	}
	decoded, err := base64.StdEncoding.DecodeString(s + "=")
	return err == nil && len(decoded) == aesKeyBytes
}

// checkEndpoint 查令牌端点的地址：https；http 只在两种情况下允许：主机是回环地址的字面量（127.0.0.0/8 或 ::1），
// 或者主机名与 plainHTTPHost 相等（只比整个主机名，不分大小写，没有后缀匹配也没有通配；
// plainHTTPHost 为空就没有这一种）。不带用户信息、查询串和片段。错误信息里没有地址本身：它可能带着用户信息。
func checkEndpoint(raw, plainHTTPHost string) error {
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
		if loopbackLiteral(u.Hostname()) || (plainHTTPHost != "" && equalASCIIFold(u.Hostname(), plainHTTPHost)) {
			return nil
		}
		return errors.New("must be https (plain http is accepted only when the host is a loopback address literal or the one configured plain-http host)")
	default:
		return errors.New("must be https")
	}
}

// equalASCIIFold 报告两个字符串是否相等，只把 ASCII 字母的大小写看作相同。
// strings.EqualFold 会按 Unicode 折叠（例如开尔文符号等于 k），主机名的比较不要这个。
func equalASCIIFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		if lowerASCII(a[i]) != lowerASCII(b[i]) {
			return false
		}
	}
	return true
}

func lowerASCII(c byte) byte {
	if 'A' <= c && c <= 'Z' {
		return c + 'a' - 'A'
	}
	return c
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
