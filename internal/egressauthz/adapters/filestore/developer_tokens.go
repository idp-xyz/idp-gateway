package filestore

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"

	"go.idp.xyz/idp-gateway/internal/egressauthz/ports"
)

// developerScheme 是这一种认证头开头固定的那个词，后面跟一个空格。
const developerScheme = "Hc-OweDeveloper"

// nonceBytes 个随机字节写成十六进制，就是认证头里的随机数：32 个字符，只有数字和小写字母。
const nonceBytes = 16

// DeveloperTokens 是从文件读入的开发者令牌，按凭证句柄（凭证绑定/账户）索引。
//
// 这一种凭证的认证头是 `Hc-OweDeveloper 账号;令牌;随机数`。账号和令牌是固定的，随机数每次要
// 凭证时现做一个（docs/adr/ADR-0011.md 第 3 条）。
//
// 文件被换掉之后，下一次要凭证时整份重读。新文件读不成或校验不过，继续用上一份读成的，
// 并记一条错误；同一份坏文件只读一次、只记一次。换文件要写临时文件再改名：就地改写而修改
// 时间和大小都没有变时，看不出它变了。
type DeveloperTokens struct {
	path     string
	reserved func(handle string) bool
	logger   *slog.Logger

	mu sync.Mutex
	// seen 是上一次看到的文件，读成没读成都记；nil 表示上一次看时它不在。
	seen os.FileInfo
	// prefixes 是句柄到 `Hc-OweDeveloper 账号;令牌;` 的表。它只会被整份换掉，不会被就地改。
	prefixes map[string]ports.Secret
}

// LoadDeveloperTokens 读开发者令牌文件：一个 JSON 对象，键是凭证句柄，值是
// {"account": 账号, "token": 令牌}。
//
// 文件对属主以外可读时拒绝。账号和令牌里出现空白、分号、控制字符或非 ASCII 字符时拒绝：
// 它们会被原样写进 HTTP 头，分号是这个头里的分隔符。同一个句柄写了两次、有不认识的字段、
// 文件后面还有内容，都拒绝。reserved 不为 nil 时，它说已经被别的凭证来源占着的句柄也拒绝：
// 一个句柄只能在一个来源里。
//
// 启动时读不成返回错误。之后重读时读不成，见 DeveloperTokens 的说明。
func LoadDeveloperTokens(path string, reserved func(handle string) bool, logger *slog.Logger) (*DeveloperTokens, error) {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	d := &DeveloperTokens{path: path, reserved: reserved, logger: logger}
	prefixes, info, err := d.read()
	if err != nil {
		return nil, err
	}
	d.prefixes, d.seen = prefixes, info
	return d, nil
}

// AuthorizationHeader 实现 ports.CredentialSource。每次调用给出的随机数都不同。
func (d *DeveloperTokens) AuthorizationHeader(_ context.Context, bindingRef, accountID string) (ports.Secret, error) {
	handle := ports.Handle(bindingRef, accountID)
	prefix, ok := d.current()[handle]
	if !ok {
		return ports.Secret{}, fmt.Errorf("%w: %s", ports.ErrCredentialNotHeld, handle)
	}
	var nonce [nonceBytes]byte
	// crypto/rand.Read 在受支持的平台上不返回错误；万一失败，Go 运行时会直接终止进程。
	_, _ = rand.Read(nonce[:])
	return ports.NewSecret(prefix.Reveal() + hex.EncodeToString(nonce[:])), nil
}

// Len 返回此刻持有的凭证数量，供启动日志使用。
func (d *DeveloperTokens) Len() int { return len(d.current()) }

// current 返回此刻该用的那张表：文件变了就先重读。
func (d *DeveloperTokens) current() map[string]ports.Secret {
	d.mu.Lock()
	defer d.mu.Unlock()

	info, err := os.Stat(d.path)
	if err != nil {
		if d.seen != nil {
			d.seen = nil
			d.logger.Error("developer tokens file cannot be seen; still using the last one that loaded",
				"path", d.path, "error", err.Error(), "entries", len(d.prefixes))
		}
		return d.prefixes
	}
	if d.seen != nil && sameFile(d.seen, info) {
		return d.prefixes
	}
	prefixes, read, err := d.read()
	if err != nil {
		// 记下看到的是哪一份：它再被换掉之前不重读，也不再记。
		d.seen = info
		d.logger.Error("developer tokens file did not load; still using the last one that loaded",
			"path", d.path, "error", err.Error(), "entries", len(d.prefixes))
		return d.prefixes
	}
	d.prefixes, d.seen = prefixes, read
	d.logger.Info("developer tokens file loaded again", "path", d.path, "entries", len(prefixes))
	return d.prefixes
}

// sameFile 报告两次看到的是不是同一份没有动过的文件。改名换上来的文件即使修改时间相同，
// 也是另一个文件。
func sameFile(a, b os.FileInfo) bool {
	return os.SameFile(a, b) && a.ModTime().Equal(b.ModTime()) && a.Size() == b.Size()
}

// read 读一遍文件。返回的 FileInfo 属于实际读到的那个文件，不是读之前按名字看到的那个。
// 返回的错误里没有文件的内容。
func (d *DeveloperTokens) read() (map[string]ports.Secret, os.FileInfo, error) {
	file, err := os.Open(d.path)
	if err != nil {
		return nil, nil, fmt.Errorf("developer tokens: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, nil, fmt.Errorf("developer tokens: %w", err)
	}
	if mode := info.Mode().Perm(); mode&0o077 != 0 {
		return nil, nil, fmt.Errorf("developer tokens %s: mode %04o is readable by others; want 0600 or stricter", d.path, mode)
	}
	raw, err := io.ReadAll(file)
	if err != nil {
		return nil, nil, fmt.Errorf("developer tokens: %w", err)
	}
	prefixes, err := parseDeveloperTokens(raw, d.reserved)
	if err != nil {
		return nil, nil, fmt.Errorf("developer tokens %s: %w", d.path, err)
	}
	return prefixes, info, nil
}

var errDeveloperTokensShape = errors.New(`not a JSON object of handle to {"account", "token"}`)

func parseDeveloperTokens(raw []byte, reserved func(handle string) bool) (map[string]ports.Secret, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	// 逐项读，是为了看得见同一个句柄写了两次：解码成 map 时后一个会悄悄盖住前一个。
	// 解码错误可能带出文件内容的片段，所以只报告固定的一句话。
	if opening, err := decoder.Token(); err != nil || opening != json.Delim('{') {
		return nil, errDeveloperTokensShape
	}
	prefixes := map[string]ports.Secret{}
	for decoder.More() {
		key, err := decoder.Token()
		if err != nil {
			return nil, errDeveloperTokensShape
		}
		handle, ok := key.(string)
		if !ok {
			return nil, errDeveloperTokensShape
		}
		var entry struct {
			Account *string `json:"account"`
			Token   *string `json:"token"`
		}
		if err := decoder.Decode(&entry); err != nil {
			return nil, errDeveloperTokensShape
		}
		if handle == "" {
			return nil, errors.New("an entry has an empty handle")
		}
		if _, twice := prefixes[handle]; twice {
			return nil, fmt.Errorf("entry %q appears twice", handle)
		}
		if entry.Account == nil || entry.Token == nil || !headerPart(*entry.Account) || !headerPart(*entry.Token) {
			return nil, fmt.Errorf("entry %q: account and token are both required, and neither may be empty or contain "+
				"a semicolon or characters that cannot go into a header", handle)
		}
		if reserved != nil && reserved(handle) {
			return nil, fmt.Errorf("entry %q is also held by another credential source; a handle may be in one source only", handle)
		}
		prefixes[handle] = ports.NewSecret(developerScheme + " " + *entry.Account + ";" + *entry.Token + ";")
	}
	if closing, err := decoder.Token(); err != nil || closing != json.Delim('}') {
		return nil, errDeveloperTokensShape
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, errors.New("unexpected data after the object")
	}
	return prefixes, nil
}

// headerPart 报告 s 能不能作为认证头里用分号隔开的一段。
func headerPart(s string) bool {
	return visibleASCII(s) && !strings.Contains(s, ";")
}
