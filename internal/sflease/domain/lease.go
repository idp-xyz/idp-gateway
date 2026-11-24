package domain

import (
	"errors"
	"time"
)

// 校验失败时的固定说法。错误里没有调用方交来的原文：那可能是密钥，或者带路径字符。
var (
	errLeaseKey = errors.New("lease_key must be 64 lowercase hexadecimal characters")
	errHolderID = errors.New("holder_id must be 1 to 128 visible ASCII characters")
	errToken    = errors.New("token must be non-empty visible ASCII without a semicolon, at most 4096 bytes")
)

// ValidateLeaseKey 要求 key 恰好是 64 位小写十六进制（SHA-256 指纹）。
// 协调器只认这个指纹：app_secret、encoding_aes_key 和路径字符到不了这里。
func ValidateLeaseKey(key string) error {
	if len(key) != 64 {
		return errLeaseKey
	}
	for i := 0; i < len(key); i++ {
		c := key[i]
		switch {
		case c >= '0' && c <= '9':
		case c >= 'a' && c <= 'f':
		default:
			return errLeaseKey
		}
	}
	return nil
}

// ValidateHolderID 要求 id 是 1 到 128 个可见 ASCII 字符，没有空白和控制字符。
func ValidateHolderID(id string) error {
	if !visibleASCII(id, 128) {
		return errHolderID
	}
	return nil
}

// ValidateToken 要求 token 非空、可见 ASCII、不含空白和分号，最长 4096 字节。
// 与顺丰访问令牌放进 "appKey;令牌;AES密钥" 时的限制一致。
func ValidateToken(token string) error {
	if !visibleASCII(token, 4096) || containsByte(token, ';') {
		return errToken
	}
	return nil
}

// LeaseRecord 是一把租约键下当前对外有效的访问令牌。Token 只经 Reveal 取出。
type LeaseRecord struct {
	LeaseKey  string
	Token     Secret
	ExpiresAt time.Time
	Lifetime  time.Duration
}

// Usable 报告 now 这一刻、按 refreshLead 提前量，这枚令牌还能不能直接交出去。
// 剩下的寿命必须严格多于提前量：刚好等于提前量时就要换新。
func (r LeaseRecord) Usable(now time.Time, refreshLead time.Duration) bool {
	return r.ExpiresAt.Sub(now) > refreshLead
}

// visibleASCII 报告 s 的长度在 1..max 之间，且每个字节都是可见 ASCII（0x21..0x7e）。
// 空白和控制字符不在这个范围里。
func visibleASCII(s string, max int) bool {
	if s == "" || len(s) > max {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x21 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

func containsByte(s string, b byte) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return true
		}
	}
	return false
}
