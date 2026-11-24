package domain

import (
	"math/bits"
	"time"
	"unicode"
)

const (
	// QuotaKeyCap 是协调器内存里配额键的上限。超过之后先丢掉闲置的，再丢掉最久没用的。
	// 丢掉的键下一次拿到满的新桶。重启也是满桶：配额不落盘。
	QuotaKeyCap = 8192
	// MaxQuotaRequests 把整数运算留在 int64 里。窗口仍是 1 到 86400 秒。
	MaxQuotaRequests = 1_000_000_000
	maxWindowSeconds = 86400
)

// Charge 是一次配额请求里的一条。Key 必须是 64 位小写十六进制，不能带内部键的原像。
type Charge struct {
	Key           string
	MaxRequests   int
	WindowSeconds int
	Capacity      int
}

// ValidateCharge 拒绝不是指纹的键、越界的数字，以及容量大于上限的组合。
func ValidateCharge(c Charge) error {
	if !quotaKey(c.Key) || c.MaxRequests < 1 || c.MaxRequests > MaxQuotaRequests {
		return ErrInvalid
	}
	if c.WindowSeconds < 1 || c.WindowSeconds > maxWindowSeconds {
		return ErrInvalid
	}
	if c.Capacity < 1 || c.Capacity > c.MaxRequests {
		return ErrInvalid
	}
	return nil
}

func quotaKey(key string) bool {
	if len(key) != 64 {
		return false
	}
	for i := 0; i < len(key); i++ {
		c := key[i]
		if c >= '0' && c <= '9' || c >= 'a' && c <= 'f' {
			continue
		}
		if unicode.IsControl(rune(c)) || c < 0x21 || c > 0x7e {
			return false
		}
		return false
	}
	return true
}

// Advance 按服务器已经过去的时间补充整令牌。residue 的单位是「纳秒 × maxRequests」，
// 范围是 [0, window)。tokens 不会超过 capacity。elapsed 不向前时原样返回。
func Advance(tokens int, residue int64, elapsed time.Duration, maxRequests, windowSeconds, capacity int) (int, int64) {
	if maxRequests < 1 || windowSeconds < 1 || capacity < 1 {
		return tokens, residue
	}
	if tokens >= capacity {
		return capacity, 0
	}
	if tokens < 0 {
		tokens = 0
	}
	windowNS := int64(windowSeconds) * int64(time.Second)
	if residue < 0 || residue >= windowNS {
		residue = 0
	}
	if elapsed <= 0 {
		return tokens, residue
	}
	hi, lo := bits.Mul64(uint64(elapsed), uint64(maxRequests))
	sumLo, carry := bits.Add64(lo, uint64(residue), 0)
	sumHi := hi + uint64(carry)
	if sumHi >= uint64(windowNS) {
		return capacity, 0
	}
	added, rest := bits.Div64(sumHi, sumLo, uint64(windowNS))
	room := capacity - tokens
	if added > uint64(room) {
		return capacity, 0
	}
	return tokens + int(added), int64(rest)
}

// RetryAfterSeconds 是凑够 1 个令牌还要多少秒，向上取整，至少 1，至多 86400。
// 用窗口和上限做整数除法，和 egressauthz/domain.retryAfter 同一条算法。
func RetryAfterSeconds(tokens, maxRequests, windowSeconds int, residue int64) int {
	if maxRequests < 1 || windowSeconds < 1 || tokens >= 1 {
		return 1
	}
	windowNS := int64(windowSeconds) * int64(time.Second)
	if residue < 0 || residue >= windowNS {
		residue = 0
	}
	remaining := windowNS - residue
	den := int64(maxRequests) * int64(time.Second)
	if den <= 0 {
		return 1
	}
	seconds := (remaining + den - 1) / den
	if seconds < 1 {
		return 1
	}
	if seconds > maxWindowSeconds {
		return maxWindowSeconds
	}
	return int(seconds)
}
