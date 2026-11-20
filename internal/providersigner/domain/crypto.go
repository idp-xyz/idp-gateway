package domain

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"sort"
	"strings"
)

const (
	// EncodedKeyLength 是 encodingAesKey 的字符数：补一个 "=" 之后做标准 base64 解码，得 32 字节。
	EncodedKeyLength = 43

	keyLength    = 32
	paddingBlock = 32 // 承运商按 32 字节的块做 PKCS#7 填充，已经是整块时再补一整块
	randomLength = 16 // 明文开头的随机字符
	headerLength = randomLength + 4

	// 随机字符取自字母和数字。随机字节小于 acceptBelow（62 的 4 倍）才用，其余丢掉重取：
	// 对 62 取余不会偏向前面的字符。
	randomAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	acceptBelow    = 248
)

// 下面的错误文字是固定的：不带密文、明文或任何一段半解开的内容。
var (
	ErrKeyMalformed   = errors.New("encodingAesKey is not a valid AES key")
	ErrNotBase64      = errors.New("ciphertext is not valid base64")
	ErrBlockSize      = errors.New("ciphertext is not a non-empty whole number of cipher blocks")
	ErrPadding        = errors.New("ciphertext padding is invalid")
	ErrTooShort       = errors.New("plaintext is shorter than its header")
	ErrLength         = errors.New("declared body length does not fit the plaintext")
	ErrAppKeyMismatch = errors.New("appKey after the body does not match")
	errBodyTooLong    = errors.New("body is too long to encrypt")
)

// Key 是解析好的 AES-256 密钥。它是秘密：输出里只有占位符。零值不是合法的密钥。
type Key struct {
	redacted
	bytes [keyLength]byte
	valid bool
}

// ParseKey 解析 encodingAesKey：43 个字符，每个都在标准 base64 字母表里，补一个 "=" 后解出 32 字节。
// 字母表逐字符核对：Go 的 base64 解码会悄悄跳过回车和换行。
func ParseKey(encoded string) (Key, error) {
	if len(encoded) != EncodedKeyLength {
		return Key{}, ErrKeyMalformed
	}
	for i := 0; i < len(encoded); i++ {
		c := encoded[i]
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '+' || c == '/') {
			return Key{}, ErrKeyMalformed
		}
	}
	raw, err := base64.StdEncoding.DecodeString(encoded + "=")
	if err != nil || len(raw) != keyLength {
		return Key{}, ErrKeyMalformed
	}
	key := Key{valid: true}
	copy(key.bytes[:], raw)
	return key, nil
}

// Encrypt 按承运商的协议加密 body：AES-256-CBC，IV 取密钥的前 16 字节；明文是 16 个随机字符、
// 4 字节大端的正文长度、正文、appKey，再做 PKCS#7 填充到 32 字节的整数倍；结果是标准 base64。
// body 逐字节原样进入明文。随机字符从 random 取。
func Encrypt(key Key, appKey string, body []byte, random io.Reader) (string, error) {
	if !key.valid {
		return "", ErrKeyMalformed
	}
	if uint64(len(body)) > math.MaxUint32 {
		return "", errBodyTooLong
	}
	prefix, err := randomText(random)
	if err != nil {
		return "", err
	}
	size := headerLength + len(body) + len(appKey)
	padding := paddingBlock - size%paddingBlock
	plain := make([]byte, 0, size+padding)
	plain = append(plain, prefix...)
	plain = binary.BigEndian.AppendUint32(plain, uint32(len(body)))
	plain = append(plain, body...)
	plain = append(plain, appKey...)
	plain = append(plain, bytes.Repeat([]byte{byte(padding)}, padding)...)

	block, err := aes.NewCipher(key.bytes[:])
	if err != nil {
		return "", ErrKeyMalformed
	}
	sealed := make([]byte, len(plain))
	cipher.NewCBCEncrypter(block, key.bytes[:aes.BlockSize]).CryptBlocks(sealed, plain)
	return base64.StdEncoding.EncodeToString(sealed), nil
}

// randomText 取 16 个字母或数字，用拒绝取样避免对 62 取余的偏差。每一轮只读还缺的字节数。
func randomText(random io.Reader) ([]byte, error) {
	text := make([]byte, 0, randomLength)
	buffer := make([]byte, randomLength)
	for len(text) < randomLength {
		chunk := buffer[:randomLength-len(text)]
		if _, err := io.ReadFull(random, chunk); err != nil {
			return nil, fmt.Errorf("random source: %w", err)
		}
		for _, b := range chunk {
			if b < acceptBelow {
				text = append(text, randomAlphabet[int(b)%len(randomAlphabet)])
			}
		}
	}
	return text, nil
}

// Decrypt 是 Encrypt 的反过程。每一步核对都不能省：长度是 16 的非零整数倍；填充字节在 1 到 32 之间、
// 不多于数据，并且每一个填充字节都等于它；去掉填充后至少有 20 字节；第 16 到 20 字节是正文长度，
// 20 加它要装得下；正文之后的字节必须恰好等于 appKey。
func Decrypt(key Key, appKey, ciphertext string) ([]byte, error) {
	if !key.valid {
		return nil, ErrKeyMalformed
	}
	data, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return nil, ErrNotBase64
	}
	if len(data) == 0 || len(data)%aes.BlockSize != 0 {
		return nil, ErrBlockSize
	}
	block, err := aes.NewCipher(key.bytes[:])
	if err != nil {
		return nil, ErrKeyMalformed
	}
	plain := make([]byte, len(data))
	cipher.NewCBCDecrypter(block, key.bytes[:aes.BlockSize]).CryptBlocks(plain, data)

	padding := int(plain[len(plain)-1])
	if padding < 1 || padding > paddingBlock || padding > len(plain) {
		return nil, ErrPadding
	}
	for _, b := range plain[len(plain)-padding:] {
		if int(b) != padding {
			return nil, ErrPadding
		}
	}
	plain = plain[:len(plain)-padding]
	if len(plain) < headerLength {
		return nil, ErrTooShort
	}
	length := uint64(binary.BigEndian.Uint32(plain[randomLength:headerLength]))
	if length > uint64(len(plain)-headerLength) {
		return nil, ErrLength
	}
	end := headerLength + int(length)
	if string(plain[end:]) != appKey {
		return nil, ErrAppKeyMismatch
	}
	return plain[headerLength:end], nil
}

// Sign 是请求头 signature 的值：令牌、时间戳、随机数、密文四个字符串按字节序排序，
// 中间不加任何东西地拼起来，取 SHA-256，写成小写十六进制。方法和路径不在签名里。
func Sign(token, timestamp, nonce, ciphertext string) string {
	parts := []string{token, timestamp, nonce, ciphertext}
	sort.Strings(parts)
	sum := sha256.Sum256([]byte(strings.Join(parts, "")))
	return hex.EncodeToString(sum[:])
}
