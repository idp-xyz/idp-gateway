package domain

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
	"testing/iotest"
)

// 取随机字符的字母表在这里再写一遍，不引用产品代码里的那一份：字母表的顺序要由测试钉住。
const testAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

type vectorCase struct {
	Name       string `json:"name"`
	Random16   string `json:"random16"`
	BodyBase64 string `json:"body_base64"`
	Ciphertext string `json:"ciphertext"`
	Timestamp  string `json:"timestamp"`
	Nonce      string `json:"nonce"`
	Signature  string `json:"signature"`
}

// vectors 是 testdata/vectors.json：用 openssl 命令行和 Python 的 hashlib 独立做出来的向量，
// 没有经过任何 Go 代码。里面的值都是编造的。
type vectors struct {
	EncodingAESKey string       `json:"encoding_aes_key"`
	AppKey         string       `json:"app_key"`
	Token          string       `json:"token"`
	Cases          []vectorCase `json:"cases"`
}

func loadVectors(t *testing.T) vectors {
	t.Helper()
	raw, err := os.ReadFile("testdata/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v vectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	if len(v.Cases) < 4 || v.EncodingAESKey == "" || v.AppKey == "" || v.Token == "" {
		t.Fatalf("向量文件不完整：%d 个用例", len(v.Cases))
	}
	return v
}

func vectorKey(t *testing.T, v vectors) Key {
	t.Helper()
	key, err := ParseKey(v.EncodingAESKey)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// rawKey 不经过 ParseKey 取出 32 字节的密钥。
func rawKey(t *testing.T, encoded string) []byte {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(encoded + "=")
	if err != nil || len(raw) != 32 {
		t.Fatalf("encodingAesKey 解不出 32 字节：%v", err)
	}
	return raw
}

// otherKey 是另一把合法的密钥（43 个字符）。
const otherKey = "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVowMTIzNDU"

// streamFor 做出一个随机源，让 Encrypt 取到的 16 个字符恰好是 random16：
// 每个字符给它在字母表里的下标，这个字节小于 248，不会被拒绝。
func streamFor(t *testing.T, random16 string) *bytes.Reader {
	t.Helper()
	stream := make([]byte, 0, len(random16))
	for i := 0; i < len(random16); i++ {
		index := strings.IndexByte(testAlphabet, random16[i])
		if index < 0 {
			t.Fatalf("%q 不是字母或数字", random16[i])
		}
		stream = append(stream, byte(index))
	}
	return bytes.NewReader(stream)
}

// seal 不经过 Encrypt，用 AES-CBC 直接加密一段手工做的明文，长度必须是 16 的整数倍。
func seal(t *testing.T, key, plain []byte) string {
	t.Helper()
	if len(plain)%aes.BlockSize != 0 {
		t.Fatalf("明文 %d 字节，不是 16 的整数倍", len(plain))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	sealed := make([]byte, len(plain))
	cipher.NewCBCEncrypter(block, key[:aes.BlockSize]).CryptBlocks(sealed, plain)
	return base64.StdEncoding.EncodeToString(sealed)
}

// open 不经过 Decrypt，只做 base64 和 AES-CBC，返回带填充的明文。
func open(t *testing.T, key []byte, ciphertext string) []byte {
	t.Helper()
	data, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	plain := make([]byte, len(data))
	cipher.NewCBCDecrypter(block, key[:aes.BlockSize]).CryptBlocks(plain, data)
	return plain
}

// layout 做出明文的版面：16 个字符、4 字节大端的长度、正文、尾部；不含填充。
func layout(body, trailer string, declared uint32) []byte {
	plain := []byte("0123456789abcdef")
	plain = binary.BigEndian.AppendUint32(plain, declared)
	plain = append(plain, body...)
	return append(plain, trailer...)
}

// pkcs 把 content 填充到 16 的整数倍（填充字节取填充的长度），用来做一份其余都合规矩的明文。
func pkcs(content []byte) []byte {
	pad := aes.BlockSize - len(content)%aes.BlockSize
	return append(content, bytes.Repeat([]byte{byte(pad)}, pad)...)
}

func TestVectors(t *testing.T) {
	v := loadVectors(t)
	key := vectorKey(t, v)
	for _, c := range v.Cases {
		t.Run(c.Name, func(t *testing.T) {
			body, err := base64.StdEncoding.DecodeString(c.BodyBase64)
			if err != nil {
				t.Fatal(err)
			}
			random := streamFor(t, c.Random16)
			got, err := Encrypt(key, v.AppKey, body, random)
			if err != nil {
				t.Fatal(err)
			}
			if got != c.Ciphertext {
				t.Errorf("Encrypt 得到 %s，向量是 %s", got, c.Ciphertext)
			}
			if random.Len() != 0 {
				t.Errorf("随机源还剩 %d 字节：Encrypt 应当恰好取 16 个", random.Len())
			}
			plain, err := Decrypt(key, v.AppKey, c.Ciphertext)
			if err != nil || !bytes.Equal(plain, body) {
				t.Errorf("Decrypt 得到 %q，%v；要的是 %q", plain, err, body)
			}
			if signature := Sign(v.Token, c.Timestamp, c.Nonce, c.Ciphertext); signature != c.Signature {
				t.Errorf("Sign 得到 %s，向量是 %s", signature, c.Signature)
			}
		})
	}
}

// 向量里要有"明文正好是 32 字节整数倍"的用例：它钉住"已经是整块时再补一整块"。
func TestVectorsCoverAFullPaddingBlock(t *testing.T) {
	v := loadVectors(t)
	key := rawKey(t, v.EncodingAESKey)
	found := false
	for _, c := range v.Cases {
		plain := open(t, key, c.Ciphertext)
		body, _ := base64.StdEncoding.DecodeString(c.BodyBase64)
		if (16+4+len(body)+len(v.AppKey))%32 == 0 {
			found = true
			if plain[len(plain)-1] != 32 {
				t.Errorf("%s：明文已是整块，填充应是 32 个 0x20，实际最后一个字节是 %d", c.Name, plain[len(plain)-1])
			}
		}
	}
	if !found {
		t.Error("向量里没有明文恰好是 32 字节整数倍的用例")
	}
}

func TestSignSortsByByteOrder(t *testing.T) {
	hash := func(s string) string { sum := sha256.Sum256([]byte(s)); return hex.EncodeToString(sum[:]) }
	for _, c := range []struct {
		name                                string
		token, timestamp, nonce, ciphertext string
		concatenated                        string
	}{
		{"given in reverse order", "d", "c", "b", "a", "abcd"},
		{"upper case sorts before lower case", "b", "B", "a", "A", "ABab"},
		{"digits sort before letters", "z", "1700000000000", "0f", "y", "0f1700000000000yz"},
		{"a prefix sorts before its extension", "ab", "a", "abc", "b", "aababcb"},
	} {
		if got := Sign(c.token, c.timestamp, c.nonce, c.ciphertext); got != hash(c.concatenated) {
			t.Errorf("%s: 得到 %s，要的是 sha256(%q) = %s", c.name, got, c.concatenated, hash(c.concatenated))
		}
	}
}

func TestParseKey(t *testing.T) {
	v := loadVectors(t)
	if len(v.EncodingAESKey) != 43 {
		t.Fatalf("向量里的密钥有 %d 个字符", len(v.EncodingAESKey))
	}
	good := v.EncodingAESKey
	for _, c := range []struct {
		name    string
		encoded string
		ok      bool
	}{
		{"the vector key", good, true},
		{"another valid key", otherKey, true},
		{"42 characters", good[:42], false},
		{"44 characters", good + "A", false},
		{"44 characters with the padding already there", good + "=", false},
		{"empty", "", false},
		{"a character outside the alphabet", good[:20] + "!" + good[21:], false},
		{"url-safe minus", good[:20] + "-" + good[21:], false},
		{"url-safe underscore", good[:20] + "_" + good[21:], false},
		{"a space", good[:20] + " " + good[21:], false},
		{"a newline that base64 decoding would skip", good[:42] + "\n", false},
		{"a carriage return that base64 decoding would skip", good[:20] + "\r" + good[21:], false},
		{"padding inside the key", good[:20] + "=" + good[21:], false},
		{"a non-ASCII character", good[:20] + "é" + good[22:], false},
	} {
		key, err := ParseKey(c.encoded)
		switch {
		case c.ok && (err != nil || !key.valid):
			t.Errorf("%s: 被拒绝：%v", c.name, err)
		case !c.ok && !errors.Is(err, ErrKeyMalformed):
			t.Errorf("%s: 错误是 %v", c.name, err)
		case !c.ok && key.valid:
			t.Errorf("%s: 拒绝了，却返回了可用的密钥", c.name)
		}
	}
	if _, err := ParseKey(good); err != nil {
		t.Fatal(err)
	}
	// 零值的密钥不能拿来加密或解密：它不是"全零的密钥"。
	if _, err := Encrypt(Key{}, "app", []byte("{}"), rand.Reader); !errors.Is(err, ErrKeyMalformed) {
		t.Errorf("零值的密钥加密：%v", err)
	}
	if _, err := Decrypt(Key{}, "app", "AAAAAAAAAAAAAAAAAAAAAA=="); !errors.Is(err, ErrKeyMalformed) {
		t.Errorf("零值的密钥解密：%v", err)
	}
}

func TestRoundTrip(t *testing.T) {
	v := loadVectors(t)
	key := vectorKey(t, v)
	raw := rawKey(t, v.EncodingAESKey)
	sizes := make([]int, 0, 202)
	for n := 0; n <= 200; n++ {
		sizes = append(sizes, n)
	}
	sizes = append(sizes, 1<<20)
	for _, n := range sizes {
		body := make([]byte, n)
		if _, err := io.ReadFull(rand.Reader, body); err != nil {
			t.Fatal(err)
		}
		ciphertext, err := Encrypt(key, v.AppKey, body, rand.Reader)
		if err != nil {
			t.Fatalf("%d 字节：%v", n, err)
		}
		plain, err := Decrypt(key, v.AppKey, ciphertext)
		if err != nil || !bytes.Equal(plain, body) {
			t.Fatalf("%d 字节：往返之后不同，%v", n, err)
		}
		// 密文是 32 字节的整数倍：填充把明文补到整块，已经是整块时再补一整块。
		sealed := open(t, raw, ciphertext)
		if len(sealed)%32 != 0 || len(sealed) <= 16+4+n+len(v.AppKey) {
			t.Fatalf("%d 字节：密文解开有 %d 字节，没有按 32 字节的块填充", n, len(sealed))
		}
	}
}

func TestEncryptWithTheRealRandomSourceDiffers(t *testing.T) {
	v := loadVectors(t)
	key := vectorKey(t, v)
	body := []byte(`{"same":"body"}`)
	seen := map[string]bool{}
	for range 20 {
		ciphertext, err := Encrypt(key, v.AppKey, body, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		if seen[ciphertext] {
			t.Fatal("同一份正文加密两次得到了同一份密文")
		}
		seen[ciphertext] = true
	}
}

// 明文开头的 16 个字符都是字母或数字。
func TestEncryptRandomPrefixIsLettersAndDigits(t *testing.T) {
	v := loadVectors(t)
	key := vectorKey(t, v)
	raw := rawKey(t, v.EncodingAESKey)
	for range 200 {
		ciphertext, err := Encrypt(key, v.AppKey, []byte("{}"), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		for _, c := range open(t, raw, ciphertext)[:16] {
			if !strings.ContainsRune(testAlphabet, rune(c)) {
				t.Fatalf("随机字符里有 %q", c)
			}
		}
	}
}

// 拒绝取样：248 及以上的字节被丢掉重取，247 还在范围之内。期望的密文由手工做的明文独立算出。
func TestEncryptRejectsBiasedBytes(t *testing.T) {
	v := loadVectors(t)
	key := vectorKey(t, v)
	raw := rawKey(t, v.EncodingAESKey)
	body := []byte(`{"a":1}`)

	// 247 % 62 = 61，是字母表的最后一个字符 '9'。
	wantPlain := layout(string(body), v.AppKey, uint32(len(body)))
	copy(wantPlain, "9999999999999999")
	padding := 32 - len(wantPlain)%32
	wantPlain = append(wantPlain, bytes.Repeat([]byte{byte(padding)}, padding)...)
	want := seal(t, raw, wantPlain)

	// 先给 16 个必须丢掉的字节，再给 247、248、255 交错的字节；只有 247 被用。
	stream := bytes.Repeat([]byte{255}, 16)
	for range 16 {
		stream = append(stream, 248, 247)
	}
	reader := bytes.NewReader(stream)
	got, err := Encrypt(key, v.AppKey, body, reader)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Error("被拒绝的字节进入了随机字符，或者 247 被拒绝了")
	}
	// 每一轮只读还缺的字节数：第一轮 16 个全丢；第二轮 16 个，八个 248 丢掉，八个 247 留下；
	// 之后各轮读 8、4、2、1 个，最后一轮前面的 248 又被丢掉一次，再读 1 个。共 16+16+8+4+2+1+1 = 48 个，
	// 恰好是流的全部。
	if reader.Len() != 0 {
		t.Errorf("随机源还剩 %d 字节", reader.Len())
	}
}

func TestEncryptFailsWhenTheRandomSourceFails(t *testing.T) {
	v := loadVectors(t)
	key := vectorKey(t, v)
	sentinel := errors.New("entropy exhausted")
	for name, reader := range map[string]io.Reader{
		"error":        iotest.ErrReader(sentinel),
		"short":        bytes.NewReader(make([]byte, 15)),
		"empty":        bytes.NewReader(nil),
		"fails midway": io.MultiReader(bytes.NewReader(make([]byte, 8)), iotest.ErrReader(sentinel)),
	} {
		ciphertext, err := Encrypt(key, v.AppKey, []byte("{}"), reader)
		if err == nil || ciphertext != "" {
			t.Errorf("%s: 得到密文 %q，错误 %v", name, ciphertext, err)
		}
	}
}

func TestDecryptRefuses(t *testing.T) {
	v := loadVectors(t)
	key := vectorKey(t, v)
	raw := rawKey(t, v.EncodingAESKey)
	other := rawKey(t, otherKey)
	appKey := v.AppKey

	real, err := Encrypt(key, appKey, []byte(`{"a":1}`), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	foreign := seal(t, other, pkcs(layout("{}", appKey, 2)))

	oneBlock := func(last byte) string {
		block := bytes.Repeat([]byte{'x'}, 16)
		block[15] = last
		return seal(t, raw, block)
	}

	// 版面合规矩，只改一处。content 的长度都凑成"加上填充恰好是 16 的整数倍"。
	cases := []struct {
		name       string
		ciphertext string
		appKey     string
		key        Key
		want       error // nil 表示只要求被拒绝
	}{
		{"not base64", "this is not base64!", appKey, key, ErrNotBase64},
		{"base64 without its padding", strings.TrimRight(real, "="), appKey, key, ErrNotBase64},
		{"empty", "", appKey, key, ErrBlockSize},
		{"length 17", base64.StdEncoding.EncodeToString(make([]byte, 17)), appKey, key, ErrBlockSize},
		{"length 15", base64.StdEncoding.EncodeToString(make([]byte, 15)), appKey, key, ErrBlockSize},
		{"encrypted under another key", foreign, appKey, key, nil},
		{"wrong appKey", real, "idpgw-test-app-key-9999", key, ErrAppKeyMismatch},
		{"appKey that is a prefix of the right one", real, appKey[:len(appKey)-1], key, ErrAppKeyMismatch},
		{"appKey that is an extension of the right one", real, appKey + "1", key, ErrAppKeyMismatch},
		{"appKey that differs in case", real, strings.ToUpper(appKey), key, ErrAppKeyMismatch},
		{"empty appKey", real, "", key, ErrAppKeyMismatch},
		{"pad byte 0", seal(t, raw, append(layout("x", appKey, 1), 0, 0, 0, 0)), appKey, key, ErrPadding},
		{"pad byte 33", seal(t, raw, append(layout("x", appKey, 1), 33, 33, 33, 33)), appKey, key, ErrPadding},
		{"pad byte larger than the data", oneBlock(32), appKey, key, ErrPadding},
		// 最后一个字节是 4，倒数第二个不是：只看最后一个字节的实现会放过它，正文和 appKey 都是对的。
		{"pad bytes not all equal", seal(t, raw, append(layout("x", appKey, 1), 4, 4, 9, 4)), appKey, key, ErrPadding},
		{"first of the pad bytes differs", seal(t, raw, append(layout("x", appKey, 1), 7, 4, 4, 4)), appKey, key, ErrPadding},
		{"declared length larger than the data", seal(t, raw, pkcs(layout("{}", appKey, 1000))), appKey, key, ErrLength},
		{"declared length of four billion", seal(t, raw, pkcs(layout("{}", appKey, 0xFFFFFFFF))), appKey, key, ErrLength},
		{"declared length one more than the data", seal(t, raw, pkcs(layout("{}", "", 3))), "", key, ErrLength},
		{"declared length shorter than the data", seal(t, raw, pkcs(layout("{}", appKey, 1))), appKey, key, ErrAppKeyMismatch},
		{"declared length zero", seal(t, raw, pkcs(layout("{}", appKey, 0))), appKey, key, ErrAppKeyMismatch},
		{"plaintext shorter than its header", seal(t, raw, append([]byte("0123456789"), 6, 6, 6, 6, 6, 6)), appKey, key, ErrTooShort},
		{"plaintext of only the padding", seal(t, raw, bytes.Repeat([]byte{16}, 16)), appKey, key, ErrTooShort},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			plain, err := Decrypt(c.key, c.appKey, c.ciphertext)
			if err == nil || plain != nil {
				t.Fatalf("没有被拒绝：%q，%v", plain, err)
			}
			if c.want != nil && !errors.Is(err, c.want) {
				t.Errorf("错误是 %v，期望 %v", err, c.want)
			}
		})
	}

	// 对照：同样的手工版面，填充合规矩时是能解开的，说明上面各例只坏了一处。
	if plain, err := Decrypt(key, appKey, seal(t, raw, pkcs(layout("{}", appKey, 2)))); err != nil || string(plain) != "{}" {
		t.Fatalf("合规矩的手工明文也解不开：%q %v", plain, err)
	}
	if plain, err := Decrypt(key, appKey, seal(t, raw, append(layout("x", appKey, 1), 4, 4, 4, 4))); err != nil || string(plain) != "x" {
		t.Fatalf("四个相同的填充字节应当通过：%q %v", plain, err)
	}
}

// 解密的错误里没有密文，也没有解了一半的明文。
func TestDecryptErrorsCarryNoContent(t *testing.T) {
	v := loadVectors(t)
	key := vectorKey(t, v)
	secret := `{"marker":"PLAINTEXT-MARKER-5c1e"}`
	ciphertext, err := Encrypt(key, v.AppKey, []byte(secret), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, appKey := range []string{"other-app-key", v.AppKey[:5]} {
		_, err := Decrypt(key, appKey, ciphertext)
		if err == nil {
			t.Fatal("应当被拒绝")
		}
		for _, leaked := range []string{ciphertext, "PLAINTEXT-MARKER", v.AppKey, appKey} {
			if strings.Contains(err.Error(), leaked) {
				t.Errorf("错误文字 %q 里有 %q", err, leaked)
			}
		}
	}
	for _, input := range []string{"!!!", ""} {
		_, err := Decrypt(key, v.AppKey, input)
		if err == nil || (input != "" && strings.Contains(err.Error(), input)) {
			t.Errorf("%q：%v", input, err)
		}
	}
}
