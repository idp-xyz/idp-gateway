package domain

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"
)

func Test合格的密钥集与顺序无关的摘要(t *testing.T) {
	first := []byte(`{"keys":[{"kty":"RSA","kid":"b","e":"AQAB"},{"kid":"a","kty":"RSA","e":"AQAB"}]}`)
	second := []byte(`  {"extra":true,"keys":[{"e":"AQAB","kid":"a","kty":"RSA"},{"e":"AQAB","kty":"RSA","kid":"b"}]}  `)
	left, err := Parse(first)
	if err != nil {
		t.Fatal(err)
	}
	right, err := Parse(second)
	if err != nil {
		t.Fatal(err)
	}
	if left.Digest() == "" || left.Digest() != right.Digest() {
		t.Fatalf("摘要应相同且非空：%s %s", left.Digest(), right.Digest())
	}
	if !bytes.Equal(left.Canonical(), right.Canonical()) {
		t.Fatalf("规范形式应相同：%s 与 %s", left.Canonical(), right.Canonical())
	}
	wantArray := `[{"e":"AQAB","kid":"a","kty":"RSA"},{"e":"AQAB","kid":"b","kty":"RSA"}]`
	sum := sha256.Sum256([]byte(wantArray))
	if left.Digest() != hex.EncodeToString(sum[:]) {
		t.Fatalf("摘要是 %s，应按规范数组计算得到 %s", left.Digest(), hex.EncodeToString(sum[:]))
	}
	wantFile := "{\"keys\":" + wantArray + "}\n"
	if string(left.Canonical()) != wantFile {
		t.Fatalf("文件内容是 %q", left.Canonical())
	}
	again, err := Parse(left.Canonical())
	if err != nil || again.Digest() != left.Digest() {
		t.Fatalf("规范形式应能再解析出同一摘要：%v %s", err, again.Digest())
	}
	kids := left.KIDs()
	if strings.Join(kids, ",") != "a,b" {
		t.Fatalf("kid 顺序是 %v", kids)
	}
	keys := left.Keys()
	if len(keys) != 2 || keys[0].KID != "a" || keys[0].KTY != "RSA" || keys[1].KID != "b" {
		t.Fatalf("密钥是 %+v", keys)
	}
	// 调用方改自己的副本，不影响文档。
	kids[0] = "changed"
	keys[0].KID = "changed"
	if left.KIDs()[0] != "a" || left.Keys()[0].KID != "a" {
		t.Fatal("返回的切片应是副本")
	}
}

func Test数组顺序影响摘要而对象成员顺序不影响(t *testing.T) {
	straight := []byte(`{"keys":[{"kty":"RSA","kid":"a","x5c":["first","second"]}]}`)
	swapped := []byte(`{"keys":[{"x5c":["second","first"],"kid":"a","kty":"RSA"}]}`)
	memberOrder := []byte(`{"keys":[{"x5c":["first","second"],"kty":"RSA","kid":"a"}]}`)
	one, err := Parse(straight)
	if err != nil {
		t.Fatal(err)
	}
	two, err := Parse(swapped)
	if err != nil {
		t.Fatal(err)
	}
	three, err := Parse(memberOrder)
	if err != nil {
		t.Fatal(err)
	}
	if one.Digest() == two.Digest() {
		t.Fatal("x5c 的顺序不同，摘要不该相同")
	}
	if one.Digest() != three.Digest() {
		t.Fatal("对象成员的顺序不同，摘要应该相同")
	}
}

func Test拒绝不合法的密钥集(t *testing.T) {
	cases := []struct {
		name, body, want string
	}{
		{"空的", "", "malformed JSON"},
		{"只有空白", " \n\t", "malformed JSON"},
		{"半截", "{", "malformed JSON"},
		{"不是对象", "[]", "not a JSON object"},
		{"是一个字符串", `"keys"`, "not a JSON object"},
		{"是 null", "null", "not a JSON object"},
		{"后面还有一个值", `{"keys":[{"kty":"RSA","kid":"a"}]}{"a":1}`, "trailing data"},
		{"后面有杂字", `{"keys":[{"kty":"RSA","kid":"a"}]} x`, "trailing data"},
		{"注释", `{"keys":[{"kty":"RSA","kid":"a"}]} /*no*/`, "trailing data"},
		{"没有 keys", `{}`, "keys is required"},
		{"keys 是空数组", `{"keys":[]}`, "at least one key"},
		{"keys 是 null", `{"keys":null}`, "must be an array"},
		{"keys 不是数组", `{"keys":{}}`, "must be an array"},
		{"元素不是对象", `{"keys":["a"]}`, "must be an object"},
		{"元素是 null", `{"keys":[null]}`, "must be an object"},
		{"没有 kid", `{"keys":[{"kty":"RSA"}]}`, "key kid must be a non-empty string"},
		{"没有 kty", `{"keys":[{"kid":"a"}]}`, "key kty must be a non-empty string"},
		{"kid 是空字符串", `{"keys":[{"kty":"RSA","kid":""}]}`, "key kid must be a non-empty string"},
		{"kty 是空字符串", `{"keys":[{"kty":"","kid":"a"}]}`, "key kty must be a non-empty string"},
		{"kid 不是字符串", `{"keys":[{"kty":"RSA","kid":1}]}`, "key kid must be a non-empty string"},
		{"kty 不是字符串", `{"keys":[{"kty":true,"kid":"a"}]}`, "key kty must be a non-empty string"},
		{"重复的 kid", `{"keys":[{"kty":"RSA","kid":"a"},{"kty":"EC","kid":"a"}]}`, `duplicate kid "a"`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := Parse([]byte(c.body)); err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("得到 %v，想包含 %q", err, c.want)
			}
		})
	}
	// 对象后面只有空白，是一份完整的 JSON。
	if _, err := Parse([]byte("\n{\"keys\":[{\"kty\":\"RSA\",\"kid\":\"a\"}]}\n")); err != nil {
		t.Fatal(err)
	}
}

func Test私钥参数一律拒绝(t *testing.T) {
	for _, name := range []string{"d", "p", "q", "dp", "dq", "qi", "oth", "k"} {
		t.Run(name, func(t *testing.T) {
			body := `{"keys":[{"kty":"RSA","kid":"a","` + name + `":"SUPERSECRET"}]}`
			_, err := Parse([]byte(body))
			if err == nil || !strings.Contains(err.Error(), `private parameter "`+name+`"`) {
				t.Fatalf("应拒绝 %s，得到 %v", name, err)
			}
			if strings.Contains(err.Error(), "SUPERSECRET") {
				t.Fatalf("错误信息带出了私钥材料：%v", err)
			}
		})
	}
	// 值为 null 也是把这个成员发出来了。
	if _, err := Parse([]byte(`{"keys":[{"kty":"RSA","kid":"a","d":null}]}`)); err == nil || !strings.Contains(err.Error(), "private parameter") {
		t.Fatalf("null 的私钥参数也应拒绝，得到 %v", err)
	}
	// 公钥参数留下。
	if _, err := Parse([]byte(`{"keys":[{"kty":"EC","kid":"a","crv":"P-256","x":"x","y":"y"}]}`)); err != nil {
		t.Fatal(err)
	}
}

func Test空密钥集不是合格文档(t *testing.T) {
	empty := EmptySet()
	if string(empty) != "{\"keys\":[]}\n" {
		t.Fatalf("空集是 %q", empty)
	}
	if _, err := Parse(empty); err == nil {
		t.Fatal("空密钥集不该通过 Parse")
	}
}

func Test过期只在超过上限时成立(t *testing.T) {
	base := time.Date(2026, 11, 20, 0, 0, 0, 0, time.UTC)
	max := time.Minute
	stale, age := StaleStatus(time.Time{}, base, max)
	if stale || age != 0 {
		t.Fatalf("还没有成功过：stale=%v age=%s", stale, age)
	}
	stale, age = StaleStatus(base, base.Add(time.Hour), 0)
	if stale || age != time.Hour {
		t.Fatalf("上限为 0 时不应过期：stale=%v age=%s", stale, age)
	}
	stale, age = StaleStatus(base, base.Add(max), max)
	if stale || age != max {
		t.Fatalf("恰好等于上限不应过期：stale=%v age=%s", stale, age)
	}
	stale, age = StaleStatus(base, base.Add(max+time.Nanosecond), max)
	if !stale || age != max+time.Nanosecond {
		t.Fatalf("超过上限应过期：stale=%v age=%s", stale, age)
	}
	stale, age = StaleStatus(base, base.Add(-time.Second), max)
	if stale || age != -time.Second {
		t.Fatalf("时钟倒退不应过期：stale=%v age=%s", stale, age)
	}
	stale, _ = StaleStatus(base, base.Add(time.Hour), -time.Second)
	if stale {
		t.Fatal("负的上限不应过期")
	}
}
