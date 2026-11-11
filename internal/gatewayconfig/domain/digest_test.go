package domain

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
)

// testdata/config_dump.json 是锁定的 agentgateway 1.7.0 镜像加载 tests/integration/compose 的一份
// 快照（路由 a、b）之后，经回读口读到的 /config_dump 原文。下面两个值是那套用例的
// published_digest（Python）对同一份原文算出来的：不计证书正文的，和计入证书正文的。
const (
	realDumpDigest                 = "d963105500f5d47848eae32fb9fee12652d5522e8d2ea2368f2247f3d85c4121"
	realDumpDigestWithCertificates = "80ff61229c79a6c3d642814c3ceec295a44b43be342956acb3bfbfddcfcc0019"
)

func realDump(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile("testdata/config_dump.json")
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// replaced 把 raw 里的 old 换成 new，并确认确实换了 want 处：换不到东西的测试什么也没测。
func replaced(t *testing.T, raw []byte, old, new string, want int) []byte {
	t.Helper()
	if got := bytes.Count(raw, []byte(old)); got != want {
		t.Fatalf("原文里有 %d 处 %q，预期 %d 处", got, old, want)
	}
	return bytes.ReplaceAll(raw, []byte(old), []byte(new))
}

func digest(t *testing.T, dump []byte) string {
	t.Helper()
	got, err := PublishedDigest(dump)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func canonical(t *testing.T, source string) string {
	t.Helper()
	decoder := json.NewDecoder(strings.NewReader(source))
	decoder.UseNumber()
	var node any
	if err := decoder.Decode(&node); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := writeCanonical(&out, node); err != nil {
		t.Fatal(err)
	}
	return out.String()
}

// 右边一列是 Python 的 json.dumps(json.loads(左边), sort_keys=True, separators=(',', ':')) 的输出。
func TestCanonicalFormIsThePythonOne(t *testing.T) {
	for name, c := range map[string]struct{ source, want string }{
		"键排序，没有空白": {
			`{"b":1,"a":[true,false,null],"c":{"y":"x","x":"y"}}`,
			`{"a":[true,false,null],"b":1,"c":{"x":"y","y":"x"}}`,
		},
		"空的对象、数组和字符串": {
			`  { "a" : [ ] , "b" : { } , "c" : "" }  `,
			`{"a":[],"b":{},"c":""}`,
		},
		"数": {
			`[0, -0, 1, -1, 1.0, 1.50, 1e3, 1E3, 1e16, 1e15, 0.0001, 0.00001, 1.2345e-7, 123456789012345678901234567890, -0.0, 0e0, 2.5e-5, 1e22, 1.7976931348623157e308, 5e-324, 0.1, 100.0, 1E+2, 12e-1, 9007199254740993, 0.30000000000000004, 123456789.123456789, 1e-4, 9999999999999998.0, 99999999999999980.0]`,
			`[0,0,1,-1,1.0,1.5,1000.0,1000.0,1e+16,1000000000000000.0,0.0001,1e-05,1.2345e-07,123456789012345678901234567890,-0.0,0.0,2.5e-05,1e+22,1.7976931348623157e+308,5e-324,0.1,100.0,100.0,1.2,9007199254740993,0.30000000000000004,123456789.12345679,0.0001,9999999999999998.0,9.999999999999998e+16]`,
		},
		"字符串的转义": {
			`"a\"b\\c\/d\n\r\t\b\f\u0001\u001f \u007f\u00e9\u4e2d\ud83d\ude00<>&\u2028~"`,
			`"a\"b\\c/d\n\r\t\b\f\u0001\u001f \u007f\u00e9\u4e2d\ud83d\ude00<>&\u2028~"`,
		},
		"键按码点排序": {
			`{"\u00e9":1,"z":2,"a":3,"\u4e2d":4,"A":5,"\ud83d\ude00":6,"":7,"a b":8,"a\u0000":9}`,
			`{"":7,"A":5,"a":3,"a\u0000":9,"a b":8,"z":2,"\u00e9":1,"\u4e2d":4,"\ud83d\ude00":6}`,
		},
	} {
		if got := canonical(t, c.source); got != c.want {
			t.Errorf("%s:\n得到 %s\n应为 %s", name, got, c.want)
		}
	}
}

func TestPublishedDigestOfARealDumpIsTheOneTheSuitesCompute(t *testing.T) {
	raw := realDump(t)
	if got := digest(t, raw); got != realDumpDigest {
		t.Fatalf("得到 %s，Python 算的是 %s", got, realDumpDigest)
	}

	// 证书正文留着时，规范形式也与 Python 的逐字节相同：这份原文里有带换行的长字符串。
	document, err := decodeObject(raw)
	if err != nil {
		t.Fatal(err)
	}
	delete(document, settingsSection)
	var out bytes.Buffer
	if err := writeCanonical(&out, document); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(out.Bytes())
	if got := hex.EncodeToString(sum[:]); got != realDumpDigestWithCertificates {
		t.Fatalf("计入证书正文：得到 %s，Python 算的是 %s", got, realDumpDigestWithCertificates)
	}
}

func TestPublishedDigestIgnoresWhatDoesNotComeFromTheSnapshot(t *testing.T) {
	raw := realDump(t)

	// 换一种写法：键的顺序和空白都变了。
	var generic any
	if err := json.Unmarshal(raw, &generic); err != nil {
		t.Fatal(err)
	}
	compact, err := json.Marshal(generic)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(compact, raw) {
		t.Fatal("重新写出来的和原文一样，这一项什么也没测")
	}
	if got := digest(t, compact); got != realDumpDigest {
		t.Errorf("换了键的顺序和空白，摘要变了：%s", got)
	}

	// 启动设置：随环境变的和不随环境变的，都不在摘要里。
	settings := replaced(t, raw, `"terminationMaxDeadline": "45s"`, `"terminationMaxDeadline": "46s"`, 1)
	settings = replaced(t, settings, `"numWorkerThreads": 20`, `"numWorkerThreads": 4`, 1)
	settings = replaced(t, settings, `"ip": "10.255.255.254"`, `"ip": "127.0.0.11"`, 1)
	if got := digest(t, settings); got != realDumpDigest {
		t.Errorf("只改了 config 段，摘要变了：%s", got)
	}

	// 证书正文：另一套证书，摘要不变。
	certificates := replaced(t, raw, `-----BEGIN CERTIFICATE-----\nMIIB`, `-----BEGIN CERTIFICATE-----\nXXXX`, 2)
	if got := digest(t, certificates); got != realDumpDigest {
		t.Errorf("只换了证书正文，摘要变了：%s", got)
	}
}

func TestCertificatesAreRecognisedByTheirHeader(t *testing.T) {
	dump := func(root string) []byte {
		encoded, err := json.Marshal(map[string]any{"policies": []any{map[string]any{"root": root, "name": "p"}}})
		if err != nil {
			t.Fatal(err)
		}
		return encoded
	}
	reference := digest(t, dump("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"))
	for name, c := range map[string]struct {
		root string
		same bool
	}{
		"另一张证书":        {"-----BEGIN CERTIFICATE-----\nBBBB\n-----END CERTIFICATE-----\n", true},
		"前面有空白的证书":     {"\n \t\r-----BEGIN CERTIFICATE-----\nCCCC\n-----END CERTIFICATE-----\n", true},
		"两张证书接在一起":     {"-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nDDDD\n-----END CERTIFICATE-----\n", true},
		"证书头不在开头":      {"see -----BEGIN CERTIFICATE-----\nAAAA", false},
		"一个文件名":        {"tls/ca.crt", false},
		"占位本身之外的别的字符串": {"<certificate> ", false},
	} {
		if got := digest(t, dump(c.root)); (got == reference) != c.same {
			t.Errorf("%s：与参照相同=%t，应为 %t", name, got == reference, c.same)
		}
	}
}

func TestPublishedDigestSeesEverythingThatDoes(t *testing.T) {
	raw := realDump(t)
	for name, changed := range map[string][]byte{
		"一条路由的主机名":   replaced(t, raw, `"b.test"`, `"c.test"`, 1),
		"一条路由的后端":    replaced(t, raw, `"inlineBackend": "echo:8000"`, `"inlineBackend": "echo:8001"`, 1),
		"回读口放行谁":     replaced(t, raw, `spiffe://idp.test/gateway-control/publisher`, `spiffe://idp.test/apps/parcel-service`, 1),
		"验证对端证书用的名字": replaced(t, raw, `"hostname": "gatekeeper.idp.test"`, `"hostname": "other.idp.test"`, 1),
		"网关的版本":      replaced(t, raw, `"version": "1.7.0"`, `"version": "1.7.1"`, 1),
		"多出一个顶层的段":   replaced(t, raw, `"workloads": [],`, `"workloads": [], "extra": {},`, 1),
		// 不是证书的长字符串不会被当成证书换掉。
		"以别的 PEM 头开始的字符串": replaced(t, raw, `-----BEGIN CERTIFICATE-----\nMIIBi`, `-----BEGIN PUBLIC KEY-----\nMIIBi`, 1),
	} {
		if got := digest(t, changed); got == realDumpDigest {
			t.Errorf("%s 变了，摘要没有变", name)
		}
	}
}

func TestPublishedDigestRefusesWhatIsNotADump(t *testing.T) {
	for name, dump := range map[string]string{
		"空的":          ``,
		"不是 JSON":     `routes: []`,
		"是数组":         `[]`,
		"是字符串":        `"dump"`,
		"后面还有东西":      `{"routes":{}} {"routes":{}}`,
		"后面有不成文的东西":   `{"routes":{}} trailing`,
		"截断的":         `{"routes":{"a":`,
		"大到装不下的数":     `{"routes":{"weight":1e999}}`,
		"config 段也截断": `{"config":{"a":1`,
	} {
		if got, err := PublishedDigest([]byte(dump)); err == nil {
			t.Errorf("%s：算出了摘要 %s", name, got)
		}
	}
	// 对照：最小的合法输入。
	if _, err := PublishedDigest([]byte(`{}`)); err != nil {
		t.Fatal(err)
	}
}

func TestStartupSettingsOfARealDump(t *testing.T) {
	raw := realDump(t)
	settings, err := StartupSettings(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(settings) != 31 || settings["terminationMaxDeadline"] != `"45s"` || settings["storage"] != `{"mode":"readOnly"}` {
		t.Fatalf("%d 项；terminationMaxDeadline=%s storage=%s", len(settings), settings["terminationMaxDeadline"], settings["storage"])
	}
	if differing := settings.Differing(settings); len(differing) != 0 {
		t.Fatalf("和自己比出了不同：%v", differing)
	}

	// 只差随环境变的两项：同一份快照在另一个地方加载就是这样。
	elsewhere := replaced(t, raw, `"numWorkerThreads": 20`, `"numWorkerThreads": 4`, 1)
	elsewhere = replaced(t, elsewhere, `"ip": "10.255.255.254"`, `"ip": "127.0.0.11"`, 1)
	other, err := StartupSettings(elsewhere)
	if err != nil {
		t.Fatal(err)
	}
	if settings["dns"] == other["dns"] || settings["numWorkerThreads"] == other["numWorkerThreads"] {
		t.Fatal("这两项没有改到，下面的断言什么也没测")
	}
	if differing := settings.Differing(other); len(differing) != 0 {
		t.Errorf("随环境变的项被算成了不同：%v", differing)
	}

	// 快照改了启动设置：SH-06 里改的就是这一项。
	tuned, err := StartupSettings(replaced(t, elsewhere, `"terminationMaxDeadline": "45s"`, `"terminationMaxDeadline": "46s"`, 1))
	if err != nil {
		t.Fatal(err)
	}
	if differing := settings.Differing(tuned); !reflect.DeepEqual(differing, []string{"terminationMaxDeadline"}) {
		t.Errorf("得到 %v", differing)
	}
	if differing := tuned.Differing(settings); !reflect.DeepEqual(differing, []string{"terminationMaxDeadline"}) {
		t.Errorf("反过来比得到 %v", differing)
	}
}

func TestSettingsDiffering(t *testing.T) {
	a := Settings{"adminAddr": `"127.0.0.1:15000"`, "storage": `{"mode":"readOnly"}`, "dns": `1`, "onlyHere": `true`}
	b := Settings{"adminAddr": `"0.0.0.0:15000"`, "storage": `{"mode":"readOnly"}`, "dns": `2`, "onlyThere": `true`, "numWorkerThreads": `4`}
	want := []string{"adminAddr", "onlyHere", "onlyThere"}
	if got := a.Differing(b); !reflect.DeepEqual(got, want) {
		t.Errorf("得到 %v，应为 %v", got, want)
	}
	if got := b.Differing(a); !reflect.DeepEqual(got, want) {
		t.Errorf("反过来比得到 %v，应为 %v", got, want)
	}
	if got := (Settings{}).Differing(nil); len(got) != 0 {
		t.Errorf("两份空的比出了 %v", got)
	}
}

func TestStartupSettingsOfOtherInputs(t *testing.T) {
	if settings, err := StartupSettings([]byte(`{"routes":{}}`)); err != nil || len(settings) != 0 {
		t.Errorf("没有 config 段：%v, %v", settings, err)
	}
	// 值用规范形式比：写法不同、内容相同的不算不同。
	a, err := StartupSettings([]byte(`{"config":{"limits":{"b":1.0,"a":[1,2]}}}`))
	if err != nil {
		t.Fatal(err)
	}
	b, err := StartupSettings([]byte(`{"config": {"limits": {"a": [1, 2], "b": 1.00}}}`))
	if err != nil {
		t.Fatal(err)
	}
	if differing := a.Differing(b); len(differing) != 0 {
		t.Errorf("只是写法不同：%v", differing)
	}
	for name, dump := range map[string]string{
		"不是 JSON":        `config: {}`,
		"config 不是对象":    `{"config":[]}`,
		"config 里有装不下的数": `{"config":{"a":1e999}}`,
	} {
		if settings, err := StartupSettings([]byte(dump)); err == nil {
			t.Errorf("%s：得到了 %v", name, settings)
		}
	}
}
