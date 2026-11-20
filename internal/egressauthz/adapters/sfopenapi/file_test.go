package sfopenapi

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadsAValidFile(t *testing.T) {
	f := newFixture(t, two("https://carrier.example.test"+tokenPath))
	if f.c.Len() != 2 || !f.c.Holds(blueHandle) || !f.c.Holds(greenHandle) || f.c.Holds("gatekeeper:other/account-blue") {
		t.Fatalf("Len %d", f.c.Len())
	}
	e := f.c.entries[blueHandle]
	if e == nil || e.appKey != blueAppKey || e.appSecret.Reveal() != blueSecret || e.aesKey.Reveal() != blueAES ||
		e.keyVersion != "v1" || e.tokenEndpoint != "https://carrier.example.test"+tokenPath {
		t.Errorf("条目读错了：%+v", e)
	}
	// 一份没有条目的文件读得进来，只是谁的凭证都没有。
	if _, err := Load(Config{Path: func() string {
		path := filepath.Join(t.TempDir(), "empty.json")
		write(t, path, `{}`, 0o600)
		return path
	}()}); err != nil {
		t.Error(err)
	}
	if _, err := Load(Config{Path: filepath.Join(t.TempDir(), "missing.json")}); err == nil {
		t.Error("不存在的文件被接受了")
	}
}

func TestFilePermissions(t *testing.T) {
	good := fileOf(entryJSON("b/a", blueApp("https://carrier.example.test"+tokenPath)))
	load := func(mode os.FileMode) error {
		path := filepath.Join(t.TempDir(), "apps.json")
		write(t, path, good, mode)
		_, err := Load(Config{Path: path})
		return err
	}
	for _, mode := range []os.FileMode{0o640, 0o604, 0o644, 0o660, 0o666, 0o601} {
		if err := load(mode); err == nil || !strings.Contains(err.Error(), "readable by others") {
			t.Errorf("权限 %04o：%v", mode, err)
		}
	}
	for _, mode := range []os.FileMode{0o600, 0o400} {
		if err := load(mode); err != nil {
			t.Errorf("权限 %04o：%v", mode, err)
		}
	}
}

// 文件里一条记录的各个字段。字段缺的、多的、类型不对的，都用它改出来。
const (
	neverSecret = "never-shown-app-secret"
	neverPath   = "/never-shown-path"
	neverHost   = "carrier.example.test"
)

var neverAES = aesKey("never")

func fieldsOf() map[string]any {
	return map[string]any{"token_endpoint": "https://" + neverHost + neverPath, "app_key": "appkey-x", "app_secret": neverSecret,
		"encoding_aes_key": neverAES, "key_version": "v1"}
}

// withField 给出一份文件：句柄 b/a 下一条记录，其中 name 字段被换成 value；value 为 nil 时换成 JSON null；
// name 是 "-" 开头时把那个字段删掉。
func withField(name string, value any) string {
	fields := fieldsOf()
	if strings.HasPrefix(name, "-") {
		delete(fields, name[1:])
	} else {
		fields[name] = value
	}
	body, err := json.Marshal(fields)
	if err != nil {
		panic(err)
	}
	return `{"b/a":` + string(body) + `}`
}

func TestFileMustBeWellFormed(t *testing.T) {
	// okFields 是一条合格的记录（大括号包着的那一段）。
	body, err := json.Marshal(fieldsOf())
	if err != nil {
		t.Fatal(err)
	}
	okFields := string(body)

	cases := map[string]struct{ content, says string }{
		"不是 JSON":                 {neverSecret + ` not json`, "not a JSON object"},
		"空文件":                     {``, "not a JSON object"},
		"顶层是数组":                   {`[` + neverSecret + `]`, "not a JSON object"},
		"值是字符串":                   {`{"b/a":"` + neverSecret + `"}`, "not a JSON object"},
		"值是 null":                 {`{"b/a":null}`, "all required"},
		"值是空对象":                   {`{"b/a":{}}`, "all required"},
		"对象没有写完":                  {strings.TrimSuffix(withField("key_version", "v1"), "}"), "not a JSON object"},
		"文件后面还有对象":                {withField("key_version", "v1") + ` {}`, "unexpected data"},
		"文件后面还有杂质":                {withField("key_version", "v1") + ` ` + neverSecret, "unexpected data"},
		"空句柄":                     {`{"":` + okFields + `}`, "empty handle"},
		"同一个句柄写了两次":               {`{"b/a":` + okFields + `,"b/a":` + okFields + `}`, "appears twice"},
		"有不认识的字段":                 {withField("app_secret_file", "/x"), "not a JSON object"},
		"没有 token_endpoint":       {withField("-token_endpoint", nil), "all required"},
		"没有 app_key":              {withField("-app_key", nil), "all required"},
		"没有 app_secret":           {withField("-app_secret", nil), "all required"},
		"没有 encoding_aes_key":     {withField("-encoding_aes_key", nil), "all required"},
		"没有 key_version":          {withField("-key_version", nil), "all required"},
		"token_endpoint 是 null":   {withField("token_endpoint", nil), "all required"},
		"app_key 是 null":          {withField("app_key", nil), "all required"},
		"app_secret 是 null":       {withField("app_secret", nil), "all required"},
		"encoding_aes_key 是 null": {withField("encoding_aes_key", nil), "all required"},
		"key_version 是 null":      {withField("key_version", nil), "all required"},
		"app_key 不是字符串":           {withField("app_key", 7), "not a JSON object"},
		"app_secret 不是字符串":        {withField("app_secret", 7), "not a JSON object"},
		"encoding_aes_key 不是字符串":  {withField("encoding_aes_key", []string{neverAES}), "not a JSON object"},
		"key_version 不是字符串":       {withField("key_version", true), "not a JSON object"},
		"token_endpoint 不是字符串":    {withField("token_endpoint", 7), "not a JSON object"},
		"app_key 为空":              {withField("app_key", ""), "app_key"},
		"app_key 里有空格":            {withField("app_key", "app key"), "app_key"},
		"app_key 里有分号":            {withField("app_key", "app;key"), "semicolon"},
		"app_key 只有分号":            {withField("app_key", ";"), "semicolon"},
		"app_key 里有非 ASCII":       {withField("app_key", "appké"), "app_key"},
		"app_key 里有制表符":           {withField("app_key", "app\tkey"), "app_key"},
		"app_secret 为空":           {withField("app_secret", ""), "app_secret"},
		"app_secret 里有空格":         {withField("app_secret", neverSecret+" x"), "app_secret"},
		"app_secret 里有换行":         {withField("app_secret", neverSecret+"\n"), "app_secret"},
		"app_secret 里有非 ASCII":    {withField("app_secret", neverSecret+"é"), "app_secret"},
		"key_version 为空":          {withField("key_version", ""), "key_version"},
		"key_version 里有空格":        {withField("key_version", "v 1"), "key_version"},
		"AES 密钥 42 个字符":           {withField("encoding_aes_key", neverAES[:42]), "encoding_aes_key"},
		"AES 密钥 44 个字符":           {withField("encoding_aes_key", neverAES+"A"), "encoding_aes_key"},
		"AES 密钥 44 个字符，补了等号":      {withField("encoding_aes_key", neverAES+"="), "encoding_aes_key"},
		"AES 密钥为空":                {withField("encoding_aes_key", ""), "encoding_aes_key"},
		"AES 密钥 43 个字符，末尾是等号":     {withField("encoding_aes_key", neverAES[:42]+"="), "encoding_aes_key"},
		"AES 密钥里有 URL 安全字母 -":     {withField("encoding_aes_key", "-"+neverAES[1:]), "encoding_aes_key"},
		"AES 密钥里有 URL 安全字母 _":     {withField("encoding_aes_key", neverAES[:20]+"_"+neverAES[21:]), "encoding_aes_key"},
		"AES 密钥里有感叹号":             {withField("encoding_aes_key", neverAES[:20]+"!"+neverAES[21:]), "encoding_aes_key"},
		"AES 密钥里有空格":              {withField("encoding_aes_key", neverAES[:20]+" "+neverAES[21:]), "encoding_aes_key"},
		"AES 密钥里有分号":              {withField("encoding_aes_key", neverAES[:20]+";"+neverAES[21:]), "encoding_aes_key"},
		"AES 密钥里有等号":              {withField("encoding_aes_key", neverAES[:20]+"="+neverAES[21:]), "encoding_aes_key"},
		"AES 密钥末尾有换行":             {withField("encoding_aes_key", neverAES[:42]+"\n"), "encoding_aes_key"},
		"AES 密钥有非 ASCII（43 字节）":   {withField("encoding_aes_key", neverAES[:41]+"é"), "encoding_aes_key"},
		"令牌端点是明文 http":            {withField("token_endpoint", "http://"+neverHost+neverPath), "token_endpoint"},
		"令牌端点带查询串":                {withField("token_endpoint", "https://"+neverHost+neverPath+"?appSecret=x"), "query"},
		"令牌端点带用户信息":               {withField("token_endpoint", "https://u:"+neverSecret+"@"+neverHost+neverPath), "user information"},
		"令牌端点带片段":                 {withField("token_endpoint", "https://"+neverHost+neverPath+"#f"), "fragment"},
		"令牌端点不是绝对地址":              {withField("token_endpoint", neverPath), "absolute URL"},
		"令牌端点为空":                  {withField("token_endpoint", ""), "token_endpoint"},
		"令牌端点是 ftp":               {withField("token_endpoint", "ftp://"+neverHost+neverPath), "must be https"},
		"令牌端点里有空格":                {withField("token_endpoint", "https://"+neverHost+neverPath+" x"), "visible ASCII"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "apps.json")
			write(t, path, tc.content, 0o600)
			_, err := Load(Config{Path: path})
			if err == nil {
				t.Fatal("被接受了")
			}
			if !strings.Contains(err.Error(), tc.says) {
				t.Errorf("错误是 %q，期望提到 %q", err, tc.says)
			}
			notInError(t, err)
		})
	}
}

// notInError 查被拒绝的文件的错误信息里没有文件的内容：应用密钥、AES 密钥、令牌端点的地址。
func notInError(t *testing.T, err error) {
	t.Helper()
	text := err.Error()
	for _, leaked := range []string{neverSecret, "never-shown", neverAES[:20], neverAES, neverHost, neverPath, "https://", "http://", "appSecret"} {
		if strings.Contains(text, leaked) {
			t.Errorf("错误信息带出了文件内容 %q：%v", leaked, err)
		}
	}
}

// 一个句柄只能在一个凭证来源里：Load 时查，重读时也查（见 TestReplacedFiles）。
func TestAHandleHeldByAnotherSourceIsRefused(t *testing.T) {
	path := filepath.Join(t.TempDir(), "apps.json")
	write(t, path, withField("key_version", "v1"), 0o600)
	taken := func(handle string) bool { return handle == "b/a" }
	_, err := Load(Config{Path: path, Reserved: taken})
	if err == nil || !strings.Contains(err.Error(), "one source only") {
		t.Fatalf("被别的来源占着的句柄：%v", err)
	}
	notInError(t, err)
	// 占着的是别的句柄：不碍事。
	if _, err := Load(Config{Path: path, Reserved: func(h string) bool { return h == "b/other" }}); err != nil {
		t.Error(err)
	}
	if _, err := Load(Config{Path: path, Reserved: func(string) bool { return false }}); err != nil {
		t.Error(err)
	}
}

// 承运商取了新令牌就让旧令牌失效：同一个 appKey 在两个句柄下，两个缓存条目会互相作废。
func TestTheSameAppKeyUnderTwoHandlesIsRefused(t *testing.T) {
	const shared = "appkey-shared-9999"
	load := func(a, b string) error {
		path := filepath.Join(t.TempDir(), "apps.json")
		one, other := blueApp("https://"+neverHost+neverPath), greenApp("https://"+neverHost+neverPath)
		one.AppKey, other.AppKey = a, b
		write(t, path, fileOf(entryJSON("b/one", one), entryJSON("b/other", other)), 0o600)
		_, err := Load(Config{Path: path})
		return err
	}
	err := load(shared, shared)
	if err == nil || !strings.Contains(err.Error(), "same app_key") {
		t.Fatalf("%v", err)
	}
	if !strings.Contains(err.Error(), `"b/one"`) || !strings.Contains(err.Error(), `"b/other"`) {
		t.Errorf("错误信息没有点出两个句柄：%v", err)
	}
	if strings.Contains(err.Error(), shared) {
		t.Errorf("错误信息里有 appKey：%v", err)
	}
	notInError(t, err)
	// 只差一个字母也是两个 appKey。
	if err := load(shared, shared+"x"); err != nil {
		t.Error(err)
	}
	if err := load(shared, strings.ToUpper(shared)); err != nil {
		t.Error(err)
	}
}

func TestTokenEndpointMustBeHTTPSOrLoopbackHTTP(t *testing.T) {
	accepted := []string{
		"https://api-ifsp.sf.global/openapi/api/token", "https://auth.example:8443/t", "https://10.0.0.1/t", "https://localhost/t",
		"http://127.0.0.1:9/openapi/api/token", "http://127.1.2.3/t", "http://[::1]:9/t", "https://[::1]/t",
	}
	rejected := map[string]string{
		"http://auth.example/t":          "https",
		"http://localhost/t":             "https",
		"http://localhost:9/t":           "https",
		"http://localhost.example/t":     "https",
		"http://10.0.0.1/t":              "https",
		"http://128.0.0.1/t":             "https",
		"http://0.0.0.0/t":               "https",
		"http://[::ffff:127.0.0.1]/t":    "https",
		"http://[::2]/t":                 "https",
		"http://2130706433/t":            "https",
		"ftp://127.0.0.1/t":              "https",
		"HTTP://auth.example/t":          "https",
		"https://user@auth.example/t":    "user information",
		"https://user:pw@auth.example/t": "user information",
		"http://user@127.0.0.1/t":        "user information",
		"https://auth.example/t?x=1":     "query",
		"https://auth.example/t?":        "query",
		"https://auth.example/t#frag":    "fragment",
		"https://auth.example/t#":        "fragment",
		"https://":                       "host",
		"/openapi/api/token":             "host",
		"auth.example/t":                 "host",
		"":                               "visible",
		"https://auth.example/ t":        "visible",
	}
	for _, endpoint := range accepted {
		if err := checkEndpoint(endpoint, ""); err != nil {
			t.Errorf("%s：%v", endpoint, err)
		}
	}
	for endpoint, says := range rejected {
		err := checkEndpoint(endpoint, "")
		if err == nil || !strings.Contains(err.Error(), says) {
			t.Errorf("%q：%v，期望提到 %q", endpoint, err, says)
			continue
		}
		if len(endpoint) > 3 && strings.Contains(err.Error(), endpoint) || strings.Contains(err.Error(), "pw@") || strings.Contains(err.Error(), "auth.example") {
			t.Errorf("%q：错误信息里有地址的内容：%v", endpoint, err)
		}
	}
}

// 沙箱没有 TLS：按主机名放开的那一个例外。
func TestPlainHTTPExceptionIsByWholeHostNameOnly(t *testing.T) {
	const sandbox = "http://sandbox.example.test" + tokenPath
	cases := []struct {
		name     string
		host     string // Config.PlainHTTPHost
		endpoint string
		accepted bool
	}{
		{"没有例外时明文 http 被拒绝", "", sandbox, false},
		{"给了主机名就接受", "sandbox.example.test", sandbox, true},
		{"配置里的大小写不同", "SANDBOX.Example.TEST", sandbox, true},
		{"地址里的大小写不同", "sandbox.example.test", "http://Sandbox.EXAMPLE.test" + tokenPath, true},
		{"带端口", "sandbox.example.test", "http://sandbox.example.test:8080" + tokenPath, true},
		{"后缀不算", "example.test", sandbox, false},
		{"别的主机名", "other.test", sandbox, false},
		{"主机名只是配置的前缀", "sandbox.example.test", "http://sandbox.example.test.evil.test" + tokenPath, false},
		{"主机名只是配置的后缀", "sandbox.example.test", "http://evil-sandbox.example.test" + tokenPath, false},
		{"配置的主机名的子域名", "sandbox.example.test", "http://x.sandbox.example.test" + tokenPath, false},
		{"配置的主机名带尾点", "sandbox.example.test", "http://sandbox.example.test." + tokenPath, false},
		{"配置的是通配符", "*.example.test", sandbox, false},
		{"配置的是空白", " ", sandbox, false},
		{"用户信息骗主机名", "sandbox.example.test", "http://sandbox.example.test@evil.test" + tokenPath, false},
		{"例外不放开用户信息", "sandbox.example.test", "http://user@sandbox.example.test" + tokenPath, false},
		{"例外不放开查询串", "sandbox.example.test", sandbox + "?appSecret=x", false},
		{"例外不放开片段", "sandbox.example.test", sandbox + "#x", false},
		{"例外只对 http，不碍 https", "sandbox.example.test", "https://sandbox.example.test" + tokenPath, true},
		{"开尔文符号不等于 k（只折 ASCII 大小写）", "\u212aandbox.example.test", "http://kandbox.example.test" + tokenPath, false},
		{"回环字面量不需要例外", "", "http://127.0.0.1:34567" + tokenPath, true},
		{"回环字面量，配了别的主机名也一样", "other.test", "http://127.0.0.1:34567" + tokenPath, true},
		{"回环 ::1 字面量", "", "http://[::1]:34567" + tokenPath, true},
		{"localhost 不算回环字面量", "", "http://localhost:34567" + tokenPath, false},
		{"localhost，配了别的主机名", "other.test", "http://localhost:34567" + tokenPath, false},
		{"远端 IP 不算", "sandbox.example.test", "http://192.0.2.1" + tokenPath, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "apps.json")
			write(t, path, fileOf(entryJSON("b/a", blueApp(tc.endpoint))), 0o600)
			_, err := Load(Config{Path: path, PlainHTTPHost: tc.host})
			if (err == nil) != tc.accepted {
				t.Fatalf("PlainHTTPHost %q，令牌端点 %s：%v，期望接受=%v", tc.host, tc.endpoint, err, tc.accepted)
			}
			if err != nil {
				if strings.Contains(err.Error(), tc.endpoint) || strings.Contains(err.Error(), "sandbox.example.test") {
					t.Errorf("错误信息里有地址：%v", err)
				}
			}
		})
	}
}

// 例外也管重读：新文件里的 http 端点不在例外之内，整份不要。
func TestPlainHTTPExceptionAlsoGuardsReloads(t *testing.T) {
	ep := newEndpoint(t)
	f := newFixture(t, two(ep.tokenURL()), func(c *Config) { c.PlainHTTPHost = "sandbox.example.test" })
	first, _ := f.get(blueHandle)
	write(t, f.path, fileOf(entryJSON(blueHandle, blueApp("http://evil.example.test"+tokenPath))), 0o600)
	if got, err := f.get(blueHandle); err != nil || got != first || f.lines("sf openapi apps file did not load") != 1 {
		t.Fatalf("%q %v\n%s", got, err, f.logs.String())
	}
	// 例外之内的新文件读得进来。这里只触发重读，不去取令牌：那个主机名不该被真的联系。
	write(t, f.path, fileOf(entryJSON(blueHandle, blueApp("http://sandbox.example.test"+tokenPath))), 0o600)
	if f.c.Len() != 1 || f.lines("sf openapi apps file loaded again") != 1 ||
		f.c.entries[blueHandle].tokenEndpoint != "http://sandbox.example.test"+tokenPath {
		t.Fatalf("新文件没有生效：\n%s", f.logs.String())
	}
}

func TestEqualASCIIFold(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		want bool
	}{
		{"", "", true}, {"a", "A", true}, {"Sandbox.Example", "sandbox.example", true}, {"a", "b", false},
		{"a", "aa", false}, {"k", "\u212a", false}, {"s", "\u017f", false}, {"a-b", "A_B", false},
	} {
		if got := equalASCIIFold(tc.a, tc.b); got != tc.want {
			t.Errorf("%q %q：%v", tc.a, tc.b, got)
		}
	}
}

func TestEveryFieldNameIsListedInTheFixture(t *testing.T) {
	// withField 里改的字段名拼错了，被拒绝的原因就会是"不认识的字段"而不是想测的那一条。
	for _, name := range []string{"token_endpoint", "app_key", "app_secret", "encoding_aes_key", "key_version"} {
		if _, ok := fieldsOf()[name]; !ok {
			t.Errorf("%s", name)
		}
	}
	path := filepath.Join(t.TempDir(), "apps.json")
	write(t, path, withField("key_version", "v1"), 0o600)
	if _, err := Load(Config{Path: path}); err != nil {
		t.Fatal(fmt.Errorf("样板文件本身要能读进来：%w", err))
	}
}
