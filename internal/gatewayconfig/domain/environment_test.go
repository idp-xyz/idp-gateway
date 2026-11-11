package domain

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func references(t *testing.T, text string) []string {
	t.Helper()
	snapshot, err := NewSnapshot([]byte(text))
	if err != nil {
		t.Fatal(err)
	}
	return snapshot.EnvironmentReferences()
}

// 左边的写法，锁定版本的网关都会拿环境变量去换（或者因为没有这个变量而加载失败）。
// 这张表与 tests/integration/compose 的 SH-08 在真的网关上看到的一致。
func TestEnvironmentReferencesAreFound(t *testing.T) {
	for text, want := range map[string][]string{
		"name: probe-$EXPANDME-end":             {"$EXPANDME"},
		"name: probe-${EXPANDME}-end":           {"${EXPANDME}"},
		"name: probe-${EXPANDME:-fallback}-end": {"${EXPANDME:-fallback}"},
		"name: probe-$1-end":                    {"$1"},
		"name: probe-${}-end":                   {"${}"},
		"name: $_private":                       {"$_private"},
		"name: $SESSION_KEY":                    {"$SESSION_KEY"},
		// 反斜杠不是转义。
		`name: probe-\$EXPANDME-end`: {"$EXPANDME"},
		// 三个 $：前两个是字面的 $，第三个开始一个名字。
		"name: $$$EXPANDME": {"$EXPANDME"},
		// 引号、注释、JSON 里的都一样：替换发生在解析之前。
		`{"routes":[{"name":"a-${HOME}"}]}`: {"${HOME}"},
		"# see $HOME\nroutes: []":           {"$HOME"},
		// 非 ASCII 的名字。
		"name: $变量-end": {"$变量"},
		// 没有合上的花括号：网关要看后文有没有 }，这里不管，一律算。
		"name: ${EXPANDME\nroutes: []": {"${EXPANDME"},
		"name: ${EXPANDME":             {"${EXPANDME"},
		// 去重，按出现的先后。
		"a: $B\nb: $A\nc: $B\nd: ${A}": {"$B", "$A", "${A}"},
	} {
		if got := references(t, text); !reflect.DeepEqual(got, want) {
			t.Errorf("%q：得到 %q，应该是 %q", text, got, want)
		}
	}
}

func TestWhatTheGatewayLeavesAloneIsNotAReference(t *testing.T) {
	for _, text := range []string{
		"routes: []",
		// 正则里结尾的 $：出站路由上的规范路径规则就是这样写的。
		`- allow: 'request.path.matches("^(/[A-Za-z0-9_~-][A-Za-z0-9._~-]*)+$")'`,
		"name: ends-with-$",
		"name: probe-$-x",
		"name: probe-$ EXPANDME",
		"name: a$|b$)c$.d$,e$'",
		// $$ 是字面的 $，后面跟着的不是名字。
		"name: probe-$$EXPANDME-end",
		"name: $$$$EXPANDME",
		"name: $${EXPANDME}",
		"price: 5$$",
		"name: probe-~-end",
		// 上游在替换之前先拿掉的那一处注释。
		"# yaml-language-server: $schema=https://agentgateway.dev/schema/config\nroutes: []",
	} {
		if got := references(t, text); len(got) != 0 {
			t.Errorf("%q：被当成了引用 %q", text, got)
		}
	}
	// 那处注释之外的 $schema 仍然算。
	if got := references(t, "# yaml-language-server: $schema=x\nname: $schema"); !reflect.DeepEqual(got, []string{"$schema"}) {
		t.Errorf("得到 %q", got)
	}
}

func TestEnvironmentReferencesAreBounded(t *testing.T) {
	// 至多 5 处。
	if got := references(t, "$A $B $C $D $E $F $G"); !reflect.DeepEqual(got, []string{"$A", "$B", "$C", "$D", "$E"}) {
		t.Errorf("得到 %q", got)
	}
	// 每一处至多 48 字节，截断处不把一个字符切成两半。
	long := references(t, "name: ${"+strings.Repeat("x", 200)+"}")
	if len(long) != 1 || long[0] != "${"+strings.Repeat("x", 46)+"…" {
		t.Errorf("得到 %q", long)
	}
	wide := references(t, "name: $"+strings.Repeat("名", 40))
	if len(wide) != 1 || wide[0] != "$"+strings.Repeat("名", 15)+"…" {
		t.Errorf("得到 %q", wide)
	}
	// 花括号里的写法只取到行尾。
	if got := references(t, "name: ${A\nb: }"); !reflect.DeepEqual(got, []string{"${A"}) {
		t.Errorf("得到 %q", got)
	}
	// 正好 48 字节的不截断。
	exact := "${" + strings.Repeat("y", 45) + "}"
	if got := references(t, exact); !reflect.DeepEqual(got, []string{exact}) {
		t.Errorf("得到 %q", got)
	}
}

// 仓库里现有的网关配置都不带这种写法：这条规则不会把它们挡在外面。
func TestTheRepositorysGatewayConfigurationsHaveNoEnvironmentReferences(t *testing.T) {
	configs, err := filepath.Glob("../../../tests/acceptance/blackbox/agentgateway.poc*.yaml")
	if err != nil || len(configs) == 0 {
		t.Fatalf("没有找到黑盒套件的网关配置：%v", err)
	}
	for _, config := range configs {
		raw, err := os.ReadFile(config)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(raw), "$") {
			continue
		}
		if got := references(t, string(raw)); len(got) != 0 {
			t.Errorf("%s：%q", filepath.Base(config), got)
		}
	}
}
