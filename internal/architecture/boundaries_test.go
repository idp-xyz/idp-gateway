// Package architecture 用测试守住 docs/adr/ADR-0009.md 定下的包边界。这里没有产品代码。
package architecture

import (
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"go.idp.xyz/idp-gateway/internal/egressauthz/domain"
)

const (
	module   = "go.idp.xyz/idp-gateway"
	bentoGo  = "go.idp.xyz/idp-bento-go"
	repoRoot = "../.."
)

// requestPath 是在出站请求路径上的包：每一次出站调用都要等它们答完。
var requestPath = []string{"internal/egressauthz", "internal/platform/workloadtls", "cmd/gateway-authz"}

// notInDomain 是 domain 包不得导入的标准库包：规则不做 I/O，不认识传输协议，不写日志。
var notInDomain = []string{"net", "net/http", "os", "os/exec", "io/fs", "log", "log/slog", "database/sql", "syscall"}

type sourceFile struct {
	path    string // 相对仓库根，正斜杠
	pkg     string // 所在目录，相对仓库根
	test    bool
	imports []string
}

func sources(t *testing.T) []sourceFile {
	t.Helper()
	var files []sourceFile
	for _, top := range []string{"cmd", "internal"} {
		err := filepath.WalkDir(filepath.Join(repoRoot, top), func(path string, entry fs.DirEntry, err error) error {
			if err != nil || entry.IsDir() || !strings.HasSuffix(path, ".go") {
				return err
			}
			parsed, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
			if err != nil {
				return err
			}
			relative, err := filepath.Rel(repoRoot, path)
			if err != nil {
				return err
			}
			relative = filepath.ToSlash(relative)
			file := sourceFile{path: relative, pkg: relative[:strings.LastIndex(relative, "/")], test: strings.HasSuffix(relative, "_test.go")}
			for _, spec := range parsed.Imports {
				imported, err := strconv.Unquote(spec.Path.Value)
				if err != nil {
					return err
				}
				file.imports = append(file.imports, imported)
			}
			files = append(files, file)
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if len(files) == 0 {
		t.Fatal("没有找到任何 Go 源文件：repoRoot 指错了地方")
	}
	return files
}

// local 把导入路径换成相对仓库根的目录；不是本模块的包返回 false。
func local(imported string) (string, bool) {
	if imported == module {
		return "", true
	}
	return strings.CutPrefix(imported, module+"/")
}

func standardLibrary(imported string) bool {
	first, _, _ := strings.Cut(imported, "/")
	return !strings.Contains(first, ".")
}

func within(pkg, dir string) bool { return pkg == dir || strings.HasPrefix(pkg, dir+"/") }

// context 返回包所属的限界上下文和它在其中的层；不在任何上下文里时 ok 为 false。
// internal/platform 和 internal/architecture 不是上下文。
func context(pkg string) (name, layer string, ok bool) {
	rest, found := strings.CutPrefix(pkg, "internal/")
	if !found {
		return "", "", false
	}
	parts := strings.Split(rest, "/")
	if parts[0] == "platform" || parts[0] == "architecture" {
		return "", "", false
	}
	if len(parts) > 1 {
		layer = parts[1]
	}
	return parts[0], layer, true
}

func TestContextsAreLayered(t *testing.T) {
	// 每一层可以导入本上下文的哪些层。adapters 之间可以互相导入，wiring 在 cmd 里。
	allowed := map[string][]string{
		"domain":      {"domain"},
		"ports":       {"domain", "ports"},
		"application": {"domain", "ports", "application"},
		"adapters":    {"domain", "ports", "application", "adapters"},
	}
	for _, file := range sources(t) {
		name, layer, ok := context(file.pkg)
		if !ok {
			continue
		}
		layers, known := allowed[layer]
		if !known {
			t.Errorf("%s: 上下文 %s 里只能有 domain、ports、application、adapters 四层", file.path, name)
			continue
		}
		for _, imported := range file.imports {
			target, isLocal := local(imported)
			if !isLocal {
				continue
			}
			otherName, otherLayer, inContext := context(target)
			if !inContext {
				continue
			}
			if otherName != name {
				t.Errorf("%s: 上下文 %s 直接导入了上下文 %s（%s）", file.path, name, otherName, imported)
				continue
			}
			permitted := false
			for _, l := range layers {
				permitted = permitted || l == otherLayer
			}
			if !permitted {
				t.Errorf("%s: %s 层导入了 %s 层（%s）", file.path, layer, otherLayer, imported)
			}
		}
	}
}

func TestDomainIsPureRules(t *testing.T) {
	for _, file := range sources(t) {
		if _, layer, ok := context(file.pkg); !ok || layer != "domain" {
			continue
		}
		for _, imported := range file.imports {
			if _, isLocal := local(imported); isLocal {
				continue // 由 TestContextsAreLayered 管
			}
			if !standardLibrary(imported) {
				t.Errorf("%s: domain 导入了第三方包 %s", file.path, imported)
			}
			if file.test {
				continue
			}
			for _, banned := range notInDomain {
				if imported == banned {
					t.Errorf("%s: domain 导入了 %s", file.path, imported)
				}
			}
		}
	}
}

func TestPlatformKnowsNoContext(t *testing.T) {
	for _, file := range sources(t) {
		if !within(file.pkg, "internal/platform") {
			continue
		}
		for _, imported := range file.imports {
			if target, isLocal := local(imported); isLocal && !within(target, "internal/platform") {
				t.Errorf("%s: platform 导入了 %s", file.path, imported)
			}
		}
	}
}

// 请求路径上只有标准库和本模块：不连数据库，不带 Bento-Go，也没有别的第三方依赖。
func TestRequestPathUsesTheStandardLibraryOnly(t *testing.T) {
	checked := 0
	for _, file := range sources(t) {
		onPath := false
		for _, dir := range requestPath {
			onPath = onPath || within(file.pkg, dir)
		}
		if !onPath {
			continue
		}
		checked++
		for _, imported := range file.imports {
			if _, isLocal := local(imported); !isLocal && !standardLibrary(imported) {
				t.Errorf("%s: 请求路径导入了 %s", file.path, imported)
			}
			if imported == "database/sql" {
				t.Errorf("%s: 请求路径导入了 database/sql", file.path)
			}
		}
	}
	if checked == 0 {
		t.Fatal("请求路径上一个文件都没有检查到")
	}
}

// Bento-Go 只出现在控制面上下文的 adapters 和装配它们的 cmd 里。
func TestBentoGoStaysInAdaptersAndWiring(t *testing.T) {
	for _, file := range sources(t) {
		for _, imported := range file.imports {
			if imported != bentoGo && !strings.HasPrefix(imported, bentoGo+"/") {
				continue
			}
			_, layer, inContext := context(file.pkg)
			if !(inContext && layer == "adapters") && !within(file.pkg, "cmd") {
				t.Errorf("%s: 在 adapters 和 cmd 之外导入了 %s", file.path, imported)
			}
		}
	}
}

func TestTestHelpersStayOutOfProductCode(t *testing.T) {
	for _, file := range sources(t) {
		if file.test || strings.HasSuffix(file.pkg, "test") {
			continue
		}
		for _, imported := range file.imports {
			if imported == "testing" || strings.HasSuffix(imported, "test") {
				t.Errorf("%s: 产品代码导入了测试用的包 %s", file.path, imported)
			}
		}
	}
}

// 验收用的控制接口只能存在于带 acceptance 标签的文件里，而且只在 cmd 下。
func TestAcceptanceControlsAreBehindTheBuildTag(t *testing.T) {
	marker := regexp.MustCompile(`(?m)^//go:build (.+)$`)
	tagged := 0
	for _, file := range sources(t) {
		raw, err := os.ReadFile(filepath.Join(repoRoot, filepath.FromSlash(file.path)))
		if err != nil {
			t.Fatal(err)
		}
		constraint := ""
		if match := marker.FindSubmatch(raw); match != nil {
			constraint = string(match[1])
		}
		if constraint == "acceptance" {
			tagged++
			if !within(file.pkg, "cmd") {
				t.Errorf("%s: 带 acceptance 标签的文件只能在 cmd 下", file.path)
			}
			continue
		}
		if file.test {
			continue
		}
		for _, word := range []string{"/admin/", "X-Poc-Admin", "GATEWAY_AUTHZ_ACCEPTANCE", "injected_pdp_failure"} {
			if strings.Contains(string(raw), word) {
				t.Errorf("%s: 产品构建的源文件里出现了验收控制的痕迹 %q", file.path, word)
			}
		}
	}
	if tagged == 0 {
		t.Fatal("没有找到带 acceptance 标签的文件：这条测试已经不在检查任何东西")
	}
}

// 网关路由上判断路径是否规范的表达式，和服务里的必须是同一个。两边不一致时，
// 网关放过去的路径服务会拒绝，或者反过来。
func TestGatewayRoutesUseTheSameCanonicalPathRule(t *testing.T) {
	rule := regexp.MustCompile(`request\.path\.matches\("([^"]*)"\)`)
	configs, err := filepath.Glob(filepath.Join(repoRoot, "tests/acceptance/blackbox/agentgateway.poc*.yaml"))
	if err != nil || len(configs) == 0 {
		t.Fatalf("没有找到黑盒套件的网关配置：%v", err)
	}
	for _, config := range configs {
		raw, err := os.ReadFile(config)
		if err != nil {
			t.Fatal(err)
		}
		found := rule.FindAllSubmatch(raw, -1)
		if len(found) == 0 {
			t.Errorf("%s: 没有任何路由带规范路径规则", filepath.Base(config))
		}
		for _, match := range found {
			if string(match[1]) != domain.CanonicalPathPattern {
				t.Errorf("%s: 路由上的表达式是 %s，服务里的是 %s", filepath.Base(config), match[1], domain.CanonicalPathPattern)
			}
		}
	}
}
