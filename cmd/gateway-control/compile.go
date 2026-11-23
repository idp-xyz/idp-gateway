package main

// compile 把一份出站编译规格或入口编译规格变成 agentgateway 配置和一份策略 JSON，
// 或者只做 RouteIntent 预检（scripts/preflight_intents.py 的 Go 版）。
//
//	gateway-control compile --spec <规格> --output-gateway <yaml> --output-policy <json> [--agentgateway <二进制>] [--lock-file <锁>] [--tls-dir <目录>]
//	gateway-control compile --preflight-only --intents <意图.json> [--provider-registry <登记表>]
//
// --spec 的文件是出站规格、入口规格（traffic_class 为字符串 INGRESS），
// 或 AI 规格（traffic_class 为字符串 AI）。没有这个字段的文档仍走出站解析。
// 入口和 AI 都写出网关 YAML，以及一份没有承运商操作的策略文件。
// --output-policy 仍然必填。
//
// 编译成功时标准输出一行 JSON：outcome 为 COMPILED，带着路由条数和两份摘要。
// native_validated 只在给了 --agentgateway 并且 --validate-only 通过时为 true。校验不过就不写文件。
//
// 预检成功时写出与脚本相同的报告，status 为 STATIC_PREFLIGHT_OK_NOT_DEPLOYABLE。
// 不给 --provider-registry 时，从当前目录向上找 contracts/gateway/policies/egress-policy.example.json；
// 找不到就按空登记表处理，出站意图会被拒绝。
//
// 退出码：
//
//	0  编译完成，或预检没有问题
//	1  读写出错，或 agentgateway 二进制起不来。预检失败时没有写文件
//	2  命令行写得不对
//	3  REFUSED：规格、预检或原生校验拒绝。什么文件都没有写

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"go.idp.xyz/idp-gateway/internal/routecompile/adapters/binaryvalidator"
	"go.idp.xyz/idp-gateway/internal/routecompile/application"
	"go.idp.xyz/idp-gateway/internal/routecompile/domain"
)

func runCompile(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	var (
		specPath   string
		gatewayOut string
		policyOut  string
		binary     string
		lockFile   string
		tlsDir     string
		preflight  bool
		intents    string
		registry   string
	)
	flags := flag.NewFlagSet("gateway-control compile", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.StringVar(&specPath, "spec", "", "编译规格 JSON：出站、入口（INGRESS）或 AI")
	flags.StringVar(&gatewayOut, "output-gateway", "", "写出的 agentgateway YAML")
	flags.StringVar(&policyOut, "output-policy", "", "写出的 gateway-authz 登记表 JSON")
	flags.StringVar(&binary, "agentgateway", "", "用来 --validate-only 的 agentgateway 二进制；不给就不做原生校验")
	flags.StringVar(&lockFile, "lock-file", "", "核对二进制 SHA-256 的锁文件；要和 --agentgateway 一起给")
	flags.StringVar(&tlsDir, "tls-dir", "", "校验时用的证书目录；不给就用临时证书，只为 --validate-only")
	flags.BoolVar(&preflight, "preflight-only", false, "只做 RouteIntent 预检，不生成配置。有问题时退出码 3（REFUSED），不是脚本的 2")
	flags.StringVar(&intents, "intents", "", "预检的意图 JSON，一个对象或一个数组")
	flags.StringVar(&registry, "provider-registry", "", "预检用的登记表；不给就找仓库里的 egress-policy.example.json")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitUsage
		}
		fmt.Fprintln(stderr, "gateway-control:", err)
		return exitUsage
	}
	if flags.NArg() > 0 {
		fmt.Fprintf(stderr, "gateway-control: unexpected argument %q\n", flags.Arg(0))
		return exitUsage
	}
	if preflight {
		if specPath != "" || gatewayOut != "" || policyOut != "" || binary != "" || lockFile != "" || tlsDir != "" {
			fmt.Fprintln(stderr, "gateway-control: --preflight-only does not take compile outputs or --agentgateway")
			return exitUsage
		}
		if intents == "" {
			fmt.Fprintln(stderr, "gateway-control: missing required flags: --intents")
			return exitUsage
		}
		return runPreflight(intents, registry, stdout, stderr)
	}
	if intents != "" || registry != "" {
		fmt.Fprintln(stderr, "gateway-control: --intents and --provider-registry are only for --preflight-only")
		return exitUsage
	}
	if lockFile != "" && binary == "" {
		fmt.Fprintln(stderr, "gateway-control: --lock-file requires --agentgateway")
		return exitUsage
	}
	var missing []string
	if specPath == "" {
		missing = append(missing, "--spec")
	}
	if gatewayOut == "" {
		missing = append(missing, "--output-gateway")
	}
	if policyOut == "" {
		missing = append(missing, "--output-policy")
	}
	if len(missing) > 0 {
		fmt.Fprintln(stderr, "gateway-control: missing required flags:", strings.Join(missing, ", "))
		return exitUsage
	}
	data, err := os.ReadFile(specPath)
	if err != nil {
		fmt.Fprintln(stderr, "gateway-control:", err)
		return exitError
	}
	compiler := application.Compiler{}
	if binary != "" {
		compiler.Validator = binaryvalidator.Validator{Binary: binary, LockFile: lockFile}
	}
	vctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	var result application.Result
	switch {
	case domain.IngressDocument(data):
		spec, parseErr := domain.ParseIngressSpec(data)
		if parseErr != nil {
			return compileError(parseErr, stdout, stderr)
		}
		result, err = compiler.CompileIngress(vctx, spec, gatewayOut, policyOut, tlsDir, "")
	case domain.AIDocument(data):
		spec, parseErr := domain.ParseAISpec(data)
		if parseErr != nil {
			return compileError(parseErr, stdout, stderr)
		}
		result, err = compiler.CompileAI(vctx, spec, gatewayOut, policyOut, tlsDir, "")
	default:
		spec, parseErr := domain.ParseSpec(data)
		if parseErr != nil {
			return compileError(parseErr, stdout, stderr)
		}
		result, err = compiler.Compile(vctx, spec, gatewayOut, policyOut, tlsDir, "")
	}
	if err != nil {
		return compileError(err, stdout, stderr)
	}
	return writeJSONLine(stdout, stderr, compileLine{
		Outcome: "COMPILED", Routes: result.Artifacts.RouteCount,
		GatewaySHA256: result.Artifacts.GatewaySHA256, PolicySHA256: result.Artifacts.PolicySHA256,
		NativeValidated: result.NativeValidated,
	})
}

type compileLine struct {
	Outcome         string         `json:"outcome"`
	Routes          int            `json:"routes,omitempty"`
	GatewaySHA256   string         `json:"gateway_sha256,omitempty"`
	PolicySHA256    string         `json:"policy_sha256,omitempty"`
	NativeValidated bool           `json:"native_validated"`
	Issues          []domain.Issue `json:"issues,omitempty"`
}

func runPreflight(intentsPath, registryPath string, stdout, stderr io.Writer) int {
	data, err := os.ReadFile(intentsPath)
	if err != nil {
		fmt.Fprintln(stderr, "gateway-control:", err)
		return exitError
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var doc any
	if err := dec.Decode(&doc); err != nil {
		fmt.Fprintln(stderr, "gateway-control:", err)
		return exitError
	}
	var items []any
	switch t := doc.(type) {
	case []any:
		items = t
	case map[string]any:
		items = []any{t}
	default:
		fmt.Fprintln(stderr, "gateway-control: intents must be a JSON object or array")
		return exitError
	}
	var registry *domain.Registry
	if registryPath == "" {
		found, findErr := defaultRegistry()
		if findErr == nil {
			registryPath = found
		}
	}
	if registryPath != "" {
		raw, err := os.ReadFile(registryPath)
		if err != nil {
			fmt.Fprintln(stderr, "gateway-control:", err)
			return exitError
		}
		registry, err = domain.ParseRegistry(raw)
		if err != nil {
			fmt.Fprintln(stderr, "gateway-control:", err)
			return exitError
		}
	}
	report := domain.EvaluateItems(items, registry, domain.PreflightOptions{})
	enc := json.NewEncoder(stdout)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(report); err != nil {
		fmt.Fprintln(stderr, "gateway-control:", err)
		return exitError
	}
	if report.IssueCount > 0 {
		return exitNotDone
	}
	return exitActive
}

func defaultRegistry() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		candidate := filepath.Join(dir, "contracts", "gateway", "policies", "egress-policy.example.json")
		if st, err := os.Stat(candidate); err == nil && !st.IsDir() {
			return candidate, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", errors.New("provider registry not found")
		}
		dir = parent
	}
}

func compileError(err error, stdout, stderr io.Writer) int {
	var refused *domain.Refusal
	if errors.As(err, &refused) {
		if writeJSONLine(stdout, stderr, compileLine{Outcome: "REFUSED", Issues: refused.Issues}) != exitActive {
			return exitError
		}
		return exitNotDone
	}
	fmt.Fprintln(stderr, "gateway-control:", err)
	return exitError
}

func writeJSONLine(stdout, stderr io.Writer, payload any) int {
	enc := json.NewEncoder(stdout)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(payload); err != nil {
		fmt.Fprintln(stderr, "gateway-control:", err)
		return exitError
	}
	return exitActive
}
