package main

// issue-publisher-cert 签发或轮换发布器出示给网关回读口的客户端证书（ADR-0010 V1.10）。
// 网关信任的是 --ca-cert 这张 CA。同一张 CA 再签一张叶子，不用改网关配置，也不用重启网关。
// 网关的服务端证书不换，锁定的镜像不动。正在跑的进程不重载 TLS；下一次 gateway-control 读新文件。
//
//	gateway-control issue-publisher-cert --ca-cert <pem> --ca-key <pem> --identity <spiffe URI> --out-cert <path> --out-key <path> [--days 30]
//
// 两个输出路径都不存在时新建（证书 0644，私钥 0600）。两个都存在时是轮换：新叶子核对过能链上这张 CA、
// 且只有这一个 URI 之后才换上去，原来的一对留在 <路径>.previous，不删除。
//
// 标准输出一行 JSON：outcome（ISSUED 或 ROTATED）、identity、not_after（RFC3339，UTC）。不打印私钥。
//
// 退出码：
//
//	0  写成了
//	1  拒绝：身份不是单个 spiffe:// URI、天数不在 1 到 825、CA 私钥与证书不配对、
//	   CA 证书不是 CA、输出路径里有环境变量引用，或文件写不成。原因在标准错误上，没有 JSON
//	2  命令行写得不对

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"go.idp.xyz/idp-gateway/internal/platform/workloadtls"
)

const commandIssuePublisherCert = "issue-publisher-cert"

func runIssuePublisherCert(args []string, stdout, stderr io.Writer) int {
	req, err := parseIssuePublisherCert(args, stderr)
	if err != nil {
		if !errors.Is(err, flag.ErrHelp) {
			fmt.Fprintln(stderr, "gateway-control:", err)
		}
		return exitUsage
	}
	result, err := workloadtls.IssuePublisherCert(req)
	if err != nil {
		fmt.Fprintln(stderr, "gateway-control:", err)
		return exitError
	}
	if err := json.NewEncoder(stdout).Encode(publisherCertLine{
		Outcome:  result.Outcome,
		Identity: result.Identity,
		NotAfter: result.NotAfter.UTC().Format(time.RFC3339),
	}); err != nil {
		fmt.Fprintln(stderr, "gateway-control:", err)
		return exitError
	}
	return exitActive
}

type publisherCertLine struct {
	Outcome  string `json:"outcome"`
	Identity string `json:"identity"`
	NotAfter string `json:"not_after"`
}

func parseIssuePublisherCert(args []string, output io.Writer) (workloadtls.PublisherCertRequest, error) {
	var req workloadtls.PublisherCertRequest
	flags := flag.NewFlagSet("gateway-control "+commandIssuePublisherCert, flag.ContinueOnError)
	flags.SetOutput(output)
	flags.StringVar(&req.CACertFile, "ca-cert", "", "签发用的 CA 证书（PEM）。必须是 CA，且与 --ca-key 配对")
	flags.StringVar(&req.CAKeyFile, "ca-key", "", "这张 CA 的私钥（PEM）")
	flags.StringVar(&req.Identity, "identity", "", "叶子的唯一身份，一个 spiffe:// URI")
	flags.StringVar(&req.OutCert, "out-cert", "", "写出的叶子证书（PEM），权限 0644")
	flags.StringVar(&req.OutKey, "out-key", "", "写出的叶子私钥（PEM），权限 0600")
	flags.IntVar(&req.Days, "days", 30, "叶子的有效天数，1 到 825")
	if err := flags.Parse(args); err != nil {
		return req, err
	}
	if flags.NArg() > 0 {
		return req, fmt.Errorf("unexpected argument %q", flags.Arg(0))
	}
	required := map[string]*string{
		"ca-cert": &req.CACertFile, "ca-key": &req.CAKeyFile, "identity": &req.Identity,
		"out-cert": &req.OutCert, "out-key": &req.OutKey,
	}
	var missing []string
	flags.VisitAll(func(f *flag.Flag) {
		if target, ok := required[f.Name]; ok && *target == "" {
			missing = append(missing, "--"+f.Name)
		}
	})
	if len(missing) > 0 {
		return req, errors.New("missing required flags: " + strings.Join(missing, ", "))
	}
	return req, nil
}
