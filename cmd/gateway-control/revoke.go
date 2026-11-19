package main

// 撤销三条命令：revoke、restore、revocations。各对着一个 gateway-authz 的撤销接口发一次请求
// （docs/adr/ADR-0012.md V1.2）。它们与池无关，不读写配置目录，也不碰 docker。
//
//	gateway-control revoke      --account <账户> --reason <原因> --authz <host:port> --authz-name <名字> --tls-cert … --tls-key … --tls-ca …
//	gateway-control restore     --account <账户> --authz … （其余同上）
//	gateway-control revocations --authz … （其余同上）
//
// 标准输出一行 JSON，标准错误一句给人看的话。结局和退出码：
//
//	0  REVOKED、LIFTED、LISTED：做成了。本来就是这个状态也是（changed 为 false），不算错
//	1  出了错，什么都没有发出去（证书文件读不了之类）。没有 JSON
//	2  命令行写得不对，什么都没做
//	3  什么都没有变：NOT_REVOKER（401，证书不是撤销者的）、NO_REVOKER_CONFIGURED（404）、
//	   UNKNOWN_ACCOUNT（422，多半是名字敲错了）、REQUEST_REFUSED（400）、
//	   LIFT_NOT_WRITTEN（恢复没有写下去，所以没有恢复，账户仍然被撤销）
//	5  UNKNOWN：不知道。没有拿到应答（连不上、TLS 建不起来、超时、中途断了），或者应答看不懂。请求可能到了，
//	   也可能没到，生效没生效不知道。再跑一次同样的命令是安全的；读到表之前不要当作已经撤销
//	7  REVOKED_NOT_WRITTEN：撤销已经生效，账户现在被拒绝，但没有写进撤销文件：gateway-authz 一重启就不是了。
//	   查它的撤销文件为什么写不了，修好之后再跑一次同样的命令
//
// 3 和 5 沿用 publish 等命令的意思（什么都没有做；不知道）；7 是这几条命令才有的。不自动重试。

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"go.idp.xyz/idp-gateway/internal/egressauthz/adapters/revokerclient"
	"go.idp.xyz/idp-gateway/internal/platform/workloadtls"
)

const (
	commandRevoke      = "revoke"
	commandRestore     = "restore"
	commandRevocations = "revocations"

	// exitRevokedNotWritten：撤销已经生效，但没有写下去。
	exitRevokedNotWritten = 7

	// defaultAuthzTimeout 是一次请求最长多久。
	defaultAuthzTimeout = 5 * time.Second
)

func isRevocationCommand(command string) bool {
	return command == commandRevoke || command == commandRestore || command == commandRevocations
}

type revocationOptions struct {
	command string
	account string
	reason  string
	address string
	name    string
	cert    string
	key     string
	ca      string
	timeout time.Duration
}

func parseRevocation(command string, args []string, output io.Writer) (revocationOptions, error) {
	o := revocationOptions{command: command}
	flags := flag.NewFlagSet("gateway-control "+command, flag.ContinueOnError)
	flags.SetOutput(output)
	required := map[string]*string{}
	text := func(target *string, name, usage string) {
		flags.StringVar(target, name, "", usage)
		required[name] = target
	}
	if command != commandRevocations {
		text(&o.account, "account", "要"+map[string]string{commandRevoke: "撤销", commandRestore: "取消撤销"}[command]+"的 Provider 账户")
	}
	if command == commandRevoke {
		text(&o.reason, "reason", "撤销的原因，必填，不能为空；会写进撤销表和 gateway-authz 的日志，不要往里放秘密")
	}
	text(&o.address, "authz", "gateway-authz 的地址，host:port")
	text(&o.name, "authz-name", "gateway-authz 证书上的名字")
	text(&o.cert, "tls-cert", "撤销者的证书（PEM）")
	text(&o.key, "tls-key", "撤销者的私钥（PEM）")
	text(&o.ca, "tls-ca", "签发 gateway-authz 证书的 CA（PEM）")
	flags.DurationVar(&o.timeout, "timeout", defaultAuthzTimeout, "这一次请求最多等多久")
	flags.Usage = func() {
		fmt.Fprintf(output, "Usage of gateway-control %s:\n", command)
		flags.PrintDefaults()
		fmt.Fprint(output, outcomesHelp)
	}
	if err := flags.Parse(args); err != nil {
		return o, err
	}
	if flags.NArg() > 0 {
		return o, fmt.Errorf("unexpected argument %q", flags.Arg(0))
	}
	var missing []string
	flags.VisitAll(func(f *flag.Flag) {
		if target, ok := required[f.Name]; ok && *target == "" {
			missing = append(missing, "--"+f.Name)
		}
	})
	if len(missing) > 0 {
		return o, errors.New("missing required flags: " + strings.Join(missing, ", "))
	}
	if command == commandRevoke && strings.TrimSpace(o.reason) == "" {
		return o, errors.New("--reason must not be blank")
	}
	if host, port, err := net.SplitHostPort(o.address); err != nil || host == "" || port == "" {
		return o, fmt.Errorf("--authz must be host:port, with the host written out; got %q", o.address)
	}
	if o.timeout <= 0 {
		return o, errors.New("--timeout must be positive")
	}
	return o, nil
}

// outcomesHelp 是 --help 末尾的结局表。
const outcomesHelp = `
Standard output is one line of JSON; standard error is one sentence. outcome (exit code):
  REVOKED, LIFTED, LISTED (0)      done; "changed": false means it was in that state already, which is not an error
  NOT_REVOKER (3)                  401: the certificate is not the revoker's; nothing changed
  NO_REVOKER_CONFIGURED (3)        404: this gateway-authz has no revoker configured; nothing changed
  UNKNOWN_ACCOUNT (3)              422: no such account, probably mistyped; nothing changed
  REQUEST_REFUSED (3)              400: the request was not accepted as well-formed; nothing changed
  LIFT_NOT_WRITTEN (3)             500: the change could not be written, so the revocation was NOT lifted
  UNKNOWN (5)                      no answer, or an answer not understood: the request may or may not have taken
                                   effect. Running the same command again is safe; until the table has been read,
                                   do not take an account as revoked. Nothing is retried automatically
  REVOKED_NOT_WRITTEN (7)          500: the account is refused now but the revocation is not in the file, so it is
                                   lost when gateway-authz restarts. Fix the file, then run the same command again
  exit 1: nothing was sent (a certificate file cannot be read, ...), no JSON; exit 2: the command line is wrong
`

// revocationReport 是标准输出上的那一行 JSON。
type revocationReport struct {
	Command         string        `json:"command"`
	Outcome         string        `json:"outcome"`
	Account         string        `json:"account,omitempty"`
	HTTPStatus      int           `json:"http_status,omitempty"`
	Revoked         *bool         `json:"revoked,omitempty"`
	Changed         *bool         `json:"changed,omitempty"`
	RevocationEpoch *uint64       `json:"revocation_epoch,omitempty"`
	RevokedAccounts *[]revokedRow `json:"revoked_accounts,omitempty"`
	Detail          string        `json:"detail,omitempty"`
}

type revokedRow struct {
	AccountID string `json:"account_id"`
	RevokedAt string `json:"revoked_at"`
	RevokedBy string `json:"revoked_by"`
	Reason    string `json:"reason"`
}

func revocationExit(outcome revokerclient.Outcome) int {
	switch outcome {
	case revokerclient.OutcomeRevoked, revokerclient.OutcomeLifted, revokerclient.OutcomeListed:
		return exitActive
	case revokerclient.OutcomeRevokedNotWritten:
		return exitRevokedNotWritten
	case revokerclient.OutcomeNotRevoker, revokerclient.OutcomeNoRevoker, revokerclient.OutcomeUnknownAccount,
		revokerclient.OutcomeRefused, revokerclient.OutcomeLiftNotWritten:
		return exitNotDone
	default: // UNKNOWN，以及任何这里不认识的结局：不认识的不当成成功
		return exitUnknown
	}
}

func runRevocation(ctx context.Context, command string, args []string, stdout, stderr io.Writer) int {
	o, err := parseRevocation(command, args, stderr)
	if err != nil {
		if !errors.Is(err, flag.ErrHelp) {
			fmt.Fprintln(stderr, "gateway-control:", err)
		}
		return exitUsage
	}
	config, err := workloadtls.ClientConfig(o.cert, o.key, o.ca, o.name)
	if err != nil {
		fmt.Fprintln(stderr, "gateway-control:", err)
		return exitError
	}
	client, err := revokerclient.New(revokerclient.Config{Address: o.address, TLS: config, Timeout: o.timeout})
	if err != nil {
		fmt.Fprintln(stderr, "gateway-control:", err)
		return exitError
	}
	var result revokerclient.Result
	switch command {
	case commandRevoke:
		result, err = client.Revoke(ctx, o.account, o.reason)
	case commandRestore:
		result, err = client.Restore(ctx, o.account)
	default:
		result = client.List(ctx)
	}
	if err != nil { // 请求没有发出去
		fmt.Fprintln(stderr, "gateway-control:", err)
		return exitUsage
	}
	if err := json.NewEncoder(stdout).Encode(reportRevocation(command, o.account, result)); err != nil {
		fmt.Fprintln(stderr, "gateway-control:", err)
	}
	fmt.Fprintln(stderr, "gateway-control:", sentence(command, o.account, result))
	return revocationExit(result.Outcome)
}

func reportRevocation(command, account string, result revokerclient.Result) revocationReport {
	report := revocationReport{Command: command, Outcome: string(result.Outcome), HTTPStatus: result.Status, Detail: result.Detail}
	if command != commandRevocations {
		report.Account = account
	}
	if s := result.State; s != nil {
		report.Revoked, report.Changed, report.RevocationEpoch = &s.Revoked, &s.Changed, &s.Epoch
	}
	if t := result.Table; t != nil {
		rows := make([]revokedRow, 0, len(t.Rows))
		for _, row := range t.Rows {
			rows = append(rows, revokedRow{AccountID: row.AccountID, RevokedAt: row.RevokedAt, RevokedBy: row.RevokedBy, Reason: row.Reason})
		}
		report.RevokedAccounts, report.RevocationEpoch = &rows, &t.Epoch
	}
	return report
}

// sentence 是标准错误上的一句话。里面没有证书、私钥，也没有应答正文。
func sentence(command, account string, result revokerclient.Result) string {
	switch result.Outcome {
	case revokerclient.OutcomeRevoked:
		if result.State.Changed {
			return fmt.Sprintf("REVOKED: %s is revoked (revocation epoch %d)", account, result.State.Epoch)
		}
		return fmt.Sprintf("REVOKED: %s was revoked already; nothing changed (revocation epoch %d)", account, result.State.Epoch)
	case revokerclient.OutcomeLifted:
		if result.State.Changed {
			return fmt.Sprintf("LIFTED: the revocation of %s is lifted (revocation epoch %d)", account, result.State.Epoch)
		}
		return fmt.Sprintf("LIFTED: %s was not revoked; nothing changed (revocation epoch %d)", account, result.State.Epoch)
	case revokerclient.OutcomeListed:
		return fmt.Sprintf("LISTED: %d revoked account(s), revocation epoch %d", len(result.Table.Rows), result.Table.Epoch)
	case revokerclient.OutcomeRevokedNotWritten:
		return fmt.Sprintf("REVOKED_NOT_WRITTEN: %s is refused now, but gateway-authz could not write the revocation to its revocations file, "+
			"so it will not be refused after gateway-authz restarts. Find out why that file cannot be written "+
			"(disk, permissions, the directory), fix it, then run the same command again to have it written", account)
	case revokerclient.OutcomeLiftNotWritten:
		return fmt.Sprintf("LIFT_NOT_WRITTEN: gateway-authz could not write the change to its revocations file, so the revocation of %s "+
			"was NOT lifted: the account is still revoked. Find out why that file cannot be written, fix it, then run the same command again", account)
	case revokerclient.OutcomeNotRevoker:
		return "NOT_REVOKER: gateway-authz does not accept this certificate as the revoker's (401). Nothing changed"
	case revokerclient.OutcomeNoRevoker:
		return "NO_REVOKER_CONFIGURED: this gateway-authz has no revoker configured, so it has no revocation interface (404). Nothing changed"
	case revokerclient.OutcomeUnknownAccount:
		return fmt.Sprintf("UNKNOWN_ACCOUNT: gateway-authz knows no account %q (422); the name is probably mistyped. Nothing changed", account)
	case revokerclient.OutcomeRefused:
		return "REQUEST_REFUSED: gateway-authz did not accept the request as well-formed (400). Nothing changed"
	}
	switch command {
	case commandRevocations:
		return "UNKNOWN: " + result.Detail + ". The table was not read. Nothing is changed by reading it; run the same command again"
	case commandRestore:
		return "UNKNOWN: " + result.Detail + ". The request may or may not have reached gateway-authz, so the revocation of " + account +
			" may or may not be lifted. Running the same command again is safe (the interface is idempotent); " +
			"until the table has been read, do not take the account as lifted or as still revoked. Nothing was retried automatically"
	}
	return "UNKNOWN: " + result.Detail + ". The request may or may not have reached gateway-authz, so " + account +
		" may or may not be revoked. Running the same command again is safe (the interface is idempotent); " +
		"until `gateway-control revocations` has shown the account in the table, do not take it as revoked. Nothing was retried automatically"
}
