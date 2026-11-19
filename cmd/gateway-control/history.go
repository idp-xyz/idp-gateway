package main

// 发布历史的接线和两条只读的命令：releases、release（docs/adr/ADR-0013.md 第 7 条）。
// rollback 是 publish 的一种，在 main.go 里和 publish、restart 一起接。
//
//	gateway-control releases --history-dir <历史目录> --pool <名字> --config-dir <池的配置目录>
//	gateway-control release  --history-dir <历史目录> --pool <名字> --id <编号>
//	gateway-control rollback --history-dir <历史目录> --pool <名字> --to <编号> [--with-restart] （其余同 publish、restart）
//
// 只读的两条命令不占池的锁，不读网关，不碰 docker。标准输出是 JSON。退出码：
//
//	0  LISTED、SHOWN：读到了。releases 把历史里最后一条 ACTIVE 与池的记录比，对不上也是 0：
//	   对不上写在输出的 comparison 里，也在标准错误上说一句
//	1  出了错，没有 JSON：历史目录不存在、历史坏了（读不懂的行、格式不认识）、池的记录读不成之外的错
//	2  命令行写得不对
//	3  NOT_FOUND：历史里没有这个编号
//
// 不给 --history-dir 时 publish、restart、reconcile、keep 都与没有历史时一字不差。给了，
// --pool 也要给。历史目录必须已经存在：不存在就报错，不自动创建，免得把历史写到一个敲错的路径里。
// 目录里的 snapshots/ 和 releases.log 第一次写的时候由发布器建（0700、0600）；目录本身的权限与属主
// 这一阶段不管。

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/user"
	"strings"
	"time"

	"go.idp.xyz/idp-gateway/internal/gatewayconfig/adapters/directory"
	"go.idp.xyz/idp-gateway/internal/gatewayconfig/adapters/history"
	"go.idp.xyz/idp-gateway/internal/gatewayconfig/adapters/scratch"
	"go.idp.xyz/idp-gateway/internal/gatewayconfig/domain"
	"go.idp.xyz/idp-gateway/internal/gatewayconfig/ports"
	"go.idp.xyz/idp-gateway/internal/platform/workloadtls"
)

const (
	commandReleases = "releases"
	commandRelease  = "release"

	outcomeListed   = "LISTED"
	outcomeShown    = "SHOWN"
	outcomeNotFound = "NOT_FOUND"

	// 没有人核实的两样东西，输出里这样说。
	unverifiedInitiator = "reported by the publisher process itself (its certificate and the operating-system account it runs as); nobody verified it"
	unverifiedNote      = "the operator's own words; nobody verified it"
)

func isHistoryReadCommand(command string) bool {
	return command == commandReleases || command == commandRelease
}

// openHistory 和 currentAccount 是测试要换掉的两处：前者换成一个一碰就失败（或者会计数）的历史。
var (
	openHistory = func(dir, pool string) (ports.History, error) {
		h, err := history.New(dir, pool)
		if err != nil {
			return nil, err
		}
		return h, nil
	}
	currentAccount = func() string {
		account, err := user.Current()
		if err != nil || account.Username == "" {
			return fmt.Sprintf("uid:%d", os.Getuid())
		}
		return fmt.Sprintf("%s (uid %s)", account.Username, account.Uid)
	}
)

// openHistoryFor 打开 o 指的历史；没有给 --history-dir 时返回 nil：之后没有一处会碰历史。
func openHistoryFor(o options) (ports.History, error) {
	if o.historyDir == "" {
		return nil, nil
	}
	return openHistory(o.historyDir, o.poolName)
}

func historyDirUsage(command string) string {
	usage := "发布历史的目录（ADR-0013）：必须已经存在，不自动创建；里面的 snapshots/ 和 releases.log 第一次写时建（0700、0600）。"
	if command == commandRollback {
		return usage + "回滚要从它取快照，必须给"
	}
	return usage + "不给就没有历史，命令与没有历史时一字不差"
}

// checkHistoryFlags 检查与历史有关的几个参数：给了 --history-dir 就要给 --pool；没给的话
// --pool、--note 没有地方可记，写错了的话悄悄丢掉它们比报错糟。
func checkHistoryFlags(flags *flag.FlagSet, o *options) error {
	given := map[string]bool{}
	flags.Visit(func(f *flag.Flag) { given[f.Name] = true })
	if given["history-dir"] && o.historyDir == "" {
		// 给了却是空的，多半是变量文件里漏了那一项：当成"不记"的话，历史就悄悄没有了。
		return errors.New("--history-dir was given but is empty")
	}
	if o.historyDir == "" {
		for _, name := range []string{"pool", "note"} {
			if given[name] {
				return fmt.Errorf("--%s was given without --history-dir: there is no history to record it in", name)
			}
		}
		return nil
	}
	if o.poolName == "" {
		return errors.New("missing required flags: --pool (it is required with --history-dir)")
	}
	if err := domain.ValidatePool(o.poolName); err != nil {
		return fmt.Errorf("--pool: %w", err)
	}
	if err := domain.ValidateNote(o.note); err != nil {
		return fmt.Errorf("--note: %w", err)
	}
	return nil
}

// initiator 是这一次发布是谁发起的：发布器证书里唯一的那个 URI，和操作系统账号。
// 证书里没有或不止一个 URI、读不出来时那一项记空，不拒绝发布。
func initiator(o options) domain.Initiator {
	identity, _ := workloadtls.CertificateIdentity(o.pool.cert)
	return domain.Initiator{Workload: identity, Account: currentAccount()}
}

type historyReadOptions struct {
	command    string
	historyDir string
	pool       string
	configDir  string
	id         uint64
}

func parseHistoryRead(command string, args []string, output io.Writer) (historyReadOptions, error) {
	o := historyReadOptions{command: command}
	flags := flag.NewFlagSet("gateway-control "+command, flag.ContinueOnError)
	flags.SetOutput(output)
	required := map[string]*string{}
	text := func(target *string, name, usage string) {
		flags.StringVar(target, name, "", usage)
		required[name] = target
	}
	text(&o.historyDir, "history-dir", "发布历史的目录：必须已经存在")
	text(&o.pool, "pool", "池的标识")
	if command == commandReleases {
		text(&o.configDir, "config-dir", "池的配置目录：只读它的记录，拿它与历史里最后一条 ACTIVE 比；不占锁")
	} else {
		flags.Uint64Var(&o.id, "id", 0, "要看的那一条的编号")
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
	if command == commandRelease && o.id == 0 {
		missing = append(missing, "--id")
	}
	if len(missing) > 0 {
		return o, errors.New("missing required flags: " + strings.Join(missing, ", "))
	}
	if err := domain.ValidatePool(o.pool); err != nil {
		return o, fmt.Errorf("--pool: %w", err)
	}
	return o, nil
}

func runHistoryRead(ctx context.Context, command string, args []string, stdout, stderr io.Writer) int {
	o, err := parseHistoryRead(command, args, stderr)
	if err != nil {
		if !errors.Is(err, flag.ErrHelp) {
			fmt.Fprintln(stderr, "gateway-control:", err)
		}
		return exitUsage
	}
	fail := func(err error) int {
		fmt.Fprintln(stderr, "gateway-control:", err)
		return exitError
	}
	h, err := openHistory(o.historyDir, o.pool)
	if err != nil {
		return fail(err)
	}
	releases, err := h.List(ctx)
	if err != nil {
		return fail(err)
	}
	releases = domain.DeriveSuperseded(releases)
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	if command == commandRelease {
		return showRelease(o, releases, encoder, stdout, stderr)
	}
	// 池的记录：只读，不占锁。读不成样子的写进输出，不当成命令的错。
	delivery, err := directory.New(o.configDir, scratch.ConfigFile)
	if err != nil {
		return fail(err)
	}
	record, recorded, recordErr := delivery.Confirmed(ctx)
	report := releasesReport{Command: command, Outcome: outcomeListed, Pool: o.pool, Releases: []releaseRow{}}
	for _, release := range releases {
		report.Releases = append(report.Releases, row(release))
	}
	report.PoolRecord, report.Comparison = compare(releases, record, recorded, recordErr)
	if err := encoder.Encode(report); err != nil {
		fmt.Fprintln(stderr, "gateway-control:", err)
	}
	if len(releases) == 0 {
		fmt.Fprintln(stderr, "gateway-control: LISTED: the history of pool", o.pool, "has no release")
	}
	if report.Comparison.Status != comparisonMatch && report.Comparison.Status != comparisonNothing {
		fmt.Fprintln(stderr, "gateway-control: the history and the pool's record do not agree:", report.Comparison.Detail)
	}
	return exitActive
}

// 比较的几种结果。
const (
	comparisonMatch      = "match"
	comparisonMismatch   = "mismatch"
	comparisonNothing    = "nothing_to_compare"
	comparisonUnreadable = "record_unreadable"
)

type releasesReport struct {
	Command    string           `json:"command"`
	Outcome    string           `json:"outcome"`
	Pool       string           `json:"pool"`
	Releases   []releaseRow     `json:"releases"`
	PoolRecord poolRecordReport `json:"pool_record"`
	Comparison comparison       `json:"comparison"`
}

// releaseRow 是 releases 的一行。state 是给人看的状态：ACTIVE 而后来有更晚的 ACTIVE 的，是 SUPERSEDED
// （读的时候推出来的，不是写下来的）；还没有结局的，是它停在的那一步。
type releaseRow struct {
	Number        uint64 `json:"number"`
	StartedAt     string `json:"started_at"`
	FinishedAt    string `json:"finished_at"`
	State         string `json:"state"`
	RecordedState string `json:"recorded_state"`
	SupersededBy  uint64 `json:"superseded_by,omitempty"`
	Command       string `json:"command"`
	// Snapshot 是快照 ID 的前 12 位。
	Snapshot          string `json:"snapshot"`
	InitiatorWorkload string `json:"initiator_workload"`
	InitiatorAccount  string `json:"initiator_account"`
	HasNote           bool   `json:"has_note"`
	RolledBackTo      uint64 `json:"rolled_back_to,omitempty"`
}

func row(release domain.Release) releaseRow {
	return releaseRow{
		Number: release.Number, StartedAt: moment(release.StartedAt()), FinishedAt: moment(release.FinishedAt()),
		State: string(release.ShownState()), RecordedState: string(release.State()), SupersededBy: release.SupersededBy,
		Command: release.Command, Snapshot: domain.ShortSnapshot(release.Snapshot),
		InitiatorWorkload: release.By.Workload, InitiatorAccount: release.By.Account, HasNote: release.Note != "",
		RolledBackTo: release.RolledBackTo,
	}
}

func moment(at time.Time) string {
	if at.IsZero() {
		return ""
	}
	return at.UTC().Format(time.RFC3339)
}

type poolRecordReport struct {
	// Status 是 present、absent 或 unreadable。
	Status      string `json:"status"`
	Snapshot    string `json:"snapshot,omitempty"`
	ConfirmedAt string `json:"confirmed_at,omitempty"`
	Error       string `json:"error,omitempty"`
}

type lastActive struct {
	Number   uint64 `json:"number"`
	Snapshot string `json:"snapshot"`
}

type comparison struct {
	Status string `json:"status"`
	// HistoryLastActive 是历史里编号最大的一条 ACTIVE；没有时为 null。
	HistoryLastActive *lastActive `json:"history_last_active"`
	Detail            string      `json:"detail"`
}

// compare 把池的记录与历史里最后一条 ACTIVE 比：谁说了算，池在跑什么以池的记录加网关的回读为准，
// 历史只说发布器记得做过什么。
func compare(releases []domain.Release, record domain.Confirmation, recorded bool, recordErr error) (poolRecordReport, comparison) {
	var pool poolRecordReport
	var result comparison
	last, hasLast := domain.LastActive(releases)
	if hasLast {
		result.HistoryLastActive = &lastActive{Number: last.Number, Snapshot: domain.ShortSnapshot(last.Snapshot)}
	}
	switch {
	case recordErr != nil:
		pool = poolRecordReport{Status: "unreadable", Error: recordErr.Error()}
		result.Status = comparisonUnreadable
		result.Detail = "the pool's record cannot be read, so it cannot be compared with the history: " + recordErr.Error()
		return pool, result
	case recorded:
		pool = poolRecordReport{Status: "present", Snapshot: record.Snapshot.ShortID(), ConfirmedAt: moment(record.At)}
	default:
		pool = poolRecordReport{Status: "absent"}
	}
	switch {
	case !recorded && !hasLast:
		result.Status = comparisonNothing
		result.Detail = "the pool has no confirmed record and the history has no ACTIVE release"
	case !recorded:
		result.Status = comparisonMismatch
		result.Detail = fmt.Sprintf("the pool has no confirmed record, but the history's last ACTIVE release is %d (snapshot %s)", last.Number, domain.ShortSnapshot(last.Snapshot))
	case !hasLast:
		result.Status = comparisonMismatch
		result.Detail = fmt.Sprintf("the pool's record confirms snapshot %s, but the history has no ACTIVE release: it was published without --history-dir, "+
			"or the history was lost or replaced", record.Snapshot.ShortID())
	case last.Snapshot != record.Snapshot.ID():
		result.Status = comparisonMismatch
		result.Detail = fmt.Sprintf("the pool's record confirms snapshot %s, but the history's last ACTIVE release is %d (snapshot %s): "+
			"the pool runs what its record and the gateway's read-back say; the history only says what the publisher remembers doing",
			record.Snapshot.ShortID(), last.Number, domain.ShortSnapshot(last.Snapshot))
	default:
		result.Status = comparisonMatch
		result.Detail = fmt.Sprintf("the pool's record and the history's last ACTIVE release (%d) are the same snapshot", last.Number)
	}
	return pool, result
}

type releaseDetailReport struct {
	Command string         `json:"command"`
	Outcome string         `json:"outcome"`
	Pool    string         `json:"pool"`
	Release *releaseDetail `json:"release"`
	Detail  string         `json:"detail,omitempty"`
}

type releaseDetail struct {
	Number        uint64 `json:"number"`
	State         string `json:"state"`
	RecordedState string `json:"recorded_state"`
	SupersededBy  uint64 `json:"superseded_by,omitempty"`
	Command       string `json:"command"`
	Snapshot      string `json:"snapshot"`
	Previous      string `json:"previous"`
	Supersedes    uint64 `json:"supersedes,omitempty"`
	RolledBackTo  uint64 `json:"rolled_back_to,omitempty"`
	StartedAt     string `json:"started_at"`
	FinishedAt    string `json:"finished_at"`
	Replaced      bool   `json:"replaced"`
	Restarted     bool   `json:"restarted"`
	// Restart 是需要重启时不同的启动设置。
	Restart        []string        `json:"restart"`
	ExpectedDigest string          `json:"expected_digest"`
	ObservedDigest string          `json:"observed_digest"`
	Version        string          `json:"version"`
	Revision       string          `json:"revision"`
	Reason         string          `json:"reason"`
	Initiator      initiatorReport `json:"initiator"`
	Note           string          `json:"note"`
	NoteStatus     string          `json:"note_status,omitempty"`
	RouteIntent    string          `json:"route_intent"`
	Steps          []stepRow       `json:"steps"`
}

type initiatorReport struct {
	Workload string `json:"workload_identity"`
	Account  string `json:"os_account"`
	Status   string `json:"status"`
}

type stepRow struct {
	State  string `json:"state"`
	Step   string `json:"step"`
	At     string `json:"at"`
	Reason string `json:"reason"`
}

func showRelease(o historyReadOptions, releases []domain.Release, encoder *json.Encoder, _ io.Writer, stderr io.Writer) int {
	report := releaseDetailReport{Command: commandRelease, Pool: o.pool}
	for _, release := range releases {
		if release.Number != o.id {
			continue
		}
		report.Outcome, report.Release = outcomeShown, detail(release)
	}
	if report.Release == nil {
		report.Outcome = outcomeNotFound
		report.Detail = fmt.Sprintf("there is no release %d in the history of pool %s", o.id, o.pool)
		fmt.Fprintln(stderr, "gateway-control: NOT_FOUND:", report.Detail)
	}
	if err := encoder.Encode(report); err != nil {
		fmt.Fprintln(stderr, "gateway-control:", err)
	}
	if report.Outcome == outcomeNotFound {
		return exitNotDone
	}
	return exitActive
}

func detail(release domain.Release) *releaseDetail {
	d := &releaseDetail{
		Number: release.Number, State: string(release.ShownState()), RecordedState: string(release.State()), SupersededBy: release.SupersededBy,
		Command: release.Command, Snapshot: release.Snapshot, Previous: release.Previous, Supersedes: release.Supersedes,
		RolledBackTo: release.RolledBackTo, StartedAt: moment(release.StartedAt()), FinishedAt: moment(release.FinishedAt()),
		Replaced: release.Replaced(), Restarted: release.Restarted(), Restart: []string{},
		ExpectedDigest: release.Expected, Reason: release.Reason(), Note: release.Note, RouteIntent: release.RouteIntent,
		Initiator: initiatorReport{Workload: release.By.Workload, Account: release.By.Account, Status: unverifiedInitiator},
		Steps:     []stepRow{},
	}
	if release.Note != "" {
		d.NoteStatus = unverifiedNote
	}
	if facts := release.Facts(); facts != nil {
		d.ObservedDigest, d.Version, d.Revision = facts.Digest, facts.Version, facts.Revision
		if facts.Restart != nil {
			d.Restart = facts.Restart
		}
	}
	for _, step := range release.Steps {
		d.Steps = append(d.Steps, stepRow{State: string(step.State), Step: step.Name, At: step.At.UTC().Format(time.RFC3339Nano), Reason: step.Reason})
	}
	return d
}
