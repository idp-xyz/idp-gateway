// Package history 是发布历史的第一个适配器：池旁边的一个目录（docs/adr/ADR-0013.md 第 8 条）。
//
//	<历史目录>/                  0700，必须已经存在，不自动创建
//	    snapshots/<SHA-256>.yaml  0600，快照的全文，不可变：写临时文件、刷盘、改名、刷目录；读的时候核对摘要
//	    releases.log              0600，只追加：一行一条状态变化，JSON，写完刷盘；新建之后刷目录
//
// 读 releases.log 的规则：最后一行没有换行结尾，算没写完，忽略（下一次追加之前把它截掉）；中间的行
// 读不懂、格式版本不认识、编号重复，算历史坏了，报错，不猜、不跳过。别的池的行（日志里带着池的标识）
// 照样要读得懂，但不算在这个池里。
//
// 并发靠调用的人占着池的那把锁（Delivery.Hold）；适配器自己只保证一行不会被写成两半：
// 进程内一把锁，每一行一次 write，以追加方式打开。
package history

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"sync"
	"time"

	"go.idp.xyz/idp-gateway/internal/gatewayconfig/domain"
	"go.idp.xyz/idp-gateway/internal/gatewayconfig/ports"
)

const (
	// LogName 和 SnapshotsDir 是历史目录里的两样东西。
	LogName      = "releases.log"
	SnapshotsDir = "snapshots"

	// logFormat 是日志每一行的格式版本。格式变得旧版本读不对时加一。
	logFormat = 1

	fileMode fs.FileMode = 0o600
	dirMode  fs.FileMode = 0o700
)

var snapshotID = regexp.MustCompile(`^[0-9a-f]{64}$`)

// writeMu 让同一个进程里的写入一个接一个：一行不会被写成两半，编号不会重复。
// 不同进程之间靠池的锁。
var writeMu sync.Mutex

// History 是一个池的发布历史。
type History struct {
	dir  string
	pool string
}

// New 指定历史目录和池的标识。目录必须已经存在：不存在就报错，免得把历史写到一个敲错的路径里。
// 目录里的 snapshots 子目录和 releases.log 第一次写的时候建。
func New(dir, pool string) (*History, error) {
	if err := domain.ValidatePool(pool); err != nil {
		return nil, fmt.Errorf("history: %w", err)
	}
	info, err := os.Stat(dir)
	if err != nil {
		return nil, fmt.Errorf("history: %w (the history directory must exist; it is not created)", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("history: %s is not a directory", dir)
	}
	return &History{dir: dir, pool: pool}, nil
}

// 日志里的一行。
type line struct {
	Format  int    `json:"format"`
	Pool    string `json:"pool"`
	Release uint64 `json:"release"`
	At      string `json:"at"`
	State   string `json:"state"`
	Step    string `json:"step,omitempty"`
	Reason  string `json:"reason,omitempty"`
	// Start 只在 STAGED 那一行上有。
	Start *start `json:"start,omitempty"`
	// Facts 只在结局的那一行上有。
	Facts *facts `json:"facts,omitempty"`
}

type start struct {
	Snapshot     string `json:"snapshot"`
	Previous     string `json:"previous,omitempty"`
	Expected     string `json:"expected_digest,omitempty"`
	Command      string `json:"command"`
	Workload     string `json:"initiator_workload,omitempty"`
	Account      string `json:"initiator_account,omitempty"`
	Note         string `json:"note,omitempty"`
	RolledBackTo uint64 `json:"rolled_back_to,omitempty"`
	Supersedes   uint64 `json:"supersedes,omitempty"`
	RouteIntent  string `json:"route_intent,omitempty"`
}

type facts struct {
	Digest   string   `json:"observed_digest,omitempty"`
	Version  string   `json:"version,omitempty"`
	Revision string   `json:"revision,omitempty"`
	Restart  []string `json:"restart,omitempty"`
}

func (h *History) logPath() string { return filepath.Join(h.dir, LogName) }

func (h *History) damaged(format string, args ...any) error {
	return fmt.Errorf("history: %w: %s: %s", ports.ErrHistoryDamaged, h.logPath(), fmt.Sprintf(format, args...))
}

// scan 是读完整个日志的结果。
type scan struct {
	// releases 是这个池的记录，按编号从小到大。
	releases []domain.Release
	// goodLength 是最后一个完整行结束的位置；torn 为真表示它之后还有没写完的几个字节。
	goodLength int64
	torn       bool
	exists     bool
}

func (h *History) read() (scan, error) {
	raw, err := os.ReadFile(h.logPath())
	if errors.Is(err, fs.ErrNotExist) {
		return scan{}, nil
	}
	if err != nil {
		return scan{}, fmt.Errorf("history: %w", err)
	}
	result := scan{exists: true}
	end := bytes.LastIndexByte(raw, '\n') + 1
	result.goodLength, result.torn = int64(end), end < len(raw)
	byNumber := map[uint64]*domain.Release{}
	var numbers []uint64
	var lines [][]byte
	if end > 0 {
		lines = bytes.Split(raw[:end-1], []byte{'\n'})
	}
	for n, text := range lines {
		parsed, err := h.parse(n+1, text)
		if err != nil {
			return scan{}, err
		}
		if parsed.Pool != h.pool {
			continue
		}
		at, _ := time.Parse(time.RFC3339Nano, parsed.At) // parse 已经检查过
		step := domain.ReleaseStep{State: domain.ReleaseState(parsed.State), Name: parsed.Step, Reason: parsed.Reason, At: at}
		if f := parsed.Facts; f != nil {
			step.Facts = &domain.StepFacts{Digest: f.Digest, Version: f.Version, Revision: f.Revision, Restart: f.Restart}
		}
		release := byNumber[parsed.Release]
		if s := parsed.Start; s != nil {
			if release != nil {
				return scan{}, h.damaged("line %d: release %d is started twice", n+1, parsed.Release)
			}
			release = &domain.Release{
				Number: parsed.Release, Pool: parsed.Pool,
				Snapshot: s.Snapshot, Previous: s.Previous, Expected: s.Expected, Command: s.Command,
				By: domain.Initiator{Workload: s.Workload, Account: s.Account}, Note: s.Note,
				RolledBackTo: s.RolledBackTo, Supersedes: s.Supersedes, RouteIntent: s.RouteIntent,
			}
			byNumber[parsed.Release] = release
			numbers = append(numbers, parsed.Release)
		} else if release == nil {
			return scan{}, h.damaged("line %d: a step of release %d, which was never started", n+1, parsed.Release)
		}
		release.Steps = append(release.Steps, step)
	}
	sort.Slice(numbers, func(i, j int) bool { return numbers[i] < numbers[j] })
	for _, number := range numbers {
		result.releases = append(result.releases, *byNumber[number])
	}
	return result, nil
}

func (h *History) parse(number int, text []byte) (line, error) {
	var parsed line
	decoder := json.NewDecoder(bytes.NewReader(text))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&parsed); err != nil {
		return line{}, h.damaged("line %d cannot be read: %v", number, err)
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return line{}, h.damaged("line %d has something after the JSON value", number)
	}
	switch {
	case parsed.Format != logFormat:
		// 不认识的格式不猜：多半是更新的版本写的。
		return line{}, h.damaged("line %d is in format %d; this version reads format %d", number, parsed.Format, logFormat)
	case parsed.Release == 0 || parsed.Pool == "":
		return line{}, h.damaged("line %d has no release number or pool", number)
	case !domain.ReleaseState(parsed.State).Known():
		return line{}, h.damaged("line %d has the unknown state %q", number, parsed.State)
	case parsed.Start != nil && parsed.State != string(domain.StateStaged):
		return line{}, h.damaged("line %d starts a release with state %s", number, parsed.State)
	case parsed.Start == nil && parsed.State == string(domain.StateStaged):
		return line{}, h.damaged("line %d is a STAGED line without the start of the release", number)
	}
	if _, err := time.Parse(time.RFC3339Nano, parsed.At); err != nil {
		return line{}, h.damaged("line %d has no usable time: %v", number, err)
	}
	return parsed, nil
}

// Begin 见 ports.History。
func (h *History) Begin(_ context.Context, begin domain.ReleaseStart) (uint64, error) {
	if begin.Snapshot.IsZero() {
		return 0, errors.New("history: a release needs a snapshot")
	}
	writeMu.Lock()
	defer writeMu.Unlock()
	seen, err := h.read()
	if err != nil {
		return 0, err
	}
	number := uint64(1)
	if count := len(seen.releases); count > 0 {
		number = seen.releases[count-1].Number + 1
	}
	var supersedes uint64
	if last, ok := domain.LastActive(seen.releases); ok {
		supersedes = last.Number
	}
	// 快照先存。存了没有引用它的日志行不碍事；有日志行却没有快照才是问题。
	for _, snapshot := range []domain.Snapshot{begin.Snapshot, begin.Previous} {
		if err := h.store(snapshot); err != nil {
			return 0, err
		}
	}
	started := line{
		Format: logFormat, Pool: h.pool, Release: number, At: stamp(begin.At), State: string(domain.StateStaged),
		Start: &start{
			Snapshot: begin.Snapshot.ID(), Previous: begin.Previous.ID(), Expected: begin.Expected, Command: begin.Command,
			Workload: begin.By.Workload, Account: begin.By.Account, Note: begin.Note,
			RolledBackTo: begin.RolledBackTo, Supersedes: supersedes,
		},
	}
	if err := h.append(started, seen); err != nil {
		return 0, err
	}
	return number, nil
}

// Advance 见 ports.History。
func (h *History) Advance(_ context.Context, number uint64, step domain.ReleaseStep) error {
	if !step.State.Known() || step.State == domain.StateStaged {
		return fmt.Errorf("history: %q is not a state a release moves to", step.State)
	}
	writeMu.Lock()
	defer writeMu.Unlock()
	seen, err := h.read()
	if err != nil {
		return err
	}
	if !contains(seen.releases, number) {
		return fmt.Errorf("history: release %d: %w", number, ports.ErrReleaseNotFound)
	}
	next := line{
		Format: logFormat, Pool: h.pool, Release: number, At: stamp(step.At), State: string(step.State),
		Step: step.Name, Reason: step.Reason,
	}
	if f := step.Facts; f != nil {
		next.Facts = &facts{Digest: f.Digest, Version: f.Version, Revision: f.Revision, Restart: f.Restart}
	}
	return h.append(next, seen)
}

func contains(releases []domain.Release, number uint64) bool {
	for _, release := range releases {
		if release.Number == number {
			return true
		}
	}
	return false
}

func stamp(at time.Time) string {
	if at.IsZero() {
		at = time.Now()
	}
	return at.UTC().Format(time.RFC3339Nano)
}

// append 把一行写到日志的末尾：没写完的尾巴先截掉（它本来就不算记录），一次 write，刷盘；
// 日志是这一次新建的，再刷目录。
func (h *History) append(next line, seen scan) error {
	raw, err := json.Marshal(next)
	if err != nil {
		return fmt.Errorf("history: %w", err)
	}
	file, err := os.OpenFile(h.logPath(), os.O_WRONLY|os.O_APPEND|os.O_CREATE, fileMode)
	if err != nil {
		return fmt.Errorf("history: %w", err)
	}
	if seen.torn {
		err = file.Truncate(seen.goodLength)
	}
	if err == nil {
		_, err = file.Write(append(raw, '\n'))
	}
	if err == nil {
		err = file.Chmod(fileMode) // 不受 umask 影响
	}
	if err == nil {
		err = file.Sync()
	}
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err == nil && !seen.exists {
		err = syncDirectory(h.dir)
	}
	if err != nil {
		return fmt.Errorf("history: %w", err)
	}
	return nil
}

// store 把一份快照存进 snapshots/。已经有的不再写：快照不可变，名字就是内容的摘要。
// 已经有的却与摘要对不上时报错，不盖掉它。
func (h *History) store(snapshot domain.Snapshot) error {
	if snapshot.IsZero() {
		return nil
	}
	dir := filepath.Join(h.dir, SnapshotsDir)
	final := filepath.Join(dir, snapshot.ID()+".yaml")
	if existing, err := os.ReadFile(final); err == nil {
		if digest(existing) != snapshot.ID() {
			return fmt.Errorf("history: %w: %s", ports.ErrSnapshotDamaged, final)
		}
		return nil
	} else if !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("history: %w", err)
	}
	if err := os.Mkdir(dir, dirMode); err == nil {
		if err := os.Chmod(dir, dirMode); err != nil { // 不受 umask 影响
			return fmt.Errorf("history: %w", err)
		}
		if err := syncDirectory(h.dir); err != nil {
			return fmt.Errorf("history: %w", err)
		}
	} else if !errors.Is(err, fs.ErrExist) {
		return fmt.Errorf("history: %w", err)
	}
	temporary := filepath.Join(dir, "."+snapshot.ID()+".tmp")
	file, err := os.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, fileMode)
	if err != nil {
		return fmt.Errorf("history: %w", err)
	}
	if _, err = file.Write(snapshot.Content()); err == nil {
		err = file.Chmod(fileMode)
	}
	if err == nil {
		err = file.Sync()
	}
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err == nil {
		err = os.Rename(temporary, final)
	}
	if err == nil {
		err = syncDirectory(dir)
	}
	if err != nil {
		_ = os.Remove(temporary)
		return fmt.Errorf("history: %w", err)
	}
	return nil
}

func digest(content []byte) string {
	sum := sha256.Sum256(content)
	return hex.EncodeToString(sum[:])
}

// Snapshot 见 ports.History。
func (h *History) Snapshot(_ context.Context, id string) (domain.Snapshot, error) {
	if !snapshotID.MatchString(id) {
		return domain.Snapshot{}, fmt.Errorf("history: %q is not a snapshot ID: %w", id, ports.ErrSnapshotNotFound)
	}
	path := filepath.Join(h.dir, SnapshotsDir, id+".yaml")
	content, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return domain.Snapshot{}, fmt.Errorf("history: snapshot %s: %w", domain.ShortSnapshot(id), ports.ErrSnapshotNotFound)
	}
	if err != nil {
		return domain.Snapshot{}, fmt.Errorf("history: %w", err)
	}
	if digest(content) != id {
		return domain.Snapshot{}, fmt.Errorf("history: %w: %s", ports.ErrSnapshotDamaged, path)
	}
	snapshot, err := domain.NewSnapshot(content)
	if err != nil {
		return domain.Snapshot{}, fmt.Errorf("history: %w: %s: %v", ports.ErrSnapshotDamaged, path, err)
	}
	return snapshot, nil
}

// List 见 ports.History。
func (h *History) List(context.Context) ([]domain.Release, error) {
	seen, err := h.read()
	if err != nil {
		return nil, err
	}
	return seen.releases, nil
}

// Get 见 ports.History。
func (h *History) Get(ctx context.Context, number uint64) (domain.Release, error) {
	releases, err := h.List(ctx)
	if err != nil {
		return domain.Release{}, err
	}
	for _, release := range releases {
		if release.Number == number {
			return release, nil
		}
	}
	return domain.Release{}, fmt.Errorf("history: release %d: %w", number, ports.ErrReleaseNotFound)
}

func syncDirectory(dir string) error {
	entry, err := os.Open(dir)
	if err != nil {
		return err
	}
	err = entry.Sync()
	if closeErr := entry.Close(); err == nil {
		err = closeErr
	}
	return err
}
