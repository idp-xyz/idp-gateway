// Package application 做一轮 JWKS 同步：取、校验、与磁盘上的摘要比较、需要时原子写入，
// 以及在取失败时决定继续沿用还是按期限作废。
package application

import (
	"context"
	"errors"
	"time"

	"go.idp.xyz/idp-gateway/internal/jwkssync/domain"
	"go.idp.xyz/idp-gateway/internal/jwkssync/ports"
)

// Outcome 是一轮同步的结局，写进命令的 JSON，也是指标要区分的几种情况。
type Outcome string

const (
	// OutcomeUpdated 写入了一份新的密钥集。
	OutcomeUpdated Outcome = "UPDATED"
	// OutcomeUnchanged 取到的密钥与磁盘上的是同一套（摘要相同），没有重写文件。
	OutcomeUnchanged Outcome = "UNCHANGED"
	// OutcomeFetchFailed 没取到，或取到的不是合格的公钥集。期限之内原来的文件不动。
	OutcomeFetchFailed Outcome = "FETCH_FAILED"
	// OutcomeStaleExpired 失败，而且距离上一次成功已经超过 MaxStale。
	OutcomeStaleExpired Outcome = "STALE_EXPIRED"
)

// Result 是一轮同步的结果。Error 只在失败时有文字。KIDs 为空时是空切片，不是 nil。
type Result struct {
	Outcome  Outcome
	KeyCount int
	KIDs     []string
	Digest   string
	Stale    bool
	// Cleared 为真：这一轮因为过期，把文件写成了空密钥集。
	Cleared bool
	Error   string
	// At 是这一轮开始取的时刻。LastSuccess 是最近一次取到合格密钥集的时刻，还没有过就是零值。
	At          time.Time
	LastSuccess time.Time
}

// Config 是一次同步器的全部配置。
type Config struct {
	Fetcher ports.Fetcher
	Store   ports.Store
	// Now 是当前时刻。为空时用 time.Now。测试传入一个可控的时钟。
	Now func() time.Time
	// MaxStale 是取失败时仍可沿用上一次成功密钥的最长时间。0 表示不因过期而作废。负值拒绝。
	MaxStale time.Duration
	// EmptyOnStale 为真时，超过 MaxStale 就把文件写成空密钥集，让验证失败关闭。
	EmptyOnStale bool
}

// Syncer 做一轮又一轮的同步。Now、MaxStale、EmptyOnStale 在每一轮读取，测试可以改它们。
//
// 启动时如果磁盘上已有一份合格的密钥集，把它的摘要当作当前摘要，并把上一次成功记成启动时刻
// （Now 返回的时刻），从而在这个进程里给它一个完整的 MaxStale 窗口。不读文件的修改时间：
// 存储端口不提供。记成零值的话，StaleStatus 会把“还没有成功过”当成永不过期，磁盘上的旧文件
// 就会在身份提供者一直不可用时被无限期信任。
type Syncer struct {
	Now          func() time.Time
	MaxStale     time.Duration
	EmptyOnStale bool

	fetcher             ports.Fetcher
	store               ports.Store
	lastSuccess         time.Time
	lastDigest          string
	keyCount            int
	kids                []string
	consecutiveFailures int
	stale               bool
}

// New 核对配置并读一次磁盘，用来给摘要和上一次成功的时刻赋初值。磁盘读不了时返回错误，同步器不往下做。
// 文件不存在，或者存在但不是合格的密钥集，都不算错误：下一轮成功的拉取会把它换掉。
func New(cfg Config) (*Syncer, error) {
	if cfg.Fetcher == nil || cfg.Store == nil {
		return nil, errors.New("jwks sync: fetcher and store are required")
	}
	if cfg.MaxStale < 0 {
		return nil, errors.New("jwks sync: max stale must not be negative")
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	s := &Syncer{Now: now, MaxStale: cfg.MaxStale, EmptyOnStale: cfg.EmptyOnStale, fetcher: cfg.Fetcher, store: cfg.Store}
	if err := s.seed(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Syncer) seed() error {
	raw, exists, err := s.store.Read()
	if err != nil {
		return err
	}
	if !exists {
		return nil
	}
	doc, err := domain.Parse(raw)
	if err != nil {
		return nil
	}
	s.lastDigest = doc.Digest()
	s.lastSuccess = s.current()
	s.keyCount = len(doc.Keys())
	s.kids = cloneKids(doc.KIDs())
	return nil
}

// Step 做一轮。取失败或文档不合格时，不把取到的字节写进文件。
func (s *Syncer) Step(ctx context.Context) Result {
	now := s.current()
	raw, err := s.fetcher.Fetch(ctx)
	if err != nil {
		return s.fail(now, err)
	}
	doc, err := domain.Parse(raw)
	if err != nil {
		return s.fail(now, err)
	}
	digest, ok, err := s.diskDigest()
	if err != nil {
		return s.fail(now, err)
	}
	if ok && digest == doc.Digest() {
		s.noteSuccess(now, doc)
		return s.success(OutcomeUnchanged, doc, now)
	}
	if err := s.store.Write(doc.Canonical()); err != nil {
		// 改名已经完成、只是随后的目录刷盘失败时，文件里已经是这一份。再读一次对得上就算写成了，
		// 不要把它当成取失败，更不要在已经过期时把刚写好的公钥集腾空。
		if again, match, readErr := s.diskDigest(); readErr == nil && match && again == doc.Digest() {
			s.noteSuccess(now, doc)
			return s.success(OutcomeUpdated, doc, now)
		}
		return s.fail(now, err)
	}
	s.noteSuccess(now, doc)
	return s.success(OutcomeUpdated, doc, now)
}

func (s *Syncer) current() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Syncer) noteSuccess(now time.Time, doc domain.Document) {
	s.lastSuccess = now
	s.lastDigest = doc.Digest()
	s.keyCount = len(doc.Keys())
	s.kids = cloneKids(doc.KIDs())
	s.consecutiveFailures = 0
	s.stale = false
}

func (s *Syncer) success(outcome Outcome, doc domain.Document, now time.Time) Result {
	return Result{
		Outcome: outcome, KeyCount: len(doc.Keys()), KIDs: cloneKids(doc.KIDs()), Digest: doc.Digest(),
		At: now, LastSuccess: s.lastSuccess,
	}
}

func (s *Syncer) fail(now time.Time, cause error) Result {
	s.consecutiveFailures++
	stale, _ := domain.StaleStatus(s.lastSuccess, now, s.MaxStale)
	s.stale = stale
	result := Result{
		Outcome: OutcomeFetchFailed, KeyCount: s.keyCount, KIDs: cloneKids(s.kids), Digest: s.lastDigest,
		Error: cause.Error(), At: now, LastSuccess: s.lastSuccess,
	}
	if !stale {
		return result
	}
	result.Outcome = OutcomeStaleExpired
	result.Stale = true
	if !s.EmptyOnStale {
		return result
	}
	empty := domain.EmptySet()
	current, exists, readErr := s.store.Read()
	if readErr == nil && exists && string(current) == string(empty) {
		s.forgetKeys()
		result.KeyCount, result.KIDs, result.Digest = 0, []string{}, ""
		return result
	}
	if writeErr := s.store.Write(empty); writeErr != nil {
		result.Error = cause.Error() + "; " + writeErr.Error()
		return result
	}
	s.forgetKeys()
	result.KeyCount, result.KIDs, result.Digest = 0, []string{}, ""
	result.Cleared = true
	return result
}

func (s *Syncer) forgetKeys() {
	s.lastDigest = ""
	s.keyCount = 0
	s.kids = nil
}

func (s *Syncer) diskDigest() (string, bool, error) {
	raw, exists, err := s.store.Read()
	if err != nil || !exists {
		return "", false, err
	}
	doc, err := domain.Parse(raw)
	if err != nil {
		return "", false, nil
	}
	return doc.Digest(), true, nil
}

func cloneKids(in []string) []string {
	if len(in) == 0 {
		return []string{}
	}
	out := make([]string, len(in))
	copy(out, in)
	return out
}
