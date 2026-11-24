// Package application 把一次发布从收下走到生效或结局。它不碰文件、也不导入别的限界上下文。
package application

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
	"unicode"

	"go.idp.xyz/idp-gateway/internal/fabricpub/domain"
	"go.idp.xyz/idp-gateway/internal/fabricpub/ports"
)

// CallError 是交给 HTTP 层的结果。Reason 不含密钥，也不含请求正文。
type CallError struct {
	Status int
	Reason string
}

func (e *CallError) Error() string {
	if e == nil {
		return ""
	}
	return e.Reason
}

// SubmitResult 是 202 的三个字段。重放时 State 仍是 DRAFT，当前进度用 Status 看。
type SubmitResult struct {
	IntentID   string
	ReleaseRef string
	State      domain.ReleaseState
}

// StatusView 是状态查询的五个字段。还没有的摘要是空串。
type StatusView struct {
	IntentID       string
	ReleaseRef     string
	DesiredDigest  string
	ObservedDigest string
	State          domain.ReleaseState
}

// Config 是一个池的发布服务。绑定和目录在进程启动时读入，运行中不改。
type Config struct {
	TargetID  string
	Base      domain.PoolBase
	Bindings  []domain.Binding
	Store     ports.StateStore
	Compiler  ports.Compiler
	Policies  ports.PolicyApplier
	Publisher ports.PoolPublisher
	// PoolWait 是在 STAGED 上等池锁的最长时间。零值取 30 秒。
	PoolWait time.Duration
	// Backoff 是池被占时的退避间隔。零值取 50 毫秒。
	Backoff time.Duration
}

// Service 收下意图，异步把它推进到结局。
type Service struct {
	targetID string
	base     domain.PoolBase
	bindings []domain.Binding
	store    ports.StateStore
	compiler ports.Compiler
	policies ports.PolicyApplier
	publish  ports.PoolPublisher
	poolWait time.Duration
	backoff  time.Duration

	mu      sync.Mutex
	ctx     context.Context
	cancel  context.CancelFunc
	workers map[string]struct{}
	wg      sync.WaitGroup
}

var (
	errReadOnly = errors.New("fabricpub: read only")
	errStop     = errors.New("fabricpub: stop")
)

// New 构造服务。Start 之后才会接着跑上次没做完的发布。
func New(cfg Config) (*Service, error) {
	if cfg.TargetID == "" || cfg.Store == nil || cfg.Compiler == nil || cfg.Policies == nil || cfg.Publisher == nil {
		return nil, errors.New("fabricpub: target, state, compiler, policy applier and publisher are required")
	}
	if cfg.PoolWait <= 0 {
		cfg.PoolWait = 30 * time.Second
	}
	if cfg.Backoff <= 0 {
		cfg.Backoff = 50 * time.Millisecond
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Service{
		targetID: cfg.TargetID,
		base:     cfg.Base,
		bindings: append([]domain.Binding(nil), cfg.Bindings...),
		store:    cfg.Store,
		compiler: cfg.Compiler,
		policies: cfg.Policies,
		publish:  cfg.Publisher,
		poolWait: cfg.PoolWait,
		backoff:  cfg.Backoff,
		ctx:      ctx,
		cancel:   cancel,
		workers:  map[string]struct{}{},
	}, nil
}

// Start 把服务的寿命接到 ctx 上，并接着跑没做完的发布、对账 UNKNOWN 和 PARTIAL。
func (s *Service) Start(ctx context.Context) {
	go func() {
		select {
		case <-ctx.Done():
			s.cancel()
		case <-s.ctx.Done():
		}
	}()
	s.resume()
}

// Close 取消后台任务并等它们结束。
func (s *Service) Close() {
	s.cancel()
	s.wg.Wait()
}

// Submit 同步做完校验、幂等、代次和编译。通过之后落 DRAFT 并返回 202。
func (s *Service) Submit(ctx context.Context, rawBody []byte) (SubmitResult, error) {
	env, err := domain.ParseEnvelope(rawBody)
	if err != nil {
		return SubmitResult{}, invalidCall(err)
	}
	if err := domain.CheckPublication(env, s.base, s.bindings); err != nil {
		return SubmitResult{}, invalidCall(err)
	}
	var (
		replay   *SubmitResult
		recordID string
	)
	err = s.withState(ctx, func(st *ports.State) error {
		if prev, ok := st.Idempotency[env.IdempotencyKey]; ok {
			if prev.Hash == env.Hash {
				replay = &SubmitResult{IntentID: prev.IntentID, ReleaseRef: prev.ReleaseRef, State: domain.StateDraft}
				return errReadOnly
			}
			return conflict("idempotency_key_reused")
		}
		if blocked(st) {
			return conflict("publish_in_progress")
		}
		if env.Intent.ExpectedGeneration != st.Generation {
			return conflict("generation_conflict")
		}
		version := policyVersion(s.base.Provider.PolicyVersion, st.Generation, env.Hash)
		merged, active, err := domain.Merge(s.base, st.Active, env, s.targetID, version)
		if err != nil {
			return invalidCall(err)
		}
		bundle, err := s.compiler.ValidateAndCompile(ctx, merged)
		if err != nil {
			if errors.Is(err, ports.ErrRefused) {
				return invalidCall(errors.New("compile_refused"))
			}
			return err
		}
		if bundle.PolicyVersion == "" {
			bundle.PolicyVersion = version
		}
		rec := ports.Record{
			ID: env.Intent.IntentID + "-" + env.Hash[:12], IntentID: env.Intent.IntentID,
			ReleaseRef: env.ReleaseRef, IdempotencyKey: env.IdempotencyKey, CanonicalHash: env.Hash,
			State: domain.StateDraft, GatewayYAML: append([]byte(nil), bundle.GatewayYAML...),
			PolicyJSON: append([]byte(nil), bundle.PolicyJSON...), PolicyVersion: bundle.PolicyVersion,
			GatewaySHA256: bundle.GatewaySHA256, NewActive: active, CreatedUnixNano: time.Now().UnixNano(),
		}
		st.Records = append(st.Records, rec)
		st.Idempotency[env.IdempotencyKey] = ports.Idempotency{
			Hash: env.Hash, IntentID: env.Intent.IntentID, ReleaseRef: env.ReleaseRef, RecordID: rec.ID,
		}
		recordID = rec.ID
		return nil
	})
	if err != nil {
		return SubmitResult{}, err
	}
	if replay != nil {
		return *replay, nil
	}
	s.start(recordID)
	return SubmitResult{IntentID: env.Intent.IntentID, ReleaseRef: env.ReleaseRef, State: domain.StateDraft}, nil
}

// Status 返回这个 intent_id 当前对外的那一条。没有时 found 为 false。
func (s *Service) Status(ctx context.Context, intentID string) (StatusView, bool, error) {
	var (
		view  StatusView
		found bool
	)
	err := s.withState(ctx, func(st *ports.State) error {
		rec, ok := latest(st, intentID)
		if !ok {
			return errReadOnly
		}
		found = true
		view = StatusView{
			IntentID: rec.IntentID, ReleaseRef: rec.ReleaseRef,
			DesiredDigest: rec.DesiredDigest, ObservedDigest: rec.ObservedDigest, State: rec.State,
		}
		return errReadOnly
	})
	return view, found, err
}

// Reconcile 对 UNKNOWN 和 PARTIAL 各做一次对账。
func (s *Service) Reconcile(ctx context.Context) error {
	ids, err := s.idsIn(ctx, domain.StateUnknown, domain.StatePartial)
	if err != nil {
		return err
	}
	var first error
	for _, id := range ids {
		rec, ok, err := s.lookup(ctx, id)
		if err != nil {
			return err
		}
		if !ok {
			continue
		}
		if err := s.reconcileOne(ctx, rec); err != nil && first == nil {
			first = err
		}
	}
	return first
}

func (s *Service) resume() {
	var ids []string
	_ = s.withState(s.ctx, func(st *ports.State) error {
		for _, rec := range st.Records {
			if rec.State == domain.StateUnknown || rec.State == domain.StatePartial || rec.State.BlocksNewPublish() {
				ids = append(ids, rec.ID)
			}
		}
		return errReadOnly
	})
	for _, id := range ids {
		s.start(id)
	}
}

func (s *Service) start(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ctx.Err() != nil {
		return
	}
	if _, ok := s.workers[id]; ok {
		return
	}
	s.workers[id] = struct{}{}
	s.wg.Add(1)
	go s.process(s.ctx, id)
}

func (s *Service) finishWorker(id string) {
	s.mu.Lock()
	delete(s.workers, id)
	s.mu.Unlock()
}

func (s *Service) process(ctx context.Context, id string) {
	defer s.wg.Done()
	defer s.finishWorker(id)
	for {
		if ctx.Err() != nil {
			return
		}
		rec, ok, err := s.lookup(ctx, id)
		if err != nil || !ok {
			return
		}
		switch rec.State {
		case domain.StateDraft:
			if err := s.mark(ctx, id, domain.StateValidated); err != nil {
				return
			}
		case domain.StateValidated:
			if err := s.mark(ctx, id, domain.StateApproved); err != nil {
				return
			}
		case domain.StateApproved, domain.StateStaged:
			if rec.DesiredDigest == "" {
				digest, err := s.stage(ctx, rec.GatewayYAML)
				if err != nil {
					_ = s.finish(ctx, id, domain.StateRejected, "")
					return
				}
				if err := s.markStaged(ctx, id, digest); err != nil {
					return
				}
				continue
			}
			s.publishLoop(ctx, id)
			return
		case domain.StateApplying, domain.StateObserving:
			s.publishLoop(ctx, id)
			return
		case domain.StateUnknown, domain.StatePartial:
			_ = s.reconcileOne(ctx, rec)
			return
		default:
			return
		}
	}
}

func (s *Service) stage(ctx context.Context, yaml []byte) (string, error) {
	deadline := time.Now().Add(s.poolWait)
	for {
		digest, err := s.publish.Stage(ctx, yaml)
		switch {
		case err == nil && digest != "":
			return digest, nil
		case err == nil:
			return "", ports.ErrRefused
		case errors.Is(err, ports.ErrBusy):
			if time.Now().After(deadline) || !sleep(ctx, s.backoff) {
				return "", err
			}
		default:
			return "", err
		}
	}
}

func (s *Service) publishLoop(ctx context.Context, id string) {
	deadline := time.Now().Add(s.poolWait)
	for {
		if ctx.Err() != nil {
			return
		}
		rec, ok, err := s.lookup(ctx, id)
		if err != nil || !ok || rec.State.Terminal() {
			return
		}
		if err := s.mark(ctx, id, domain.StateApplying); err != nil {
			return
		}
		prev, err := s.policies.Apply(ctx, rec.PolicyJSON, rec.PolicyVersion)
		if err != nil {
			next := domain.StateFailed
			if errors.Is(err, ports.ErrPartial) {
				next = domain.StatePartial
			}
			_ = s.finish(ctx, id, next, "")
			return
		}
		if err := s.rememberPrevious(ctx, id, prev); err != nil {
			return
		}
		if err := s.mark(ctx, id, domain.StateObserving); err != nil {
			return
		}
		out, err := s.publish.Publish(ctx, rec.GatewayYAML, rec.ReleaseRef)
		if errors.Is(err, ports.ErrBusy) || out.Busy {
			if rerr := s.policies.Restore(ctx, prev); rerr != nil {
				_ = s.finish(ctx, id, domain.StatePartial, out.ObservedDigest)
				return
			}
			if time.Now().After(deadline) || !sleep(ctx, s.backoff) {
				_ = s.finish(ctx, id, domain.StateRejected, "")
				return
			}
			if err := s.mark(ctx, id, domain.StateStaged); err != nil {
				return
			}
			continue
		}
		s.settle(ctx, rec, prev, out, err)
		return
	}
}

func (s *Service) settle(ctx context.Context, rec ports.Record, prev []byte, out ports.PublishOutcome, err error) {
	observed := out.ObservedDigest
	switch {
	case err != nil && out.Replaced:
		_ = s.finish(ctx, rec.ID, domain.StateUnknown, observed)
	case err != nil:
		s.restoreAs(ctx, rec.ID, prev, domain.StateFailed, observed)
	case (out.Outcome == ports.OutcomeActive || out.Outcome == ports.OutcomeActiveNotRecorded) &&
		observed != "" && observed == rec.DesiredDigest:
		_ = s.activate(ctx, rec.ID, observed)
	case out.Outcome == ports.OutcomeRefused && !out.Replaced:
		s.restoreAs(ctx, rec.ID, prev, domain.StateRejected, observed)
	case (out.Outcome == ports.OutcomeRestartRequired || out.Outcome == ports.OutcomePoolNotReady) && !out.Replaced:
		s.restoreAs(ctx, rec.ID, prev, domain.StateFailed, observed)
	case out.Outcome == ports.OutcomeRestored:
		s.restoreAs(ctx, rec.ID, prev, domain.StateFailed, observed)
	default:
		_ = s.finish(ctx, rec.ID, domain.StateUnknown, observed)
	}
}

func (s *Service) restoreAs(ctx context.Context, id string, prev []byte, okState domain.ReleaseState, observed string) {
	if err := s.policies.Restore(ctx, prev); err != nil {
		_ = s.finish(ctx, id, domain.StatePartial, observed)
		return
	}
	_ = s.finish(ctx, id, okState, observed)
}

func (s *Service) reconcileOne(ctx context.Context, rec ports.Record) error {
	out, err := s.publish.Reconcile(ctx)
	if err != nil {
		return err
	}
	fresh, ok, err := s.lookup(ctx, rec.ID)
	if err != nil || !ok {
		return err
	}
	if fresh.State != domain.StateUnknown && fresh.State != domain.StatePartial {
		return nil
	}
	if fresh.DesiredDigest != "" && out.ObservedDigest == fresh.DesiredDigest && digestConverged(out.Outcome) {
		if _, err := s.policies.Apply(ctx, fresh.PolicyJSON, fresh.PolicyVersion); err != nil {
			return nil
		}
		return s.activate(ctx, fresh.ID, out.ObservedDigest)
	}
	if out.Outcome == ports.OutcomeRestored || (out.Outcome == ports.OutcomeInSync && out.ObservedDigest != fresh.DesiredDigest) {
		previous := fresh.PreviousPolicy
		if !fresh.HasPrevious {
			previous = nil
		}
		if err := s.policies.Restore(ctx, previous); err != nil {
			return s.finish(ctx, fresh.ID, domain.StatePartial, out.ObservedDigest)
		}
		return s.finish(ctx, fresh.ID, domain.StateFailed, out.ObservedDigest)
	}
	return nil
}

func digestConverged(outcome string) bool {
	switch outcome {
	case ports.OutcomeInSync, ports.OutcomeActive, ports.OutcomeActiveNotRecorded, ports.OutcomeRestartPending:
		return true
	default:
		return false
	}
}

func (s *Service) activate(ctx context.Context, id, observed string) error {
	return s.withState(ctx, func(st *ports.State) error {
		i := st.Index(id)
		if i < 0 {
			return errStop
		}
		rec := st.Records[i]
		if rec.State == domain.StateActive {
			return errReadOnly
		}
		rec.State = domain.StateActive
		rec.ObservedDigest = observed
		st.Records[i] = rec
		st.Generation++
		for j := range st.Records {
			if j == i {
				continue
			}
			if st.Records[j].IntentID == rec.IntentID && st.Records[j].State == domain.StateActive {
				st.Records[j].State = domain.StateSuperseded
			}
		}
		st.Active = append([]domain.AcceptedIntent(nil), rec.NewActive...)
		return nil
	})
}

func (s *Service) mark(ctx context.Context, id string, next domain.ReleaseState) error {
	return s.withState(ctx, func(st *ports.State) error {
		i := st.Index(id)
		if i < 0 {
			return errStop
		}
		if st.Records[i].State == next || st.Records[i].State.Terminal() {
			return errReadOnly
		}
		st.Records[i].State = next
		return nil
	})
}

func (s *Service) markStaged(ctx context.Context, id, digest string) error {
	return s.withState(ctx, func(st *ports.State) error {
		i := st.Index(id)
		if i < 0 {
			return errStop
		}
		if st.Records[i].State.Terminal() {
			return errReadOnly
		}
		st.Records[i].State = domain.StateStaged
		st.Records[i].DesiredDigest = digest
		return nil
	})
}

func (s *Service) rememberPrevious(ctx context.Context, id string, previous []byte) error {
	return s.withState(ctx, func(st *ports.State) error {
		i := st.Index(id)
		if i < 0 {
			return errStop
		}
		st.Records[i].PreviousPolicy = append([]byte(nil), previous...)
		st.Records[i].HasPrevious = true
		return nil
	})
}

func (s *Service) finish(ctx context.Context, id string, next domain.ReleaseState, observed string) error {
	return s.withState(ctx, func(st *ports.State) error {
		i := st.Index(id)
		if i < 0 {
			return errStop
		}
		if st.Records[i].State == domain.StateActive || st.Records[i].State == domain.StateSuperseded {
			return errReadOnly
		}
		st.Records[i].State = next
		if observed != "" {
			st.Records[i].ObservedDigest = observed
		}
		return nil
	})
}

func (s *Service) lookup(ctx context.Context, id string) (ports.Record, bool, error) {
	var (
		rec   ports.Record
		found bool
	)
	err := s.withState(ctx, func(st *ports.State) error {
		i := st.Index(id)
		if i < 0 {
			return errReadOnly
		}
		rec = st.Records[i]
		found = true
		return errReadOnly
	})
	return rec, found, err
}

func (s *Service) idsIn(ctx context.Context, states ...domain.ReleaseState) ([]string, error) {
	want := map[domain.ReleaseState]struct{}{}
	for _, state := range states {
		want[state] = struct{}{}
	}
	var ids []string
	err := s.withState(ctx, func(st *ports.State) error {
		for _, rec := range st.Records {
			if _, ok := want[rec.State]; ok {
				ids = append(ids, rec.ID)
			}
		}
		return errReadOnly
	})
	return ids, err
}

func (s *Service) withState(ctx context.Context, fn func(*ports.State) error) error {
	release, err := s.store.Hold(ctx)
	if err != nil {
		return err
	}
	defer release()
	st, err := s.store.Load(ctx)
	if err != nil {
		return err
	}
	st.Normalize()
	if err := fn(&st); err != nil {
		if errors.Is(err, errReadOnly) {
			return nil
		}
		return err
	}
	return s.store.Save(ctx, st)
}

func blocked(st *ports.State) bool {
	for _, rec := range st.Records {
		if rec.State.BlocksNewPublish() {
			return true
		}
	}
	return false
}

func latest(st *ports.State, intentID string) (ports.Record, bool) {
	var (
		chosen ports.Record
		found  bool
		any    ports.Record
		anyOK  bool
	)
	for _, rec := range st.Records {
		if rec.IntentID != intentID {
			continue
		}
		if !anyOK || rec.CreatedUnixNano >= any.CreatedUnixNano {
			any, anyOK = rec, true
		}
		if rec.State == domain.StateSuperseded {
			continue
		}
		if !found || rec.CreatedUnixNano >= chosen.CreatedUnixNano {
			chosen, found = rec, true
		}
	}
	if found {
		return chosen, true
	}
	return any, anyOK
}

func policyVersion(base string, generation int, hash string) string {
	short := hash
	if len(short) > 8 {
		short = short[:8]
	}
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s|%d|%s", base, generation, hash)))
	if short == "" {
		short = hex.EncodeToString(sum[:4])
	}
	return fmt.Sprintf("%s-g%d-%s", base, generation, short)
}

func invalidCall(err error) error {
	return &CallError{Status: 422, Reason: oneLine(err)}
}

func conflict(reason string) error {
	return &CallError{Status: 409, Reason: reason}
}

func oneLine(err error) string {
	if err == nil {
		return "invalid"
	}
	text := strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, err.Error())
	if len(text) > 180 {
		text = text[:180]
	}
	if text == "" {
		return "invalid"
	}
	return text
}

func sleep(ctx context.Context, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}
