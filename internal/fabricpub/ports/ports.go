// Package ports 是 fabricpub 对外部的要求。编译、发布和策略文件由 cmd/gateway-fabric 接到别的上下文，
// 本上下文的适配器不导入那些上下文。
package ports

import (
	"context"
	"errors"

	"go.idp.xyz/idp-gateway/internal/fabricpub/domain"
)

var (
	// ErrRefused 表示校验、预检或离线加载拒绝了这份配置。池还没有被改。
	ErrRefused = errors.New("fabricpub: refused")
	// ErrBusy 表示池上的锁正被别的发布占着。
	ErrBusy = errors.New("fabricpub: pool is busy")
	// ErrPartial 表示策略文件和该回到的那一份对不上，而且换不回去。
	ErrPartial = errors.New("fabricpub: partial")
)

// State 是 --state-dir 里的整份状态。
type State struct {
	Generation  int                     `json:"generation"`
	Records     []Record                `json:"records"`
	Idempotency map[string]Idempotency  `json:"idempotency"`
	Active      []domain.AcceptedIntent `json:"active"`
}

// Normalize 把缺了的集合补成空的，免得调用方再判 nil。
func (s *State) Normalize() {
	if s.Records == nil {
		s.Records = []Record{}
	}
	if s.Idempotency == nil {
		s.Idempotency = map[string]Idempotency{}
	}
	if s.Active == nil {
		s.Active = []domain.AcceptedIntent{}
	}
}

// Index 返回记录在切片里的位置。没有时是 -1。
func (s *State) Index(id string) int {
	for i := range s.Records {
		if s.Records[i].ID == id {
			return i
		}
	}
	return -1
}

// Record 是一条发布。编译产物存在记录里，发布时不再重编。
type Record struct {
	ID              string                  `json:"id"`
	IntentID        string                  `json:"intent_id"`
	ReleaseRef      string                  `json:"release_ref"`
	IdempotencyKey  string                  `json:"idempotency_key"`
	CanonicalHash   string                  `json:"canonical_hash"`
	State           domain.ReleaseState     `json:"state"`
	DesiredDigest   string                  `json:"desired_digest,omitempty"`
	ObservedDigest  string                  `json:"observed_digest,omitempty"`
	GatewayYAML     []byte                  `json:"gateway_yaml,omitempty"`
	PolicyJSON      []byte                  `json:"policy_json,omitempty"`
	PolicyVersion   string                  `json:"policy_version,omitempty"`
	GatewaySHA256   string                  `json:"gateway_sha256,omitempty"`
	PreviousPolicy  []byte                  `json:"previous_policy,omitempty"`
	HasPrevious     bool                    `json:"has_previous,omitempty"`
	NewActive       []domain.AcceptedIntent `json:"new_active,omitempty"`
	CreatedUnixNano int64                   `json:"created_unix_nano"`
}

// Idempotency 把一把键绑在第一次收下的正文上。
type Idempotency struct {
	Hash       string `json:"hash"`
	IntentID   string `json:"intent_id"`
	ReleaseRef string `json:"release_ref"`
	RecordID   string `json:"record_id"`
}

// StateStore 是 --state-dir。Hold 是目录锁，Load 和 Save 由占着锁的人调用。
type StateStore interface {
	Hold(ctx context.Context) (release func(), err error)
	Load(ctx context.Context) (State, error)
	Save(ctx context.Context, state State) error
}

// CompiledBundle 是一次编译的产物。PolicyVersion 是登记表里的 version。
type CompiledBundle struct {
	GatewayYAML   []byte
	PolicyJSON    []byte
	GatewaySHA256 string
	PolicyVersion string
}

// Compiler 校验并编译整份出站规格。拒绝时错误带 ErrRefused。
type Compiler interface {
	ValidateAndCompile(ctx context.Context, specJSON []byte) (CompiledBundle, error)
}

// PolicyApplier 原子换上 gateway-authz 的策略文件，并确认版本已经生效。
// 确认不了时自己把旧文件换回去；换不回去时错误带 ErrPartial。
type PolicyApplier interface {
	Apply(ctx context.Context, policyJSON []byte, wantVersion string) (previous []byte, err error)
	Restore(ctx context.Context, previous []byte) error
}

// 发布和对账的结局词。与 gatewayconfig 写出的词相同；OVERTAKEN 只在这里被认出来，不往外写。
const (
	OutcomeActive            = "ACTIVE"
	OutcomeActiveNotRecorded = "ACTIVE_NOT_RECORDED"
	OutcomeRefused           = "REFUSED"
	OutcomeRestartRequired   = "RESTART_REQUIRED"
	OutcomePoolNotReady      = "POOL_NOT_READY"
	OutcomeRestored          = "RESTORED"
	OutcomeUnknown           = "UNKNOWN"
	OutcomeOvertaken         = "OVERTAKEN"
	OutcomeInSync            = "IN_SYNC"
	OutcomeRestartPending    = "RESTART_PENDING"
	OutcomeUnconfirmed       = "UNCONFIRMED"
)

// PublishOutcome 是一次往池上发布的结果。
type PublishOutcome struct {
	Outcome        string
	DesiredDigest  string
	ObservedDigest string
	Replaced       bool
	Busy           bool
	Reason         string
}

// ReconcileOutcome 是一次对账的结果。
type ReconcileOutcome struct {
	Outcome        string
	DesiredDigest  string
	ObservedDigest string
	Replaced       bool
	Reason         string
}

// PoolPublisher 把快照送到一个池。Stage 只离线加载，不改池。
type PoolPublisher interface {
	Stage(ctx context.Context, gatewayYAML []byte) (desiredDigest string, err error)
	Publish(ctx context.Context, gatewayYAML []byte, note string) (PublishOutcome, error)
	Reconcile(ctx context.Context) (ReconcileOutcome, error)
}
