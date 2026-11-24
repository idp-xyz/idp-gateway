// Package application 把一次出站判定串起来：选定账户、按登记表判定、查撤销状态，
// 账户没有被撤销时再看这个操作有没有被封禁，配置了授权来源时再问一次账户的使用授权，
// 配置了配额时再按 Provider 账户限流，需要时取出凭证。它不知道请求是经哪种协议来的。
package application

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"

	"go.idp.xyz/idp-gateway/internal/egressauthz/domain"
	"go.idp.xyz/idp-gateway/internal/egressauthz/ports"
)

// 判定做不出来时的原因码。它们不是拒绝，更不是放行。
const (
	ReasonAccountRevoked             = "ACCOUNT_REVOKED"
	ReasonOperationBanned            = "OPERATION_BANNED"
	ReasonRevocationStateUnavailable = "REVOCATION_STATE_UNAVAILABLE"
	ReasonCredentialUnavailable      = "CREDENTIAL_UNAVAILABLE"
	ReasonGrantStateUnavailable      = "GRANT_STATE_UNAVAILABLE"
	ReasonRateLimited                = "RATE_LIMITED"
	ReasonRateLimitUnavailable       = "RATE_LIMIT_STATE_UNAVAILABLE"
)

// ErrIndeterminate 表示判定没能完成。调用方必须按拒绝处理，并且不能把它报告成策略拒绝。
var ErrIndeterminate = errors.New("egressauthz: decision indeterminate")

// ErrUnknownAccount 表示要撤销或恢复的账户既不在登记表里，也不在撤销表里。多半是名字打错了。
var ErrUnknownAccount = errors.New("egressauthz: account is neither in the policy nor revoked")

// ErrUnknownOperation 表示要封禁或解除的操作既不在登记表里，也不在封禁表里。多半是名字打错了。
var ErrUnknownOperation = errors.New("egressauthz: operation is neither in the policy nor banned")

// ErrNoRevocationLedger 表示这个服务没有配置可以改的撤销表。
var ErrNoRevocationLedger = errors.New("egressauthz: no revocation ledger configured")

// Input 是判定所需的上下文。除 RequestedAccount 外，各项都由网关从已验签的 Token 和
// 路由常量写出；RequestedAccount 来自调用方，只是申请。
type Input struct {
	Subject          string
	Tenant           string
	TokenEnvironment string
	RouteID          string
	ProviderID       string
	OperationID      string
	Environment      string
	Method           string
	Path             string
	RequestedAccount string
}

// Outcome 是一次判定的结果。
type Outcome struct {
	DecisionID      string
	Allowed         bool
	Reason          string
	PolicyVersion   string
	RevocationEpoch uint64
	// Account 是判定所针对的账户：调用方申请的，或在它没有申请时选出的唯一获授账户。
	Account string
	// BindingRef 只在放行时有值。
	BindingRef string
	// RateLimited 为 true 时这次请求因配额被拒绝：Allowed 为 false，RetryAfter 是至少 1 的秒数。
	RateLimited bool
	// RetryAfter 是调用方应当等待的秒数，只在 RateLimited 为 true 时大于 0。
	RetryAfter int
}

// CredentialHandle 返回放行结果对应的凭证句柄；未放行时为空。
func (o Outcome) CredentialHandle() string {
	if !o.Allowed {
		return ""
	}
	return ports.Handle(o.BindingRef, o.Account)
}

// Service 执行出站判定。
type Service struct {
	policy       domain.Policy
	policySource ports.PolicySource
	credentials  ports.CredentialSource
	revocations  ports.Revocations
	ledger       ports.RevocationLedger
	grants       ports.Grants
	limiter      ports.RateLimiter
	newID        func() string
}

// Option 调整 Service 的构造。
type Option func(*Service)

// WithGrants 让每一次登记表放行的判定再去问一次 grants。登记表只能被它收窄：
// 登记表拒绝的请求不会去问，grants 说没有授权或答不出来的请求不会放行。
func WithGrants(grants ports.Grants) Option {
	return func(s *Service) { s.grants = grants }
}

// WithRevocationLedger 让撤销表可以经本服务改动。判定读的仍是构造时给的 revocations；两者
// 应当是同一张表，由装配的一方保证。
func WithRevocationLedger(ledger ports.RevocationLedger) Option {
	return func(s *Service) { s.ledger = ledger }
}

// WithRateLimiter 在策略、撤销和授权都放行之后按 Provider 账户配额限流。
// limiter 为 nil 时不限流。限流器报错按没有结论处理（失败关闭）；被拒绝的请求不取凭证。
func WithRateLimiter(limiter ports.RateLimiter) Option {
	return func(s *Service) { s.limiter = limiter }
}

// WithPolicySource 让判定和管理校验读取 source 此刻的登记表，而不是一直用构造时的那一份。
// 登记表文件因此可以热重载。source 为 nil 时与不传相同。
func WithPolicySource(source ports.PolicySource) Option {
	return func(s *Service) { s.policySource = source }
}

// New 构造 Service。没有传入 WithPolicySource 时，policy 在进程生命周期内不变，换登记表要换进程。
// 传入 WithPolicySource 时，每次判定和管理校验改读来源此刻的登记表，登记表可以热重载。
func New(policy domain.Policy, credentials ports.CredentialSource, revocations ports.Revocations, options ...Option) *Service {
	s := &Service{policy: policy, credentials: credentials, revocations: revocations, newID: randomDecisionID}
	for _, option := range options {
		option(s)
	}
	return s
}

// currentPolicy 返回这一次调用要用的那一份登记表。配置了来源时读来源的当前一份，否则用构造时的那一份。
func (s *Service) currentPolicy() domain.Policy {
	if s.policySource != nil {
		return s.policySource.Current()
	}
	return s.policy
}

// PolicyVersion 返回当前登记表的版本。
func (s *Service) PolicyVersion() string { return s.currentPolicy().Version }

// RevocationEpoch 返回当前撤销代次，用在没有做出判定的响应里；读不到时为 0。
func (s *Service) RevocationEpoch(ctx context.Context) uint64 {
	epoch, err := s.revocations.Epoch(ctx)
	if err != nil {
		return 0
	}
	return epoch
}

// Decide 只做判定，不取凭证。返回的错误包装了 ErrIndeterminate，此时 Outcome 里的
// 原因码说明是哪一步没能完成。
func (s *Service) Decide(ctx context.Context, in Input) (Outcome, error) {
	policy := s.currentPolicy()
	out := Outcome{DecisionID: s.newID(), PolicyVersion: policy.Version, Account: in.RequestedAccount}

	var principal *domain.Principal
	if in.Subject != "" && in.Tenant != "" && in.TokenEnvironment != "" {
		principal = &domain.Principal{ServiceID: in.Subject, TenantID: in.Tenant, Environment: in.TokenEnvironment}
	}
	if out.Account == "" && principal != nil {
		if account, ok := policy.SoleAccount(principal.TenantID, in.ProviderID, in.OperationID, in.Environment); ok {
			out.Account = account
		}
	}

	// 撤销状态在每次判定时读取，与路由发布无关。读不到就不出结论：既不能当作没撤销，
	// 也没有可以如实填写的撤销代次。账户是否被撤销、操作是否被封禁，和代次一起读出。
	revoked, banned, epoch, err := s.revocations.View(ctx, out.Account, in.OperationID)
	if err != nil {
		out.Reason = ReasonRevocationStateUnavailable
		return out, fmt.Errorf("%w: revocation state: %w", ErrIndeterminate, err)
	}
	out.RevocationEpoch = epoch

	decision := policy.Evaluate(principal, domain.Request{
		ProviderID: in.ProviderID, OperationID: in.OperationID, Environment: in.Environment,
		Method: in.Method, Path: in.Path, AccountID: out.Account,
	})
	out.Reason = string(decision.Reason)
	if !decision.Allowed {
		return out, nil
	}
	// 账户撤销先于操作封禁：两样都碰上时原因仍是 ACCOUNT_REVOKED。封禁只在登记表本来会放行时
	// 才成为原因，并且排在取凭证、问授权、扣配额之前。
	if revoked {
		out.Reason = ReasonAccountRevoked
		return out, nil
	}
	if banned {
		out.Reason = ReasonOperationBanned
		return out, nil
	}
	// 放在配额之前问：前面任何一步拒绝，都不必为这个请求发一次网络调用，也不扣配额。
	if s.grants != nil {
		granted, err := s.grants.MayUse(ctx, principal.ServiceID, principal.TenantID, out.Account)
		if err != nil {
			out.Reason = ReasonGrantStateUnavailable
			return out, fmt.Errorf("%w: grant state: %w", ErrIndeterminate, err)
		}
		if !granted {
			out.Reason = string(domain.ReasonAccountNotGranted)
			return out, nil
		}
	}
	// 配额排在策略、撤销、授权之后：前面任何一步拒绝，都不消耗额度，也不为这个请求取凭证。
	// 多条规则是否同时放行由限流器在一次调用里决定；这里只在它允许之后才把判定标成放行。
	if s.limiter != nil {
		allowed, retryAfter, err := s.limiter.Allow(ctx, domain.RateLimitSubject{
			ProviderID: in.ProviderID, AccountID: out.Account, TenantID: in.Tenant,
			OperationID: in.OperationID, ServiceID: in.Subject,
		})
		if err != nil {
			out.Reason = ReasonRateLimitUnavailable
			return out, fmt.Errorf("%w: rate limit: %w", ErrIndeterminate, err)
		}
		if !allowed {
			if retryAfter < 1 {
				retryAfter = 1
			}
			out.Allowed = false
			out.RateLimited = true
			out.RetryAfter = retryAfter
			out.Reason = ReasonRateLimited
			return out, nil
		}
	}
	out.Allowed = true
	out.BindingRef = decision.CredentialBindingRef
	return out, nil
}

// Authorize 做判定，并在放行时取出本次请求要用的凭证。放行而取不到凭证不是放行：
// 返回包装了 ErrIndeterminate 的错误，Outcome.Allowed 为 false。
func (s *Service) Authorize(ctx context.Context, in Input) (Outcome, ports.Secret, error) {
	out, err := s.Decide(ctx, in)
	if err != nil || !out.Allowed {
		return out, ports.Secret{}, err
	}
	credential, err := s.credentials.AuthorizationHeader(ctx, out.BindingRef, out.Account)
	if err == nil && credential.IsZero() {
		err = ports.ErrCredentialNotHeld
	}
	if err != nil {
		out.Allowed, out.BindingRef, out.Reason = false, "", ReasonCredentialUnavailable
		return out, ports.Secret{}, fmt.Errorf("%w: credential: %w", ErrIndeterminate, err)
	}
	return out, credential, nil
}

// RevokeAccount 撤销一个账户：从下一次判定起，它在哪条路由上都不放行。by 是做这件事的
// 工作负载身份。
//
// 只接受登记表里出现过的账户（已经在撤销表里的也接受，那是重复撤销）：名字打错了要得到
// ErrUnknownAccount，而不是一次什么都没拦住的成功。返回的错误包装了
// ports.ErrRevocationNotWritten 时，撤销已经生效，只是没有保存下来。
func (s *Service) RevokeAccount(ctx context.Context, accountID, by, reason string) (ports.RevocationChange, error) {
	policy := s.currentPolicy()
	if s.ledger == nil {
		return ports.RevocationChange{}, ErrNoRevocationLedger
	}
	if !policy.NamesAccount(accountID) {
		revoked, epoch, err := s.ledger.State(ctx, accountID)
		if err != nil {
			return ports.RevocationChange{}, err
		}
		if !revoked {
			return ports.RevocationChange{Epoch: epoch}, ErrUnknownAccount
		}
	}
	return s.ledger.Revoke(ctx, accountID, by, reason)
}

// RestoreAccount 取消对一个账户的撤销。账户没有被撤销时什么都不改；账户既不在登记表里也
// 不在撤销表里时返回 ErrUnknownAccount。恢复没有保存下来就不生效。
func (s *Service) RestoreAccount(ctx context.Context, accountID string) (ports.RevocationChange, error) {
	policy := s.currentPolicy()
	if s.ledger == nil {
		return ports.RevocationChange{}, ErrNoRevocationLedger
	}
	revoked, epoch, err := s.ledger.State(ctx, accountID)
	if err != nil {
		return ports.RevocationChange{}, err
	}
	if !revoked && !policy.NamesAccount(accountID) {
		return ports.RevocationChange{Epoch: epoch}, ErrUnknownAccount
	}
	return s.ledger.Restore(ctx, accountID)
}

// RevokedAccounts 返回整张撤销表和当前代次。
func (s *Service) RevokedAccounts(ctx context.Context) ([]ports.RevokedAccount, uint64, error) {
	if s.ledger == nil {
		return nil, 0, ErrNoRevocationLedger
	}
	return s.ledger.Revoked(ctx)
}

// BanOperation 封禁一个操作：从下一次判定起，每个账户做这个操作都不放行。by 是做这件事的
// 工作负载身份。别的操作不变。这不是路由发布。
//
// 只接受登记表里出现过的 operation_id（已经在封禁表里的也接受，那是重复封禁）：名字打错了要得到
// ErrUnknownOperation，而不是一次什么都没拦住的成功。返回的错误包装了
// ports.ErrRevocationNotWritten 时，封禁已经生效，只是没有保存下来。
func (s *Service) BanOperation(ctx context.Context, operationID, by, reason string) (ports.BanChange, error) {
	policy := s.currentPolicy()
	if s.ledger == nil {
		return ports.BanChange{}, ErrNoRevocationLedger
	}
	if !policy.NamesOperation(operationID) {
		_, banned, epoch, err := s.ledger.View(ctx, "", operationID)
		if err != nil {
			return ports.BanChange{}, err
		}
		if !banned {
			return ports.BanChange{Epoch: epoch}, ErrUnknownOperation
		}
	}
	return s.ledger.Ban(ctx, operationID, by, reason)
}

// LiftOperationBan 解除对一个操作的封禁。操作没有被封禁时什么都不改；操作既不在登记表里也
// 不在封禁表里时返回 ErrUnknownOperation。解除没有保存下来就不生效。
func (s *Service) LiftOperationBan(ctx context.Context, operationID string) (ports.BanChange, error) {
	policy := s.currentPolicy()
	if s.ledger == nil {
		return ports.BanChange{}, ErrNoRevocationLedger
	}
	_, banned, epoch, err := s.ledger.View(ctx, "", operationID)
	if err != nil {
		return ports.BanChange{}, err
	}
	if !banned && !policy.NamesOperation(operationID) {
		return ports.BanChange{Epoch: epoch}, ErrUnknownOperation
	}
	return s.ledger.Lift(ctx, operationID)
}

// BannedOperations 返回被封禁的操作和当前代次。
func (s *Service) BannedOperations(ctx context.Context) ([]ports.BannedOperation, uint64, error) {
	if s.ledger == nil {
		return nil, 0, ErrNoRevocationLedger
	}
	return s.ledger.Banned(ctx)
}

func randomDecisionID() string {
	var b [6]byte
	// crypto/rand.Read 在受支持的平台上不返回错误；万一失败，Go 运行时会直接终止进程。
	_, _ = rand.Read(b[:])
	return "dec-" + hex.EncodeToString(b[:])
}
