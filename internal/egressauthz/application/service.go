// Package application 把一次出站判定串起来：选定账户、按登记表判定、查撤销状态，
// 配置了授权来源时再问一次账户的使用授权，需要时取出凭证。它不知道请求是经哪种协议来的。
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
	ReasonRevocationStateUnavailable = "REVOCATION_STATE_UNAVAILABLE"
	ReasonCredentialUnavailable      = "CREDENTIAL_UNAVAILABLE"
	ReasonGrantStateUnavailable      = "GRANT_STATE_UNAVAILABLE"
)

// ErrIndeterminate 表示判定没能完成。调用方必须按拒绝处理，并且不能把它报告成策略拒绝。
var ErrIndeterminate = errors.New("egressauthz: decision indeterminate")

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
	policy      domain.Policy
	credentials ports.CredentialSource
	revocations ports.Revocations
	grants      ports.Grants
	newID       func() string
}

// Option 调整 Service 的构造。
type Option func(*Service)

// WithGrants 让每一次登记表放行的判定再去问一次 grants。登记表只能被它收窄：
// 登记表拒绝的请求不会去问，grants 说没有授权或答不出来的请求不会放行。
func WithGrants(grants ports.Grants) Option {
	return func(s *Service) { s.grants = grants }
}

// New 构造 Service。policy 在进程生命周期内不变；换登记表要换进程。
func New(policy domain.Policy, credentials ports.CredentialSource, revocations ports.Revocations, options ...Option) *Service {
	s := &Service{policy: policy, credentials: credentials, revocations: revocations, newID: randomDecisionID}
	for _, option := range options {
		option(s)
	}
	return s
}

// PolicyVersion 返回当前登记表的版本。
func (s *Service) PolicyVersion() string { return s.policy.Version }

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
	out := Outcome{DecisionID: s.newID(), PolicyVersion: s.policy.Version, Account: in.RequestedAccount}

	var principal *domain.Principal
	if in.Subject != "" && in.Tenant != "" && in.TokenEnvironment != "" {
		principal = &domain.Principal{ServiceID: in.Subject, TenantID: in.Tenant, Environment: in.TokenEnvironment}
	}
	if out.Account == "" && principal != nil {
		if account, ok := s.policy.SoleAccount(principal.TenantID, in.ProviderID, in.OperationID, in.Environment); ok {
			out.Account = account
		}
	}

	// 撤销状态在每次判定时读取，与路由发布无关。读不到就不出结论：既不能当作没撤销，
	// 也没有可以如实填写的撤销代次。
	revoked, epoch, err := s.revocations.State(ctx, out.Account)
	if err != nil {
		out.Reason = ReasonRevocationStateUnavailable
		return out, fmt.Errorf("%w: revocation state: %w", ErrIndeterminate, err)
	}
	out.RevocationEpoch = epoch

	decision := s.policy.Evaluate(principal, domain.Request{
		ProviderID: in.ProviderID, OperationID: in.OperationID, Environment: in.Environment,
		Method: in.Method, Path: in.Path, AccountID: out.Account,
	})
	out.Reason = string(decision.Reason)
	if !decision.Allowed {
		return out, nil
	}
	if revoked {
		out.Reason = ReasonAccountRevoked
		return out, nil
	}
	// 放在最后问：前面任何一步拒绝，都不必为这个请求发一次网络调用。
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

func randomDecisionID() string {
	var b [6]byte
	// crypto/rand.Read 在受支持的平台上不返回错误；万一失败，Go 运行时会直接终止进程。
	_, _ = rand.Read(b[:])
	return "dec-" + hex.EncodeToString(b[:])
}
