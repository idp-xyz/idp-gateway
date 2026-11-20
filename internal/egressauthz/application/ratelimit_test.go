package application

import (
	"context"
	"errors"
	"testing"
	"time"

	"go.idp.xyz/idp-gateway/internal/egressauthz/domain"
)

// countingLimiter 包住一张真的配额表，并数被问了几次。
type countingLimiter struct {
	table *domain.QuotaTable
	now   time.Time
	calls int
	err   error
	last  domain.RateLimitSubject
}

func (c *countingLimiter) Allow(_ context.Context, subject domain.RateLimitSubject) (bool, int, error) {
	c.calls++
	c.last = subject
	if c.err != nil {
		return false, 0, c.err
	}
	allowed, retry := c.table.Allow(c.now, subject)
	return allowed, retry, nil
}

func newLimited(t *testing.T, max int, grants *fakeGrants) (*Service, *fakeCredentials, *fakeRevocations, *countingLimiter) {
	t.Helper()
	table, err := domain.NewQuotaTable([]domain.QuotaRule{{
		ID: "per-account", KeyDimensions: []string{"provider", "provider_account"},
		MaxRequests: max, WindowSeconds: 60,
	}})
	if err != nil {
		t.Fatal(err)
	}
	limiter := &countingLimiter{table: table, now: time.Unix(1_700_000_000, 0)}
	_, credentials, revocations := newService()
	options := []Option{WithRateLimiter(limiter)}
	if grants != nil {
		options = append(options, WithGrants(grants))
	}
	return New(twoTenantPolicy(), credentials, revocations, options...), credentials, revocations, limiter
}

// 策略拒绝、撤销、授权拒绝都不问配额，因此也不会把蓝账户的额度扣掉。
func TestRateLimitIsAfterPolicyRevocationAndGrants(t *testing.T) {
	t.Run("未获授的服务", func(t *testing.T) {
		service, credentials, _, limiter := newLimited(t, 1, nil)
		in := blueInput()
		in.Subject = "cargo-service"
		out, err := service.Decide(context.Background(), in)
		if err != nil || out.Allowed || out.Reason != string(domain.ReasonServiceNotGranted) || out.RateLimited || limiter.calls != 0 {
			t.Fatalf("未获授仍问了配额：%+v calls=%d err=%v", out, limiter.calls, err)
		}
		out, credential, err := service.Authorize(context.Background(), blueInput())
		if err != nil || !out.Allowed || credential.Reveal() != "Bearer blue-token" || limiter.calls != 1 {
			t.Fatalf("蓝账户的额度被未获授的调用方扣掉了：%+v calls=%d %v", out, limiter.calls, err)
		}
		if len(credentials.asked) != 1 {
			t.Fatalf("凭证来源被问了 %d 次", len(credentials.asked))
		}
	})

	t.Run("申请别人的账户", func(t *testing.T) {
		service, credentials, _, limiter := newLimited(t, 1, nil)
		in := blueInput()
		in.RequestedAccount = "account-green"
		out, _, err := service.Authorize(context.Background(), in)
		if err != nil || out.Reason != string(domain.ReasonAccountNotGranted) || limiter.calls != 0 || len(credentials.asked) != 0 {
			t.Fatalf("%+v calls=%d asked=%v err=%v", out, limiter.calls, credentials.asked, err)
		}
		if out, _, err := service.Authorize(context.Background(), blueInput()); err != nil || !out.Allowed || limiter.calls != 1 {
			t.Fatalf("蓝账户的额度被对绿账户的申请扣掉了：%+v calls=%d %v", out, limiter.calls, err)
		}
	})

	t.Run("已撤销", func(t *testing.T) {
		service, credentials, revocations, limiter := newLimited(t, 1, nil)
		revocations.revoked["account-blue"] = true
		out, _, err := service.Authorize(context.Background(), blueInput())
		if err != nil || out.Reason != ReasonAccountRevoked || out.RateLimited || limiter.calls != 0 || len(credentials.asked) != 0 {
			t.Fatalf("%+v calls=%d err=%v", out, limiter.calls, err)
		}
		revocations.revoked["account-blue"] = false
		if out, _, err := service.Authorize(context.Background(), blueInput()); err != nil || !out.Allowed || limiter.calls != 1 {
			t.Fatalf("撤销的请求扣了配额：%+v calls=%d %v", out, limiter.calls, err)
		}
	})

	t.Run("授权来源拒绝", func(t *testing.T) {
		grants := &fakeGrants{}
		service, credentials, _, limiter := newLimited(t, 1, grants)
		out, _, err := service.Authorize(context.Background(), blueInput())
		if err != nil || out.Reason != string(domain.ReasonAccountNotGranted) || limiter.calls != 0 || len(credentials.asked) != 0 {
			t.Fatalf("%+v calls=%d err=%v", out, limiter.calls, err)
		}
		grants.granted = true
		if out, _, err := service.Authorize(context.Background(), blueInput()); err != nil || !out.Allowed || limiter.calls != 1 {
			t.Fatalf("没有授权的请求扣了配额：%+v calls=%d %v", out, limiter.calls, err)
		}
	})

	t.Run("授权来源没有结论", func(t *testing.T) {
		grants := &fakeGrants{err: errors.New("pdp down")}
		service, credentials, _, limiter := newLimited(t, 1, grants)
		out, _, err := service.Authorize(context.Background(), blueInput())
		if !errors.Is(err, ErrIndeterminate) || out.Reason != ReasonGrantStateUnavailable || limiter.calls != 0 || len(credentials.asked) != 0 {
			t.Fatalf("%+v calls=%d err=%v", out, limiter.calls, err)
		}
	})
}

func TestRateLimitDeniesWithoutACredential(t *testing.T) {
	service, credentials, _, limiter := newLimited(t, 1, nil)
	first, credential, err := service.Authorize(context.Background(), blueInput())
	if err != nil || !first.Allowed || credential.IsZero() || limiter.calls != 1 {
		t.Fatalf("第一次：%+v %v calls=%d", first, err, limiter.calls)
	}
	if limiter.last.AccountID != "account-blue" || limiter.last.ProviderID != "mockcarrier" ||
		limiter.last.TenantID != "tenant-blue" || limiter.last.OperationID != "tracking.get" || limiter.last.ServiceID != "parcel-service" {
		t.Fatalf("配额键用的主体不对：%+v", limiter.last)
	}
	second, credential, err := service.Authorize(context.Background(), blueInput())
	if err != nil || second.Allowed || !second.RateLimited || second.Reason != ReasonRateLimited || second.RetryAfter != 60 ||
		second.BindingRef != "" || !credential.IsZero() || len(credentials.asked) != 1 {
		t.Fatalf("第二次：%+v credentialZero=%v asked=%d err=%v", second, credential.IsZero(), len(credentials.asked), err)
	}
	// 只做判定的接口同样拒绝，而且同样不取凭证。
	third, err := service.Decide(context.Background(), blueInput())
	if err != nil || third.Allowed || third.Reason != ReasonRateLimited || third.CredentialHandle() != "" {
		t.Fatalf("判定接口：%+v %v", third, err)
	}

	// 另一个账户不受影响。
	green := blueInput()
	green.Tenant = "tenant-green"
	if out, _, err := service.Authorize(context.Background(), green); err != nil || !out.Allowed {
		t.Fatalf("绿账户：%+v %v", out, err)
	}
}

func TestRateLimitErrorIsIndeterminate(t *testing.T) {
	service, credentials, _, limiter := newLimited(t, 1, nil)
	limiter.err = errors.New("table locked")
	out, credential, err := service.Authorize(context.Background(), blueInput())
	if !errors.Is(err, ErrIndeterminate) || out.Allowed || out.RateLimited || out.Reason != ReasonRateLimitUnavailable || !credential.IsZero() || len(credentials.asked) != 0 {
		t.Fatalf("%+v %v asked=%d", out, err, len(credentials.asked))
	}
}

func TestRateLimitRetryAfterIsAtLeastOneSecond(t *testing.T) {
	service, _, _, _ := newLimited(t, 1, nil)
	// 限流器拒绝但给出 0 秒时，服务把它抬到至少 1 秒。
	service.limiter = zeroRetryLimiter{}
	out, _, err := service.Authorize(context.Background(), blueInput())
	if err != nil || !out.RateLimited || out.RetryAfter != 1 || out.Reason != ReasonRateLimited {
		t.Fatalf("%+v %v", out, err)
	}
}

type zeroRetryLimiter struct{}

func (zeroRetryLimiter) Allow(context.Context, domain.RateLimitSubject) (bool, int, error) {
	return false, 0, nil
}
