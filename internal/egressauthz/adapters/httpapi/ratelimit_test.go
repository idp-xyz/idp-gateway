package httpapi

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"testing"
	"time"

	"go.idp.xyz/idp-gateway/internal/egressauthz/application"
	"go.idp.xyz/idp-gateway/internal/egressauthz/domain"
	"go.idp.xyz/idp-gateway/internal/egressauthz/ports"
)

func quotaTable(t *testing.T, max int) *domain.QuotaTable {
	t.Helper()
	table, err := domain.NewQuotaTable([]domain.QuotaRule{{
		ID: "per-account", KeyDimensions: []string{"provider", "provider_account"},
		MaxRequests: max, WindowSeconds: 60,
	}})
	if err != nil {
		t.Fatal(err)
	}
	return table
}

type tableLimiter struct{ table *domain.QuotaTable }

func (t tableLimiter) Allow(_ context.Context, subject domain.RateLimitSubject) (bool, int, error) {
	allowed, retry := t.table.Allow(time.Unix(1_700_000_000, 0), subject)
	return allowed, retry, nil
}

func fixtureWithLimiter(t *testing.T, limiter ports.RateLimiter) *fixture {
	t.Helper()
	f := newFixture(t)
	policy := domain.Policy{Version: "policy-7", Operations: []domain.Operation{{
		ProviderID: "mockcarrier", OperationID: "tracking.get", Environment: "TEST", Method: "GET",
		PathPrefix: tracking, CredentialBindingRef: binding,
		AllowedTenants: []string{"tenant-blue", "tenant-green"}, AllowedServiceIDs: []string{"parcel-service"},
		AccountsByTenant: map[string][]string{"tenant-blue": {"account-blue"}, "tenant-green": {"account-green"}},
	}}}
	service := application.New(policy, f.credentials, f.revocations, application.WithRateLimiter(limiter))
	f.logs.Reset()
	f.handler = New(service, Callers{Gateway: gatewayID, Broker: brokerID}, slog.New(slog.NewJSONHandler(f.logs, nil)))
	f.handler.now = func() time.Time { return time.Date(2026, 11, 10, 8, 0, 0, 0, time.UTC) }
	return f
}

func TestExtAuthzRateLimit(t *testing.T) {
	f := fixtureWithLimiter(t, tableLimiter{quotaTable(t, 2)})
	for i := 1; i <= 2; i++ {
		recorder := f.call("gateway", "GET", PathExtAuthz, trusted("tenant-blue"), "")
		if recorder.Code != http.StatusOK || recorder.Header().Get("Authorization") != blueToken {
			t.Fatalf("第 %d 次：%d %s", i, recorder.Code, recorder.Body)
		}
	}
	limited := f.call("gateway", "GET", PathExtAuthz, trusted("tenant-blue"), "")
	body := decode(t, limited)
	retry, err := strconv.Atoi(limited.Header().Get("Retry-After"))
	if limited.Code != http.StatusTooManyRequests || err != nil || retry < 1 || retry > 60 {
		t.Fatalf("429：status=%d retry=%q err=%v body=%s", limited.Code, limited.Header().Get("Retry-After"), err, limited.Body)
	}
	if body["result"] != "DENY" || body["reason_code"] != application.ReasonRateLimited || body["policy_version"] != "policy-7" {
		t.Fatalf("正文：%v", body)
	}
	if limited.Header().Get("Authorization") != "" || carriesCredential(limited) {
		t.Fatalf("429 带了凭证：%v %s", limited.Header(), limited.Body)
	}
	requireDecisionID(t, f, limited, body)
	logged := lastLog(t, f)
	if logged["msg"] != "egress authorization" || logged["status"] != float64(http.StatusTooManyRequests) ||
		logged["result"] != "DENY" || logged["reason"] != application.ReasonRateLimited {
		t.Fatalf("日志：%v", logged)
	}
	// 绿账户是另一只桶。
	if recorder := f.call("gateway", "GET", PathExtAuthz, trusted("tenant-green"), ""); recorder.Code != http.StatusOK || recorder.Header().Get("Authorization") != greenToken {
		t.Fatalf("绿账户：%d %s", recorder.Code, recorder.Body)
	}
}

func TestDeniedRequestDoesNotConsumeTheRateLimit(t *testing.T) {
	f := fixtureWithLimiter(t, tableLimiter{quotaTable(t, 1)})
	headers := append(trusted("tenant-blue"), [2]string{"X-Provider-Account", "account-green"})
	denied := f.call("gateway", "GET", PathExtAuthz, headers, "")
	if denied.Code != http.StatusForbidden || decode(t, denied)["reason_code"] != "ACCOUNT_NOT_GRANTED" {
		t.Fatalf("申请绿账户：%d %s", denied.Code, denied.Body)
	}
	allowed := f.call("gateway", "GET", PathExtAuthz, trusted("tenant-blue"), "")
	if allowed.Code != http.StatusOK || allowed.Header().Get("Authorization") != blueToken {
		t.Fatalf("蓝账户的额度被没获授的申请扣掉了：%d %s", allowed.Code, allowed.Body)
	}
}

func TestDecisionRateLimitStaysDenyAt200(t *testing.T) {
	f := fixtureWithLimiter(t, tableLimiter{quotaTable(t, 1)})
	first := f.call("broker", "POST", PathDecision, nil, decisionJSON(nil))
	if first.Code != http.StatusOK || decode(t, first)["result"] != "ALLOW" {
		t.Fatalf("第一次：%d %s", first.Code, first.Body)
	}
	second := f.call("broker", "POST", PathDecision, nil, decisionJSON(nil))
	body := decode(t, second)
	if second.Code != http.StatusOK || body["result"] != "DENY" || body["reason_code"] != application.ReasonRateLimited {
		t.Fatalf("判定接口：%d %v", second.Code, body)
	}
	if _, has := body["credential_handle"]; has || second.Header().Get("Authorization") != "" || carriesCredential(second) {
		t.Fatalf("判定接口带了凭证：%v %v", second.Header(), body)
	}
	if logged := lastLog(t, f); logged["status"] != float64(http.StatusOK) || logged["reason"] != application.ReasonRateLimited {
		t.Fatalf("日志：%v", logged)
	}
}

type errLimiter struct{}

func (errLimiter) Allow(context.Context, domain.RateLimitSubject) (bool, int, error) {
	return false, 0, errors.New("limiter down")
}

func TestRateLimitFailureIsServiceUnavailable(t *testing.T) {
	f := fixtureWithLimiter(t, errLimiter{})
	recorder := f.call("gateway", "GET", PathExtAuthz, trusted("tenant-blue"), "")
	body := decode(t, recorder)
	if recorder.Code != http.StatusServiceUnavailable || body["result"] != "INDETERMINATE" || body["reason_code"] != application.ReasonRateLimitUnavailable {
		t.Fatalf("%d %v", recorder.Code, body)
	}
	if recorder.Header().Get("Authorization") != "" || recorder.Header().Get("Retry-After") != "" || carriesCredential(recorder) {
		t.Fatalf("没有结论的限流带了不该有的头：%v", recorder.Header())
	}
}
