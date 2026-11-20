package filestore

import (
	"bytes"
	"context"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"go.idp.xyz/idp-gateway/internal/egressauthz/domain"
)

func rateLimitSubject(account string) domain.RateLimitSubject {
	return domain.RateLimitSubject{
		ProviderID: "mockcarrier", AccountID: account, TenantID: "tenant-blue",
		OperationID: "tracking.get", ServiceID: "parcel-service",
	}
}

const validRateLimits = `{
  "version": "v1",
  "buckets": [{
    "id": "per-account",
    "provider_id": "",
    "operation_id": "",
    "key_dimensions": ["provider", "provider_account"],
    "max_requests": 1,
    "window_seconds": 60
  }]
}`

func loadRateLimits(t *testing.T, content string, mode os.FileMode, logger *slog.Logger) *RateLimits {
	t.Helper()
	store, err := LoadRateLimits(writeFile(t, content, mode), logger)
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func TestRateLimitsLoadAndAllow(t *testing.T) {
	for _, mode := range []os.FileMode{0o644, 0o600} {
		store := loadRateLimits(t, validRateLimits, mode, nil)
		if store.Len() != 1 {
			t.Fatalf("权限 %04o：%d 条", mode, store.Len())
		}
		allowed, retry, err := store.Allow(context.Background(), rateLimitSubject("account-blue"))
		if err != nil || !allowed || retry != 0 {
			t.Fatalf("权限 %04o：第一次 %v %d %v", mode, allowed, retry, err)
		}
		allowed, retry, err = store.Allow(context.Background(), rateLimitSubject("account-blue"))
		if err != nil || allowed || retry < 1 {
			t.Fatalf("权限 %04o：第二次 %v %d %v", mode, allowed, retry, err)
		}
		allowed, _, err = store.Allow(context.Background(), rateLimitSubject("account-green"))
		if err != nil || !allowed {
			t.Fatalf("权限 %04o：绿账户 %v %v", mode, allowed, err)
		}
	}

	empty, err := LoadRateLimits(writeFile(t, `{"version":"v1","buckets":[]}`, 0o644), nil)
	if err != nil || empty.Len() != 0 {
		t.Fatalf("空配额：%v，%d 条", err, empty.Len())
	}
	if allowed, _, err := empty.Allow(context.Background(), rateLimitSubject("account-blue")); err != nil || !allowed {
		t.Fatalf("没有规则时应放行：%v %v", allowed, err)
	}
}

func TestRateLimitsRejectsBadFiles(t *testing.T) {
	for name, content := range map[string]string{
		"不是 JSON":             `not json`,
		"空文件":                 ``,
		"没有版本":                `{"buckets":[]}`,
		"空版本":                 `{"version":"","buckets":[]}`,
		"版本是数字":               `{"version":1,"buckets":[]}`,
		"没有 buckets":          `{"version":"v1"}`,
		"buckets 是 null":      `{"version":"v1","buckets":null}`,
		"顶层是数组":               `[]`,
		"不认识的顶层字段":            `{"version":"v1","buckets":[],"notes":"x"}`,
		"桶里有不认识的字段":           `{"version":"v1","buckets":[{"id":"a","key_dimensions":["provider_account"],"max_requests":1,"window_seconds":1,"coordination":"LOCAL_APPROXIMATE"}]}`,
		"缺少 provider_account": `{"version":"v1","buckets":[{"id":"a","key_dimensions":["provider","tenant"],"max_requests":1,"window_seconds":60}]}`,
		"不认识的维度":              `{"version":"v1","buckets":[{"id":"a","key_dimensions":["provider_account","pool"],"max_requests":1,"window_seconds":60}]}`,
		"重复的 id":              `{"version":"v1","buckets":[{"id":"a","key_dimensions":["provider_account"],"max_requests":1,"window_seconds":1},{"id":"a","key_dimensions":["provider_account"],"max_requests":2,"window_seconds":2}]}`,
		"max_requests 为 0":    `{"version":"v1","buckets":[{"id":"a","key_dimensions":["provider_account"],"max_requests":0,"window_seconds":1}]}`,
		"窗口太大":                `{"version":"v1","buckets":[{"id":"a","key_dimensions":["provider_account"],"max_requests":1,"window_seconds":86401}]}`,
		"空 id":                `{"version":"v1","buckets":[{"id":"","key_dimensions":["provider_account"],"max_requests":1,"window_seconds":1}]}`,
		"后面还有内容":              `{"version":"v1","buckets":[]}{"version":"v2","buckets":[]}`,
		"burst 超过容量":          `{"version":"v1","buckets":[{"id":"a","key_dimensions":["provider_account"],"max_requests":1,"window_seconds":1,"burst":2}]}`,
	} {
		if _, err := LoadRateLimits(writeFile(t, content, 0o644), nil); err == nil {
			t.Errorf("%s: 被接受了", name)
		}
	}
	if _, err := LoadRateLimits(t.TempDir()+"/missing.json", nil); err == nil {
		t.Fatal("不存在的文件被接受了")
	}
}

func TestRateLimitsReloadKeepsTheLastGoodFile(t *testing.T) {
	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, nil))
	path := writeFile(t, validRateLimits, 0o644)
	store, err := LoadRateLimits(path, logger)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if allowed, _, err := store.Allow(ctx, rateLimitSubject("account-blue")); err != nil || !allowed {
		t.Fatalf("加载后的第一次：%v %v", allowed, err)
	}
	if allowed, _, _ := store.Allow(ctx, rateLimitSubject("account-blue")); allowed {
		t.Fatal("旧配额没有生效")
	}

	replaceFile(t, path, `{`, 0o644)
	// 改名换上来的是另一个文件，不依赖修改时间的分辨率。
	if !waitUntil(t, func() bool {
		allowed, _, err := store.Allow(ctx, rateLimitSubject("account-blue"))
		return err == nil && !allowed && strings.Contains(logs.String(), "did not load")
	}) {
		t.Fatalf("坏文件没有被拒绝，或把旧配额丢掉了：%s", logs.String())
	}
	if allowed, _, err := store.Allow(ctx, rateLimitSubject("account-blue")); err != nil || allowed {
		t.Fatalf("坏的重读把配额清空了：%v %v", allowed, err)
	}

	replaced := strings.Replace(validRateLimits, `"max_requests": 1`, `"max_requests": 10`, 1)
	replaceFile(t, path, replaced, 0o644)
	if !waitUntil(t, func() bool {
		allowed, _, err := store.Allow(ctx, rateLimitSubject("account-blue"))
		return err == nil && allowed && strings.Contains(logs.String(), "loaded again")
	}) {
		t.Fatalf("新配额没有生效：%s", logs.String())
	}
	if store.Len() != 1 {
		t.Fatalf("重读之后 %d 条", store.Len())
	}
}

func waitUntil(t *testing.T, ready func() bool) bool {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if ready() {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return ready()
}
