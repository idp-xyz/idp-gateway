package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func mustTable(t *testing.T, rules ...QuotaRule) *QuotaTable {
	t.Helper()
	table, err := NewQuotaTable(rules)
	if err != nil {
		t.Fatal(err)
	}
	return table
}

func accountRule(id string, maxRequests, window int) QuotaRule {
	return QuotaRule{
		ID: id, KeyDimensions: []string{dimensionProvider, dimensionProviderAccount},
		MaxRequests: maxRequests, WindowSeconds: window,
	}
}

func subject(account string) RateLimitSubject {
	return RateLimitSubject{
		ProviderID: "mockcarrier", AccountID: account, TenantID: "tenant-blue",
		OperationID: "tracking.get", ServiceID: "parcel-service",
	}
}

func TestValidateQuotaRules(t *testing.T) {
	good := accountRule("per-account", 60, 60)
	if err := ValidateQuotaRules([]QuotaRule{good}); err != nil {
		t.Fatal(err)
	}
	wide := good
	wide.WindowSeconds = 86400
	wide.Burst = 60
	if err := ValidateQuotaRules([]QuotaRule{wide}); err != nil {
		t.Fatal(err)
	}
	omitted := good
	omitted.Burst = 0
	omitted.WindowSeconds = 1
	if err := ValidateQuotaRules([]QuotaRule{omitted}); err != nil {
		t.Fatal(err)
	}
	if err := ValidateQuotaRules(nil); err != nil {
		t.Fatal(err)
	}

	cases := map[string]QuotaRule{
		"empty id":              {KeyDimensions: []string{dimensionProviderAccount}, MaxRequests: 1, WindowSeconds: 1},
		"missing account":       {ID: "a", KeyDimensions: []string{dimensionProvider, dimensionTenant}, MaxRequests: 1, WindowSeconds: 1},
		"unknown dimension":     {ID: "a", KeyDimensions: []string{dimensionProviderAccount, "pool"}, MaxRequests: 1, WindowSeconds: 1},
		"duplicate dimension":   {ID: "a", KeyDimensions: []string{dimensionProviderAccount, dimensionProviderAccount}, MaxRequests: 1, WindowSeconds: 1},
		"max requests zero":     {ID: "a", KeyDimensions: []string{dimensionProviderAccount}, MaxRequests: 0, WindowSeconds: 1},
		"max requests negative": {ID: "a", KeyDimensions: []string{dimensionProviderAccount}, MaxRequests: -1, WindowSeconds: 1},
		"window zero":           {ID: "a", KeyDimensions: []string{dimensionProviderAccount}, MaxRequests: 1, WindowSeconds: 0},
		"window too long":       {ID: "a", KeyDimensions: []string{dimensionProviderAccount}, MaxRequests: 1, WindowSeconds: 86401},
		"burst too big":         {ID: "a", KeyDimensions: []string{dimensionProviderAccount}, MaxRequests: 2, WindowSeconds: 1, Burst: 3},
		"burst negative":        {ID: "a", KeyDimensions: []string{dimensionProviderAccount}, MaxRequests: 2, WindowSeconds: 1, Burst: -1},
		"no dimensions":         {ID: "a", MaxRequests: 1, WindowSeconds: 1},
	}
	for name, rule := range cases {
		if err := ValidateQuotaRules([]QuotaRule{rule}); err == nil {
			t.Errorf("%s: 被接受了", name)
		}
	}
	dup := []QuotaRule{accountRule("same", 1, 1), accountRule("same", 2, 2)}
	if err := ValidateQuotaRules(dup); err == nil {
		t.Fatal("重复的 id 被接受了")
	}
}

func TestTokenBucketAllowDenyAndRefill(t *testing.T) {
	table := mustTable(t, accountRule("per-account", 2, 60))
	now := time.Unix(1_700_000_000, 0)
	blue := subject("account-blue")

	for i := 0; i < 2; i++ {
		allowed, retry := table.Allow(now, blue)
		if !allowed || retry != 0 {
			t.Fatalf("第 %d 次：allowed=%v retry=%d", i+1, allowed, retry)
		}
	}
	allowed, retry := table.Allow(now, blue)
	if allowed || retry != 30 {
		t.Fatalf("用尽：allowed=%v retry=%d，期望拒绝且 30 秒", allowed, retry)
	}

	// 15 秒补充 0.5 个令牌，还差半个，要再等 15 秒。
	half := now.Add(15 * time.Second)
	allowed, retry = table.Allow(half, blue)
	if allowed || retry != 15 {
		t.Fatalf("补充一半：allowed=%v retry=%d", allowed, retry)
	}
	// 再过 15 秒凑满 1 个，可以过；过完又空了。
	full := now.Add(30 * time.Second)
	allowed, retry = table.Allow(full, blue)
	if !allowed || retry != 0 {
		t.Fatalf("补充一个：allowed=%v retry=%d", allowed, retry)
	}
	allowed, retry = table.Allow(full, blue)
	if allowed || retry != 30 {
		t.Fatalf("刚用掉补充的那个：allowed=%v retry=%d", allowed, retry)
	}
}

func TestBurstCapsTheBucket(t *testing.T) {
	// 速率仍是 MaxRequests/WindowSeconds = 每秒 1 个。容量是 Burst 2，不是 MaxRequests 10。
	rule := accountRule("per-account", 10, 10)
	rule.Burst = 2
	table := mustTable(t, rule)
	now := time.Unix(1_700_000_000, 0)
	blue := subject("account-blue")

	for i := 0; i < 2; i++ {
		allowed, retry := table.Allow(now, blue)
		if !allowed || retry != 0 {
			t.Fatalf("t0 第 %d 次：allowed=%v retry=%d", i+1, allowed, retry)
		}
	}
	allowed, retry := table.Allow(now, blue)
	if allowed || retry != 1 {
		t.Fatalf("t0 第 3 次：allowed=%v retry=%d，期望拒绝且 retryAfter=1", allowed, retry)
	}

	plusOne := now.Add(time.Second)
	allowed, retry = table.Allow(plusOne, blue)
	if !allowed || retry != 0 {
		t.Fatalf("t0+1s：allowed=%v retry=%d，期望放行 1 次", allowed, retry)
	}
	allowed, retry = table.Allow(plusOne, blue)
	if allowed || retry != 1 {
		t.Fatalf("t0+1s 第 2 次：allowed=%v retry=%d，这一秒只该补进 1 个", allowed, retry)
	}

	// 从 t0+1s 再过 59 秒会补进 59 个令牌，但容量封在 2，攒不满 10。
	plusSixty := now.Add(60 * time.Second)
	for i := 0; i < 2; i++ {
		allowed, retry = table.Allow(plusSixty, blue)
		if !allowed || retry != 0 {
			t.Fatalf("t0+60s 第 %d 次：allowed=%v retry=%d", i+1, allowed, retry)
		}
	}
	if allowed, _ := table.Allow(plusSixty, blue); allowed {
		t.Fatal("t0+60s 第 3 次仍放行：容量没有按 burst=2 封顶")
	}
}

func TestAccountsDoNotShareABucket(t *testing.T) {
	table := mustTable(t, accountRule("per-account", 1, 60))
	now := time.Unix(1_700_000_000, 0)
	if allowed, _ := table.Allow(now, subject("account-blue")); !allowed {
		t.Fatal("蓝账户的第一次被拒绝了")
	}
	if allowed, _ := table.Allow(now, subject("account-blue")); allowed {
		t.Fatal("蓝账户用尽之后仍放行")
	}
	if allowed, retry := table.Allow(now, subject("account-green")); !allowed || retry != 0 {
		t.Fatalf("绿账户被蓝账户拖累：allowed=%v retry=%d", allowed, retry)
	}
	other := subject("account-blue")
	other.ProviderID = "other"
	// 这条规则的键含 provider，另一个 provider 的同名账户是另一只桶。
	if allowed, _ := table.Allow(now, other); !allowed {
		t.Fatal("另一个 provider 共用了桶")
	}
}

func TestProviderAndOperationFilters(t *testing.T) {
	table := mustTable(t, QuotaRule{
		ID: "sf-orders", ProviderID: "sf", OperationID: "orders.create",
		KeyDimensions: []string{dimensionProviderAccount},
		MaxRequests:   1, WindowSeconds: 60,
	})
	now := time.Unix(1_700_000_000, 0)
	other := subject("account-blue")
	for range 5 {
		if allowed, _ := table.Allow(now, other); !allowed {
			t.Fatal("不匹配的 provider 被这条规则限了")
		}
	}
	matched := RateLimitSubject{ProviderID: "sf", AccountID: "acct", OperationID: "orders.create"}
	if allowed, _ := table.Allow(now, matched); !allowed {
		t.Fatal("匹配的第一次被拒绝了")
	}
	if allowed, _ := table.Allow(now, matched); allowed {
		t.Fatal("匹配的第二次仍放行")
	}
	// 同一账户的另一个操作不受这条规则限制。
	otherOp := matched
	otherOp.OperationID = "orders.cancel"
	if allowed, _ := table.Allow(now, otherOp); !allowed {
		t.Fatal("别的操作被这条规则限了")
	}
}

func TestTwoPhaseCheckDoesNotConsumeTheAllowingRule(t *testing.T) {
	// A 的窗口很长，10 秒里几乎补不进一个令牌。B 每 10 秒恢复 1 个。
	// 若在 B 拒绝时提前扣了 A，三次放行凑不齐。
	table := mustTable(t,
		QuotaRule{ID: "A", KeyDimensions: []string{dimensionProviderAccount}, MaxRequests: 3, WindowSeconds: 86400},
		QuotaRule{ID: "B", KeyDimensions: []string{dimensionProviderAccount}, MaxRequests: 1, WindowSeconds: 10},
	)
	now := time.Unix(1_700_000_000, 0)
	blue := subject("account-blue")
	allows := 0
	for step := 0; step < 4; step++ {
		at := now.Add(time.Duration(step) * 10 * time.Second)
		allowed, retry := table.Allow(at, blue)
		if step == 0 && (!allowed || retry != 0) {
			t.Fatalf("第一次应放行：%v %d", allowed, retry)
		}
		again, againRetry := table.Allow(at, blue)
		if again {
			t.Fatalf("t=%ds 的第二次应被 B 拒绝", step*10)
		}
		if step == 0 && againRetry != 10 {
			t.Fatalf("两条规则里应取 B 的 10 秒，得到 %d", againRetry)
		}
		if allowed {
			allows++
		}
	}
	if allows != 3 {
		t.Fatalf("放行了 %d 次，期望 3：被拒绝的那次把另一条规则也扣掉了", allows)
	}
}

func TestDeniedRulesTakeTheLongerRetry(t *testing.T) {
	table := mustTable(t,
		QuotaRule{ID: "short", KeyDimensions: []string{dimensionProviderAccount}, MaxRequests: 1, WindowSeconds: 10},
		QuotaRule{ID: "long", KeyDimensions: []string{dimensionProviderAccount}, MaxRequests: 1, WindowSeconds: 30},
	)
	now := time.Unix(1_700_000_000, 0)
	blue := subject("account-blue")
	if allowed, _ := table.Allow(now, blue); !allowed {
		t.Fatal("第一次被拒绝了")
	}
	allowed, retry := table.Allow(now, blue)
	if allowed || retry != 30 {
		t.Fatalf("同时拒绝时应等更久的那条：allowed=%v retry=%d", allowed, retry)
	}
}

func TestQuotaTableConcurrent(t *testing.T) {
	const maxRequests = 50
	table := mustTable(t, accountRule("per-account", maxRequests, 60))
	now := time.Unix(1_700_000_000, 0)
	var allowed atomic.Int32
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 20 {
				ok, _ := table.Allow(now, subject("account-blue"))
				if ok {
					allowed.Add(1)
				}
			}
		}()
	}
	wg.Wait()
	if got := allowed.Load(); got != maxRequests {
		t.Fatalf("并发下放行了 %d 次，期望 %d", got, maxRequests)
	}
	// 另一账户不受上面这 50 次的影响，也不和它们抢同一把桶。
	if ok, _ := table.Allow(now, subject("account-green")); !ok {
		t.Fatal("并发之后绿账户没有配额")
	}
}

func TestChargesDoNotMutateAndHideTheKey(t *testing.T) {
	table := mustTable(t, QuotaRule{
		ID: "per-account", ProviderID: "mockcarrier",
		KeyDimensions: []string{dimensionProvider, dimensionProviderAccount},
		MaxRequests:   2, WindowSeconds: 60, Burst: 1,
	})
	sub := subject("account-blue")
	charges := table.Charges(sub)
	if len(charges) != 1 {
		t.Fatal(len(charges))
	}
	got := charges[0]
	if len(got.Key) != 64 || got.Key != strings.ToLower(got.Key) || strings.Contains(got.Key, "account-blue") || strings.Contains(got.Key, "\x00") {
		t.Fatalf("key %q", got.Key)
	}
	if got.MaxRequests != 2 || got.WindowSeconds != 60 || got.Capacity != 1 {
		t.Fatalf("%+v", got)
	}
	raw := "per-account\x00provider\x00mockcarrier\x00provider_account\x00account-blue\x00"
	sum := sha256.Sum256([]byte(raw))
	if hex.EncodeToString(sum[:]) != got.Key {
		t.Fatalf("hash %s", got.Key)
	}
	now := time.Unix(1_700_000_000, 0)
	if ok, _ := table.Allow(now, sub); !ok {
		t.Fatal("Charges 扣掉了令牌")
	}
	if ok, _ := table.Allow(now, sub); ok {
		t.Fatal("容量 1 的第二次仍放行")
	}
	if len(table.Charges(RateLimitSubject{ProviderID: "other", AccountID: "account-blue"})) != 0 {
		t.Fatal("没命中的规则返回了扣费")
	}
	empty := mustTable(t)
	if len(empty.Charges(sub)) != 0 {
		t.Fatal("没有规则时不该有扣费")
	}
}

func TestQuotaTableDropsBucketsPastTheCap(t *testing.T) {
	table := mustTable(t, accountRule("per-account", 1, 60))
	now := time.Unix(1_700_000_000, 0)
	for i := 0; i < quotaBucketCap+1000; i++ {
		table.Allow(now, subject(strconv.Itoa(i)))
	}
	table.mu.Lock()
	n := len(table.buckets)
	table.mu.Unlock()
	if n > quotaBucketCap+1 {
		t.Fatalf("桶有 %d 只，上限是 %d", n, quotaBucketCap)
	}
}
