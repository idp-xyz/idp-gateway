package domain

import (
	"errors"
	"fmt"
	"math"
	"sort"
	"strings"
	"sync"
	"time"
)

// 配额维度。key 里必须有 provider_account：出站配额按 Provider 账户分开，
// 这和 contracts/gateway/policies/traffic-policy.schema.json 对 EGRESS 的要求一致。
const (
	dimensionProvider        = "provider"
	dimensionProviderAccount = "provider_account"
	dimensionTenant          = "tenant"
	dimensionOperation       = "operation"
	dimensionService         = "service"
)

// quotaBucketCap 是进程内令牌桶的上限。超过之后先丢掉闲置的，再丢掉最久没用的。
// 被丢掉的键下一次请求会拿到满的新桶，所以这是内存上限，不是跨重启的精确配额。
const quotaBucketCap = 8192

// tokenEpsilon 用来吸收浮点误差：整数次补充之后，差一丁点不到 1 的余额仍算有一个令牌。
const tokenEpsilon = 1e-9

// QuotaRule 是一条配额。ProviderID、OperationID 为空表示不按这一项过滤。
// Burst 为 0 表示不单独给出，容量仍是 MaxRequests；给出时容量就是 Burst。
// 补充速率始终是 MaxRequests/WindowSeconds。
type QuotaRule struct {
	ID            string
	ProviderID    string
	OperationID   string
	KeyDimensions []string
	MaxRequests   int
	WindowSeconds int
	// Burst 可选。0 表示缺省，容量等于 MaxRequests。给出时必须满足 1 <= Burst <= MaxRequests，
	// 桶的容量取 Burst。补充速率始终是 MaxRequests/WindowSeconds，不随 Burst 改变。
	Burst int
}

// RateLimitSubject 是一次出站调用里参与配额键的身份。账户是判定选定的那个，不是调用方随口申请的。
type RateLimitSubject struct {
	ProviderID  string
	AccountID   string
	TenantID    string
	OperationID string
	ServiceID   string
}

// ValidateQuotaRules 拒绝重复的 id、缺少 provider_account、不认识或重复的维度，以及越界的数字。
// 空列表是合法的：没有任何配额，请求都放行。
func ValidateQuotaRules(rules []QuotaRule) error {
	seen := make(map[string]struct{}, len(rules))
	for _, rule := range rules {
		if rule.ID == "" {
			return errors.New("quota rule has an empty id")
		}
		if _, ok := seen[rule.ID]; ok {
			return fmt.Errorf("quota rule %q is duplicated", rule.ID)
		}
		seen[rule.ID] = struct{}{}
		if rule.MaxRequests < 1 {
			return fmt.Errorf("quota rule %q: max_requests must be at least 1", rule.ID)
		}
		if rule.WindowSeconds < 1 || rule.WindowSeconds > 86400 {
			return fmt.Errorf("quota rule %q: window_seconds must be between 1 and 86400", rule.ID)
		}
		if rule.Burst < 0 || rule.Burst > rule.MaxRequests {
			return fmt.Errorf("quota rule %q: burst must be omitted or between 1 and max_requests", rule.ID)
		}
		if err := validateDimensions(rule); err != nil {
			return err
		}
	}
	return nil
}

func validateDimensions(rule QuotaRule) error {
	if len(rule.KeyDimensions) == 0 {
		return fmt.Errorf("quota rule %q: key_dimensions must include provider_account", rule.ID)
	}
	seen := make(map[string]struct{}, len(rule.KeyDimensions))
	hasAccount := false
	for _, name := range rule.KeyDimensions {
		if !knownDimension(name) {
			return fmt.Errorf("quota rule %q: unknown key dimension %q", rule.ID, name)
		}
		if _, ok := seen[name]; ok {
			return fmt.Errorf("quota rule %q: key dimension %q is duplicated", rule.ID, name)
		}
		seen[name] = struct{}{}
		if name == dimensionProviderAccount {
			hasAccount = true
		}
	}
	if !hasAccount {
		return fmt.Errorf("quota rule %q: key_dimensions must include provider_account", rule.ID)
	}
	return nil
}

func knownDimension(name string) bool {
	switch name {
	case dimensionProvider, dimensionProviderAccount, dimensionTenant, dimensionOperation, dimensionService:
		return true
	default:
		return false
	}
}

// QuotaTable 是一组令牌桶。规则在构造之后不变；每个键一个桶，由互斥锁保护。
//
// 补充速率是 MaxRequests/WindowSeconds 个每秒。桶的容量在给出 Burst 时取 Burst，否则取 MaxRequests。
// 一条请求要过全部匹配的规则：先在锁里看完，再一起扣。被第二条规则拒绝时，第一条的桶不动。
// 多条规则同时拒绝时，等待时间取其中最大的，并且至少 1 秒。
type QuotaTable struct {
	mu      sync.Mutex
	rules   []compiledRule
	buckets map[string]*tokenBucket
	idleFor time.Duration
}

type compiledRule struct {
	id            string
	providerID    string
	operationID   string
	dimensions    []string
	capacity      float64
	rate          float64
	maxRequests   int
	windowSeconds int
}

type tokenBucket struct {
	tokens   float64
	updated  time.Time
	lastUsed time.Time
}

type bucketCharge struct {
	bucket *tokenBucket
}

// NewQuotaTable 校验并编译规则。规则切片之后再改，不影响这张表。
func NewQuotaTable(rules []QuotaRule) (*QuotaTable, error) {
	if err := ValidateQuotaRules(rules); err != nil {
		return nil, err
	}
	compiled := make([]compiledRule, len(rules))
	maxWindow := 1
	for i, rule := range rules {
		if rule.WindowSeconds > maxWindow {
			maxWindow = rule.WindowSeconds
		}
		dimensions := make([]string, len(rule.KeyDimensions))
		copy(dimensions, rule.KeyDimensions)
		capacity := rule.MaxRequests
		if rule.Burst > 0 {
			capacity = rule.Burst
		}
		compiled[i] = compiledRule{
			id:            rule.ID,
			providerID:    rule.ProviderID,
			operationID:   rule.OperationID,
			dimensions:    dimensions,
			capacity:      float64(capacity),
			rate:          float64(rule.MaxRequests) / float64(rule.WindowSeconds),
			maxRequests:   rule.MaxRequests,
			windowSeconds: rule.WindowSeconds,
		}
	}
	return &QuotaTable{
		rules:   compiled,
		buckets: make(map[string]*tokenBucket),
		idleFor: time.Duration(maxWindow) * time.Second * 2,
	}, nil
}

// Allow 报告 now 这一刻 subject 是否还有配额。拒绝时 retryAfterSeconds 至少为 1。
// 没有任何规则匹配时放行，也不创建桶。
func (t *QuotaTable) Allow(now time.Time, subject RateLimitSubject) (allowed bool, retryAfterSeconds int) {
	if t == nil {
		return true, 0
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.rules) == 0 {
		return true, 0
	}
	t.sweep(now)

	charges := make([]bucketCharge, 0, len(t.rules))
	denied := false
	retry := 0
	for i := range t.rules {
		rule := &t.rules[i]
		if !rule.matches(subject) {
			continue
		}
		bucket := t.bucket(now, rule, subject)
		bucket.refill(now, rule.capacity, rule.rate)
		bucket.lastUsed = now
		if bucket.tokens < 1-tokenEpsilon {
			denied = true
			if wait := retryAfter(bucket.tokens, rule); wait > retry {
				retry = wait
			}
			continue
		}
		charges = append(charges, bucketCharge{bucket: bucket})
	}
	if !denied && len(charges) == 0 {
		return true, 0
	}
	if denied {
		if retry < 1 {
			retry = 1
		}
		return false, retry
	}
	for _, charge := range charges {
		charge.bucket.tokens -= 1
		if charge.bucket.tokens < 0 {
			charge.bucket.tokens = 0
		}
	}
	return true, 0
}

func (r *compiledRule) matches(subject RateLimitSubject) bool {
	if r.providerID != "" && r.providerID != subject.ProviderID {
		return false
	}
	return r.operationID == "" || r.operationID == subject.OperationID
}

func (t *QuotaTable) bucket(now time.Time, rule *compiledRule, subject RateLimitSubject) *tokenBucket {
	key := rule.key(subject)
	bucket := t.buckets[key]
	if bucket == nil {
		bucket = &tokenBucket{tokens: rule.capacity, updated: now, lastUsed: now}
		t.buckets[key] = bucket
	}
	return bucket
}

func (r *compiledRule) key(subject RateLimitSubject) string {
	var b strings.Builder
	b.WriteString(r.id)
	b.WriteByte(0)
	for _, name := range r.dimensions {
		b.WriteString(name)
		b.WriteByte(0)
		b.WriteString(dimensionValue(name, subject))
		b.WriteByte(0)
	}
	return b.String()
}

func dimensionValue(name string, subject RateLimitSubject) string {
	switch name {
	case dimensionProvider:
		return subject.ProviderID
	case dimensionProviderAccount:
		return subject.AccountID
	case dimensionTenant:
		return subject.TenantID
	case dimensionOperation:
		return subject.OperationID
	case dimensionService:
		return subject.ServiceID
	default:
		return ""
	}
}

func (b *tokenBucket) refill(now time.Time, capacity, rate float64) {
	if now.After(b.updated) {
		elapsed := now.Sub(b.updated).Seconds()
		b.tokens += elapsed * rate
		b.updated = now
	}
	if b.tokens > capacity {
		b.tokens = capacity
	}
	if b.tokens < 0 {
		b.tokens = 0
	}
}

// retryAfter 是凑够 1 个令牌还要多少秒，向上取整，至少 1。
// 用窗口和上限来算，避免先把速率收成不精确的小数再除掉。
func retryAfter(tokens float64, rule *compiledRule) int {
	if tokens < 0 {
		tokens = 0
	}
	deficit := 1 - tokens
	if deficit <= tokenEpsilon || rule.maxRequests < 1 {
		return 1
	}
	seconds := math.Ceil(deficit * float64(rule.windowSeconds) / float64(rule.maxRequests))
	if math.IsNaN(seconds) || math.IsInf(seconds, 0) || seconds < 1 {
		return 1
	}
	if seconds > 86400 {
		return 86400
	}
	return int(seconds)
}

// sweep 在桶的数量超过上限时回收。先丢闲置超过两个最长窗口的，还多就丢最久没用的。
func (t *QuotaTable) sweep(now time.Time) {
	if len(t.buckets) <= quotaBucketCap {
		return
	}
	cutoff := now.Add(-t.idleFor)
	for key, bucket := range t.buckets {
		if !bucket.lastUsed.After(cutoff) {
			delete(t.buckets, key)
		}
	}
	if len(t.buckets) <= quotaBucketCap {
		return
	}
	type aged struct {
		key  string
		when time.Time
	}
	order := make([]aged, 0, len(t.buckets))
	for key, bucket := range t.buckets {
		order = append(order, aged{key: key, when: bucket.lastUsed})
	}
	sort.Slice(order, func(i, j int) bool {
		if order[i].when.Equal(order[j].when) {
			return order[i].key < order[j].key
		}
		return order[i].when.Before(order[j].when)
	})
	extra := len(t.buckets) - quotaBucketCap
	for i := 0; i < extra; i++ {
		delete(t.buckets, order[i].key)
	}
}
