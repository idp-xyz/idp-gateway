package application

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"go.idp.xyz/idp-gateway/internal/jwkssync/domain"
)

const (
	keyA          = `{"kty":"RSA","kid":"kid-a","n":"nA","e":"AQAB"}`
	keyAReordered = `{"e":"AQAB","n":"nA","kid":"kid-a","kty":"RSA"}`
	keyB          = `{"kty":"RSA","kid":"kid-b","n":"nB","e":"AQAB"}`
)

func setOf(keys ...string) []byte {
	return []byte(`{"keys":[` + strings.Join(keys, ",") + `]}`)
}

type clock struct{ t time.Time }

func (c *clock) Now() time.Time { return c.t }

type fetchStep struct {
	body []byte
	err  error
}

type scriptedFetch struct {
	steps []fetchStep
	n     int
}

func (s *scriptedFetch) Fetch(context.Context) ([]byte, error) {
	step := s.steps[len(s.steps)-1]
	if s.n < len(s.steps) {
		step = s.steps[s.n]
		s.n++
	}
	return append([]byte(nil), step.body...), step.err
}

type memStore struct {
	data     []byte
	exists   bool
	writes   int
	writeErr error
	readErr  error
}

func (m *memStore) Read() ([]byte, bool, error) {
	if m.readErr != nil {
		return nil, false, m.readErr
	}
	if !m.exists {
		return nil, false, nil
	}
	return append([]byte(nil), m.data...), true, nil
}

func (m *memStore) Write(data []byte) error {
	m.writes++
	if m.writeErr != nil {
		return m.writeErr
	}
	m.data = append([]byte(nil), data...)
	m.exists = true
	return nil
}

func newSync(t *testing.T, fetch *scriptedFetch, store *memStore, clk *clock, max time.Duration, empty bool) *Syncer {
	t.Helper()
	syncer, err := New(Config{Fetcher: fetch, Store: store, Now: clk.Now, MaxStale: max, EmptyOnStale: empty})
	if err != nil {
		t.Fatal(err)
	}
	return syncer
}

func Test初次拉取写入同样的密钥不重写轮换再写入(t *testing.T) {
	clk := &clock{t: time.Date(2026, 11, 20, 0, 0, 0, 0, time.UTC)}
	fetch := &scriptedFetch{steps: []fetchStep{{body: setOf(keyB, keyA)}}}
	store := &memStore{}
	syncer := newSync(t, fetch, store, clk, time.Minute, false)

	first := syncer.Step(context.Background())
	if first.Outcome != OutcomeUpdated || first.KeyCount != 2 || first.Stale || first.Cleared || first.Error != "" {
		t.Fatalf("初次：%+v", first)
	}
	if strings.Join(first.KIDs, ",") != "kid-a,kid-b" {
		t.Fatalf("kid 是 %v", first.KIDs)
	}
	if store.writes != 1 {
		t.Fatalf("写入 %d 次", store.writes)
	}
	written := append([]byte(nil), store.data...)

	clk.t = clk.t.Add(time.Second)
	fetch.steps = append(fetch.steps, fetchStep{body: setOf(keyAReordered, keyB)})
	second := syncer.Step(context.Background())
	if second.Outcome != OutcomeUnchanged || second.Digest != first.Digest || second.Stale || store.writes != 1 {
		t.Fatalf("同样的密钥应不重写：%+v，写入 %d 次", second, store.writes)
	}
	if !bytes.Equal(store.data, written) {
		t.Fatal("文件被改过")
	}

	clk.t = clk.t.Add(time.Second)
	fetch.steps = append(fetch.steps, fetchStep{body: setOf(keyB)})
	third := syncer.Step(context.Background())
	if third.Outcome != OutcomeUpdated || third.KeyCount != 1 || strings.Join(third.KIDs, ",") != "kid-b" || store.writes != 2 {
		t.Fatalf("轮换：%+v，写入 %d 次", third, store.writes)
	}
	if third.Digest == first.Digest {
		t.Fatal("轮换之后摘要不该相同")
	}
	if syncer.consecutiveFailures != 0 || syncer.stale {
		t.Fatal("成功之后不该记着失败或过期")
	}
}

func Test拉取失败在期限内不动文件(t *testing.T) {
	clk := &clock{t: time.Date(2026, 11, 20, 0, 0, 0, 0, time.UTC)}
	fetch := &scriptedFetch{steps: []fetchStep{{body: setOf(keyA)}}}
	store := &memStore{}
	syncer := newSync(t, fetch, store, clk, time.Minute, true)
	if syncer.Step(context.Background()).Outcome != OutcomeUpdated {
		t.Fatal("预置失败")
	}
	kept := append([]byte(nil), store.data...)
	writes := store.writes

	clk.t = clk.t.Add(time.Minute) // 恰好等于上限，还没过期
	fetch.steps = append(fetch.steps, fetchStep{err: errors.New("jwks fetch: HTTP 503")})
	failed := syncer.Step(context.Background())
	if failed.Outcome != OutcomeFetchFailed || failed.Stale || failed.Cleared || failed.KeyCount != 1 || failed.Error == "" {
		t.Fatalf("期限内：%+v", failed)
	}
	if store.writes != writes || !bytes.Equal(store.data, kept) {
		t.Fatal("期限内文件被改过")
	}
	if syncer.consecutiveFailures != 1 {
		t.Fatalf("连续失败 %d 次", syncer.consecutiveFailures)
	}

	clk.t = clk.t.Add(time.Nanosecond)
	fetch.steps = append(fetch.steps, fetchStep{err: errors.New("jwks fetch: HTTP 503")})
	// 这一轮已经超过上限，但本测试只看到“恰好不超过”的那一轮；超过的在别的测试里。
	_ = syncer
}

func Test超过期限不腾空时保留文件(t *testing.T) {
	clk := &clock{t: time.Date(2026, 11, 20, 0, 0, 0, 0, time.UTC)}
	fetch := &scriptedFetch{steps: []fetchStep{
		{body: setOf(keyA)},
		{err: errors.New("jwks fetch: timed out")},
	}}
	store := &memStore{}
	syncer := newSync(t, fetch, store, clk, time.Minute, false)
	if syncer.Step(context.Background()).Outcome != OutcomeUpdated {
		t.Fatal("预置失败")
	}
	kept := append([]byte(nil), store.data...)
	clk.t = clk.t.Add(time.Minute + time.Nanosecond)
	got := syncer.Step(context.Background())
	if got.Outcome != OutcomeStaleExpired || !got.Stale || got.Cleared || got.KeyCount != 1 {
		t.Fatalf("不腾空：%+v", got)
	}
	if !bytes.Equal(store.data, kept) || store.writes != 1 {
		t.Fatal("不腾空时文件不该被写")
	}
}

func Test超过期限要求腾空时写成空集(t *testing.T) {
	clk := &clock{t: time.Date(2026, 11, 20, 0, 0, 0, 0, time.UTC)}
	fetch := &scriptedFetch{steps: []fetchStep{
		{body: setOf(keyA)},
		{err: errors.New("jwks fetch: HTTP 503")},
		{err: errors.New("jwks fetch: HTTP 503")},
	}}
	store := &memStore{}
	syncer := newSync(t, fetch, store, clk, time.Minute, true)
	if syncer.Step(context.Background()).Outcome != OutcomeUpdated {
		t.Fatal("预置失败")
	}
	clk.t = clk.t.Add(time.Minute + time.Second)
	got := syncer.Step(context.Background())
	if got.Outcome != OutcomeStaleExpired || !got.Stale || !got.Cleared || got.KeyCount != 0 || got.Digest != "" {
		t.Fatalf("腾空：%+v", got)
	}
	if !bytes.Equal(store.data, domain.EmptySet()) {
		t.Fatalf("文件是 %q", store.data)
	}
	// 已经是空集时再失败一轮，不再重写。
	clk.t = clk.t.Add(time.Second)
	writes := store.writes
	again := syncer.Step(context.Background())
	if again.Outcome != OutcomeStaleExpired || again.Cleared || store.writes != writes {
		t.Fatalf("已经腾空不应再写：%+v，写入 %d 次", again, store.writes)
	}
}

func Test腾空之后恢复写入且不再过期(t *testing.T) {
	clk := &clock{t: time.Date(2026, 11, 20, 0, 0, 0, 0, time.UTC)}
	fetch := &scriptedFetch{steps: []fetchStep{
		{body: setOf(keyA)},
		{err: errors.New("jwks fetch: HTTP 503")},
		{body: setOf(keyB, keyA)},
	}}
	store := &memStore{}
	syncer := newSync(t, fetch, store, clk, time.Minute, true)
	if syncer.Step(context.Background()).Outcome != OutcomeUpdated {
		t.Fatal("预置失败")
	}
	clk.t = clk.t.Add(2 * time.Minute)
	if got := syncer.Step(context.Background()); got.Outcome != OutcomeStaleExpired || !got.Cleared {
		t.Fatalf("腾空：%+v", got)
	}
	clk.t = clk.t.Add(time.Second)
	got := syncer.Step(context.Background())
	if got.Outcome != OutcomeUpdated || got.Stale || got.Cleared || got.KeyCount != 2 || syncer.stale {
		t.Fatalf("恢复：%+v，内部过期 %v", got, syncer.stale)
	}
	if bytes.Equal(store.data, domain.EmptySet()) {
		t.Fatal("恢复之后文件仍是空集")
	}
	if syncer.consecutiveFailures != 0 {
		t.Fatalf("恢复之后连续失败 %d 次", syncer.consecutiveFailures)
	}
}

func Test拉取失败不把正文写入文件(t *testing.T) {
	clk := &clock{t: time.Date(2026, 11, 20, 0, 0, 0, 0, time.UTC)}
	fetch := &scriptedFetch{steps: []fetchStep{{body: setOf(keyA)}}}
	store := &memStore{}
	syncer := newSync(t, fetch, store, clk, time.Minute, true)
	if syncer.Step(context.Background()).Outcome != OutcomeUpdated {
		t.Fatal("预置失败")
	}
	kept := append([]byte(nil), store.data...)
	garbage := []byte(`GARBAGE-NOT-A-JWKS`)
	fetch.steps = append(fetch.steps, fetchStep{body: garbage, err: errors.New("jwks fetch: HTTP 503")})
	clk.t = clk.t.Add(time.Second)
	got := syncer.Step(context.Background())
	if got.Outcome != OutcomeFetchFailed || store.writes != 1 || !bytes.Equal(store.data, kept) {
		t.Fatalf("503 的正文被写进了文件：%+v，文件 %q", got, store.data)
	}
	if bytes.Contains(store.data, garbage) {
		t.Fatal("文件里出现了失败的正文")
	}
}

func Test启动时已有文件则不重写(t *testing.T) {
	existing, err := domain.Parse(setOf(keyAReordered))
	if err != nil {
		t.Fatal(err)
	}
	// 磁盘上是另一套键序，不是规范形式也行：摘要对得上就不重写。
	store := &memStore{data: setOf(keyA), exists: true}
	clk := &clock{t: time.Date(2026, 11, 20, 8, 0, 0, 0, time.UTC)}
	fetch := &scriptedFetch{steps: []fetchStep{{body: setOf(keyAReordered)}}}
	syncer := newSync(t, fetch, store, clk, time.Minute, false)
	if syncer.lastDigest != existing.Digest() || !syncer.lastSuccess.Equal(clk.t) {
		t.Fatalf("启动没有用磁盘上的密钥集做初值：digest %s success %s", syncer.lastDigest, syncer.lastSuccess)
	}
	got := syncer.Step(context.Background())
	if got.Outcome != OutcomeUnchanged || store.writes != 0 {
		t.Fatalf("启动后同一套密钥不该重写：%+v，写入 %d 次", got, store.writes)
	}
	fetch.steps = append(fetch.steps, fetchStep{err: errors.New("jwks fetch: HTTP 503")})
	clk.t = clk.t.Add(time.Second)
	if failed := syncer.Step(context.Background()); failed.Outcome != OutcomeFetchFailed || failed.Stale {
		t.Fatalf("刚启动的失败不该算过期：%+v", failed)
	}
}

func Test上限为零时失败也不作废(t *testing.T) {
	clk := &clock{t: time.Date(2026, 11, 20, 0, 0, 0, 0, time.UTC)}
	fetch := &scriptedFetch{steps: []fetchStep{{body: setOf(keyA)}, {err: errors.New("down")}}}
	store := &memStore{}
	syncer := newSync(t, fetch, store, clk, 0, true)
	if syncer.Step(context.Background()).Outcome != OutcomeUpdated {
		t.Fatal("预置失败")
	}
	kept := append([]byte(nil), store.data...)
	clk.t = clk.t.Add(24 * time.Hour)
	got := syncer.Step(context.Background())
	if got.Outcome != OutcomeFetchFailed || got.Stale || got.Cleared || !bytes.Equal(store.data, kept) {
		t.Fatalf("上限为 0：%+v", got)
	}
}

func Test配置不合法或磁盘读不了(t *testing.T) {
	clk := &clock{t: time.Date(2026, 11, 20, 0, 0, 0, 0, time.UTC)}
	store := &memStore{}
	fetch := &scriptedFetch{steps: []fetchStep{{body: setOf(keyA)}}}
	if _, err := New(Config{Store: store, Now: clk.Now}); err == nil {
		t.Fatal("没有 fetcher 也建好了")
	}
	if _, err := New(Config{Fetcher: fetch, Now: clk.Now}); err == nil {
		t.Fatal("没有 store 也建好了")
	}
	if _, err := New(Config{Fetcher: fetch, Store: store, MaxStale: -time.Second}); err == nil {
		t.Fatal("负的上限也建好了")
	}
	store.readErr = errors.New("jwks file: permission denied")
	if _, err := New(Config{Fetcher: fetch, Store: store, Now: clk.Now}); err == nil || !strings.Contains(err.Error(), "permission") {
		t.Fatalf("磁盘读不了时应失败：%v", err)
	}
}

func Test解析失败与期限内的写入失败都不改文件(t *testing.T) {
	clk := &clock{t: time.Date(2026, 11, 20, 0, 0, 0, 0, time.UTC)}
	fetch := &scriptedFetch{steps: []fetchStep{{body: setOf(keyA)}, {body: []byte(`{"no":"keys"}`)}}}
	store := &memStore{}
	syncer := newSync(t, fetch, store, clk, time.Minute, false)
	if syncer.Step(context.Background()).Outcome != OutcomeUpdated {
		t.Fatal("预置失败")
	}
	kept := append([]byte(nil), store.data...)
	clk.t = clk.t.Add(time.Second)
	got := syncer.Step(context.Background())
	if got.Outcome != OutcomeFetchFailed || !bytes.Equal(store.data, kept) || store.writes != 1 {
		t.Fatalf("解析失败：%+v", got)
	}
	fetch.steps = append(fetch.steps, fetchStep{body: setOf(keyB)})
	store.writeErr = errors.New("jwks file: disk full")
	clk.t = clk.t.Add(time.Second)
	got = syncer.Step(context.Background())
	if got.Outcome != OutcomeFetchFailed || !strings.Contains(got.Error, "disk full") || !bytes.Equal(store.data, kept) {
		t.Fatalf("写入失败：%+v，文件 %q", got, store.data)
	}
}
