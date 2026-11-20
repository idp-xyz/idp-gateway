package domain

import (
	"sync"
	"testing"
	"time"
)

func mustBreaker(t *testing.T, threshold int, open time.Duration) *CircuitBreaker {
	t.Helper()
	breaker, err := NewCircuitBreaker(CircuitBreakerConfig{FailureThreshold: threshold, OpenDuration: open})
	if err != nil {
		t.Fatal(err)
	}
	return breaker
}

func TestCircuitBreakerDisabled(t *testing.T) {
	breaker := mustBreaker(t, 0, 0)
	now := time.Unix(1_700_000_000, 0)
	for range 5 {
		breaker.RecordFailure(now)
		allowed, probe := breaker.Allow(now)
		if !allowed || probe || breaker.State(now) != "closed" {
			t.Fatalf("关闭的电路不该挡住请求：allowed=%v probe=%v state=%s", allowed, probe, breaker.State(now))
		}
	}
	if _, err := NewCircuitBreaker(CircuitBreakerConfig{FailureThreshold: -1, OpenDuration: time.Second}); err == nil {
		t.Fatal("负的阈值被接受了")
	}
	if _, err := NewCircuitBreaker(CircuitBreakerConfig{FailureThreshold: 2, OpenDuration: 0}); err == nil {
		t.Fatal("打开时长为 0 被接受了")
	}
	if _, err := NewCircuitBreaker(CircuitBreakerConfig{FailureThreshold: 2, OpenDuration: -time.Second}); err == nil {
		t.Fatal("打开时长为负被接受了")
	}
}

func TestCircuitBreakerTripsAndResets(t *testing.T) {
	breaker := mustBreaker(t, 3, time.Minute)
	now := time.Unix(1_700_000_000, 0)
	for i := 0; i < 2; i++ {
		breaker.RecordFailure(now)
		allowed, probe := breaker.Allow(now)
		if !allowed || probe || breaker.State(now) != "closed" {
			t.Fatalf("第 %d 次失败后不该打开：allowed=%v state=%s", i+1, allowed, breaker.State(now))
		}
	}
	breaker.RecordFailure(now)
	if breaker.State(now) != "open" {
		t.Fatalf("三次失败后状态是 %s", breaker.State(now))
	}
	if allowed, probe := breaker.Allow(now); allowed || probe {
		t.Fatal("打开期间仍放行")
	}

	// 中间一次成功把连续失败清零，接着的两次失败还开不了。
	breaker = mustBreaker(t, 3, time.Minute)
	breaker.RecordFailure(now)
	breaker.RecordFailure(now)
	breaker.RecordSuccess()
	breaker.RecordFailure(now)
	breaker.RecordFailure(now)
	if allowed, _ := breaker.Allow(now); !allowed || breaker.State(now) != "closed" {
		t.Fatal("成功没有把计数清零")
	}
	breaker.RecordFailure(now)
	if breaker.State(now) != "open" {
		t.Fatal("清零之后的第三次失败没有打开")
	}
}

func TestCircuitBreakerHalfOpenAllowsOneProbe(t *testing.T) {
	openFor := 30 * time.Second
	breaker := mustBreaker(t, 1, openFor)
	now := time.Unix(1_700_000_000, 0)
	breaker.RecordFailure(now)
	if allowed, _ := breaker.Allow(now.Add(openFor - time.Nanosecond)); allowed {
		t.Fatal("差一纳秒就放了探测")
	}
	if breaker.State(now.Add(openFor)) != "half_open" {
		t.Fatalf("时间到了仍是 %s", breaker.State(now.Add(openFor)))
	}
	// State 不占探测：紧接着的 Allow 还能拿到那一次。
	allowed, probe := breaker.Allow(now.Add(openFor))
	if !allowed || !probe {
		t.Fatalf("半开的探测：allowed=%v probe=%v", allowed, probe)
	}
	second, secondProbe := breaker.Allow(now.Add(openFor))
	if second || secondProbe {
		t.Fatal("探测还在途时放进了第二个请求")
	}
	if breaker.State(now.Add(openFor)) != "half_open" {
		t.Fatalf("探测在途时状态是 %s", breaker.State(now.Add(openFor)))
	}

	breaker.RecordSuccess()
	if breaker.State(now.Add(openFor)) != "closed" {
		t.Fatalf("探测成功后是 %s", breaker.State(now.Add(openFor)))
	}
	if allowed, probe := breaker.Allow(now.Add(openFor)); !allowed || probe {
		t.Fatal("关闭之后的请求被当成探测")
	}

	// 探测失败立刻重新打开，要再等一个完整的窗口。
	breaker.RecordFailure(now)
	opened := now.Add(openFor)
	if allowed, probe := breaker.Allow(opened); !allowed || !probe {
		t.Fatal("没有进入第二次半开")
	}
	breaker.RecordFailure(opened)
	if breaker.State(opened) != "open" {
		t.Fatalf("探测失败后是 %s", breaker.State(opened))
	}
	if allowed, _ := breaker.Allow(opened); allowed {
		t.Fatal("刚重新打开就放行了")
	}
	if allowed, _ := breaker.Allow(opened.Add(openFor - time.Nanosecond)); allowed {
		t.Fatal("重新打开的窗口被缩短了")
	}
	if allowed, probe := breaker.Allow(opened.Add(openFor)); !allowed || !probe {
		t.Fatal("重新打开的窗口结束时没有给探测")
	}
}

func TestCircuitBreakerNeutralDoesNotTripOrReset(t *testing.T) {
	breaker := mustBreaker(t, 2, time.Minute)
	now := time.Unix(1_700_000_000, 0)
	breaker.RecordFailure(now)
	breaker.RecordNeutral()
	breaker.RecordFailure(now)
	if breaker.State(now) != "open" {
		t.Fatal("中性的一笔把连续失败清零了，电路没有打开")
	}
	fresh := mustBreaker(t, 1, time.Minute)
	fresh.RecordNeutral()
	fresh.RecordNeutral()
	if fresh.State(now) != "closed" {
		t.Fatal("只有中性记录就把电路打开了")
	}
}

func TestCircuitBreakerRace(t *testing.T) {
	breaker := mustBreaker(t, 3, time.Millisecond)
	now := time.Unix(1_700_000_000, 0)
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range 100 {
				at := now.Add(time.Duration(j) * time.Millisecond)
				breaker.Allow(at)
				if j%2 == 0 {
					breaker.RecordFailure(at)
				} else {
					breaker.RecordSuccess()
				}
				breaker.RecordNeutral()
				_ = breaker.State(at)
			}
		}()
	}
	wg.Wait()
}
