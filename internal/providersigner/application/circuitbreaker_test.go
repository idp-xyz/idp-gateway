package application

import (
	"context"
	"testing"
	"time"

	"go.idp.xyz/idp-gateway/internal/providersigner/domain"
	"go.idp.xyz/idp-gateway/internal/providersigner/ports"
)

func mustBreaker(t *testing.T, threshold int, open time.Duration) *domain.CircuitBreaker {
	t.Helper()
	breaker, err := domain.NewCircuitBreaker(domain.CircuitBreakerConfig{FailureThreshold: threshold, OpenDuration: open})
	if err != nil {
		t.Fatal(err)
	}
	return breaker
}

func TestCircuitBreakerTripsOnCarrierFailures(t *testing.T) {
	cases := []struct {
		name     string
		response ports.CarrierResponse
		err      error
		status   int
		code     string
	}{
		{"timeout", ports.CarrierResponse{}, ports.ErrTimeout, 504, "carrier_timeout"},
		{"unreachable", ports.CarrierResponse{}, ports.ErrUnreachable, 502, "carrier_unreachable"},
		{"answer too large", ports.CarrierResponse{}, ports.ErrAnswerTooLarge, 502, "carrier_answer_unreadable"},
		{"status 503", ports.CarrierResponse{Status: 503}, nil, 502, "carrier_status"},
		{"html 200", ports.CarrierResponse{Status: 200, Body: []byte("<html>down</html>")}, nil, 502, "carrier_answer_unreadable"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			carrier := answering(c.response, c.err)
			now := time.Unix(1_700_000_000, 0)
			breaker := mustBreaker(t, 1, time.Minute)
			service := newService(t, carrier, WithClock(func() time.Time { return now }), WithCircuitBreaker(breaker))
			first := service.Handle(context.Background(), call(`{}`))
			code, _ := failureOf(t, first)
			if first.Status != c.status || code != c.code || len(carrier.calls) != 1 || breaker.State(now) != "open" {
				t.Fatalf("第一次：%d %s calls=%d state=%s", first.Status, code, len(carrier.calls), breaker.State(now))
			}
			second := service.Handle(context.Background(), call(`{}`))
			code, _ = failureOf(t, second)
			if second.Status != 503 || code != "carrier_circuit_open" || len(carrier.calls) != 1 || second.CarrierStatus != 0 {
				t.Fatalf("打开之后仍联系了承运商：%d %s calls=%d %+v", second.Status, code, len(carrier.calls), second)
			}
			// 电路开着时，坏的 JSON 仍是 400，不改成 503，也不再联系承运商。
			garbage := service.Handle(context.Background(), call(`[]`))
			code, _ = failureOf(t, garbage)
			if garbage.Status != 400 || code != "body_not_json_object" || len(carrier.calls) != 1 {
				t.Fatalf("坏正文：%d %s calls=%d", garbage.Status, code, len(carrier.calls))
			}
		})
	}
}

func TestCircuitBreakerIgnoresCallerErrorsAndHealthyRefusals(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	key := testKey(t)

	t.Run("caller 400", func(t *testing.T) {
		carrier := answering(ports.CarrierResponse{Status: 200, Body: envelope(t, key, `{}`)}, nil)
		breaker := mustBreaker(t, 1, time.Minute)
		service := newService(t, carrier, WithClock(func() time.Time { return now }), WithCircuitBreaker(breaker))
		for range 3 {
			result := service.Handle(context.Background(), call(`[]`))
			code, _ := failureOf(t, result)
			if result.Status != 400 || code != "body_not_json_object" || breaker.State(now) != "closed" || len(carrier.calls) != 0 {
				t.Fatalf("%d %s state=%s calls=%d", result.Status, code, breaker.State(now), len(carrier.calls))
			}
		}
	})

	t.Run("carrier 200 business refusal", func(t *testing.T) {
		refused := []byte(`{"apiResultCode":500,"apiErrorMsg":"no","apiTimestamp":1}`)
		carrier := answering(ports.CarrierResponse{Status: 200, Body: refused}, nil)
		breaker := mustBreaker(t, 1, time.Minute)
		service := newService(t, carrier, WithClock(func() time.Time { return now }), WithCircuitBreaker(breaker))
		first := service.Handle(context.Background(), call(`{}`))
		if first.Status != 200 || first.Outcome != domain.OutcomeCarrierRefused || breaker.State(now) != "closed" {
			t.Fatalf("拒绝被当成故障：%d %s state=%s", first.Status, first.Outcome, breaker.State(now))
		}
		second := service.Handle(context.Background(), call(`{}`))
		if second.Status != 200 || len(carrier.calls) != 2 {
			t.Fatalf("第二次没有再问承运商：%d calls=%d", second.Status, len(carrier.calls))
		}
	})

	t.Run("business success false", func(t *testing.T) {
		carrier := answering(ports.CarrierResponse{Status: 200, Body: envelope(t, key, `{"success":false}`)}, nil)
		breaker := mustBreaker(t, 1, time.Minute)
		service := newService(t, carrier, WithClock(func() time.Time { return now }), WithCircuitBreaker(breaker))
		if result := service.Handle(context.Background(), call(`{}`)); result.Status != 200 || breaker.State(now) != "closed" {
			t.Fatalf("%d state=%s", result.Status, breaker.State(now))
		}
		if result := service.Handle(context.Background(), call(`{}`)); result.Status != 200 || len(carrier.calls) != 2 {
			t.Fatalf("业务失败打开了电路：%d calls=%d", result.Status, len(carrier.calls))
		}
	})

	t.Run("carrier 400 does not trip or reset", func(t *testing.T) {
		carrier := answering(ports.CarrierResponse{}, ports.ErrTimeout)
		breaker := mustBreaker(t, 2, time.Minute)
		service := newService(t, carrier, WithClock(func() time.Time { return now }), WithCircuitBreaker(breaker))
		if result := service.Handle(context.Background(), call(`{}`)); result.Status != 504 || breaker.State(now) != "closed" {
			t.Fatalf("第一次超时：%d %s", result.Status, breaker.State(now))
		}
		carrier.respond = func(ports.CarrierRequest) (ports.CarrierResponse, error) {
			return ports.CarrierResponse{Status: 400}, nil
		}
		if result := service.Handle(context.Background(), call(`{}`)); result.Status != 502 || breaker.State(now) != "closed" {
			t.Fatalf("400：%d %s", result.Status, breaker.State(now))
		}
		carrier.respond = func(ports.CarrierRequest) (ports.CarrierResponse, error) {
			return ports.CarrierResponse{}, ports.ErrTimeout
		}
		if result := service.Handle(context.Background(), call(`{}`)); result.Status != 504 || breaker.State(now) != "open" {
			t.Fatalf("400 把连续失败清零了：%d %s", result.Status, breaker.State(now))
		}
	})
}

func TestCircuitBreakerHalfOpenProbe(t *testing.T) {
	key := testKey(t)
	okBody := envelope(t, key, `{"success":false}`)
	now := time.Unix(1_700_000_000, 0)
	carrier := answering(ports.CarrierResponse{}, ports.ErrTimeout)
	breaker := mustBreaker(t, 2, 30*time.Second)
	service := newService(t, carrier, WithClock(func() time.Time { return now }), WithCircuitBreaker(breaker))
	for range 2 {
		if result := service.Handle(context.Background(), call(`{}`)); result.Status != 504 {
			t.Fatalf("预热失败：%d", result.Status)
		}
	}
	if len(carrier.calls) != 2 || breaker.State(now) != "open" {
		t.Fatalf("calls=%d state=%s", len(carrier.calls), breaker.State(now))
	}
	// 还没到时间：失败快速返回，承运商调用数不变。
	if result := service.Handle(context.Background(), call(`{}`)); result.Status != 503 || len(carrier.calls) != 2 {
		t.Fatalf("窗口内：%d calls=%d", result.Status, len(carrier.calls))
	}

	now = now.Add(30 * time.Second)
	entered := make(chan struct{})
	release := make(chan struct{})
	carrier.respond = func(ports.CarrierRequest) (ports.CarrierResponse, error) {
		close(entered)
		<-release
		return ports.CarrierResponse{Status: 200, Body: okBody}, nil
	}
	probeDone := make(chan Result, 1)
	go func() {
		probeDone <- service.Handle(context.Background(), call(`{}`))
	}()
	<-entered
	blocked := service.Handle(context.Background(), call(`{}`))
	if code, _ := failureOf(t, blocked); blocked.Status != 503 || code != "carrier_circuit_open" || len(carrier.calls) != 3 {
		t.Fatalf("探测在途时放进了第二个：%d %s calls=%d", blocked.Status, code, len(carrier.calls))
	}
	close(release)
	probe := <-probeDone
	if probe.Status != 200 || breaker.State(now) != "closed" || len(carrier.calls) != 3 {
		t.Fatalf("探测：%d state=%s calls=%d", probe.Status, breaker.State(now), len(carrier.calls))
	}
	// 业务 success 为 false 的可读信封把电路关上了，下一笔照常发送。
	carrier.respond = func(ports.CarrierRequest) (ports.CarrierResponse, error) {
		return ports.CarrierResponse{Status: 200, Body: okBody}, nil
	}
	if result := service.Handle(context.Background(), call(`{}`)); result.Status != 200 || len(carrier.calls) != 4 || breaker.State(now) != "closed" {
		t.Fatalf("恢复之后：%d calls=%d state=%s", result.Status, len(carrier.calls), breaker.State(now))
	}
}

func TestCircuitBreakerProbeFailureReopens(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	carrier := answering(ports.CarrierResponse{}, ports.ErrTimeout)
	breaker := mustBreaker(t, 1, 30*time.Second)
	service := newService(t, carrier, WithClock(func() time.Time { return now }), WithCircuitBreaker(breaker))
	_ = service.Handle(context.Background(), call(`{}`))
	now = now.Add(30 * time.Second)
	carrier.respond = func(ports.CarrierRequest) (ports.CarrierResponse, error) {
		return ports.CarrierResponse{Status: 503}, nil
	}
	probe := service.Handle(context.Background(), call(`{}`))
	if code, carrierStatus := failureOf(t, probe); probe.Status != 502 || code != "carrier_status" || carrierStatus != 503 || breaker.State(now) != "open" {
		t.Fatalf("探测失败：%d %s state=%s", probe.Status, code, breaker.State(now))
	}
	if result := service.Handle(context.Background(), call(`{}`)); result.Status != 503 || len(carrier.calls) != 2 {
		t.Fatalf("重新打开之后仍发送了：%d calls=%d", result.Status, len(carrier.calls))
	}
	now = now.Add(30 * time.Second)
	key := testKey(t)
	body := envelope(t, key, `{}`)
	carrier.respond = func(ports.CarrierRequest) (ports.CarrierResponse, error) {
		return ports.CarrierResponse{Status: 200, Body: body}, nil
	}
	if result := service.Handle(context.Background(), call(`{}`)); result.Status != 200 || breaker.State(now) != "closed" {
		t.Fatalf("第二次探测：%d %s", result.Status, breaker.State(now))
	}
	if result := service.Handle(context.Background(), call(`{}`)); result.Status != 200 || len(carrier.calls) != 4 {
		t.Fatalf("关闭之后：%d calls=%d", result.Status, len(carrier.calls))
	}
}

func TestCircuitBreakerProbePanicDoesNotStick(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	carrier := answering(ports.CarrierResponse{}, ports.ErrTimeout)
	breaker := mustBreaker(t, 1, 30*time.Second)
	service := newService(t, carrier, WithClock(func() time.Time { return now }), WithCircuitBreaker(breaker))
	_ = service.Handle(context.Background(), call(`{}`))
	now = now.Add(30 * time.Second)
	panicked := false
	key := testKey(t)
	body := envelope(t, key, `{}`)
	carrier.respond = func(ports.CarrierRequest) (ports.CarrierResponse, error) {
		if !panicked {
			panicked = true
			panic("carrier blew up")
		}
		return ports.CarrierResponse{Status: 200, Body: body}, nil
	}
	func() {
		defer func() { _ = recover() }()
		service.Handle(context.Background(), call(`{}`))
	}()
	if !panicked {
		t.Fatal("探测没有发出去")
	}
	// panic 被记成失败，电路重新打开。再等一个窗口，探测能再出去。
	now = now.Add(30 * time.Second)
	result := service.Handle(context.Background(), call(`{}`))
	if result.Status != 200 || breaker.State(now) != "closed" || len(carrier.calls) != 3 {
		t.Fatalf("panic 之后探测卡住了：%d state=%s calls=%d", result.Status, breaker.State(now), len(carrier.calls))
	}
}

func TestSuccessResetsTheFailureCount(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	key := testKey(t)
	body := envelope(t, key, `{}`)
	carrier := answering(ports.CarrierResponse{}, ports.ErrTimeout)
	breaker := mustBreaker(t, 3, time.Minute)
	service := newService(t, carrier, WithClock(func() time.Time { return now }), WithCircuitBreaker(breaker))
	_ = service.Handle(context.Background(), call(`{}`))
	carrier.respond = func(ports.CarrierRequest) (ports.CarrierResponse, error) {
		return ports.CarrierResponse{Status: 200, Body: body}, nil
	}
	if result := service.Handle(context.Background(), call(`{}`)); result.Status != 200 || breaker.State(now) != "closed" {
		t.Fatalf("成功：%d %s", result.Status, breaker.State(now))
	}
	carrier.respond = func(ports.CarrierRequest) (ports.CarrierResponse, error) {
		return ports.CarrierResponse{}, ports.ErrTimeout
	}
	_ = service.Handle(context.Background(), call(`{}`))
	_ = service.Handle(context.Background(), call(`{}`))
	if breaker.State(now) != "closed" {
		t.Fatal("成功没有把计数清零")
	}
	_ = service.Handle(context.Background(), call(`{}`))
	if breaker.State(now) != "open" {
		t.Fatal("清零之后的第三次没有打开")
	}
}
