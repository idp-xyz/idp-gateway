package main

import (
	"context"
	"crypto/rand"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"go.idp.xyz/idp-gateway/internal/providersigner/domain"
)

func encryptedOK(t *testing.T) string {
	t.Helper()
	key, err := domain.ParseKey(aesKey)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := domain.Encrypt(key, appKey, []byte(`{"success":true}`), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return `{"apiResultCode":0,"apiErrorMsg":null,"apiResultData":"` + ciphertext + `","apiTimestamp":1}`
}

func TestCircuitBreakerOpensAndRecovers(t *testing.T) {
	okBody := encryptedOK(t)
	var mu sync.Mutex
	healthy := false
	carrier := newFakeCarrier(t, func(w http.ResponseWriter, r *http.Request, _ seenRequest) {
		mu.Lock()
		ok := healthy
		mu.Unlock()
		if !ok {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_, _ = io.WriteString(w, okBody)
	})
	h := newHarness(t, carrier)
	h.extra = []string{"--cb-failure-threshold", "2", "--cb-open-duration", "300ms"}
	h.start()
	if logs := h.logs.String(); !strings.Contains(logs, `"cb_failure_threshold":2`) || !strings.Contains(logs, `"cb_open_duration":"300ms"`) {
		t.Fatalf("启动日志没有熔断参数：%s", logs)
	}
	for i := 1; i <= 2; i++ {
		a := h.post("/sfintl/v1/orders", `{}`, false)
		fields := a.fields(t)
		if a.status != http.StatusBadGateway || fields["error"] != "carrier_status" || fields["carrier_status"] != float64(503) {
			t.Fatalf("第 %d 次：%d %s", i, a.status, a.body)
		}
	}
	if carrier.count() != 2 {
		t.Fatalf("承运商收到 %d 次，期望 2", carrier.count())
	}
	opened := h.post("/sfintl/v1/orders", `{}`, false)
	fields := opened.fields(t)
	if opened.status != http.StatusServiceUnavailable || fields["error"] != "carrier_circuit_open" || fields["detail"] != "The carrier circuit breaker is open." {
		t.Fatalf("打开之后：%d %s", opened.status, opened.body)
	}
	if carrier.count() != 2 {
		t.Fatalf("电路打开后仍联系了承运商：%d 次", carrier.count())
	}
	garbage := h.post("/sfintl/v1/orders", `[]`, false)
	if garbage.status != http.StatusBadRequest || garbage.fields(t)["error"] != "body_not_json_object" || carrier.count() != 2 {
		t.Fatalf("坏正文：%d %s calls=%d", garbage.status, garbage.body, carrier.count())
	}
	time.Sleep(900 * time.Millisecond)
	mu.Lock()
	healthy = true
	mu.Unlock()
	for i := 1; i <= 2; i++ {
		a := h.post("/sfintl/v1/orders", `{}`, false)
		if a.status != http.StatusOK {
			t.Fatalf("恢复后第 %d 次：%d %s", i, a.status, a.body)
		}
	}
	if carrier.count() != 4 {
		t.Fatalf("恢复后承运商收到 %d 次，期望 4", carrier.count())
	}
}

func TestCircuitBreakerDisabledDoesNotTrip(t *testing.T) {
	carrier := newFakeCarrier(t, func(w http.ResponseWriter, _ *http.Request, _ seenRequest) {
		w.WriteHeader(http.StatusServiceUnavailable)
	})
	h := newHarness(t, carrier)
	h.extra = []string{"--cb-failure-threshold", "0"}
	h.start()
	for i := 1; i <= 3; i++ {
		a := h.post("/sfintl/v1/orders", `{}`, false)
		if a.status != http.StatusBadGateway || a.fields(t)["error"] != "carrier_status" {
			t.Fatalf("第 %d 次：%d %s", i, a.status, a.body)
		}
	}
	if carrier.count() != 3 {
		t.Fatalf("关闭的熔断挡住了请求：calls=%d", carrier.count())
	}
	if !strings.Contains(h.logs.String(), `"cb_failure_threshold":0`) || !strings.Contains(h.logs.String(), `"cb_open_duration":"30s"`) {
		t.Fatalf("默认打开时长没有记下来：%s", h.logs)
	}
}

func TestCircuitBreakerFlags(t *testing.T) {
	h := newHarness(t, newFakeCarrier(t, nil))
	base := h.args("127.0.0.1:0")
	o, err := parse(base, io.Discard)
	if err != nil || o.cbFailureThreshold != 0 || o.cbOpenDuration != 30*time.Second {
		t.Fatalf("默认值：%+v %v", o, err)
	}
	o, err = parse(append(append([]string{}, base...), "--cb-failure-threshold", "0", "--cb-open-duration", "0s"), io.Discard)
	if err != nil || o.cbFailureThreshold != 0 || o.cbOpenDuration != 0 {
		t.Fatalf("阈值为 0 时打开时长 0 应被接受：%+v %v", o, err)
	}
	cases := []struct {
		name string
		args []string
		says string
	}{
		{"negative threshold", []string{"--cb-failure-threshold", "-1"}, "cb-failure-threshold"},
		{"zero open duration", []string{"--cb-failure-threshold", "2", "--cb-open-duration", "0s"}, "cb-open-duration"},
		{"negative open duration", []string{"--cb-failure-threshold", "2", "--cb-open-duration", "-1s"}, "cb-open-duration"},
		{"threshold not a number", []string{"--cb-failure-threshold", "many"}, "cb-failure-threshold"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			var output lockedBuffer
			err := run(ctx, append(append([]string{}, base...), c.args...), &output, func(net.Addr) {
				t.Error("拒绝启动的参数却开始接受连接了")
			})
			if err == nil {
				t.Fatal("启动了")
			}
			if !strings.Contains(err.Error(), c.says) && !strings.Contains(output.String(), c.says) {
				t.Errorf("错误是 %q，期望提到 %q", err, c.says)
			}
		})
	}
}
