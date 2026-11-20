// Package metrics 把 JWKS 同步的结果记成数，按 Prometheus 的文本格式给出来。
//
// 命令有变化才写一行，安稳的时候不出声。这里是另一条路：每一轮都记，外面的监控隔一阵来读。
// 数里没有密钥、没有地址、没有文件路径。
package metrics

import (
	"bytes"
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"time"

	"go.idp.xyz/idp-gateway/internal/jwkssync/application"
)

// Path 是给出指标的路径；ContentType 是 Prometheus 文本格式的类型。
const (
	Path        = "/metrics"
	ContentType = "text/plain; version=0.0.4; charset=utf-8"
)

// Metrics 是一次同步进程的指标。每一轮结束调用 Observe；Handler 给来读的人当时的样子。
type Metrics struct {
	mu          sync.Mutex
	lastSuccess time.Time
	keyCount    int
	stale       bool
	failures    uint64
}

// New 返回还没有同步过的指标：成功时刻是 0，密钥数是 0，没有过期，失败次数是 0。
func New() *Metrics { return &Metrics{} }

// Observe 记下刚结束的这一轮。失败和过期都计入失败次数；成功不把这个计数清零。
func (m *Metrics) Observe(result application.Result) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if result.Outcome == application.OutcomeFetchFailed || result.Outcome == application.OutcomeStaleExpired {
		m.failures++
	}
	if !result.LastSuccess.IsZero() {
		m.lastSuccess = result.LastSuccess
	}
	m.keyCount = result.KeyCount
	m.stale = result.Stale
}

// Text 是此刻的全部指标，Prometheus 的文本格式。
func (m *Metrics) Text() []byte {
	m.mu.Lock()
	defer m.mu.Unlock()
	var b bytes.Buffer
	one := func(name, kind, help, value string) {
		fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s %s\n%s %s\n", name, help, name, kind, name, value)
	}
	one("idp_gateway_jwks_last_success_timestamp_seconds", "gauge",
		"When a JWKS document was last fetched and accepted, in seconds since the epoch; 0 until the first success.",
		moment(m.lastSuccess))
	one("idp_gateway_jwks_key_count", "gauge",
		"How many keys are in the JWKS document this process last confirmed.",
		strconv.Itoa(m.keyCount))
	one("idp_gateway_jwks_stale", "gauge",
		"1 when the last successful fetch is older than the allowed stale time, 0 otherwise.",
		flag(m.stale))
	one("idp_gateway_jwks_sync_failures_total", "counter",
		"JWKS sync attempts that failed to fetch or refused the document.",
		strconv.FormatUint(m.failures, 10))
	return b.Bytes()
}

// Handler 在 Path 上给出指标，别的路径一概 404。它只读：除了 GET 和 HEAD 都不接受。
func (m *Metrics) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(Path, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", ContentType)
		_, _ = w.Write(m.Text())
	})
	return mux
}

func flag(set bool) string {
	if set {
		return "1"
	}
	return "0"
}

// moment 是一个时刻：从纪元算起的秒数，到毫秒。零值是 0，表示还没有成功过。
func moment(t time.Time) string {
	if t.IsZero() {
		return "0"
	}
	return strconv.FormatFloat(float64(t.UnixMilli())/1000, 'f', 3, 64)
}
