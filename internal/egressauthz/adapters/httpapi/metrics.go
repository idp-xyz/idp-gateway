package httpapi

import (
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// 判定耗时的直方图桶，单位秒。最后另有 +Inf。
var authzDurationBounds = []struct {
	le    string
	bound float64
}{
	{"0.001", 0.001},
	{"0.005", 0.005},
	{"0.01", 0.01},
	{"0.025", 0.025},
	{"0.05", 0.05},
	{"0.1", 0.1},
	{"0.25", 0.25},
	{"0.5", 0.5},
	{"1.0", 1},
	{"2.5", 2.5},
}

// decisionSeries 是计数器的标签。没有账户、租户、主体或令牌。
type decisionSeries struct {
	endpoint, result, reason, provider, operation, environment string
}

func (s decisionSeries) clean() decisionSeries {
	s.endpoint = clipLabel(s.endpoint)
	s.result = clipLabel(s.result)
	s.reason = clipLabel(s.reason)
	s.provider = clipLabel(s.provider)
	s.operation = clipLabel(s.operation)
	s.environment = clipLabel(s.environment)
	return s
}

func (s decisionSeries) less(o decisionSeries) bool {
	return s.endpoint+"\x00"+s.result+"\x00"+s.reason+"\x00"+s.provider+"\x00"+s.operation+"\x00"+s.environment <
		o.endpoint+"\x00"+o.result+"\x00"+o.reason+"\x00"+o.provider+"\x00"+o.operation+"\x00"+o.environment
}

// AuthzMetrics 是 gateway-authz 的 Prometheus 文本指标。只由单独的明文监听提供。
type AuthzMetrics struct {
	mu        sync.Mutex
	decisions map[decisionSeries]uint64
	hist      durationHistogram
	epoch     atomic.Uint64
	epochFn   func() uint64
	traces    func() (exported, dropped, failed uint64)
}

// NewAuthzMetrics 构造指标。epochFn 在抓取时读撤销代次，traces 读导出器计数；都可以是 nil。
func NewAuthzMetrics(epochFn func() uint64, traces func() (exported, dropped, failed uint64)) *AuthzMetrics {
	return &AuthzMetrics{
		decisions: map[decisionSeries]uint64{},
		epochFn:   epochFn,
		traces:    traces,
	}
}

// Observe 记一次判定的计数、耗时和当时的撤销代次。
func (m *AuthzMetrics) Observe(series decisionSeries, elapsed time.Duration, epoch uint64) {
	if m == nil {
		return
	}
	series = series.clean()
	seconds := elapsed.Seconds()
	if seconds < 0 {
		seconds = 0
	}
	m.mu.Lock()
	m.decisions[series]++
	m.hist.observe(seconds)
	m.mu.Unlock()
	if epoch > 0 {
		m.epoch.Store(epoch)
	}
}

// ServeHTTP 只回答 GET /metrics。别的路径是 404，别的方法是 405。
func (m *AuthzMetrics) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/metrics" {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body := m.expose()
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

func (m *AuthzMetrics) expose() []byte {
	m.mu.Lock()
	series := make([]decisionSeries, 0, len(m.decisions))
	counts := make([]uint64, 0, len(m.decisions))
	for key, count := range m.decisions {
		series = append(series, key)
		counts = append(counts, count)
	}
	hist := m.hist.snapshot()
	m.mu.Unlock()
	order := make([]int, len(series))
	for i := range order {
		order[i] = i
	}
	sort.Slice(order, func(i, j int) bool { return series[order[i]].less(series[order[j]]) })

	var b strings.Builder
	b.WriteString("# HELP idp_gateway_authz_decisions_total Authorization decisions.\n")
	b.WriteString("# TYPE idp_gateway_authz_decisions_total counter\n")
	for _, i := range order {
		s := series[i]
		b.WriteString("idp_gateway_authz_decisions_total{")
		writeLabel(&b, "endpoint", s.endpoint)
		b.WriteByte(',')
		writeLabel(&b, "result", s.result)
		b.WriteByte(',')
		writeLabel(&b, "reason", s.reason)
		b.WriteByte(',')
		writeLabel(&b, "provider_id", s.provider)
		b.WriteByte(',')
		writeLabel(&b, "operation_id", s.operation)
		b.WriteByte(',')
		writeLabel(&b, "environment", s.environment)
		b.WriteString("} ")
		b.WriteString(strconv.FormatUint(counts[i], 10))
		b.WriteByte('\n')
	}
	writeHistogram(&b, "idp_gateway_authz_decision_duration_seconds", "Authorization decision latency in seconds.", hist)
	b.WriteString("# HELP idp_gateway_authz_revocation_epoch Current revocation epoch.\n")
	b.WriteString("# TYPE idp_gateway_authz_revocation_epoch gauge\n")
	b.WriteString("idp_gateway_authz_revocation_epoch ")
	b.WriteString(strconv.FormatUint(m.currentEpoch(), 10))
	b.WriteByte('\n')
	exported, dropped, failed := uint64(0), uint64(0), uint64(0)
	if m.traces != nil {
		exported, dropped, failed = m.traces()
	}
	writeCounter(&b, "idp_gateway_authz_otlp_spans_exported_total", "OTLP spans accepted by the collector.", exported)
	writeCounter(&b, "idp_gateway_authz_otlp_spans_dropped_total", "OTLP spans dropped before export.", dropped)
	writeCounter(&b, "idp_gateway_authz_otlp_spans_failed_total", "OTLP spans the collector did not accept.", failed)
	return []byte(b.String())
}

func (m *AuthzMetrics) currentEpoch() uint64 {
	stored := m.epoch.Load()
	if m.epochFn == nil {
		return stored
	}
	live := m.epochFn()
	if live == 0 && stored > 0 {
		return stored
	}
	return live
}

type durationHistogram struct {
	buckets []uint64
	inf     uint64
	sum     float64
	count   uint64
}

func (h *durationHistogram) observe(seconds float64) {
	if h.buckets == nil {
		h.buckets = make([]uint64, len(authzDurationBounds))
	}
	h.count++
	h.sum += seconds
	for i, bound := range authzDurationBounds {
		if seconds <= bound.bound {
			h.buckets[i]++
			return
		}
	}
	h.inf++
}

type histogramSnapshot struct {
	buckets []uint64
	inf     uint64
	sum     float64
	count   uint64
}

func (h durationHistogram) snapshot() histogramSnapshot {
	return histogramSnapshot{buckets: append([]uint64(nil), h.buckets...), inf: h.inf, sum: h.sum, count: h.count}
}

func writeHistogram(b *strings.Builder, name, help string, snap histogramSnapshot) {
	b.WriteString("# HELP ")
	b.WriteString(name)
	b.WriteByte(' ')
	b.WriteString(help)
	b.WriteByte('\n')
	b.WriteString("# TYPE ")
	b.WriteString(name)
	b.WriteString(" histogram\n")
	if len(snap.buckets) < len(authzDurationBounds) {
		snap.buckets = append(snap.buckets, make([]uint64, len(authzDurationBounds)-len(snap.buckets))...)
	}
	var cumulative uint64
	for i, bound := range authzDurationBounds {
		cumulative += snap.buckets[i]
		b.WriteString(name)
		b.WriteString("_bucket{le=\"")
		b.WriteString(bound.le)
		b.WriteString("\"} ")
		b.WriteString(strconv.FormatUint(cumulative, 10))
		b.WriteByte('\n')
	}
	cumulative += snap.inf
	b.WriteString(name)
	b.WriteString("_bucket{le=\"+Inf\"} ")
	b.WriteString(strconv.FormatUint(cumulative, 10))
	b.WriteByte('\n')
	b.WriteString(name)
	b.WriteString("_sum ")
	b.WriteString(strconv.FormatFloat(snap.sum, 'f', -1, 64))
	b.WriteByte('\n')
	b.WriteString(name)
	b.WriteString("_count ")
	b.WriteString(strconv.FormatUint(snap.count, 10))
	b.WriteByte('\n')
}

func writeCounter(b *strings.Builder, name, help string, value uint64) {
	b.WriteString("# HELP ")
	b.WriteString(name)
	b.WriteByte(' ')
	b.WriteString(help)
	b.WriteByte('\n')
	b.WriteString("# TYPE ")
	b.WriteString(name)
	b.WriteString(" counter\n")
	b.WriteString(name)
	b.WriteByte(' ')
	b.WriteString(strconv.FormatUint(value, 10))
	b.WriteByte('\n')
}

func writeLabel(b *strings.Builder, name, value string) {
	b.WriteString(name)
	b.WriteString("=\"")
	b.WriteString(promEscape(value))
	b.WriteByte('"')
}

func promEscape(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\\':
			b.WriteString(`\\`)
		case '\n':
			b.WriteString(`\n`)
		case '"':
			b.WriteString(`\"`)
		default:
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

func clipLabel(s string) string {
	if strings.ContainsAny(s, "\r\n") {
		s = strings.ReplaceAll(strings.ReplaceAll(s, "\r", ""), "\n", "")
	}
	if len(s) > 128 {
		s = s[:128]
	}
	return s
}
