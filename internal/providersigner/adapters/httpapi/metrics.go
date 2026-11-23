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

var signerDurationBounds = []struct {
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

type signerSeries struct {
	operation, outcome, status string
}

func (s signerSeries) clean() signerSeries {
	s.operation = clipSignerLabel(s.operation)
	s.outcome = clipSignerLabel(s.outcome)
	s.status = clipSignerLabel(s.status)
	return s
}

func (s signerSeries) less(o signerSeries) bool {
	return s.operation+"\x00"+s.outcome+"\x00"+s.status < o.operation+"\x00"+o.outcome+"\x00"+o.status
}

// SignerMetrics 是 provider-signer 的 Prometheus 文本指标，只挂在单独的明文监听上。
type SignerMetrics struct {
	mu      sync.Mutex
	calls   map[signerSeries]uint64
	hist    signerHistogram
	circuit atomic.Uint64
	traces  func() (exported, dropped, failed uint64)
}

// NewSignerMetrics 构造指标。traces 在抓取时读导出器计数，可以是 nil。
func NewSignerMetrics(traces func() (exported, dropped, failed uint64)) *SignerMetrics {
	return &SignerMetrics{calls: map[signerSeries]uint64{}, traces: traces}
}

// Observe 记一次调用。circuitOpen 为 0 或 1；negative 表示这次调用没有碰到熔断器，不改仪表。
func (m *SignerMetrics) Observe(series signerSeries, elapsed time.Duration, circuitOpen int) {
	if m == nil {
		return
	}
	series = series.clean()
	seconds := elapsed.Seconds()
	if seconds < 0 {
		seconds = 0
	}
	m.mu.Lock()
	m.calls[series]++
	m.hist.observe(seconds)
	m.mu.Unlock()
	switch circuitOpen {
	case 0, 1:
		m.circuit.Store(uint64(circuitOpen))
	}
}

// ServeHTTP 只回答 GET /metrics。
func (m *SignerMetrics) ServeHTTP(w http.ResponseWriter, r *http.Request) {
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

func (m *SignerMetrics) expose() []byte {
	m.mu.Lock()
	series := make([]signerSeries, 0, len(m.calls))
	counts := make([]uint64, 0, len(m.calls))
	for key, count := range m.calls {
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
	b.WriteString("# HELP idp_gateway_signer_calls_total Carrier signer calls.\n")
	b.WriteString("# TYPE idp_gateway_signer_calls_total counter\n")
	for _, i := range order {
		s := series[i]
		b.WriteString("idp_gateway_signer_calls_total{")
		writeSignerLabel(&b, "operation", s.operation)
		b.WriteByte(',')
		writeSignerLabel(&b, "outcome", s.outcome)
		b.WriteByte(',')
		writeSignerLabel(&b, "status", s.status)
		b.WriteString("} ")
		b.WriteString(strconv.FormatUint(counts[i], 10))
		b.WriteByte('\n')
	}
	writeSignerHistogram(&b, "idp_gateway_signer_call_duration_seconds", "Signer call latency in seconds.", hist)
	b.WriteString("# HELP idp_gateway_signer_circuit_open Carrier circuit breaker; 1 is open.\n")
	b.WriteString("# TYPE idp_gateway_signer_circuit_open gauge\n")
	b.WriteString("idp_gateway_signer_circuit_open ")
	b.WriteString(strconv.FormatUint(m.circuit.Load(), 10))
	b.WriteByte('\n')
	exported, dropped, failed := uint64(0), uint64(0), uint64(0)
	if m.traces != nil {
		exported, dropped, failed = m.traces()
	}
	writeSignerCounter(&b, "idp_gateway_signer_otlp_spans_exported_total", "OTLP spans accepted by the collector.", exported)
	writeSignerCounter(&b, "idp_gateway_signer_otlp_spans_dropped_total", "OTLP spans dropped before export.", dropped)
	writeSignerCounter(&b, "idp_gateway_signer_otlp_spans_failed_total", "OTLP spans the collector did not accept.", failed)
	return []byte(b.String())
}

type signerHistogram struct {
	buckets []uint64
	inf     uint64
	sum     float64
	count   uint64
}

func (h *signerHistogram) observe(seconds float64) {
	if h.buckets == nil {
		h.buckets = make([]uint64, len(signerDurationBounds))
	}
	h.count++
	h.sum += seconds
	for i, bound := range signerDurationBounds {
		if seconds <= bound.bound {
			h.buckets[i]++
			return
		}
	}
	h.inf++
}

type signerHistogramSnapshot struct {
	buckets []uint64
	inf     uint64
	sum     float64
	count   uint64
}

func (h signerHistogram) snapshot() signerHistogramSnapshot {
	return signerHistogramSnapshot{buckets: append([]uint64(nil), h.buckets...), inf: h.inf, sum: h.sum, count: h.count}
}

func writeSignerHistogram(b *strings.Builder, name, help string, snap signerHistogramSnapshot) {
	b.WriteString("# HELP ")
	b.WriteString(name)
	b.WriteByte(' ')
	b.WriteString(help)
	b.WriteByte('\n')
	b.WriteString("# TYPE ")
	b.WriteString(name)
	b.WriteString(" histogram\n")
	if len(snap.buckets) < len(signerDurationBounds) {
		snap.buckets = append(snap.buckets, make([]uint64, len(signerDurationBounds)-len(snap.buckets))...)
	}
	var cumulative uint64
	for i, bound := range signerDurationBounds {
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

func writeSignerCounter(b *strings.Builder, name, help string, value uint64) {
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

func writeSignerLabel(b *strings.Builder, name, value string) {
	b.WriteString(name)
	b.WriteString("=\"")
	b.WriteString(escapeSignerLabel(value))
	b.WriteByte('"')
}

func escapeSignerLabel(s string) string {
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

func clipSignerLabel(s string) string {
	if strings.ContainsAny(s, "\r\n") {
		s = strings.ReplaceAll(strings.ReplaceAll(s, "\r", ""), "\n", "")
	}
	if len(s) > 128 {
		s = s[:128]
	}
	return s
}
