// Package telemetry 把看守每一眼看到的记成数，按 Prometheus 的文本格式给出来，供告警用
// （docs/adr/ADR-0010.md 第 10 条"告警"）。
//
// 看守有事才写一行，安稳的时候不出声：它不出声，说明不了它还在看。这里是另一条路：每看完一眼记一次，
// 外面的监控隔一阵来读。读不到，或者"上一眼"的时刻不再往前走，就是看守出了事。
//
// 这里只有数。池出了什么事、为什么，还在看守写的那些行里。数里没有配置的内容，也没有凭证。
package telemetry

import (
	"bytes"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"go.idp.xyz/idp-gateway/internal/gatewayconfig/application"
	"go.idp.xyz/idp-gateway/internal/gatewayconfig/domain"
)

// Path 是给出指标的路径；ContentType 是 Prometheus 文本格式的类型。
const (
	Path        = "/metrics"
	ContentType = "text/plain; version=0.0.4; charset=utf-8"
)

// ConditionUnknown：看守这一眼没看成，三个容器现在是什么样子不知道。另外三个取值是 domain 里的。
const ConditionUnknown = "unknown"

var conditions = []string{string(domain.ConditionWhole), string(domain.ConditionDown), string(domain.ConditionOrphaned), ConditionUnknown}

// outcomes 是对账会有的几个结局。看守报告了别的，也照样给出来。
var outcomes = []application.Outcome{
	application.OutcomeInSync, application.OutcomeRestored, application.OutcomeRestartPending,
	application.OutcomeUnknown, application.OutcomeUnconfirmed,
}

// Metrics 是一个看守的指标。看守每看完一眼叫一次 Observe；Handler 给来读的人当时的样子。
type Metrics struct {
	project string
	pace    application.Pace
	started time.Time

	mu           sync.Mutex
	looks        uint64
	lookedAt     time.Time
	failed       bool
	condition    string
	busy         bool
	unrepaired   int
	starts       uint64
	putBack      uint64
	outcome      application.Outcome
	reconciledAt time.Time

	// 看守另外照看的服务（ADR-0024）。没有时下面这几样一样都不给出，给出来的与没有它们时一字不差。
	tended  []string
	pinned  map[string]bool
	running map[string]bool
	moved   int
	repins  uint64
}

// New 返回一个还没有看过一眼的看守的指标。project 是它守着的 compose 项目，started 是它启动的时刻。
func New(project string, pace application.Pace, started time.Time) *Metrics {
	return &Metrics{project: project, pace: pace, started: started, lookedAt: started, condition: ConditionUnknown}
}

// Tend 让指标另外给出看守照看的这几个服务（--tend、--tend-pinned，ADR-0024）；pinned 是其中钉在网关出口规则里的。
// 要在第一次 Observe 之前设。
func (m *Metrics) Tend(services, pinned []string) *Metrics {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tended, m.pinned, m.running = append([]string(nil), services...), map[string]bool{}, map[string]bool{}
	for _, name := range pinned {
		m.pinned[name] = true
	}
	return m
}

// Observe 记下看守刚看完的这一眼。at 是看完的时刻。
func (m *Metrics) Observe(tending application.Tending, at time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.looks++
	m.lookedAt = at
	m.failed = tending.Err != nil
	m.busy = tending.Busy
	m.unrepaired = tending.Failures
	// 池现在的样子：动过手的，是动手之后的；动过手之后没看成，就是不知道。
	m.condition = ConditionUnknown
	switch {
	case tending.After != nil:
		condition, _ := tending.After.Condition()
		m.condition = string(condition)
	case tending.Acted():
	case tending.Condition != "":
		m.condition = string(tending.Condition)
	}
	if tending.Started {
		m.starts++
	}
	if tending.Reconciled != nil {
		m.outcome, m.reconciledAt = tending.Reconciled.Outcome, at
		if tending.Reconciled.Replaced {
			m.putBack++
		}
	}
	if len(m.tended) == 0 {
		return
	}
	// 与池的样子同一个取法：动过手的，是动手之后的；动过手之后没看成、或者这一眼没看成，一个都不算在跑。
	seen := tending.Services
	switch {
	case tending.After != nil:
		seen = tending.ServicesAfter
	case tending.Acted(), tending.Err != nil:
		seen = nil
	}
	m.running = map[string]bool{}
	for _, service := range seen {
		m.running[service.Name] = service.Running()
	}
	if tending.Forgot {
		m.repins++
	}
	// 出口规则重新解析了、网关也停下了，那些地址从这时起就是记下的。
	m.moved = len(tending.Moved)
	if tending.Forgot && tending.Stopped {
		m.moved = 0
	}
}

// Text 是此刻的全部指标，Prometheus 的文本格式。
func (m *Metrics) Text() []byte {
	m.mu.Lock()
	defer m.mu.Unlock()
	var b bytes.Buffer
	family := func(name, kind, help string) {
		fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s %s\n", name, help, name, kind)
	}
	sample := func(name, labels string, value string) {
		if labels != "" {
			labels = "{" + labels + "}"
		}
		fmt.Fprintf(&b, "%s%s %s\n", name, labels, value)
	}
	one := func(name, kind, help, value string) {
		family(name, kind, help)
		sample(name, "", value)
	}

	family("idp_gateway_keeper_info", "gauge", "The docker compose project this keeper watches.")
	sample("idp_gateway_keeper_info", label("project", m.project), "1")
	one("idp_gateway_keeper_start_time_seconds", "gauge",
		"When this keeper started, in seconds since the epoch.", moment(m.started))
	one("idp_gateway_keeper_look_interval_seconds", "gauge",
		"How often the keeper looks at the pool's long-running containers.", seconds(m.pace.Interval))
	one("idp_gateway_keeper_reconcile_interval_seconds", "gauge",
		"How often the keeper reconciles the pool while its gateway runs.", seconds(m.pace.Reconcile))
	one("idp_gateway_keeper_looks_total", "counter",
		"Looks at the pool that the keeper has finished.", count(m.looks))
	one("idp_gateway_keeper_last_look_timestamp_seconds", "gauge",
		"When the keeper finished its last look at the pool; its start time until the first look is finished.", moment(m.lookedAt))
	one("idp_gateway_keeper_last_look_failed", "gauge",
		"1 when the keeper could not see the pool at its last look or a step of that look failed, 0 otherwise. The reason is in the keeper's output.",
		flag(m.failed))

	family("idp_gateway_pool_condition", "gauge",
		"What the pool's three long-running containers looked like when the last look ended: 1 for the condition that holds. "+
			"whole: all three run. down: one is not running. orphaned: the gateway or the front proxy is attached to a network namespace that is gone. "+
			"unknown: the keeper could not see them.")
	for _, condition := range conditions {
		sample("idp_gateway_pool_condition", label("condition", condition), flag(m.condition == condition))
	}
	one("idp_gateway_pool_busy", "gauge",
		"1 when a publication held the pool at the last look, so that the keeper did not do what was due, 0 otherwise.", flag(m.busy))
	one("idp_gateway_pool_unrepaired_attempts", "gauge",
		"How many times in a row the keeper has acted on the pool without making it whole.", strconv.Itoa(m.unrepaired))
	one("idp_gateway_pool_starts_total", "counter",
		"Times the keeper ran the command that starts the pool.", count(m.starts))

	family("idp_gateway_pool_reconcile_outcome", "gauge",
		"The outcome of the keeper's last reconcile: 1 for that outcome. All 0 until it has reconciled once.")
	known := false
	for _, outcome := range outcomes {
		sample("idp_gateway_pool_reconcile_outcome", label("outcome", string(outcome)), flag(m.outcome == outcome))
		known = known || m.outcome == outcome
	}
	if m.outcome != "" && !known {
		sample("idp_gateway_pool_reconcile_outcome", label("outcome", string(m.outcome)), "1")
	}
	reconciledAt := "0"
	if !m.reconciledAt.IsZero() {
		reconciledAt = moment(m.reconciledAt)
	}
	one("idp_gateway_pool_last_reconcile_timestamp_seconds", "gauge",
		"When the keeper last finished a reconcile, in seconds since the epoch; 0 until it has reconciled once.", reconciledAt)
	one("idp_gateway_pool_snapshots_put_back_total", "counter",
		"Times a reconcile by the keeper wrote the recorded snapshot back into the configuration directory.", count(m.putBack))
	if len(m.tended) == 0 {
		return b.Bytes()
	}

	family("idp_gateway_pool_tended_running", "gauge",
		"1 when every container of this service the keeper tends besides the three (--tend, --tend-pinned) ran when the last look ended, 0 otherwise: "+
			"one is not running, it has no container, or the keeper could not see it. pinned: the gateway reaches it by name through its egress rules.")
	for _, name := range m.tended {
		sample("idp_gateway_pool_tended_running", label("service", name)+","+label("pinned", strconv.FormatBool(m.pinned[name])), flag(m.running[name]))
	}
	one("idp_gateway_pool_unfollowed_addresses", "gauge",
		"Addresses the pinned services had at the last look that the keeper had not recorded and has not yet made the gateway follow.", strconv.Itoa(m.moved))
	one("idp_gateway_pool_repins_total", "counter",
		"Times the keeper ran egress forget because a pinned service had an address it had not recorded; when that worked it then "+
			"stopped the front proxy and the gateway and ran the command that starts the pool.", count(m.repins))
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

func label(name, value string) string {
	escaped := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`).Replace(value)
	return name + `="` + escaped + `"`
}

func flag(set bool) string {
	if set {
		return "1"
	}
	return "0"
}

func count(n uint64) string { return strconv.FormatUint(n, 10) }

func seconds(d time.Duration) string { return strconv.FormatFloat(d.Seconds(), 'f', -1, 64) }

// moment 是一个时刻：从纪元算起的秒数，到毫秒。
func moment(t time.Time) string {
	return strconv.FormatFloat(float64(t.UnixMilli())/1000, 'f', 3, 64)
}
