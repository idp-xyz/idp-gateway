package domain

import (
	"errors"
	"sync"
	"time"
)

// 电路的三种状态。半开时最多有一个探测在途：探测还没回来之前，别的请求直接失败，
// 避免电路刚要恢复就被同时放进来的请求再次打满。
const (
	breakerClosed state = iota
	breakerOpen
	breakerHalfOpen
)

type state int

// CircuitBreakerConfig 是被动熔断的参数。FailureThreshold 为 0（或负数以外的关闭值）表示不启用。
// FailureThreshold >= 1 时，连续这么多次故障就把电路打开 OpenDuration。
type CircuitBreakerConfig struct {
	FailureThreshold int
	OpenDuration     time.Duration
}

// CircuitBreaker 按连续故障计数。它不认识网络：调用方传入时间，并在承运商有了结局之后来记一笔。
// 传输错误、HTTP 5xx、HTTP 200 但信封读不成，记失败；HTTP 200 且信封读得成，记成功
// （apiResultCode 不是 0 也算成功：那是健康承运商的应用层答复）；其它 HTTP 状态记中性，
// 不增加也不清零连续失败，只把在途探测放掉，免得探测永远占着。
type CircuitBreaker struct {
	mu            sync.Mutex
	cfg           CircuitBreakerConfig
	state         state
	consecutive   int
	openedAt      time.Time
	probeInFlight bool
}

// NewCircuitBreaker 校验参数。阈值为 0 时电路永远关闭；阈值大于 0 时打开时长必须大于 0。
func NewCircuitBreaker(cfg CircuitBreakerConfig) (*CircuitBreaker, error) {
	if cfg.FailureThreshold < 0 {
		return nil, errors.New("circuit breaker failure threshold must not be negative")
	}
	if cfg.FailureThreshold > 0 && cfg.OpenDuration <= 0 {
		return nil, errors.New("circuit breaker open duration must be greater than zero")
	}
	return &CircuitBreaker{cfg: cfg, state: breakerClosed}, nil
}

// Allow 报告现在能不能联系承运商。halfOpenProbe 为 true 表示这一次是半开后的那一个探测，
// 调用方必须在结局出来时记成功、失败或中性；如果探测的调用没能记上（例如 panic），
// 连续失败会被记一笔，避免 probeInFlight 永远为真。
//
// 关闭或未启用时返回 (true, false)。打开且未到时间返回 (false, false)。
// 打开且时间已到，转入半开并占住探测，返回 (true, true)。
// 半开且已有探测在途，返回 (false, false)。
func (b *CircuitBreaker) Allow(now time.Time) (allowed bool, halfOpenProbe bool) {
	if b == nil || b.cfg.FailureThreshold <= 0 {
		return true, false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	switch b.state {
	case breakerOpen:
		if now.Sub(b.openedAt) < b.cfg.OpenDuration {
			return false, false
		}
		b.state = breakerHalfOpen
		b.probeInFlight = true
		return true, true
	case breakerHalfOpen:
		if b.probeInFlight {
			return false, false
		}
		b.probeInFlight = true
		return true, true
	default:
		return true, false
	}
}

// RecordSuccess 把连续失败清零，电路回到关闭。
func (b *CircuitBreaker) RecordSuccess() {
	if b == nil || b.cfg.FailureThreshold <= 0 {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.consecutive = 0
	b.probeInFlight = false
	b.state = breakerClosed
}

// RecordFailure 记一次故障。半开时立刻重新打开；关闭时连续失败加一，达到阈值就打开。
// 已经打开时不把打开时刻往后推，避免多出来的失败把恢复时间无限延后。
func (b *CircuitBreaker) RecordFailure(now time.Time) {
	if b == nil || b.cfg.FailureThreshold <= 0 {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.probeInFlight = false
	switch b.state {
	case breakerHalfOpen:
		b.state = breakerOpen
		b.openedAt = now
		b.consecutive = b.cfg.FailureThreshold
	case breakerOpen:
	default:
		b.consecutive++
		if b.consecutive >= b.cfg.FailureThreshold {
			b.state = breakerOpen
			b.openedAt = now
			b.consecutive = b.cfg.FailureThreshold
		}
	}
}

// RecordNeutral 用于承运商给出了不是故障的 HTTP 状态（4xx、3xx 等）：
// 不增加连续失败，也不把它清零，只释放在途探测。
func (b *CircuitBreaker) RecordNeutral() {
	if b == nil || b.cfg.FailureThreshold <= 0 {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.probeInFlight = false
}

// State 返回 "closed"、"open" 或 "half_open"。打开时长已经过去、探测还没发出时报告 half_open，
// 但不会因此占住探测；真正转入半开并发出探测的是 Allow。
func (b *CircuitBreaker) State(now time.Time) string {
	if b == nil || b.cfg.FailureThreshold <= 0 {
		return "closed"
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	switch b.state {
	case breakerOpen:
		if now.Sub(b.openedAt) >= b.cfg.OpenDuration {
			return "half_open"
		}
		return "open"
	case breakerHalfOpen:
		return "half_open"
	default:
		return "closed"
	}
}
