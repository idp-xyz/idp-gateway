package otlp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const scopeName = "go.idp.xyz/idp-gateway"

// Config 是导出器的配置。零值用默认：一批 64 条，每秒刷一次，单次超时 2 秒，缓冲 1024 条。
// Client 为空时自己建一个：回环地址不走代理，也不跟随重定向。
type Config struct {
	Endpoint       string
	ServiceName    string
	ServiceVersion string
	BatchSize      int
	FlushInterval  time.Duration
	Timeout        time.Duration
	BufferSize     int
	Client         *http.Client
}

// Span 是一条要送出的 span。Kind 与 StatusCode 用本包的常量。
// Attributes 在 Record 时就按键名丢掉秘密，字符串截断并去掉换行。
type Span struct {
	TraceID       string
	SpanID        string
	ParentSpanID  string
	Name          string
	Kind          int
	StartTime     time.Time
	EndTime       time.Time
	StatusCode    int
	StatusMessage string
	Attributes    map[string]any
}

// Exporter 在后台把 span 按批 POST 到 OTLP/HTTP JSON。Record 不等待网络。
type Exporter struct {
	cfg      Config
	client   *http.Client
	ch       chan Span
	mu       sync.Mutex
	stopped  bool
	closeCtx context.Context
	base     context.Context
	cancel   context.CancelFunc
	done     chan struct{}

	exported atomic.Uint64
	dropped  atomic.Uint64
	failed   atomic.Uint64
}

// ValidateEndpoint 要求 http 或 https、有主机、没有用户信息、查询串、片段和换行。
// 错误信息不回显地址，避免把写错的用户信息带进日志。
func ValidateEndpoint(raw string) error {
	if raw == "" || strings.ContainsAny(raw, " \t\r\n") {
		return errors.New("otlp: endpoint is empty or contains whitespace")
	}
	parsed, err := url.Parse(raw)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Hostname() == "" ||
		parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return errors.New("otlp: endpoint must be http or https with a host and no userinfo, query, or fragment")
	}
	return nil
}

// NewExporter 校验地址并启动后台发送。校验失败时没有 goroutine 留下。
func NewExporter(cfg Config) (*Exporter, error) {
	if err := ValidateEndpoint(cfg.Endpoint); err != nil {
		return nil, err
	}
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = 64
	}
	if cfg.FlushInterval <= 0 {
		cfg.FlushInterval = time.Second
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 2 * time.Second
	}
	if cfg.BufferSize <= 0 {
		cfg.BufferSize = 1024
	}
	client := cfg.Client
	if client == nil {
		base, ok := http.DefaultTransport.(*http.Transport)
		if !ok {
			base = &http.Transport{}
		}
		transport := base.Clone()
		transport.Proxy = proxyExceptLoopback
		transport.DisableKeepAlives = true
		client = &http.Client{
			Timeout:       cfg.Timeout,
			Transport:     transport,
			CheckRedirect: refuseRedirect,
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	e := &Exporter{
		cfg:    cfg,
		client: client,
		ch:     make(chan Span, cfg.BufferSize),
		base:   ctx,
		cancel: cancel,
		done:   make(chan struct{}),
	}
	go e.loop()
	return e, nil
}

func refuseRedirect(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

func proxyExceptLoopback(req *http.Request) (*url.URL, error) {
	host := ""
	if req != nil && req.URL != nil {
		host = req.URL.Hostname()
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return nil, nil
	}
	if strings.EqualFold(host, "localhost") {
		return nil, nil
	}
	return http.ProxyFromEnvironment(req)
}

// Record 把 span 放进缓冲。缓冲满或导出器已关闭时丢掉并增加 Dropped，绝不阻塞调用方，也不访问网络。
func (e *Exporter) Record(span Span) {
	if span.TraceID == "" || span.SpanID == "" {
		e.dropped.Add(1)
		return
	}
	span.Name = clip(span.Name)
	span.StatusMessage = clip(span.StatusMessage)
	span.Attributes = sanitizeAttributes(span.Attributes)
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.stopped {
		e.dropped.Add(1)
		return
	}
	select {
	case e.ch <- span:
	default:
		e.dropped.Add(1)
	}
}

// Dropped 是因为缓冲满或已关闭而没有送出的 span 数。
func (e *Exporter) Dropped() uint64 { return e.dropped.Load() }

// Stats 返回已确认送出、丢弃、以及发送失败的 span 数。
func (e *Exporter) Stats() (exported, dropped, failed uint64) {
	return e.exported.Load(), e.dropped.Load(), e.failed.Load()
}

// Close 不再接收新 span，并在 ctx 的期限内把缓冲里剩下的送出。
// 已经在发送的请求会在 ctx 取消时中止。再次调用只等待上一次结束。
func (e *Exporter) Close(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	e.mu.Lock()
	if !e.stopped {
		e.stopped = true
		e.closeCtx = ctx
		close(e.ch)
		go func() {
			select {
			case <-ctx.Done():
				e.cancel()
			case <-e.done:
			}
		}()
	}
	e.mu.Unlock()
	select {
	case <-e.done:
		return nil
	case <-ctx.Done():
		e.cancel()
		return ctx.Err()
	}
}

func (e *Exporter) loop() {
	defer close(e.done)
	ticker := time.NewTicker(e.cfg.FlushInterval)
	defer ticker.Stop()
	batch := make([]Span, 0, e.cfg.BatchSize)
	flush := func() {
		if len(batch) == 0 {
			return
		}
		spans := batch
		batch = make([]Span, 0, e.cfg.BatchSize)
		_ = e.export(spans)
	}
	for {
		select {
		case span, ok := <-e.ch:
			if !ok {
				flush()
				return
			}
			batch = append(batch, span)
			if len(batch) >= e.cfg.BatchSize {
				flush()
			}
		case <-ticker.C:
			flush()
		}
	}
}

func (e *Exporter) export(spans []Span) error {
	if len(spans) == 0 {
		return nil
	}
	body, err := e.encode(spans)
	if err != nil {
		e.failed.Add(uint64(len(spans)))
		return err
	}
	e.mu.Lock()
	parent := e.base
	if e.closeCtx != nil {
		parent = e.closeCtx
	}
	e.mu.Unlock()
	ctx, cancel := context.WithTimeout(parent, e.cfg.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.cfg.Endpoint, bytes.NewReader(body))
	if err != nil {
		e.failed.Add(uint64(len(spans)))
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := e.client.Do(req)
	if resp != nil {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}
	if err != nil || resp == nil || resp.StatusCode < 200 || resp.StatusCode >= 300 {
		e.failed.Add(uint64(len(spans)))
		if err == nil {
			err = errors.New("otlp: collector rejected the batch")
		}
		return err
	}
	e.exported.Add(uint64(len(spans)))
	return nil
}

func (e *Exporter) encode(spans []Span) ([]byte, error) {
	resourceAttrs := make([]otlpAttribute, 0, 2)
	if e.cfg.ServiceName != "" {
		resourceAttrs = append(resourceAttrs, stringAttribute("service.name", e.cfg.ServiceName))
	}
	if e.cfg.ServiceVersion != "" {
		resourceAttrs = append(resourceAttrs, stringAttribute("service.version", e.cfg.ServiceVersion))
	}
	encoded := make([]otlpSpan, len(spans))
	for i, span := range spans {
		encoded[i] = encodeSpan(span)
	}
	doc := otlpExport{
		ResourceSpans: []otlpResourceSpan{{
			Resource: otlpResource{Attributes: resourceAttrs},
			ScopeSpans: []otlpScopeSpan{{
				Scope: otlpScope{Name: scopeName},
				Spans: encoded,
			}},
		}},
	}
	return json.Marshal(doc)
}

type otlpExport struct {
	ResourceSpans []otlpResourceSpan `json:"resourceSpans"`
}

type otlpResourceSpan struct {
	Resource   otlpResource    `json:"resource"`
	ScopeSpans []otlpScopeSpan `json:"scopeSpans"`
}

type otlpResource struct {
	Attributes []otlpAttribute `json:"attributes,omitempty"`
}

type otlpScopeSpan struct {
	Scope otlpScope  `json:"scope"`
	Spans []otlpSpan `json:"spans"`
}

type otlpScope struct {
	Name string `json:"name"`
}

type otlpSpan struct {
	TraceID           string          `json:"traceId"`
	SpanID            string          `json:"spanId"`
	ParentSpanID      string          `json:"parentSpanId,omitempty"`
	Name              string          `json:"name"`
	Kind              int             `json:"kind"`
	StartTimeUnixNano string          `json:"startTimeUnixNano"`
	EndTimeUnixNano   string          `json:"endTimeUnixNano"`
	Attributes        []otlpAttribute `json:"attributes,omitempty"`
	Status            otlpStatus      `json:"status"`
}

type otlpStatus struct {
	Code    int    `json:"code"`
	Message string `json:"message,omitempty"`
}

type otlpAttribute struct {
	Key   string `json:"key"`
	Value any    `json:"value"`
}

func encodeSpan(span Span) otlpSpan {
	attrs := sanitizeAttributes(span.Attributes)
	return otlpSpan{
		TraceID:           span.TraceID,
		SpanID:            span.SpanID,
		ParentSpanID:      span.ParentSpanID,
		Name:              clip(span.Name),
		Kind:              span.Kind,
		StartTimeUnixNano: strconv.FormatInt(span.StartTime.UnixNano(), 10),
		EndTimeUnixNano:   strconv.FormatInt(span.EndTime.UnixNano(), 10),
		Attributes:        encodeAttributes(attrs),
		Status:            otlpStatus{Code: span.StatusCode, Message: clip(span.StatusMessage)},
	}
}

func encodeAttributes(attrs map[string]any) []otlpAttribute {
	if len(attrs) == 0 {
		return nil
	}
	out := make([]otlpAttribute, 0, len(attrs))
	for _, key := range sortedKeys(attrs) {
		value, ok := attributeValue(attrs[key])
		if !ok {
			continue
		}
		out = append(out, otlpAttribute{Key: key, Value: value})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func attributeValue(value any) (any, bool) {
	switch v := value.(type) {
	case string:
		return struct {
			StringValue string `json:"stringValue"`
		}{v}, true
	case bool:
		return struct {
			BoolValue bool `json:"boolValue"`
		}{v}, true
	case int64:
		return struct {
			IntValue string `json:"intValue"`
		}{strconv.FormatInt(v, 10)}, true
	default:
		return nil, false
	}
}

func stringAttribute(key, value string) otlpAttribute {
	return otlpAttribute{Key: key, Value: struct {
		StringValue string `json:"stringValue"`
	}{value}}
}
