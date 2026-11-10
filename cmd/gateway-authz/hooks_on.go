//go:build acceptance

package main

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"crypto/tls"

	"go.idp.xyz/idp-gateway/internal/egressauthz/adapters/httpapi"
	"go.idp.xyz/idp-gateway/internal/platform/workloadtls"
)

// 这个文件只存在于带 acceptance 标签的构建里。它给黑盒验收套件
// （tests/acceptance/blackbox）提供观察和注入故障的手段：看服务收到了什么、让它答 500、
// 让它变慢、让它放行却不给凭证、撤销一个账户。产品构建里没有这些代码。

const buildFlavor = "acceptance"

const (
	envAdminSecret = "GATEWAY_AUTHZ_ACCEPTANCE_ADMIN_SECRET"
	envOperator    = "GATEWAY_AUTHZ_ACCEPTANCE_OPERATOR_IDENTITY"
	envSlowSeconds = "GATEWAY_AUTHZ_ACCEPTANCE_SLOW_SECONDS"
	adminHeader    = "X-Poc-Admin"
)

var modes = []string{"normal", "error500", "slow", "allow_without_credential"}

type entry struct {
	Seq          int         `json:"seq"`
	ReceivedAt   float64     `json:"received_at"`
	Method       string      `json:"method"`
	RawTarget    string      `json:"raw_target"`
	Proto        string      `json:"proto"`
	PeerIdentity string      `json:"peer_identity"`
	TLSVersion   string      `json:"tls_version"`
	Headers      [][2]string `json:"headers"`
	BodyLen      int64       `json:"body_len"`
}

type controls struct {
	next     http.Handler
	seams    seams
	secret   string
	operator string
	slow     time.Duration

	mu      sync.Mutex
	mode    string
	log     []entry
	refused []string
}

// install 装上验收控制。控制接口要求操作者的工作负载证书和一个只在本次运行里有效的
// 口令；缺任何一样配置都拒绝启动，监听地址不是回环地址也拒绝启动。
func install(handler http.Handler, serverLog io.Writer, s seams) (http.Handler, io.Writer, error) {
	c := &controls{next: handler, seams: s, mode: "normal",
		secret: os.Getenv(envAdminSecret), operator: os.Getenv(envOperator)}
	if len(c.secret) < 16 || c.operator == "" {
		return nil, nil, fmt.Errorf("acceptance build: %s (16 characters or more) and %s must be set", envAdminSecret, envOperator)
	}
	if c.operator == s.callers.Gateway || c.operator == s.callers.Broker {
		return nil, nil, errors.New("acceptance build: the operator identity must not be a caller identity")
	}
	seconds, err := strconv.ParseFloat(os.Getenv(envSlowSeconds), 64)
	if err != nil || seconds <= 0 || seconds > 60 {
		return nil, nil, fmt.Errorf("acceptance build: %s must be a number of seconds between 0 and 60", envSlowSeconds)
	}
	c.slow = time.Duration(seconds * float64(time.Second))
	host, _, err := net.SplitHostPort(s.listen)
	if ip := net.ParseIP(host); err != nil || ip == nil || !ip.IsLoopback() {
		return nil, nil, fmt.Errorf("acceptance build: refusing to listen on %q; this build only serves a loopback address", s.listen)
	}
	s.logger.Warn("ACCEPTANCE BUILD: test controls are enabled (/admin/*, fault injection). Not for deployment.")
	return c, &handshakeWatcher{next: serverLog, controls: c}, nil
}

func (c *controls) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	identity := workloadtls.PeerIdentity(r.TLS)
	if strings.HasPrefix(path, "/admin/") {
		if identity != c.operator || subtle.ConstantTimeCompare([]byte(r.Header.Get(adminHeader)), []byte(c.secret)) != 1 {
			reply(w, http.StatusNotFound, map[string]string{"error": "not_found"})
			return
		}
		c.admin(w, r)
		return
	}
	if path != httpapi.PathExtAuthz && path != httpapi.PathDecision {
		c.next.ServeHTTP(w, r)
		return
	}

	// 先记下收到了什么，再看是谁：身份不对的调用也要留在记录里。
	mode := c.record(r, identity)
	// 故障只注入给本来会被受理的调用方；身份不对的照常由服务自己拒绝。
	if !c.seams.callers.MayCall(path, identity) {
		c.next.ServeHTTP(w, r)
		return
	}
	switch mode {
	case "error500":
		reply(w, http.StatusInternalServerError, map[string]string{"error": "injected_pdp_failure"})
		return
	case "slow":
		select {
		case <-time.After(c.slow):
		case <-r.Context().Done():
			// 调用方已经走了。不能不写就返回：那会变成一个空的 200。
			reply(w, http.StatusServiceUnavailable, map[string]string{"error": "caller_gone"})
			return
		}
	case "allow_without_credential":
		if path == httpapi.PathExtAuthz {
			w = &withoutCredential{ResponseWriter: w}
		}
	}
	c.next.ServeHTTP(w, r)
}

func (c *controls) record(r *http.Request, identity string) string {
	names := make([]string, 0, len(r.Header))
	for name := range r.Header {
		names = append(names, name)
	}
	sort.Strings(names)
	headers := [][2]string{{"Host", r.Host}} // net/http 把 Host 从头部表里拿走了
	for _, name := range names {
		for _, value := range r.Header[name] {
			headers = append(headers, [2]string{name, value})
		}
	}
	e := entry{
		ReceivedAt: float64(time.Now().UnixNano()) / 1e9, Method: r.Method, RawTarget: r.RequestURI, Proto: r.Proto,
		PeerIdentity: identity, TLSVersion: tlsVersionName(r.TLS), Headers: headers, BodyLen: max(r.ContentLength, 0),
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	e.Seq = len(c.log) + 1
	c.log = append(c.log, e)
	return c.mode
}

// tlsVersionName 用 OpenSSL 的写法（TLSv1.3），与套件此前记录的格式一致。
func tlsVersionName(state *tls.ConnectionState) string {
	if state == nil {
		return ""
	}
	switch state.Version {
	case tls.VersionTLS12:
		return "TLSv1.2"
	case tls.VersionTLS13:
		return "TLSv1.3"
	}
	return tls.VersionName(state.Version)
}

func (c *controls) admin(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	switch r.URL.Path {
	case "/admin/log":
		c.mu.Lock()
		// 空切片要编码成 []，不能是 null。
		state := struct {
			Log     []entry  `json:"log"`
			Refused []string `json:"tls_handshakes_refused"`
		}{append([]entry{}, c.log...), append([]string{}, c.refused...)}
		c.mu.Unlock()
		reply(w, http.StatusOK, state)
	case "/admin/reset":
		c.mu.Lock()
		c.log, c.refused, c.mode = nil, nil, "normal"
		c.mu.Unlock()
		c.seams.revocations.RestoreAll()
		reply(w, http.StatusOK, map[string]bool{"reset": true})
	case "/admin/mode":
		mode := query.Get("value")
		if !slices.Contains(modes, mode) {
			reply(w, http.StatusBadRequest, map[string]string{"error": "unknown_mode"})
			return
		}
		c.mu.Lock()
		c.mode = mode
		c.mu.Unlock()
		reply(w, http.StatusOK, map[string]string{"mode": mode})
	case "/admin/revoke", "/admin/restore":
		account := query.Get("account")
		if account == "" {
			reply(w, http.StatusBadRequest, map[string]string{"error": "account_required"})
			return
		}
		if strings.HasSuffix(r.URL.Path, "revoke") {
			c.seams.revocations.Revoke(account)
		} else {
			c.seams.revocations.Restore(account)
		}
		revoked := c.seams.revocations.Revoked()
		sort.Strings(revoked)
		epoch, _ := c.seams.revocations.Epoch(r.Context())
		reply(w, http.StatusOK, map[string]any{"revoked": revoked, "revocation_epoch": epoch})
	default:
		reply(w, http.StatusNotFound, map[string]string{"error": "unknown_admin_operation"})
	}
}

// withoutCredential 模拟"判定放行，但凭证没能交出来"：放行响应照常发出，只是没有凭证头。
type withoutCredential struct {
	http.ResponseWriter
	wrote bool
}

func (w *withoutCredential) WriteHeader(status int) {
	if !w.wrote && status == http.StatusOK {
		w.Header().Del("Authorization")
		w.Header().Del("X-Idp-Decision-Id")
	}
	w.wrote = true
	w.ResponseWriter.WriteHeader(status)
}

func (w *withoutCredential) Write(p []byte) (int, error) {
	if !w.wrote {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(p)
}

// handshakeWatcher 数 net/http 报告的失败 TLS 握手。握手没完成的连接到不了任何处理器，
// 服务端日志是唯一看得见它们的地方。
type handshakeWatcher struct {
	next     io.Writer
	controls *controls
}

func (h *handshakeWatcher) Write(p []byte) (int, error) {
	if _, rest, ok := strings.Cut(string(p), "TLS handshake error from "); ok {
		if _, reason, ok := strings.Cut(rest, ": "); ok {
			rest = reason
		}
		h.controls.mu.Lock()
		h.controls.refused = append(h.controls.refused, strings.TrimSpace(rest))
		h.controls.mu.Unlock()
	}
	return h.next.Write(p)
}

func reply(w http.ResponseWriter, status int, body any) {
	encoded, err := json.Marshal(body)
	if err != nil {
		http.Error(w, `{"error":"internal"}`, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Length", strconv.Itoa(len(encoded)))
	w.WriteHeader(status)
	_, _ = w.Write(encoded)
}
