// Package filestore 从本地 JSON 文件读登记表和凭证，并把撤销表存在一个文件里。
//
// 这是第一版的占位：登记表将来由控制面下发，凭证将来来自 Secret Manager 或 Provider 的
// 令牌端点。登记表文件被换掉之后会重读（policy.go）：新文件读不成时继续用上一份，绝不换成空表。
// Bearer 凭证文件在启动时读一次，之后不再重读；开发者令牌文件被换掉之后会重读
// （developer_tokens.go）；撤销文件在启动时读一次，之后只由本进程写（revocations.go）。
package filestore

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"

	"go.idp.xyz/idp-gateway/internal/egressauthz/domain"
	"go.idp.xyz/idp-gateway/internal/egressauthz/ports"
)

type policyDocument struct {
	Version         *string        `json:"version"`
	DefaultDecision *string        `json:"default_decision"`
	Operations      []operationRow `json:"registered_operations"`
}

type operationRow struct {
	RouteID              string              `json:"route_id"`
	ProviderID           string              `json:"provider_id"`
	OperationID          string              `json:"operation_id"`
	Environment          string              `json:"environment"`
	Method               string              `json:"method"`
	PathPrefix           string              `json:"path_prefix"`
	CredentialBindingRef string              `json:"credential_binding_ref"`
	AllowedTenants       []string            `json:"allowed_tenants"`
	AllowedServiceIDs    []string            `json:"allowed_service_ids"`
	AccountsByTenant     map[string][]string `json:"accounts_by_tenant"`
}

// LoadPolicy 读登记表文件，格式见 contracts/gateway/policies/egress-policy.example.json。
//
// 文件里与判定无关的字段被忽略。类型不对的字段让整份文件读取失败：宁可起不来，
// 也不带着一份只读懂了一半的登记表运行。
func LoadPolicy(path string) (domain.Policy, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return domain.Policy{}, fmt.Errorf("read policy: %w", err)
	}
	policy, err := parsePolicy(raw)
	if err != nil {
		return domain.Policy{}, fmt.Errorf("policy %s: %w", path, err)
	}
	return policy, nil
}

func parsePolicy(raw []byte) (domain.Policy, error) {
	var doc policyDocument
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if err := decoder.Decode(&doc); err != nil {
		return domain.Policy{}, err
	}
	if decoder.More() {
		return domain.Policy{}, errors.New("unexpected data after the policy document")
	}
	if doc.Version == nil || *doc.Version == "" {
		return domain.Policy{}, errors.New("version is required")
	}
	// 本服务只会默认拒绝。一份声明了别的默认值的登记表是为另一种执行方式写的。
	if doc.DefaultDecision != nil && *doc.DefaultDecision != "DENY" {
		return domain.Policy{}, fmt.Errorf("default_decision %q is not supported: only DENY", *doc.DefaultDecision)
	}
	policy := domain.Policy{Version: *doc.Version}
	for _, row := range doc.Operations {
		policy.Operations = append(policy.Operations, domain.Operation(row))
	}
	return policy, nil
}

// maxPolicyBytes 是登记表文件的上限。它在请求路径上被重读，不能把一份巨大的文件整个吞进来。
const maxPolicyBytes = 4 << 20

// PolicyFile 是从文件读入的登记表，实现 ports.PolicySource。
//
// 文件里没有秘密，0644 和 0600 都可以。启动时读不成就返回错误，拒绝启动。之后文件被换掉则整份重读，
// 新文件读不成、或文件不见，都继续用上一份，并记一条错误；同一份坏文件只记一次。错误日志只写路径、
// 错误和仍在用的版本，不写登记表正文。换文件要写临时文件再改名。
type PolicyFile struct {
	path   string
	logger *slog.Logger

	mu     sync.Mutex
	seen   os.FileInfo
	policy domain.Policy
	count  int
}

var _ ports.PolicySource = (*PolicyFile)(nil)

// LoadPolicyFile 读登记表文件。格式与 LoadPolicy 相同。logger 为 nil 时丢弃日志。
// 缺失、超过 4 MiB、非法 JSON、尾随内容、缺少 version、default_decision 不是 DENY，都返回错误。
func LoadPolicyFile(path string, logger *slog.Logger) (*PolicyFile, error) {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	loaded := &PolicyFile{path: path, logger: logger}
	policy, info, count, err := loaded.read()
	if err != nil {
		return nil, err
	}
	loaded.policy, loaded.seen, loaded.count = policy, info, count
	return loaded, nil
}

// Current 实现 ports.PolicySource。文件没变就返回上一份；换了就重读。重读失败时仍返回上一份。
func (p *PolicyFile) Current() domain.Policy { return p.current() }

// Len 返回最近一次读成的操作条数，供启动日志使用。
func (p *PolicyFile) Len() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.count
}

// current 返回此刻该用的那份登记表。文件没变就用上一份。坏文件和消失的文件都不换成空表。
func (p *PolicyFile) current() domain.Policy {
	p.mu.Lock()
	defer p.mu.Unlock()

	info, err := os.Stat(p.path)
	if err != nil {
		if p.seen != nil {
			p.seen = nil
			p.logger.Error("policy file cannot be seen; still using the last one that loaded",
				"path", p.path, "error", err.Error(), "version", p.policy.Version)
		}
		return p.policy
	}
	if p.seen != nil && sameFile(p.seen, info) {
		return p.policy
	}
	policy, readInfo, count, err := p.read()
	if err != nil {
		// 记下看到的是哪一份：它再被换掉之前不重读，也不再记。
		p.seen = info
		p.logger.Error("policy file did not load; still using the last one that loaded",
			"path", p.path, "error", policyErrorForLog(err), "version", p.policy.Version)
		return p.policy
	}
	p.policy, p.seen, p.count = policy, readInfo, count
	p.logger.Info("policy file loaded again", "path", p.path, "version", policy.Version, "operations", count)
	return p.policy
}

// read 读一遍文件。返回的 FileInfo 属于实际读到的那个文件。返回的错误在日志里还要再过一遍
// policyErrorForLog：解码错误可能带出文件内容的片段。
func (p *PolicyFile) read() (domain.Policy, os.FileInfo, int, error) {
	file, err := os.Open(p.path)
	if err != nil {
		return domain.Policy{}, nil, 0, fmt.Errorf("read policy: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return domain.Policy{}, nil, 0, fmt.Errorf("read policy: %w", err)
	}
	raw, err := io.ReadAll(io.LimitReader(file, maxPolicyBytes+1))
	if err != nil {
		return domain.Policy{}, nil, 0, fmt.Errorf("read policy: %w", err)
	}
	if int64(len(raw)) > maxPolicyBytes {
		return domain.Policy{}, nil, 0, fmt.Errorf("policy %s: file is larger than %d bytes", p.path, maxPolicyBytes)
	}
	policy, err := parsePolicy(raw)
	if err != nil {
		return domain.Policy{}, nil, 0, fmt.Errorf("policy %s: %w", p.path, err)
	}
	return policy, info, len(policy.Operations), nil
}

// policyErrorForLog 是写进重载失败日志的原因。JSON 解码错误和 default_decision 的原文会带出
// 文件内容，这里换成固定的一句话。
func policyErrorForLog(err error) string {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "version is required"):
		return "version is required"
	case strings.Contains(msg, "unexpected data after the policy document"):
		return "unexpected data after the policy document"
	case strings.Contains(msg, "only DENY"):
		return "default_decision is not supported: only DENY"
	case strings.Contains(msg, "file is larger than"):
		if i := strings.LastIndex(msg, "file is larger than"); i >= 0 {
			return msg[i:]
		}
		return "file is larger than the limit"
	}
	var syntax *json.SyntaxError
	var typeErr *json.UnmarshalTypeError
	var pathErr *os.PathError
	switch {
	case errors.As(err, &syntax), errors.As(err, &typeErr):
		return "invalid JSON"
	case errors.As(err, &pathErr):
		return msg
	default:
		return "policy document was not accepted"
	}
}
