// Package filestore 从本地 JSON 文件读登记表和凭证。
//
// 这是第一版的占位：登记表将来由控制面下发，凭证将来来自 Secret Manager 或 Provider 的
// 令牌端点。文件在启动时读一次，之后不再重读。
package filestore

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"go.idp.xyz/idp-gateway/internal/egressauthz/domain"
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
