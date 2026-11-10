// Package domain 是出站请求的判定规则：一个已被网关验证过身份的调用方，能否以某个
// 账户调用某个已登记的 Provider 操作。
//
// 规则是白名单：只有与登记表中某一行完全吻合的请求才放行，其余一律拒绝。本包只用
// 标准库，不做 I/O；策略从哪里来、凭证从哪里取、撤销状态在哪里，都在包外。
package domain

import (
	"slices"
	"strings"
)

// Principal 是网关转述的调用方身份，取自它已经验签的 Token。
type Principal struct {
	ServiceID string
	TenantID  string
	// Environment 是 Token 为哪个环境签发的。
	Environment string
}

// Request 是要判定的那一次出站调用。
type Request struct {
	ProviderID  string
	OperationID string
	// Environment 是网关池所在的环境，由路由常量给出。
	Environment string
	Method      string
	// Path 是调用方请求的路径，不含查询串，按收到的原样，不做规范化。
	Path string
	// AccountID 是调用方申请使用的账户。它是申请，不是事实。
	AccountID string
}

// Operation 是登记表的一行：一个 Provider 操作，以及谁可以用哪些账户调用它。
type Operation struct {
	RouteID              string
	ProviderID           string
	OperationID          string
	Environment          string
	Method               string
	PathPrefix           string
	CredentialBindingRef string
	AllowedTenants       []string
	AllowedServiceIDs    []string
	AccountsByTenant     map[string][]string
}

// Policy 是一个版本的登记表。
type Policy struct {
	Version    string
	Operations []Operation
}

// Reason 是判定结果的原因码，会出现在给网关的响应和日志里。
type Reason string

const (
	ReasonActiveAccountGrant       Reason = "ACTIVE_ACCOUNT_GRANT"
	ReasonUnauthenticated          Reason = "UNAUTHENTICATED"
	ReasonEnvironmentMismatch      Reason = "ENVIRONMENT_MISMATCH"
	ReasonPathNotCanonical         Reason = "PATH_NOT_CANONICAL"
	ReasonMethodNotAllowed         Reason = "METHOD_NOT_ALLOWED"
	ReasonTenantNotGranted         Reason = "TENANT_NOT_GRANTED"
	ReasonServiceNotGranted        Reason = "SERVICE_NOT_GRANTED"
	ReasonAccountNotGranted        Reason = "ACCOUNT_NOT_GRANTED"
	ReasonCredentialBindingMissing Reason = "CREDENTIAL_BINDING_MISSING"
	ReasonNoMatchingOperation      Reason = "NO_MATCHING_ALLOWLIST_OPERATION"
)

// Decision 是一次判定的结果。CredentialBindingRef 只在放行时有值。
type Decision struct {
	Allowed              bool
	Reason               Reason
	CredentialBindingRef string
}

func deny(reason Reason) Decision { return Decision{Reason: reason} }

var allowedMethods = []string{"GET", "POST", "PUT", "PATCH", "DELETE"}

// Evaluate 判定一次出站调用。principal 为 nil 表示网关没有转述出完整的调用方身份。
//
// 检查顺序决定了调用方看到的原因码，改动顺序等于改动对外行为。
func (p Policy) Evaluate(principal *Principal, req Request) Decision {
	if principal == nil || principal.ServiceID == "" || principal.TenantID == "" || principal.Environment == "" {
		return deny(ReasonUnauthenticated)
	}
	if req.Environment != principal.Environment {
		return deny(ReasonEnvironmentMismatch)
	}
	if !IsCanonicalPath(req.Path) {
		return deny(ReasonPathNotCanonical)
	}
	if !slices.Contains(allowedMethods, req.Method) {
		return deny(ReasonMethodNotAllowed)
	}
	for _, op := range p.Operations {
		if !op.matches(req) {
			continue
		}
		if !slices.Contains(op.AllowedTenants, principal.TenantID) {
			return deny(ReasonTenantNotGranted)
		}
		if !slices.Contains(op.AllowedServiceIDs, principal.ServiceID) {
			return deny(ReasonServiceNotGranted)
		}
		// 空账户永远不算获授：登记表里即使误写了空串，也不能让"没说用哪个账户"通过。
		if req.AccountID == "" || !slices.Contains(op.AccountsByTenant[principal.TenantID], req.AccountID) {
			return deny(ReasonAccountNotGranted)
		}
		if op.CredentialBindingRef == "" {
			return deny(ReasonCredentialBindingMissing)
		}
		return Decision{Allowed: true, Reason: ReasonActiveAccountGrant, CredentialBindingRef: op.CredentialBindingRef}
	}
	return deny(ReasonNoMatchingOperation)
}

// SoleAccount 用在调用方没有指明账户的时候：该租户在这个操作上恰好只有一个获授账户，
// 才把它当作申请的账户。选出来的账户仍要经过 Evaluate，这里不构成授权。
func (p Policy) SoleAccount(tenantID, providerID, operationID, environment string) (string, bool) {
	var found []string
	for _, op := range p.Operations {
		if !op.registered() || op.ProviderID != providerID || op.OperationID != operationID || op.Environment != environment {
			continue
		}
		for _, account := range op.AccountsByTenant[tenantID] {
			if account != "" && !slices.Contains(found, account) {
				found = append(found, account)
			}
		}
	}
	if len(found) != 1 {
		return "", false
	}
	return found[0], true
}

// registered 判断这一行是否写全了。没有写出规范路径前缀或标识不全的行不授权任何请求：
// 缺省值不能被解释成"全部"。
func (op Operation) registered() bool {
	return op.ProviderID != "" && op.OperationID != "" && op.Environment != "" && op.Method != "" &&
		IsCanonicalPath(op.PathPrefix)
}

func (op Operation) matches(req Request) bool {
	if !op.registered() {
		return false
	}
	if req.ProviderID != op.ProviderID || req.OperationID != op.OperationID ||
		req.Environment != op.Environment || req.Method != op.Method {
		return false
	}
	// 按段比较前缀：/a/b 在 /a 之下，/ab 不在。
	return req.Path == op.PathPrefix || strings.HasPrefix(req.Path, op.PathPrefix+"/")
}
