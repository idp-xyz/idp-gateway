package filestore

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go.idp.xyz/idp-gateway/internal/egressauthz/domain"
	"go.idp.xyz/idp-gateway/internal/egressauthz/ports"
)

const repoRoot = "../../../.."

// 仓库里的两份登记表都要读得进来，并且按它们写的那样判定。
func TestLoadPolicyFilesInTheRepository(t *testing.T) {
	blue := &domain.Principal{ServiceID: "parcel-service", TenantID: "tenant-blue", Environment: "TEST"}
	request := domain.Request{ProviderID: "mockcarrier", OperationID: "tracking.get", Environment: "TEST", Method: "GET",
		Path: "/providers/mockcarrier/v1/tracking/123", AccountID: "account-blue"}

	for file, operations := range map[string]int{
		"contracts/gateway/policies/egress-policy.example.json": 1,
		"tests/acceptance/blackbox/policy.poc.json":             4,
	} {
		policy, err := LoadPolicy(filepath.Join(repoRoot, file))
		if err != nil {
			t.Fatalf("%s: %v", file, err)
		}
		if policy.Version == "" || len(policy.Operations) != operations {
			t.Fatalf("%s: 版本 %q，%d 行", file, policy.Version, len(policy.Operations))
		}
		if got := policy.Evaluate(blue, request); !got.Allowed || got.CredentialBindingRef != "gatekeeper:mockcarrier-test" {
			t.Fatalf("%s: 登记过的调用被拒：%+v", file, got)
		}
		other := request
		other.AccountID = "account-green"
		if got := policy.Evaluate(blue, other); got.Allowed || got.Reason != domain.ReasonAccountNotGranted {
			t.Fatalf("%s: 蓝租户用绿账户：%+v", file, got)
		}
	}
}

func TestParsePolicyRejectsWhatItCannotFullyRead(t *testing.T) {
	row := `{"provider_id":"p","operation_id":"o","environment":"TEST","method":"GET","path_prefix":"/a",` +
		`"credential_binding_ref":"b","allowed_tenants":["t"],"allowed_service_ids":["s"],"accounts_by_tenant":{"t":["a"]}}`
	bad := map[string]string{
		"不是 JSON":   `not json`,
		"没有版本":      `{"registered_operations":[]}`,
		"空版本":       `{"version":"","registered_operations":[]}`,
		"版本不是字符串":   `{"version":7,"registered_operations":[]}`,
		"默认放行":      `{"version":"1","default_decision":"ALLOW","registered_operations":[]}`,
		"登记表不是数组":   `{"version":"1","registered_operations":{}}`,
		"前缀是数字":     `{"version":"1","registered_operations":[` + strings.Replace(row, `"/a"`, `7`, 1) + `]}`,
		"前缀是数组":     `{"version":"1","registered_operations":[` + strings.Replace(row, `"/a"`, `["/a"]`, 1) + `]}`,
		"租户列表是字符串":  `{"version":"1","registered_operations":[` + strings.Replace(row, `["t"]`, `"t"`, 1) + `]}`,
		"账户表的值不是数组": `{"version":"1","registered_operations":[` + strings.Replace(row, `{"t":["a"]}`, `{"t":"a"}`, 1) + `]}`,
		"文档后面还有内容":  `{"version":"1","registered_operations":[]} {"version":"2"}`,
		"顶层是数组":     `[]`,
	}
	for name, doc := range bad {
		if policy, err := parsePolicy([]byte(doc)); err == nil {
			t.Errorf("%s: 被接受了：%+v", name, policy)
		}
	}

	policy, err := parsePolicy([]byte(`{"version":"1","default_decision":"DENY","notes":"ignored","registered_operations":[` + row + `]}`))
	if err != nil || len(policy.Operations) != 1 || policy.Operations[0].PathPrefix != "/a" {
		t.Fatalf("%+v, %v", policy, err)
	}
}

// 前缀缺失或为 null 的行读得进来，但不授权任何请求。
func TestRowWithoutPathPrefixAuthorisesNothing(t *testing.T) {
	for name, prefix := range map[string]string{"缺失": ``, "null": `"path_prefix":null,`, "空串": `"path_prefix":"",`, "根": `"path_prefix":"/",`} {
		doc := `{"version":"1","registered_operations":[{"provider_id":"p","operation_id":"o","environment":"TEST","method":"GET",` + prefix +
			`"credential_binding_ref":"b","allowed_tenants":["t"],"allowed_service_ids":["s"],"accounts_by_tenant":{"t":["a"]}}]}`
		policy, err := parsePolicy([]byte(doc))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		principal := &domain.Principal{ServiceID: "s", TenantID: "t", Environment: "TEST"}
		for _, path := range []string{"/a", "/anything/else"} {
			got := policy.Evaluate(principal, domain.Request{ProviderID: "p", OperationID: "o", Environment: "TEST", Method: "GET", Path: path, AccountID: "a"})
			if got.Allowed {
				t.Fatalf("%s: %q 被放行", name, path)
			}
		}
	}
}

func writeFile(t *testing.T, content string, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "credentials.json")
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil { // WriteFile 的权限受 umask 影响
		t.Fatal(err)
	}
	return path
}

func TestCredentials(t *testing.T) {
	path := writeFile(t, `{"gatekeeper:mockcarrier-test/account-blue":"blue-token-123"}`, 0o600)
	store, err := LoadCredentials(path)
	if err != nil {
		t.Fatal(err)
	}
	if store.Len() != 1 {
		t.Fatal(store.Len())
	}
	credential, err := store.AuthorizationHeader(context.Background(), "gatekeeper:mockcarrier-test", "account-blue")
	if err != nil || credential.Reveal() != "Bearer blue-token-123" {
		t.Fatalf("%v", err)
	}
	for _, miss := range [][2]string{{"gatekeeper:mockcarrier-test", "account-green"}, {"other-binding", "account-blue"}, {"", ""},
		{"gatekeeper:mockcarrier-test/account-blue", ""}} {
		if _, err := store.AuthorizationHeader(context.Background(), miss[0], miss[1]); !errors.Is(err, ports.ErrCredentialNotHeld) {
			t.Errorf("%v: err = %v", miss, err)
		}
	}
}

func TestCredentialsFileMustBePrivateAndWellFormed(t *testing.T) {
	const good = `{"b/a":"token"}`
	for _, mode := range []os.FileMode{0o640, 0o604, 0o644, 0o660} {
		if _, err := LoadCredentials(writeFile(t, good, mode)); err == nil {
			t.Errorf("权限 %04o 的凭证文件被接受了", mode)
		}
	}
	for _, mode := range []os.FileMode{0o600, 0o400} {
		if _, err := LoadCredentials(writeFile(t, good, mode)); err != nil {
			t.Errorf("权限 %04o: %v", mode, err)
		}
	}
	const secret = "super-secret-token"
	for name, content := range map[string]string{
		"不是 JSON":     secret + ` not json`,
		"值不是字符串":      `{"b/a":{"token":"` + secret + `"}}`,
		"空令牌":         `{"b/a":""}`,
		"令牌里有空格":      `{"b/a":"` + secret + ` x"}`,
		"令牌里有换行":      `{"b/a":"` + secret + `\r\nX-Injected: 1"}`,
		"令牌里有非 ASCII": `{"b/a":"` + secret + `é"}`,
		"空句柄":         `{"":"` + secret + `"}`,
		"顶层是数组":       `["` + secret + `"]`,
	} {
		_, err := LoadCredentials(writeFile(t, content, 0o600))
		if err == nil {
			t.Errorf("%s: 被接受了", name)
			continue
		}
		if strings.Contains(err.Error(), secret) {
			t.Errorf("%s: 错误信息带出了文件内容：%v", name, err)
		}
	}
	if _, err := LoadCredentials(filepath.Join(t.TempDir(), "missing.json")); err == nil {
		t.Error("不存在的文件被接受了")
	}
}
