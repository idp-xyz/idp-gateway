package filestore

import (
	"bytes"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const policyBodyMarker = "POLICY-BODY-MARKER"

func policyDocumentJSON(version, operation string) string {
	return fmt.Sprintf(`{
	  "version": %q,
	  "default_decision": "DENY",
	  "registered_operations": [{
	    "route_id": "r",
	    "provider_id": "mockcarrier",
	    "operation_id": %q,
	    "environment": "TEST",
	    "method": "GET",
	    "path_prefix": "/providers/mockcarrier/v1/tracking",
	    "credential_binding_ref": "binding",
	    "allowed_tenants": ["tenant-blue"],
	    "allowed_service_ids": ["parcel-service"],
	    "accounts_by_tenant": {"tenant-blue": [%q]}
	  }]
	}`, version, operation, "account-"+operation)
}

func loadPolicyFile(t *testing.T, content string, logger *slog.Logger) (*PolicyFile, string) {
	t.Helper()
	path := writeFile(t, content, 0o644)
	store, err := LoadPolicyFile(path, logger)
	if err != nil {
		t.Fatal(err)
	}
	return store, path
}

func requirePolicy(t *testing.T, store *PolicyFile, version, operation string) {
	t.Helper()
	policy := store.Current()
	if policy.Version != version || len(policy.Operations) != 1 || policy.Operations[0].OperationID != operation {
		t.Fatalf("登记表是 version=%q ops=%+v，期望 %s / %s", policy.Version, policy.Operations, version, operation)
	}
}

func TestLoadPolicyFileRejectsUnusableFiles(t *testing.T) {
	store, err := LoadPolicyFile(writeFile(t, policyDocumentJSON("v1", "tracking.get"), 0o600), nil)
	if err != nil || store.Len() != 1 || store.Current().Version != "v1" {
		t.Fatalf("正常文件：%v，%d 条", err, storeLen(store))
	}
	for name, content := range map[string]string{
		"不是 JSON": `not json`,
		"空文件":     ``,
		"没有版本":    `{"default_decision":"DENY","registered_operations":[]}`,
		"空版本":     `{"version":"","registered_operations":[]}`,
		"默认放行":    `{"version":"v","default_decision":"ALLOW"}`,
		"后面还有内容":  `{"version":"v","registered_operations":[]}{"version":"w"}`,
		"顶层是数组":   `[]`,
		"登记表不是数组": `{"version":"v","registered_operations":{}}`,
	} {
		if _, err := LoadPolicyFile(writeFile(t, content, 0o644), nil); err == nil {
			t.Errorf("%s: 被接受了", name)
		}
	}
	if _, err := LoadPolicyFile(filepath.Join(t.TempDir(), "missing.json"), nil); err == nil {
		t.Fatal("不存在的文件被接受了")
	}
	big := filepath.Join(t.TempDir(), "big.json")
	if err := os.WriteFile(big, bytes.Repeat([]byte("x"), maxPolicyBytes+1), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPolicyFile(big, nil); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Fatalf("超限：%v", err)
	}
}

func storeLen(store *PolicyFile) int {
	if store == nil {
		return -1
	}
	return store.Len()
}

func TestPolicyFileReloadsAndKeepsTheLastGoodFile(t *testing.T) {
	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, nil))
	store, path := loadPolicyFile(t, policyDocumentJSON("v1", "tracking.get"), logger)
	for range 3 {
		requirePolicy(t, store, "v1", "tracking.get")
	}
	if logs.Len() != 0 || store.Len() != 1 {
		t.Fatalf("没变的文件不该重读：%s", logs.String())
	}

	// 原子改名换上一份新的：版本和操作都变。
	replaceFile(t, path, policyDocumentJSON("v2", "labels.print"), 0o644)
	requirePolicy(t, store, "v2", "labels.print")
	if store.Len() != 1 || strings.Count(logs.String(), "loaded again") != 1 || !strings.Contains(logs.String(), `"version":"v2"`) {
		t.Fatalf("新文件没有生效：len=%d %s", store.Len(), logs.String())
	}
	requirePolicy(t, store, "v2", "labels.print")
	if strings.Count(logs.String(), "loaded again") != 1 {
		t.Fatalf("同一份新文件又读了一遍：%s", logs.String())
	}

	// 每一种坏文件都留着上一份，同一份只记一次，日志里没有登记表正文。
	before := strings.Count(logs.String(), "did not load")
	cases := []string{
		policyBodyMarker + " not json",
		`{"default_decision":"DENY","registered_operations":[{"operation_id":"` + policyBodyMarker + `"}]}`,
		`{"version":"v-bad","default_decision":"` + policyBodyMarker + `","registered_operations":[]}`,
		policyBodyMarker + strings.Repeat("x", maxPolicyBytes),
	}
	for i, bad := range cases {
		replaceFile(t, path, bad, 0o644)
		for range 3 {
			requirePolicy(t, store, "v2", "labels.print")
		}
		got := strings.Count(logs.String(), "did not load")
		if got != before+i+1 {
			t.Fatalf("第 %d 份坏文件应当正好多记一次，现在 %d 次：%s", i, got, logs.String())
		}
		if store.Len() != 1 {
			t.Fatalf("坏文件把条数改了：%d", store.Len())
		}
	}
	if strings.Contains(logs.String(), policyBodyMarker) {
		t.Fatalf("错误日志带出了登记表正文：%s", logs.String())
	}

	// 文件不见：仍用上一份，只记一次。回来之后用新的。
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		requirePolicy(t, store, "v2", "labels.print")
	}
	if strings.Count(logs.String(), "cannot be seen") != 1 || strings.Contains(logs.String(), policyBodyMarker) {
		t.Fatalf("文件不见：%s", logs.String())
	}
	replaceFile(t, path, policyDocumentJSON("v3", "quotes.get"), 0o644)
	requirePolicy(t, store, "v3", "quotes.get")
	if store.Len() != 1 {
		t.Fatalf("文件回来之后 %d 条", store.Len())
	}

	// nil logger 的重载失败也不能 panic，并且不能换成空表。
	quiet, quietPath := loadPolicyFile(t, policyDocumentJSON("v9", "tracking.get"), nil)
	replaceFile(t, quietPath, policyBodyMarker+" {", 0o644)
	requirePolicy(t, quiet, "v9", "tracking.get")
}

// 一边换文件，一边有很多请求在读：每一次拿到的都是某一份完整登记表。
func TestPolicyFileWhileTheFileKeepsBeingReplaced(t *testing.T) {
	path := writeFile(t, policyDocumentJSON("v-0", "op-0"), 0o644)
	store, err := LoadPolicyFile(path, nil)
	if err != nil {
		t.Fatal(err)
	}

	const workers, replacements = 8, 40
	var wg sync.WaitGroup
	var mu sync.Mutex
	seen, problems := map[string]bool{}, []string{}
	done := make(chan struct{})
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-done:
					return
				default:
				}
				policy := store.Current()
				var problem string
				switch {
				case len(policy.Operations) != 1:
					problem = fmt.Sprintf("操作条数 %d", len(policy.Operations))
				default:
					n := strings.TrimPrefix(policy.Version, "v-")
					op := policy.Operations[0]
					account := ""
					if accounts := op.AccountsByTenant["tenant-blue"]; len(accounts) == 1 {
						account = accounts[0]
					}
					if op.OperationID != "op-"+n || account != "account-op-"+n {
						problem = fmt.Sprintf("撕开的登记表 version=%s operation=%s account=%s", policy.Version, op.OperationID, account)
					}
				}
				mu.Lock()
				if problem != "" {
					problems = append(problems, problem)
				} else {
					seen[policy.Version] = true
				}
				mu.Unlock()
			}
		}()
	}
	for n := 1; n <= replacements; n++ {
		replaceFile(t, path, policyDocumentJSON(fmt.Sprintf("v-%d", n), fmt.Sprintf("op-%d", n)), 0o644)
		used, deadline := false, time.Now().Add(5*time.Second)
		want := fmt.Sprintf("v-%d", n)
		for !used && time.Now().Before(deadline) {
			time.Sleep(50 * time.Microsecond)
			mu.Lock()
			used = seen[want]
			mu.Unlock()
		}
		if !used {
			close(done)
			wg.Wait()
			t.Fatalf("第 %d 份换上去 5 秒了，还没有请求用上它", n)
		}
	}
	close(done)
	wg.Wait()
	if len(problems) > 0 {
		t.Fatalf("%d 次不对，头一次：%s", len(problems), problems[0])
	}
	requirePolicy(t, store, fmt.Sprintf("v-%d", replacements), fmt.Sprintf("op-%d", replacements))
}
