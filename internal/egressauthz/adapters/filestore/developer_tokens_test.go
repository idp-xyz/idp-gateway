package filestore

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"go.idp.xyz/idp-gateway/internal/egressauthz/ports"
)

// 认证头的样子：固定的词，一个空格，账号、令牌、随机数用分号隔开，随机数之后没有分号。
// 随机数是 32 个十六进制字符；对接文档允许的是字母、数字、短横线和下划线。
var developerHeader = regexp.MustCompile(`^Hc-OweDeveloper ([^; ]+);([^; ]+);([0-9a-f]{32})$`)

func developerTokensFile(entries ...[3]string) string {
	items := make([]string, 0, len(entries))
	for _, e := range entries {
		items = append(items, fmt.Sprintf(`%q:{"account":%q,"token":%q}`, e[0], e[1], e[2]))
	}
	return "{" + strings.Join(items, ",") + "}"
}

// replaceFile 照说明里要求的办法换文件：写临时文件，再改名盖上去。
func replaceFile(t *testing.T, path, content string, mode os.FileMode) {
	t.Helper()
	next := path + ".next"
	if err := os.WriteFile(next, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(next, mode); err != nil { // WriteFile 的权限受 umask 影响
		t.Fatal(err)
	}
	if err := os.Rename(next, path); err != nil {
		t.Fatal(err)
	}
}

// parts 取一次凭证，返回头里的账号、令牌和随机数；头的样子不对就算失败。
func parts(t *testing.T, store *DeveloperTokens, bindingRef, accountID string) (account, token, nonce string) {
	t.Helper()
	credential, err := store.AuthorizationHeader(context.Background(), bindingRef, accountID)
	if err != nil {
		t.Fatalf("%s/%s: %v", bindingRef, accountID, err)
	}
	match := developerHeader.FindStringSubmatch(credential.Reveal())
	if match == nil {
		t.Fatalf("%s/%s: 认证头的样子不对（%d 个字符）", bindingRef, accountID, len(credential.Reveal()))
	}
	return match[1], match[2], match[3]
}

func TestDeveloperTokens(t *testing.T) {
	path := writeFile(t, developerTokensFile(
		[3]string{"carrier-test/account-blue", "ACCT-1", "tok_abc-123"},
		[3]string{"carrier-test/account-green", "ACCT-2", "tok_def-456"}), 0o600)
	store, err := LoadDeveloperTokens(path, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if store.Len() != 2 {
		t.Fatal(store.Len())
	}

	// 每次要凭证，随机数都是新的。
	nonces := map[string]bool{}
	for range 500 {
		account, token, nonce := parts(t, store, "carrier-test", "account-blue")
		if account != "ACCT-1" || token != "tok_abc-123" {
			t.Fatal("蓝账户拿到的不是它自己的账号和令牌")
		}
		if nonces[nonce] {
			t.Fatalf("随机数 %s 出现了两次", nonce)
		}
		nonces[nonce] = true
	}
	if account, token, _ := parts(t, store, "carrier-test", "account-green"); account != "ACCT-2" || token != "tok_def-456" {
		t.Fatal("绿账户拿到的不是它自己的账号和令牌")
	}

	for _, miss := range [][2]string{{"carrier-test", "account-red"}, {"other-binding", "account-blue"}, {"", ""},
		{"carrier-test/account-blue", ""}} {
		if _, err := store.AuthorizationHeader(context.Background(), miss[0], miss[1]); !errors.Is(err, ports.ErrCredentialNotHeld) {
			t.Errorf("%v: err = %v", miss, err)
		}
	}

	// 拿到的是 ports.Secret：不显式取，哪种写法都只得到占位符。
	credential, err := store.AuthorizationHeader(context.Background(), "carrier-test", "account-blue")
	if err != nil {
		t.Fatal(err)
	}
	if printed := fmt.Sprintf("%v %+v %s", credential, credential, credential); strings.Contains(printed, "tok_abc") || strings.Contains(printed, "ACCT-1") {
		t.Errorf("凭证被打印出来了：%s", printed)
	}

	// 一份没有任何条目的文件读得进来，只是谁的凭证都没有。
	empty, err := LoadDeveloperTokens(writeFile(t, `{}`, 0o600), nil, nil)
	if err != nil || empty.Len() != 0 {
		t.Fatalf("空对象：%v", err)
	}
}

func TestDeveloperTokensFileMustBePrivateAndWellFormed(t *testing.T) {
	good := developerTokensFile([3]string{"b/a", "ACCT", "token"})
	for _, mode := range []os.FileMode{0o640, 0o604, 0o644, 0o660} {
		if _, err := LoadDeveloperTokens(writeFile(t, good, mode), nil, nil); err == nil {
			t.Errorf("权限 %04o 的文件被接受了", mode)
		}
	}
	for _, mode := range []os.FileMode{0o600, 0o400} {
		if _, err := LoadDeveloperTokens(writeFile(t, good, mode), nil, nil); err != nil {
			t.Errorf("权限 %04o: %v", mode, err)
		}
	}

	const secret, account = "super-secret-token", "ACCT-NOT-TO-BE-SHOWN"
	entry := func(account, token string) string { return developerTokensFile([3]string{"b/a", account, token}) }
	for name, content := range map[string]string{
		"不是 JSON": secret + ` not json`,
		"空文件":     ``,
		"顶层是数组":   `[{"account":"` + account + `","token":"` + secret + `"}]`,
		"值是字符串（Bearer 文件的写法）": `{"b/a":"` + secret + `"}`,
		"值是 null":     `{"b/a":null}`,
		"没有令牌":        `{"b/a":{"account":"` + account + `"}}`,
		"没有账号":        `{"b/a":{"token":"` + secret + `"}}`,
		"令牌不是字符串":     `{"b/a":{"account":"` + account + `","token":7}}`,
		"空令牌":         entry(account, ""),
		"空账号":         entry("", secret),
		"令牌里有空格":      entry(account, secret+" x"),
		"令牌里有分号":      entry(account, secret+";x"),
		"令牌里有换行":      entry(account, secret+"\r\nX-Injected: 1"),
		"令牌里有非 ASCII": entry(account, secret+"é"),
		"账号里有分号":      entry(account+";x", secret),
		"账号里有空格":      entry(account+" x", secret),
		"有不认识的字段":     `{"b/a":{"account":"` + account + `","token":"` + secret + `","nonce":"fixed"}}`,
		"空句柄":         developerTokensFile([3]string{"", account, secret}),
		"同一个句柄写了两次":   developerTokensFile([3]string{"b/a", account, secret}, [3]string{"b/a", account, secret + "2"}),
		"文件后面还有内容":    entry(account, secret) + ` {"b/c":{"account":"x","token":"y"}}`,
		"对象没有写完":      `{"b/a":{"account":"` + account + `","token":"` + secret + `"}`,
	} {
		_, err := LoadDeveloperTokens(writeFile(t, content, 0o600), nil, nil)
		if err == nil {
			t.Errorf("%s: 被接受了", name)
			continue
		}
		if strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), account) {
			t.Errorf("%s: 错误信息带出了文件内容：%v", name, err)
		}
	}
	if _, err := LoadDeveloperTokens(filepath.Join(t.TempDir(), "missing.json"), nil, nil); err == nil {
		t.Error("不存在的文件被接受了")
	}

	// 一个句柄只能在一个凭证来源里。
	taken := func(handle string) bool { return handle == "b/a" }
	if _, err := LoadDeveloperTokens(writeFile(t, good, 0o600), taken, nil); err == nil || !strings.Contains(err.Error(), "one source only") {
		t.Errorf("被别的来源占着的句柄：err = %v", err)
	}
	if _, err := LoadDeveloperTokens(writeFile(t, developerTokensFile([3]string{"b/other", "ACCT", "token"}), 0o600), taken, nil); err != nil {
		t.Errorf("没有被占着的句柄：%v", err)
	}
}

func TestDeveloperTokensAreReadAgainWhenTheFileIsReplaced(t *testing.T) {
	var logs bytes.Buffer
	said := func(message string) int { return strings.Count(logs.String(), `"msg":"`+message) }
	const loaded, notLoaded, gone = "developer tokens file loaded again", "developer tokens file did not load", "developer tokens file cannot be seen"
	taken := func(handle string) bool { return handle == "b/held-elsewhere" }

	path := writeFile(t, developerTokensFile([3]string{"b/a", "ACCT", "tok-one"}), 0o600)
	store, err := LoadDeveloperTokens(path, taken, slog.New(slog.NewJSONHandler(&logs, nil)))
	if err != nil {
		t.Fatal(err)
	}
	token := func() string {
		t.Helper()
		_, token, _ := parts(t, store, "b", "a")
		return token
	}
	held := func(accountID string) bool {
		_, err := store.AuthorizationHeader(context.Background(), "b", accountID)
		return err == nil
	}
	if token() != "tok-one" || said(loaded) != 0 {
		t.Fatalf("启动时读到的不是第一份，或者没换文件就重读了：%s", logs.String())
	}

	// 换上新文件：下一次要凭证用的就是新令牌，新加的账户也有了。
	replaceFile(t, path, developerTokensFile([3]string{"b/a", "ACCT", "tok-two"}, [3]string{"b/c", "ACCT-C", "tok-c"}), 0o600)
	if token() != "tok-two" || !held("c") || store.Len() != 2 {
		t.Fatal("换上新文件之后，用的不是新的")
	}
	if token() != "tok-two" || said(loaded) != 1 {
		t.Fatalf("文件没有再变，却又读了一遍：%s", logs.String())
	}

	// 新文件读不成、别人可读、或者带着被别的来源占着的句柄：继续用上一份。同一份坏文件只记一次。
	const secret = "tok-that-must-not-be-logged"
	for name, bad := range map[string]struct {
		content string
		mode    os.FileMode
		says    string
	}{
		"令牌里有空格":    {developerTokensFile([3]string{"b/a", "ACCT", secret + " x"}), 0o600, "cannot go into a header"},
		"不是 JSON":   {secret + " not json", 0o600, "not a JSON object"},
		"别人可读":      {developerTokensFile([3]string{"b/a", "ACCT", secret}), 0o644, "readable by others"},
		"句柄被别的来源占着": {developerTokensFile([3]string{"b/a", "ACCT", secret}, [3]string{"b/held-elsewhere", "ACCT", secret}), 0o600, "one source only"},
	} {
		before := said(notLoaded)
		replaceFile(t, path, bad.content, bad.mode)
		for range 3 {
			if token() != "tok-two" || !held("c") {
				t.Fatalf("%s: 坏文件换上来之后，没有继续用上一份", name)
			}
		}
		if said(notLoaded) != before+1 || !strings.Contains(logs.String(), bad.says) {
			t.Fatalf("%s: 应当正好记一次，并说出原因 %q：%s", name, bad.says, logs.String())
		}
	}

	// 好文件又来了：用新的；被去掉的账户不再有凭证。
	replaceFile(t, path, developerTokensFile([3]string{"b/a", "ACCT", "tok-three"}), 0o600)
	if token() != "tok-three" || held("c") || store.Len() != 1 {
		t.Fatal("坏文件之后换上好文件，用的不是新的")
	}

	// 文件不见了：继续用上一份，只记一次。它回来之后用新的。
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		if token() != "tok-three" {
			t.Fatal("文件不见之后，没有继续用上一份")
		}
	}
	if said(gone) != 1 {
		t.Fatalf("文件不见应当正好记一次：%s", logs.String())
	}
	replaceFile(t, path, developerTokensFile([3]string{"b/a", "ACCT", "tok-four"}), 0o600)
	if token() != "tok-four" {
		t.Fatal("文件回来之后，用的不是新的")
	}

	// 就地改写：修改时间变了就看得出来。
	rewrite := func(tokenValue string, modified time.Time) {
		t.Helper()
		if err := os.WriteFile(path, []byte(developerTokensFile([3]string{"b/a", "ACCT", tokenValue})), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(path, modified, modified); err != nil {
			t.Fatal(err)
		}
	}
	later := time.Now().Add(time.Hour).Truncate(time.Second)
	rewrite("tok-five", later)
	if token() != "tok-five" {
		t.Fatal("就地改写、修改时间变了，用的不是新的")
	}
	// 要知道的：就地改写成一样长的内容，修改时间又没有变，看不出来。所以换文件要用改名。
	rewrite("tok-six!", later)
	if token() != "tok-five" {
		t.Fatal("这条测试记的是一处已知的看不出来；现在看出来了，把说明和这条测试一起改掉")
	}

	// 账号和令牌没有进日志。
	if all := logs.String(); strings.Contains(all, "tok-") || strings.Contains(all, "ACCT") {
		t.Errorf("日志里有账号或令牌：%s", all)
	}
}

// 一边换文件，一边有很多请求在要凭证：每一次拿到的都是某一份完整文件里的账号和令牌，随机数互不相同。
func TestDeveloperTokensWhileTheFileKeepsBeingReplaced(t *testing.T) {
	file := func(n int) string {
		return developerTokensFile([3]string{"b/a", fmt.Sprintf("ACCT-%d", n), fmt.Sprintf("tok-%d", n)})
	}
	path := writeFile(t, file(0), 0o600)
	store, err := LoadDeveloperTokens(path, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	const workers, replacements = 8, 40
	var wg sync.WaitGroup
	var mu sync.Mutex
	requests, nonces, files, problems := 0, map[string]bool{}, map[string]bool{}, []string{}
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
				credential, err := store.AuthorizationHeader(context.Background(), "b", "a")
				var problem string
				match := developerHeader.FindStringSubmatch(credential.Reveal())
				switch {
				case err != nil:
					problem = err.Error()
				case match == nil:
					problem = "认证头的样子不对"
				case strings.TrimPrefix(match[1], "ACCT-") != strings.TrimPrefix(match[2], "tok-"):
					problem = "账号和令牌出自两份不同的文件"
				}
				mu.Lock()
				requests++
				if problem == "" && nonces[match[3]] {
					problem = "随机数重复"
				}
				if problem != "" {
					problems = append(problems, problem)
				} else {
					nonces[match[3]], files[match[2]] = true, true
				}
				mu.Unlock()
			}
		}()
	}
	// 每换一次，等到有请求用上了这一份，再换下一份：这样换文件确实是夹在请求中间的。
	for n := 1; n <= replacements; n++ {
		replaceFile(t, path, file(n), 0o600)
		used, deadline := false, time.Now().Add(5*time.Second)
		for !used && time.Now().Before(deadline) {
			time.Sleep(50 * time.Microsecond)
			mu.Lock()
			used = files[fmt.Sprintf("tok-%d", n)]
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
	if len(nonces) != requests || requests < replacements {
		t.Fatalf("随机数 %d 个，请求 %d 个", len(nonces), requests)
	}
	if _, token, _ := parts(t, store, "b", "a"); token != fmt.Sprintf("tok-%d", replacements) {
		t.Fatalf("最后用的是 %s，不是最后换上去的那一份", token)
	}
}
