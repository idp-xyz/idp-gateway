package sfopenapi

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"go.idp.xyz/idp-gateway/internal/egressauthz/ports"
)

// 各种取不到。每一种：这次请求拿不到凭证；错误信息有固定的样子、类别对；错误信息和日志里没有应用密钥、
// 查询串、令牌端点的地址，也没有应答正文里的任何东西（应答里故意放了应用密钥和标记，看会不会被带出来）；
// 端点恢复之后下一个请求照常。
func TestWhenTheEndpointAnswersBadlyTheRequestIsRefused(t *testing.T) {
	// 应答里的这些内容，哪一句出现在错误或日志里都是错的。
	message := `"apiErrorMsg":"` + bodyMarker + ` appSecret=` + blueSecret + `"`
	data := func(token, expire string) string {
		return `"apiResultData":{"expireIn":` + expire + `,"accessToken":` + token + `}`
	}
	goodData := data(`"leaked-`+bodyMarker+`"`, `7200`)
	envelope := func(parts ...string) string { return `{` + strings.Join(parts, ",") + `}` }
	big := `{"apiResultCode":0,"apiResultData":{"expireIn":7200,"accessToken":"leaked-x"},"pad":"` + strings.Repeat("a", maxBody) + `"}`

	cases := []struct {
		name   string
		status int
		body   string
		result string
	}{
		// 状态。
		{"HTTP 500", 500, envelope(`"apiResultCode":500`, message), "status 500"},
		{"HTTP 401", 401, envelope(`"apiResultCode":401`, message), "status 401"},
		{"HTTP 404", 404, `<html>` + bodyMarker + `</html>`, "status 404"},
		{"HTTP 201 带着完好的应答", 201, envelope(`"apiResultCode":0`, goodData), "status 201"},
		{"HTTP 204", 204, ``, "status 204"},
		{"HTTP 202", 202, envelope(`"apiResultCode":0`, goodData), "status 202"},
		// 正文。
		{"正文不是 JSON", 200, `<html>` + bodyMarker + ` ` + blueSecret + `</html>`, "bad_answer"},
		{"正文为空", 200, ``, "bad_answer"},
		{"正文是 JSON 数组", 200, `[` + envelope(`"apiResultCode":0`, goodData) + `]`, "bad_answer"},
		{"正文是 JSON 字符串", 200, `"` + bodyMarker + `"`, "bad_answer"},
		{"正文是 null", 200, `null`, "bad_answer"},
		{"对象后面还有内容", 200, envelope(`"apiResultCode":0`, goodData) + ` ` + bodyMarker, "bad_answer"},
		{"对象后面还有一个对象", 200, envelope(`"apiResultCode":0`, goodData) + `{}`, "bad_answer"},
		{"对象没有写完", 200, strings.TrimSuffix(envelope(`"apiResultCode":0`, goodData), `}`), "bad_answer"},
		{"正文超过 64KiB", 200, big, "bad_answer"},
		// 信封里的 apiResultCode。
		{"apiResultCode 500，带着说明", 200, envelope(`"apiResultCode":500`, message, `"apiResultData":null`), "code 500"},
		{"apiResultCode 1，带着完好的数据", 200, envelope(`"apiResultCode":1`, message, goodData), "code 1"},
		{"apiResultCode 为负", 200, envelope(`"apiResultCode":-7`, message), "code -7"},
		{"apiResultCode 很大但能放进 int64", 200, envelope(`"apiResultCode":9007199254740993`, message), "code 9007199254740993"},
		{"没有 apiResultCode", 200, envelope(message, goodData), "bad_answer"},
		{"apiResultCode 是字符串 \"0\"", 200, envelope(`"apiResultCode":"0"`, goodData), "bad_answer"},
		{"apiResultCode 是 0.0", 200, envelope(`"apiResultCode":0.0`, goodData), "bad_answer"},
		{"apiResultCode 是 0e0", 200, envelope(`"apiResultCode":0e0`, goodData), "bad_answer"},
		{"apiResultCode 是 null", 200, envelope(`"apiResultCode":null`, goodData), "bad_answer"},
		{"apiResultCode 是 false", 200, envelope(`"apiResultCode":false`, goodData), "bad_answer"},
		{"apiResultCode 超出 int64", 200, envelope(`"apiResultCode":99999999999999999999`, goodData), "bad_answer"},
		{"成员名大小写不对", 200, envelope(`"APIRESULTCODE":0`, goodData), "bad_answer"},
		// apiResultData。
		{"没有 apiResultData", 200, envelope(`"apiResultCode":0`, message), "bad_answer"},
		{"apiResultData 是 null", 200, envelope(`"apiResultCode":0`, `"apiResultData":null`, message), "bad_answer"},
		{"apiResultData 是字符串（密文的样子）", 200, envelope(`"apiResultCode":0`, `"apiResultData":"`+bodyMarker+`"`), "bad_answer"},
		{"apiResultData 是数组", 200, envelope(`"apiResultCode":0`, `"apiResultData":[{"expireIn":7200,"accessToken":"x"}]`), "bad_answer"},
		{"apiResultData 是数字", 200, envelope(`"apiResultCode":0`, `"apiResultData":7200`), "bad_answer"},
		{"apiResultData 里没有 accessToken", 200, envelope(`"apiResultCode":0`, `"apiResultData":{"expireIn":7200,"x":"`+bodyMarker+`"}`), "bad_answer"},
		{"apiResultData 里没有 expireIn", 200, envelope(`"apiResultCode":0`, `"apiResultData":{"accessToken":"leaked-`+bodyMarker+`"}`), "bad_answer"},
		{"apiResultData 是空对象", 200, envelope(`"apiResultCode":0`, `"apiResultData":{}`), "bad_answer"},
		// accessToken。
		{"accessToken 为空", 200, envelope(`"apiResultCode":0`, data(`""`, `7200`)), "bad_answer"},
		{"accessToken 是 null", 200, envelope(`"apiResultCode":0`, data(`null`, `7200`)), "bad_answer"},
		{"accessToken 是数字", 200, envelope(`"apiResultCode":0`, data(`7`, `7200`)), "bad_answer"},
		{"accessToken 里有分号", 200, envelope(`"apiResultCode":0`, data(`"leaked-`+bodyMarker+`;x"`, `7200`)), "bad_answer"},
		{"accessToken 只有分号", 200, envelope(`"apiResultCode":0`, data(`";"`, `7200`)), "bad_answer"},
		{"accessToken 里的分号写成转义", 200, envelope(`"apiResultCode":0`, data(`"leaked-a\u003bb"`, `7200`)), "bad_answer"},
		{"accessToken 里有空格", 200, envelope(`"apiResultCode":0`, data(`"leaked-a b"`, `7200`)), "bad_answer"},
		{"accessToken 里有换行", 200, envelope(`"apiResultCode":0`, data(`"leaked-a\r\nX: 1"`, `7200`)), "bad_answer"},
		{"accessToken 里有制表符", 200, envelope(`"apiResultCode":0`, data(`"leaked-a\tb"`, `7200`)), "bad_answer"},
		{"accessToken 里有非 ASCII", 200, envelope(`"apiResultCode":0`, data(`"leaked-é"`, `7200`)), "bad_answer"},
		{"accessToken 里有 DEL", 200, envelope(`"apiResultCode":0`, data(`"leaked-\u007f"`, `7200`)), "bad_answer"},
		// expireIn。
		{"expireIn 为 0", 200, envelope(`"apiResultCode":0`, data(`"leaked-x"`, `0`)), "bad_answer"},
		{"expireIn 为负", 200, envelope(`"apiResultCode":0`, data(`"leaked-x"`, `-5`)), "bad_answer"},
		{"expireIn 是字符串", 200, envelope(`"apiResultCode":0`, data(`"leaked-x"`, `"7200"`)), "bad_answer"},
		{"expireIn 是小数", 200, envelope(`"apiResultCode":0`, data(`"leaked-x"`, `1.5`)), "bad_answer"},
		{"expireIn 是指数写法", 200, envelope(`"apiResultCode":0`, data(`"leaked-x"`, `7.2e3`)), "bad_answer"},
		{"expireIn 是 7200.0", 200, envelope(`"apiResultCode":0`, data(`"leaked-x"`, `7200.0`)), "bad_answer"},
		{"expireIn 是 null", 200, envelope(`"apiResultCode":0`, data(`"leaked-x"`, `null`)), "bad_answer"},
		{"expireIn 是 true", 200, envelope(`"apiResultCode":0`, data(`"leaked-x"`, `true`)), "bad_answer"},
		{"expireIn 超出 int64", 200, envelope(`"apiResultCode":0`, data(`"leaked-x"`, `99999999999999999999`)), "bad_answer"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ep := newEndpoint(t)
			f := newFixture(t, two(ep.tokenURL()))
			ep.set(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				io.WriteString(w, tc.body)
			})
			got, err := f.get(blueHandle)
			if err == nil || got != "" || errors.Is(err, ports.ErrCredentialNotHeld) {
				t.Fatalf("%q %v", got, err)
			}
			if err.Error() != failed(blueHandle, tc.result) {
				t.Errorf("错误信息 %q，期望 %q", err, failed(blueHandle, tc.result))
			}
			noSecrets(t, err.Error()+f.logs.String(), tc.name, ep.URL, ep.Listener.Addr().String())
			if !strings.Contains(f.logs.String(), `"result":"`+tc.result+`"`) || !strings.Contains(f.logs.String(), `"msg":"sf openapi token not fetched"`) ||
				strings.Contains(f.logs.String(), `"expires_in"`) {
				t.Errorf("日志里没有类别 %q：%s", tc.result, f.logs.String())
			}
			if f.lines("sf openapi token") != 1 {
				t.Errorf("该只有一行日志：%s", f.logs.String())
			}
			// 一次失败不留下东西：端点恢复，下一个请求照常。
			ep.set(nil)
			if got, err := f.get(blueHandle); err != nil || !releasedShape.MatchString(got) {
				t.Fatalf("恢复之后：%q %v", got, err)
			}
		})
	}
}

// 正文的上限是 64KiB：正好这么多的完好应答读得进来，多一个字节就算答错。
func TestTheBodyLimitIsSixtyFourKiB(t *testing.T) {
	pad := func(total int) string {
		base := answer("7200", "limit-token")
		filler := `,"pad":""`
		body := base[:len(base)-1] + filler + `}`
		return base[:len(base)-1] + `,"pad":"` + strings.Repeat("a", total-len(body)) + `"}`
	}
	for size, accepted := range map[int]bool{maxBody - 1: true, maxBody: true, maxBody + 1: false, 2 * maxBody: false} {
		ep := newEndpoint(t)
		f := newFixture(t, two(ep.tokenURL()))
		body := pad(size)
		if len(body) != size {
			t.Fatalf("样板的长度 %d，要 %d", len(body), size)
		}
		ep.set(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, body) })
		got, err := f.get(blueHandle)
		if (err == nil) != accepted {
			t.Errorf("%d 字节：%q %v，期望接受=%v", size, got, err, accepted)
		}
		if err != nil && err.Error() != failed(blueHandle, "bad_answer") {
			t.Errorf("%d 字节：%v", size, err)
		}
	}
}

// 信封和 apiResultData 里别的成员不碍事。
func TestUnknownMembersAreTolerated(t *testing.T) {
	ep := newEndpoint(t)
	f := newFixture(t, two(ep.tokenURL()))
	ep.set(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"apiResultCode":0,"apiErrorMsg":"ignored","extra":[1,2,{"a":null}],"apiResultData":{"x":1,"expireIn":7200,"accessToken":"auth_token-ok","y":{"z":[]}},"apiTimestamp":1763611200000}`)
	})
	got, err := f.get(blueHandle)
	if err != nil || got != "Sf-OpenApi "+blueAppKey+";auth_token-ok;"+blueAES {
		t.Fatalf("%q %v", got, err)
	}
	// apiErrorMsg 是承运商写的文字：成功时也不记。
	if strings.Contains(f.logs.String(), "ignored") {
		t.Error("apiErrorMsg 进了日志")
	}
}

func TestATokenOf55VisibleCharactersIsAccepted(t *testing.T) {
	token := "auth_" + strings.Repeat("0123456789", 5) // 55 个字符，样子同承运商沙箱发的
	if len(token) != 55 {
		t.Fatal(len(token))
	}
	ep := newEndpoint(t)
	f := newFixture(t, two(ep.tokenURL()))
	ep.set(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, answer("7200", token)) })
	if got, err := f.get(blueHandle); err != nil || got != "Sf-OpenApi "+blueAppKey+";"+token+";"+blueAES {
		t.Fatalf("%q %v", got, err)
	}
}

func TestTimeoutUnreachableAndRedirects(t *testing.T) {
	t.Run("超时", func(t *testing.T) {
		ep := newEndpoint(t)
		release := make(chan struct{})
		t.Cleanup(func() { close(release) })
		ep.set(func(w http.ResponseWriter, r *http.Request) { <-release })
		f := newFixture(t, two(ep.tokenURL()), withTimeout(100*time.Millisecond))
		begun := time.Now()
		_, err := f.get(blueHandle)
		if err == nil || time.Since(begun) > 2*time.Second || !strings.Contains(f.logs.String(), `"result":"timeout"`) {
			t.Fatalf("%v %v %s", err, time.Since(begun), f.logs.String())
		}
		if err.Error() != failed(blueHandle, "timeout") {
			t.Errorf("%v", err)
		}
		noSecrets(t, err.Error()+f.logs.String(), "超时", ep.URL)
	})
	t.Run("应答头来了正文迟迟不来", func(t *testing.T) {
		ep := newEndpoint(t)
		release := make(chan struct{})
		t.Cleanup(func() { close(release) })
		ep.set(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(200)
			w.(http.Flusher).Flush()
			<-release
		})
		f := newFixture(t, two(ep.tokenURL()), withTimeout(100*time.Millisecond))
		begun := time.Now()
		_, err := f.get(blueHandle)
		if err == nil || time.Since(begun) > 2*time.Second {
			t.Fatalf("%v %v", err, time.Since(begun))
		}
		noSecrets(t, err.Error()+f.logs.String(), "正文迟迟不来", ep.URL)
	})
	t.Run("连不上", func(t *testing.T) {
		closed := httptest.NewServer(http.NotFoundHandler())
		address := closed.URL
		closed.Close()
		f := newFixture(t, two(address+tokenPath))
		_, err := f.get(blueHandle)
		if err == nil || err.Error() != failed(blueHandle, "unreachable") || !strings.Contains(f.logs.String(), `"result":"unreachable"`) {
			t.Fatalf("%v %s", err, f.logs.String())
		}
		// net/http 的错误里有完整的请求地址，地址里有应用密钥：一个字也不能带出来。
		noSecrets(t, err.Error()+f.logs.String(), "连不上", address, strings.TrimPrefix(address, "http://"), "connection refused", "dial tcp", "Get ")
	})
	t.Run("不跟随重定向", func(t *testing.T) {
		var elsewhere atomic.Int32
		other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			elsewhere.Add(1)
			fmt.Fprint(w, answer("7200", "stolen"))
		}))
		defer other.Close()
		for _, status := range []int{http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther, http.StatusTemporaryRedirect, http.StatusPermanentRedirect} {
			ep := newEndpoint(t)
			ep.set(func(w http.ResponseWriter, r *http.Request) {
				// 重定向的目标带着同样的查询串：跟过去的话应用密钥就送到了别处。
				http.Redirect(w, r, other.URL+"/stolen?"+r.URL.RawQuery, status)
			})
			f := newFixture(t, two(ep.tokenURL()))
			_, err := f.get(blueHandle)
			category := fmt.Sprintf("status %d", status)
			if err == nil || err.Error() != failed(blueHandle, category) || elsewhere.Load() != 0 || !strings.Contains(f.logs.String(), `"result":"`+category+`"`) {
				t.Fatalf("%d：%v %d %s", status, err, elsewhere.Load(), f.logs.String())
			}
			noSecrets(t, err.Error()+f.logs.String(), category, other.URL, "/stolen")
		}
	})
}
