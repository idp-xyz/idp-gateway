package telemetry

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"go.idp.xyz/idp-gateway/internal/gatewayconfig/application"
	"go.idp.xyz/idp-gateway/internal/gatewayconfig/domain"
)

var started = time.Date(2026, 11, 12, 0, 0, 0, 0, time.UTC)

func after(d time.Duration) time.Time { return started.Add(d) }

// three 是三个都在跑的容器；down 里列出的那几个（"holder"、"gateway"、"front"）没在跑。
func three(down ...string) domain.Members {
	up := func(n int) domain.Member {
		return domain.Member{Running: true, Started: started.Add(time.Duration(n) * time.Second), State: "running"}
	}
	members := domain.Members{Holder: up(-30), Gateway: up(-20), Front: up(-10)}
	for _, name := range down {
		dead := domain.Member{State: "exited (137)"}
		switch name {
		case "holder":
			members.Holder = dead
		case "gateway":
			members.Gateway = dead
		case "front":
			members.Front = dead
		}
	}
	return members
}

// looked 是看守看了一眼之后的 Tending：容器是 members 的样子，没有动手。
func looked(members domain.Members) application.Tending {
	condition, why := members.Condition()
	return application.Tending{Members: members, Condition: condition, Why: why}
}

func reconciled(outcome application.Outcome, replaced bool) *application.Result {
	return &application.Result{Outcome: outcome, Replaced: replaced}
}

// samples 把文本格式读成 名字{标签} -> 值。每个指标都得先有 HELP 和 TYPE 两行，名字不能重复。
func samples(t *testing.T, text string) map[string]string {
	t.Helper()
	found, typed := map[string]string{}, map[string]string{}
	var helped string
	for _, line := range strings.Split(strings.TrimSuffix(text, "\n"), "\n") {
		switch {
		case strings.HasPrefix(line, "# HELP "):
			helped = strings.Fields(line)[2]
			if len(strings.Fields(line)) < 4 {
				t.Fatalf("没有说明的 HELP：%q", line)
			}
		case strings.HasPrefix(line, "# TYPE "):
			fields := strings.Fields(line)
			if len(fields) != 4 || fields[2] != helped || (fields[3] != "gauge" && fields[3] != "counter") {
				t.Fatalf("TYPE 这一行不对，或者前面没有它的 HELP：%q", line)
			}
			if _, twice := typed[fields[2]]; twice {
				t.Fatalf("%s 出现了两次", fields[2])
			}
			typed[fields[2]] = fields[3]
		default:
			at := strings.LastIndex(line, " ")
			if at < 0 {
				t.Fatalf("读不懂的一行：%q", line)
			}
			series, value := line[:at], line[at+1:]
			name, _, _ := strings.Cut(series, "{")
			if _, ok := typed[name]; !ok {
				t.Fatalf("%s 前面没有 TYPE", series)
			}
			if _, twice := found[series]; twice {
				t.Fatalf("%s 出现了两次", series)
			}
			if strings.HasSuffix(name, "_total") != (typed[name] == "counter") {
				t.Fatalf("%s 是 %s：只有计数的名字以 _total 结尾", name, typed[name])
			}
			found[series] = value
		}
	}
	return found
}

// set 是一组取值里哪几个是 1。
func set(t *testing.T, found map[string]string, name string) []string {
	t.Helper()
	var on []string
	for series, value := range found {
		if !strings.HasPrefix(series, name+"{") {
			continue
		}
		switch value {
		case "1":
			on = append(on, series[len(name):])
		case "0":
		default:
			t.Fatalf("%s 是 %s", series, value)
		}
	}
	sort.Strings(on)
	return on
}

func TestBeforeTheFirstLookNothingIsKnown(t *testing.T) {
	m := New("idp-gateway-pool", application.DefaultPace(), started)
	found := samples(t, string(m.Text()))

	want := map[string]string{
		`idp_gateway_keeper_info{project="idp-gateway-pool"}`: "1",
		"idp_gateway_keeper_start_time_seconds":               "1794441600.000",
		"idp_gateway_keeper_look_interval_seconds":            "5",
		"idp_gateway_keeper_reconcile_interval_seconds":       "60",
		"idp_gateway_keeper_looks_total":                      "0",
		// 还没有看完一眼：这里是它启动的时刻，不是 0。不然"多久没看了"一上来就是几十年。
		"idp_gateway_keeper_last_look_timestamp_seconds":    "1794441600.000",
		"idp_gateway_keeper_last_look_failed":               "0",
		"idp_gateway_pool_busy":                             "0",
		"idp_gateway_pool_unrepaired_attempts":              "0",
		"idp_gateway_pool_starts_total":                     "0",
		"idp_gateway_pool_last_reconcile_timestamp_seconds": "0",
		"idp_gateway_pool_snapshots_put_back_total":         "0",
	}
	for series, value := range want {
		if found[series] != value {
			t.Errorf("%s 是 %q，要的是 %q", series, found[series], value)
		}
	}
	// 池是什么样子还不知道；还没有对过账，哪个结局都不是。
	if on := set(t, found, "idp_gateway_pool_condition"); !reflect.DeepEqual(on, []string{`{condition="unknown"}`}) {
		t.Errorf("池的样子：%v", on)
	}
	if on := set(t, found, "idp_gateway_pool_reconcile_outcome"); len(on) != 0 {
		t.Errorf("对账的结局：%v", on)
	}
	if len(found) != len(want)+4+5 {
		t.Errorf("一共 %d 个数，要的是 %d 个：%v", len(found), len(want)+4+5, found)
	}
}

func TestEachLookReplacesWhatThePoolLookedLike(t *testing.T) {
	m := New("idp-gateway-pool", application.DefaultPace(), started)
	read := func() map[string]string { return samples(t, string(m.Text())) }
	condition := func() []string { return set(t, read(), "idp_gateway_pool_condition") }
	outcome := func() []string { return set(t, read(), "idp_gateway_pool_reconcile_outcome") }

	// 三个都在跑，账对得上。
	quiet := looked(three())
	quiet.Reconciled = reconciled(application.OutcomeInSync, false)
	m.Observe(quiet, after(5*time.Second))
	if found := read(); found["idp_gateway_keeper_looks_total"] != "1" || found["idp_gateway_keeper_last_look_timestamp_seconds"] != "1794441605.000" ||
		found["idp_gateway_pool_last_reconcile_timestamp_seconds"] != "1794441605.000" {
		t.Fatalf("%v", found)
	}
	if !reflect.DeepEqual(condition(), []string{`{condition="whole"}`}) || !reflect.DeepEqual(outcome(), []string{`{outcome="IN_SYNC"}`}) {
		t.Fatalf("池的样子 %v，对账的结局 %v", condition(), outcome())
	}

	// 网关死了，一次发布正占着池：看守没有动手。这一眼没有对账，上一次的结局和时刻留着。
	held := looked(three("gateway"))
	held.Busy = true
	m.Observe(held, after(10*time.Second))
	if found := read(); found["idp_gateway_pool_busy"] != "1" || found["idp_gateway_pool_starts_total"] != "0" ||
		found["idp_gateway_pool_last_reconcile_timestamp_seconds"] != "1794441605.000" || found["idp_gateway_keeper_last_look_failed"] != "0" {
		t.Fatalf("%v", found)
	}
	if !reflect.DeepEqual(condition(), []string{`{condition="down"}`}) || !reflect.DeepEqual(outcome(), []string{`{outcome="IN_SYNC"}`}) {
		t.Fatalf("池的样子 %v，对账的结局 %v", condition(), outcome())
	}

	// 跑了启动命令，没修好，第二回了：给出来的是动手之后的样子。
	failing := looked(three("gateway"))
	still := three("gateway")
	failing.Started, failing.StartErr, failing.After, failing.Failures = true, "exit 5", &still, 2
	m.Observe(failing, after(15*time.Second))
	if found := read(); found["idp_gateway_pool_busy"] != "0" || found["idp_gateway_pool_starts_total"] != "1" ||
		found["idp_gateway_pool_unrepaired_attempts"] != "2" {
		t.Fatalf("%v", found)
	}
	if !reflect.DeepEqual(condition(), []string{`{condition="down"}`}) {
		t.Fatalf("池的样子 %v", condition())
	}

	// 等着下一次动手的那些眼：次数留着，启动命令没有再跑。
	waiting := looked(three("gateway"))
	waiting.RetryIn, waiting.Failures = 15*time.Second, 2
	m.Observe(waiting, after(20*time.Second))
	if found := read(); found["idp_gateway_pool_starts_total"] != "1" || found["idp_gateway_pool_unrepaired_attempts"] != "2" {
		t.Fatalf("%v", found)
	}

	// 这一回修好了：动手之前是 down，给出来的是 whole。
	repaired := looked(three("gateway"))
	whole := three()
	repaired.Started, repaired.After, repaired.Reconciled = true, &whole, reconciled(application.OutcomeInSync, false)
	m.Observe(repaired, after(40*time.Second))
	if found := read(); found["idp_gateway_pool_starts_total"] != "2" || found["idp_gateway_pool_unrepaired_attempts"] != "0" {
		t.Fatalf("%v", found)
	}
	if !reflect.DeepEqual(condition(), []string{`{condition="whole"}`}) {
		t.Fatalf("池的样子 %v", condition())
	}

	// 占着命名空间的那个单独死了。
	orphaned := looked(three("holder"))
	orphaned.Busy = true
	m.Observe(orphaned, after(45*time.Second))
	if !reflect.DeepEqual(condition(), []string{`{condition="orphaned"}`}) {
		t.Fatalf("池的样子 %v", condition())
	}

	// 这一眼没看成（问不到 docker）：池是什么样子不知道，上一眼的不留着。
	m.Observe(application.Tending{Err: errors.New("pool: docker ps: exit status 1")}, after(50*time.Second))
	if found := read(); found["idp_gateway_keeper_last_look_failed"] != "1" || found["idp_gateway_keeper_looks_total"] != "7" {
		t.Fatalf("%v", found)
	}
	if !reflect.DeepEqual(condition(), []string{`{condition="unknown"}`}) {
		t.Fatalf("池的样子 %v", condition())
	}

	// 动过手之后没看成：也是不知道，不拿动手之前的样子充数。
	blind := looked(three("front"))
	blind.Started, blind.Err = true, errors.New("pool: docker ps: exit status 1")
	m.Observe(blind, after(55*time.Second))
	if !reflect.DeepEqual(condition(), []string{`{condition="unknown"}`}) || read()["idp_gateway_pool_starts_total"] != "3" {
		t.Fatalf("池的样子 %v，%v", condition(), read())
	}

	// 对账把记录的那一份放回去了；下一次对账说要重启；再下一次读不到网关。往回放只数写过文件的那些。
	for i, c := range []struct {
		outcome  application.Outcome
		replaced bool
		putBack  string
	}{
		{application.OutcomeRestored, true, "1"},
		{application.OutcomeRestartPending, false, "1"},
		{application.OutcomeUnknown, true, "2"},
		{application.OutcomeUnconfirmed, false, "2"},
		{application.OutcomeInSync, false, "2"},
	} {
		tending := looked(three())
		tending.Reconciled = reconciled(c.outcome, c.replaced)
		m.Observe(tending, after(time.Duration(60+i)*time.Second))
		if found := read(); found["idp_gateway_pool_snapshots_put_back_total"] != c.putBack || found["idp_gateway_keeper_last_look_failed"] != "0" {
			t.Fatalf("%s：%v", c.outcome, found)
		}
		if want := []string{`{outcome="` + string(c.outcome) + `"}`}; !reflect.DeepEqual(outcome(), want) {
			t.Fatalf("%s：对账的结局 %v", c.outcome, outcome())
		}
	}

	// 一个这里没有列的结局：照样给出来，不当成没有对过账。
	odd := looked(three())
	odd.Reconciled = reconciled("SOMETHING_NEW", false)
	m.Observe(odd, after(70*time.Second))
	if want := []string{`{outcome="SOMETHING_NEW"}`}; !reflect.DeepEqual(outcome(), want) {
		t.Fatalf("对账的结局 %v", outcome())
	}
}

// testdata/exposition.txt 是一个看守看了四眼之后给出来的全部内容。tests/contracts 拿它核对
// deploy/compose 里的告警规则用到的名字和取值：改了指标，这个文件和那些规则要跟着改。
func TestTheExpositionIsTheOneTheAlertRulesWereWrittenAgainst(t *testing.T) {
	m := New("idp-gateway-pool", application.DefaultPace(), started)
	first := looked(three())
	first.Reconciled = reconciled(application.OutcomeInSync, false)
	m.Observe(first, after(5*time.Second))
	back, whole := looked(three("gateway")), three()
	back.Started, back.After, back.Reconciled = true, &whole, reconciled(application.OutcomeInSync, false)
	m.Observe(back, after(10*time.Second))
	restored := looked(three())
	restored.Reconciled = reconciled(application.OutcomeRestored, true)
	m.Observe(restored, after(65*time.Second))
	m.Observe(looked(three()), after(70*time.Second))

	golden := filepath.Join("testdata", "exposition.txt")
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(m.Text()); got != string(want) {
		t.Fatalf("给出来的与 %s 不一样：\n%s", golden, got)
	}
	samples(t, string(want)) // 格式本身也过一遍
}

func TestTheHandlerOnlyGivesTheMetricsAndOnlyToReaders(t *testing.T) {
	m := New(`a "quoted" \ project`, application.Pace{Interval: 1500 * time.Millisecond, Reconcile: 5 * time.Second, MaxBackoff: time.Minute}, started)
	server := httptest.NewServer(m.Handler())
	defer server.Close()

	ask := func(method, path string) (*http.Response, string) {
		t.Helper()
		request, err := http.NewRequest(method, server.URL+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		response, err := http.DefaultClient.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		body, err := io.ReadAll(response.Body)
		if err != nil {
			t.Fatal(err)
		}
		return response, string(body)
	}

	response, body := ask(http.MethodGet, "/metrics")
	if response.StatusCode != http.StatusOK || response.Header.Get("Content-Type") != "text/plain; version=0.0.4; charset=utf-8" || body != string(m.Text()) {
		t.Fatalf("%d %q\n%s", response.StatusCode, response.Header.Get("Content-Type"), body)
	}
	found := samples(t, body)
	// 标签里的引号和反斜杠是转义过的；不是整秒的间隔照实写。
	if found[`idp_gateway_keeper_info{project="a \"quoted\" \\ project"}`] != "1" || found["idp_gateway_keeper_look_interval_seconds"] != "1.5" {
		t.Fatalf("%v", found)
	}
	if response, body := ask(http.MethodHead, "/metrics"); response.StatusCode != http.StatusOK || body != "" {
		t.Fatalf("HEAD：%d %q", response.StatusCode, body)
	}
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete} {
		if response, _ := ask(method, "/metrics"); response.StatusCode != http.StatusMethodNotAllowed || response.Header.Get("Allow") != "GET, HEAD" {
			t.Errorf("%s：%d，Allow %q", method, response.StatusCode, response.Header.Get("Allow"))
		}
	}
	for _, path := range []string{"/", "/metrics/", "/metrics/x", "/config_dump", "/debug/pprof/"} {
		if response, _ := ask(http.MethodGet, path); response.StatusCode != http.StatusNotFound {
			t.Errorf("%s：%d", path, response.StatusCode)
		}
	}
}
