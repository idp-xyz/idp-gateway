package domain

import (
	"strings"
	"testing"
	"time"
)

func TestTheConditionOfThePoolsContainers(t *testing.T) {
	boot := time.Date(2026, 11, 12, 9, 0, 0, 0, time.UTC)
	up := func(after time.Duration) Member {
		return Member{Running: true, Started: boot.Add(after), State: "running"}
	}
	var (
		killed  = Member{Started: boot, State: "exited (137)"}
		created = Member{State: "created"}
		absent  = Member{}
	)
	for name, c := range map[string]struct {
		members Members
		want    Condition
		says    []string
	}{
		"三个都在跑，后两个比第一个起得晚": {Members{up(0), up(time.Second), up(2 * time.Second)}, ConditionWhole, nil},
		"同一时刻起来的不算更早":      {Members{up(0), up(0), up(0)}, ConditionWhole, nil},

		"网关死了": {Members{up(0), killed, up(2 * time.Second)}, ConditionDown,
			[]string{"the gateway is not running (exited (137))"}},
		"前置代理从来没有启动过": {Members{up(0), up(time.Second), created}, ConditionDown,
			[]string{"the front proxy is not running (created)"}},
		"前置代理的容器不存在": {Members{up(0), up(time.Second), absent}, ConditionDown,
			[]string{"the front proxy is not running (there is no such container)"}},
		"一个容器都没有": {Members{}, ConditionDown, []string{
			"the container that holds the network namespace is not running (there is no such container)",
			"the gateway is not running", "the front proxy is not running"}},
		"三个都停了": {Members{killed, killed, killed}, ConditionDown, []string{
			"the container that holds the network namespace is not running (exited (137))",
			"the gateway is not running (exited (137))", "the front proxy is not running (exited (137))"}},

		"占着命名空间的那个死了，另外两个还在跑": {Members{killed, up(time.Second), up(2 * time.Second)}, ConditionOrphaned, []string{
			"the gateway is running but the container that holds its network namespace is not",
			"the front proxy is running but the container that holds its network namespace is not"}},
		"占着命名空间的那个死了，只有前置代理还在跑": {Members{killed, killed, up(2 * time.Second)}, ConditionOrphaned,
			[]string{"the front proxy is running but"}},
		"占着命名空间的那个不存在，网关却在跑": {Members{absent, up(time.Second), absent}, ConditionOrphaned,
			[]string{"the gateway is running but"}},
		"占着命名空间的那个重新启动过，另外两个还是原来的": {Members{up(time.Minute), up(time.Second), up(2 * time.Second)}, ConditionOrphaned, []string{
			"the gateway started before the container that holds its network namespace did",
			"the front proxy started before the container that holds its network namespace did"}},
		"占着命名空间的那个重新启动过，网关跟着重新起来了，前置代理还是原来的": {
			Members{up(time.Minute), up(time.Minute + time.Second), up(2 * time.Second)}, ConditionOrphaned,
			[]string{"the front proxy started before"}},
		// 没在跑的容器不接在哪个命名空间里：它上一次是什么时候启动的不要紧，起起来就接到现在的这个。
		"占着命名空间的那个重新启动过，另外两个都停着": {Members{up(time.Minute), killed, killed}, ConditionDown,
			[]string{"the gateway is not running", "the front proxy is not running"}},
	} {
		condition, why := c.members.Condition()
		if condition != c.want {
			t.Errorf("%s：得到 %s（%s），要的是 %s", name, condition, why, c.want)
		}
		if (why == "") != (condition == ConditionWhole) {
			t.Errorf("%s：%s 时的依据是 %q", name, condition, why)
		}
		for _, says := range c.says {
			if !strings.Contains(why, says) {
				t.Errorf("%s：依据 %q 里没有 %q", name, why, says)
			}
		}
	}
}

// 孤儿优先于没在跑的：只报"没在跑"的话，看守只会把没在跑的起起来，接错了的那个还是谁也连不到。
func TestAnOrphanIsReportedEvenWhenSomethingElseIsDown(t *testing.T) {
	boot := time.Date(2026, 11, 12, 9, 0, 0, 0, time.UTC)
	members := Members{
		Holder:  Member{Running: true, Started: boot.Add(time.Minute), State: "running"},
		Gateway: Member{Started: boot, State: "exited (1)"},
		Front:   Member{Running: true, Started: boot.Add(time.Second), State: "running"},
	}
	condition, why := members.Condition()
	if condition != ConditionOrphaned || strings.Contains(why, "the gateway") {
		t.Fatalf("得到 %s（%s）", condition, why)
	}
}
