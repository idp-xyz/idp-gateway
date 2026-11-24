package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

// overlayNetwork 是这个 compose 项目的网络的 ID。
var overlayNetwork = strings.Repeat("ab", 32)

// overlay 在 fakeProject（三个常驻的）之上加两个叠加文件里的服务（ADR-0024）：gateway-authz 两个副本、
// authz-state 一个。docker compose up -d 也把它们里面没在跑的起起来；config --services 答出全部服务名；
// run --rm --no-deps egress forget 只记下来。
type overlay struct {
	h         *harness
	mu        sync.Mutex
	replicas  []*overlayReplica
	commands  []string // 这个项目的 docker compose 命令，各取文件之后的那一段
	declared  string
	configErr error
}

type overlayReplica struct {
	id, name, service string
	running           bool
	status            string
	exit              int
	address, was      string
}

func (h *harness) overlay() (*overlay, *fakeProject) {
	h.t.Helper()
	project := h.compose()
	o := &overlay{h: h, declared: "netns\nplace\negress\nagentgateway\nconfirm\nfront\negress-watch\ngateway-authz\nauthz-state\n"}
	for i, r := range []struct{ name, service, address string }{
		{"gateway-authz-1", "gateway-authz", "172.30.0.5"}, {"gateway-authz-2", "gateway-authz", "172.30.0.6"}, {"authz-state-1", "authz-state", "172.30.0.4"},
	} {
		o.replicas = append(o.replicas, &overlayReplica{id: strings.Repeat(string(rune('d'+i)), 64), name: testProject + "-" + r.name,
			service: r.service, running: true, status: "running", address: r.address})
	}
	return o, project
}

func (o *overlay) replica(name string) *overlayReplica {
	for _, r := range o.replicas {
		if r.name == testProject+"-"+name {
			return r
		}
	}
	o.h.t.Fatalf("没有叫 %s 的容器", name)
	return nil
}

func (o *overlay) kill(name string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	r := o.replica(name)
	r.running, r.status, r.exit, r.was, r.address = false, "exited", 137, r.address, ""
}

// move 让一个在跑的容器换了地址：它一直在跑。
func (o *overlay) move(name, address string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.replica(name).address = address
}

func (o *overlay) composed() []string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]string(nil), o.commands...)
}

// line 是 docker inspect 为一个容器答的一行：services 为真时按 servicesFormat（多一项网络），不然按 memberFormat。
func (o *overlay) line(name, service string, running bool, status string, exit int, address string, services bool) string {
	fields := []any{service, "False", running, status, exit, "0001-01-01T00:00:00Z"}
	if services {
		networks := map[string]map[string]string{}
		if name != "" {
			networks[testProject+"_default"] = map[string]string{"NetworkID": overlayNetwork, "IPAddress": address}
		}
		fields = []any{"/" + name, service, "False", running, status, exit, networks}
	}
	var parts []string
	for _, field := range fields {
		raw, _ := json.Marshal(field)
		parts = append(parts, string(raw))
	}
	return strings.Join(parts, "\t") + "\n"
}

func (o *overlay) run(ctx context.Context, env []string, argv ...string) (string, error) {
	switch argv[0] {
	case "ps":
		out, err := o.h.docker.run(ctx, env, argv...)
		if err != nil || argv[len(argv)-1] != "label=com.docker.compose.project="+testProject {
			return out, err
		}
		o.mu.Lock()
		defer o.mu.Unlock()
		for _, r := range o.replicas {
			out += r.id + "\n"
		}
		return out, nil
	case "inspect":
		services := strings.Contains(argv[2], ".NetworkSettings.Networks")
		var resident []string
		var lines string
		o.mu.Lock()
		for _, id := range argv[3:] {
			found := false
			for _, r := range o.replicas {
				if r.id == id {
					lines += o.line(r.name, r.service, r.running, r.status, r.exit, r.address, services)
					found = true
				}
			}
			if !found {
				resident = append(resident, id)
			}
		}
		o.mu.Unlock()
		if services {
			for range resident { // 三个常驻的：这一问里不看它们，只要答得上
				lines += o.line("", "netns", true, "running", 0, "", true)
			}
			return lines, nil
		}
		if len(resident) > 0 {
			out, err := o.h.docker.run(ctx, env, append([]string{"inspect", "-f", argv[2]}, resident...)...)
			if err != nil {
				return out, err
			}
			lines = out + lines
		}
		return lines, nil
	case "network":
		return overlayNetwork + "\n", nil
	case "compose":
		for i, arg := range argv {
			if arg == "config" || arg == "run" || arg == "up" || arg == "stop" {
				o.mu.Lock()
				o.commands = append(o.commands, strings.Join(argv[i:], " "))
				o.mu.Unlock()
				break
			}
		}
		switch {
		case contains(argv, "config"):
			return o.declared, o.configErr
		case contains(argv, "run"):
			return " Container " + testProject + "-egress-run-1  Started\npinned gateway-authz:9443 -> 172.30.0.9\n", nil
		case contains(argv, "up"):
			out, err := o.h.docker.run(ctx, env, argv...)
			o.mu.Lock()
			for _, r := range o.replicas {
				if !r.running {
					r.running, r.status, r.exit, r.address = true, "running", 0, r.was
				}
			}
			o.mu.Unlock()
			return out, err
		}
	}
	return o.h.docker.run(ctx, env, argv...)
}

func contains(argv []string, word string) bool {
	for _, arg := range argv {
		if arg == word {
			return true
		}
	}
	return false
}

// keepOver 与 harness.keep 一样起一个 keep，docker 命令行由 docker 扮演。
func (h *harness) keepOver(docker dockerRunner, extra ...string) *keeping {
	h.t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	k := &keeping{t: h.t, stdout: &shared{}, stderr: &shared{}, cancel: cancel, exited: make(chan int, 1)}
	args := append(h.keepArgs(), extra...)
	go func() { k.exited <- run(ctx, args, k.stdout, k.stderr, docker) }()
	h.t.Cleanup(func() {
		cancel()
		select {
		case code := <-k.exited:
			k.exited <- code
		case <-time.After(30 * time.Second):
			h.t.Error("keep 被叫停之后没有退出")
		}
	})
	return k
}

func TestKeepTendsTheServicesItIsGiven(t *testing.T) {
	h := newHarness(t)
	if r := h.publish(two); r.code != exitActive {
		t.Fatalf("发布：退出码 %d，%s%s", r.code, r.stdout, r.stderr)
	}
	o, _ := h.overlay()
	address := freeAddress(t)
	k := h.keepOver(o.run, "--tend-pinned", "gateway-authz", "--tend", "authz-state", "--metrics-listen", address)

	// 开头一行：两个服务各自的容器和地址；头一眼只记下地址。
	first := k.next("开头的那一行", func(tended) bool { return true })
	if first.Condition != "whole" || first.Action != "" || first.TendedWhy != "" || first.Moved != nil || len(first.Tended) != 2 || first.TendedAfter != nil {
		t.Fatalf("%+v", first)
	}
	authz, state := first.Tended[0], first.Tended[1]
	if authz.Service != "gateway-authz" || !authz.Pinned || len(authz.Containers) != 2 || state.Service != "authz-state" || state.Pinned ||
		!reflect.DeepEqual(authz.Containers[0], tendedReplica{Name: testProject + "-gateway-authz-1", Running: true, State: "running", Addresses: []string{"172.30.0.5"}}) {
		t.Fatalf("%+v", first.Tended)
	}

	// authz-state 死了：三个常驻的都在跑，看守照样跑启动命令。
	o.kill("authz-state-1")
	back := k.next("把 authz-state 起回来的那一行", acted)
	if back.Action != "start" || back.Condition != "whole" || !back.Repaired || back.StartError != "" || back.Moved != nil ||
		back.TendedWhy != "authz-state: "+testProject+"-authz-state-1 is not running (exited (137))" {
		t.Fatalf("%+v", back)
	}
	if len(back.TendedAfter) != 2 || !back.TendedAfter[1].Containers[0].Running || !reflect.DeepEqual(back.TendedAfter[1].Containers[0].Addresses, []string{"172.30.0.4"}) {
		t.Fatalf("%+v", back.TendedAfter)
	}
	if back.After == nil || back.After.Gateway != back.Pool.Gateway || back.Reconcile == nil || back.Reconcile.Outcome != "IN_SYNC" {
		t.Fatalf("网关被动过：之前 %+v，之后 %+v", back.Pool, back.After)
	}

	// gateway-authz 的一个副本在跑着的时候换了地址：forget，停前置代理和网关，跑启动命令。
	o.move("gateway-authz-1", "172.30.0.9")
	followed := k.next("让网关跟上新地址的那一行", acted)
	if followed.Action != "forget+stop+start" || !reflect.DeepEqual(followed.Moved, []string{"gateway-authz 172.30.0.9"}) || !followed.Repaired ||
		followed.StartError != "" || followed.Error != "" || followed.TendedWhy != "" {
		t.Fatalf("%+v", followed)
	}
	if followed.After.Gateway.Started == followed.Pool.Gateway.Started || followed.After.Front.Started == followed.Pool.Front.Started ||
		followed.After.Holder != followed.Pool.Holder || followed.Reconcile == nil || followed.Reconcile.Outcome != "IN_SYNC" {
		t.Fatalf("之前 %+v，之后 %+v，对账 %+v", followed.Pool, followed.After, followed.Reconcile)
	}
	want := []string{"config --services", "up -d", "run --rm --no-deps egress forget", "stop front agentgateway", "up -d"}
	if got := o.composed(); !reflect.DeepEqual(got, want) {
		t.Fatalf("docker compose 命令 %q", got)
	}
	metrics := until(t, address, "repin 数了一次", func(found map[string]string) bool { return found["idp_gateway_pool_repins_total"] == "1" })
	for series, value := range map[string]string{
		`idp_gateway_pool_tended_running{service="gateway-authz",pinned="true"}`: "1",
		`idp_gateway_pool_tended_running{service="authz-state",pinned="false"}`:  "1",
		"idp_gateway_pool_unfollowed_addresses":                                  "0",
		"idp_gateway_pool_starts_total":                                          "2",
	} {
		if metrics[series] != value {
			t.Errorf("%s 是 %q，要的是 %q", series, metrics[series], value)
		}
	}
	// 记下的是新的那一组：之后安安稳稳。
	time.Sleep(200 * time.Millisecond)
	if got := o.composed(); !reflect.DeepEqual(got, want) {
		t.Fatalf("docker compose 命令 %q", got)
	}
	if code := k.stop(); code != exitActive || k.stderr.String() != "" {
		t.Fatalf("退出码 %d，标准错误 %q", code, k.stderr.String())
	}
}

// 不给 --tend、--tend-pinned：与原来一样，只看三个常驻的。另外的服务死了、换了地址，它都不知道。
func TestKeepWithoutTendLooksOnlyAtTheThree(t *testing.T) {
	h := newHarness(t)
	if r := h.publish(two); r.code != exitActive {
		t.Fatalf("发布：退出码 %d，%s%s", r.code, r.stdout, r.stderr)
	}
	o, _ := h.overlay()
	k := h.keepOver(o.run)
	k.next("开头的那一行", func(tended) bool { return true })
	o.kill("authz-state-1")
	o.move("gateway-authz-1", "172.30.0.9")
	time.Sleep(300 * time.Millisecond) // 十几眼
	if len(k.lines()) != 1 || len(o.composed()) != 0 {
		t.Fatalf("写了 %d 行，docker compose 命令 %q", len(k.lines()), o.composed())
	}
	// 那一行里没有新的几项：与原来一字不差。
	for _, key := range []string{`"tended"`, `"tended_why"`, `"moved"`, `"tended_after"`} {
		if strings.Contains(k.stdout.String(), key) {
			t.Fatalf("没给 --tend 时这一行里有 %s：%s", key, k.stdout.String())
		}
	}
	if code := k.stop(); code != exitActive {
		t.Fatalf("退出码 %d", code)
	}
}

func TestUsageOfKeepTend(t *testing.T) {
	h := newHarness(t)
	o, project := h.overlay()
	project.kill("agentgateway")
	with := func(extra ...string) []string { return append(h.keepArgs(), extra...) }
	runOver := func(args []string) result {
		var stdout, stderr bytes.Buffer
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		r := result{code: run(ctx, args, &stdout, &stderr, o.run)}
		r.stdout, r.stderr = stdout.String(), stderr.String()
		return r
	}
	// 名字本身不对：命令行写错了，退出码 2，什么都没做（docker 一条都没有跑）。
	for _, c := range []struct {
		name string
		args []string
		says string
	}{
		{"三个常驻的之一", with("--tend", "netns"), "--tend, --tend-pinned: container: service to tend \"netns\": the keeper always looks at netns, agentgateway and front"},
		{"网关", with("--tend-pinned", "agentgateway"), "always looks at"},
		{"跑完就退出的一步", with("--tend", "place"), "a step that runs to completion and exits"},
		{"签名器的出口那一步", with("--tend-pinned", "signer-egress"), "a step that runs to completion and exits"},
		{"不是服务名", with("--tend", "gateway authz"), "not a compose service name"},
		{"像一个参数", with("--tend", "-x"), "not a compose service name"},
		{"空的", with("--tend", ""), "not a compose service name"},
		{"两边各给了一次", with("--tend", "gateway-authz", "--tend-pinned", "gateway-authz"), `"gateway-authz": given more than once`},
		{"给了两次", with("--tend", "authz-state", "--tend", "authz-state"), "given more than once"},
	} {
		r := runOver(c.args)
		if r.code != exitUsage || r.stdout != "" || !strings.Contains(r.stderr, c.says) {
			t.Errorf("%s：退出码 %d，标准输出 %q，标准错误 %q", c.name, r.code, r.stdout, r.stderr)
		}
	}
	if len(o.composed()) != 0 || len(h.docker.commands) != 0 {
		t.Fatalf("不该跑任何 docker 命令：%q %q", o.composed(), h.docker.commands)
	}

	// 名字不在给的 compose 文件里：只问过 docker compose config --services，退出码 2，池没有被碰过。
	r := runOver(with("--tend-pinned", "gateway-authz", "--tend", "sf-token-coordinator"))
	if r.code != exitUsage || r.stdout != "" || !strings.Contains(r.stderr, `gateway-control: --tend, --tend-pinned: "sf-token-coordinator" is not a service of the compose files keep was given `+
		`(docker compose config --services lists netns, place, egress, agentgateway, confirm, front, egress-watch, gateway-authz, authz-state)`) {
		t.Fatalf("退出码 %d，标准输出 %q，标准错误 %q", r.code, r.stdout, r.stderr)
	}
	if !reflect.DeepEqual(o.composed(), []string{"config --services"}) || project.running("agentgateway") || len(h.pool.peers) != 0 {
		t.Fatalf("docker compose 命令 %q，网关在跑 %t，池见到 %v", o.composed(), project.running("agentgateway"), h.pool.peers)
	}
	// 问不成（docker 够不着、文件里缺变量）：不是命令行写错了，退出码 1。
	o.configErr = errors.New("exit status 1")
	o.declared = "Cannot connect to the Docker daemon at unix:///var/run/docker.sock\n"
	r = runOver(with("--tend", "authz-state"))
	if r.code != exitError || r.stdout != "" || !strings.Contains(r.stderr, "gateway-control: container: docker compose config --services: exit status 1: Cannot connect to the Docker daemon") {
		t.Fatalf("退出码 %d，标准输出 %q，标准错误 %q", r.code, r.stdout, r.stderr)
	}
	if project.running("agentgateway") {
		t.Fatal("网关被起起来了")
	}

	// 别的命令没有这两个参数；keep 的帮助里有。
	if r := h.run(append(h.reconcileArgs(), "--tend", "authz-state")); r.code != exitUsage || !strings.Contains(r.stderr, "flag provided but not defined: -tend") {
		t.Fatalf("reconcile 接受了 --tend：退出码 %d，%q", r.code, r.stderr)
	}
	if r := h.run([]string{"keep", "--help"}); r.code != exitUsage || !strings.Contains(r.stderr, "-tend value") || !strings.Contains(r.stderr, "-tend-pinned value") {
		t.Fatalf("退出码 %d，%q", r.code, r.stderr)
	}
	// 不给：只看三个常驻的。
	parsed, err := parse("keep", h.reconcileArgs()[1:], io.Discard)
	if err != nil || len(parsed.tend) != 0 || len(parsed.tendPinned) != 0 || len(parsed.tended()) != 0 {
		t.Fatalf("%+v，%v", parsed, err)
	}
	parsed, err = parse("keep", append(h.reconcileArgs()[1:], "--tend", "authz-state", "--tend-pinned", "gateway-authz", "--tend", "signer", "--tend-pinned", "provider-signer"), io.Discard)
	if err != nil || !reflect.DeepEqual(parsed.tended(), []string{"gateway-authz", "provider-signer", "authz-state", "signer"}) ||
		!reflect.DeepEqual([]string(parsed.tendPinned), []string{"gateway-authz", "provider-signer"}) {
		t.Fatalf("%+v，%v", parsed, err)
	}
}
