package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"go.idp.xyz/idp-gateway/internal/gatewayconfig/adapters/directory"
	"go.idp.xyz/idp-gateway/internal/gatewayconfig/application"
	"go.idp.xyz/idp-gateway/internal/gatewayconfig/ports"
)

const testProject = "idp-gateway-test-pool"

// services 是池里常驻的三个服务，按启动的先后。
var services = []string{"netns", "agentgateway", "front"}

// fakeProject 是 fakeDocker 扮演的 compose 项目：池里常驻的三个容器，和启动、停止它们的两条命令。
// up -d 做的与 deploy/compose/compose.yml 规定的一样：netns；place；网关；reconcile；对上了才是 front。
// 其中 place 和 reconcile 跑的是真的命令。
type fakeProject struct {
	mu      sync.Mutex
	state   map[string]*fakeContainer
	calls   [][]string // docker compose 的各条命令，全部参数
	gateway *fakeGateway
	place   func() int // 两步各自的退出码
	confirm func() int
}

type fakeContainer struct {
	id      string
	running bool
	status  string // 空串表示没有这个容器
	exit    int
	started time.Time
}

func (p *fakeProject) handles(argv []string) bool {
	switch argv[0] {
	case "ps", "compose":
		return true
	case "inspect":
		return len(argv) > 2 && strings.Contains(argv[2], "com.docker.compose.service")
	}
	return false
}

func (p *fakeProject) run(argv []string) (string, error) {
	switch argv[0] {
	case "ps":
		if argv[len(argv)-1] != "label=com.docker.compose.project="+testProject {
			return "", nil // 别的项目：一个容器都没有
		}
		p.mu.Lock()
		defer p.mu.Unlock()
		var ids string
		for _, service := range services {
			if c := p.state[service]; c.status != "" {
				ids += c.id + "\n"
			}
		}
		return ids, nil
	case "inspect":
		p.mu.Lock()
		defer p.mu.Unlock()
		var lines string
		for _, id := range argv[3:] {
			for _, service := range services {
				c := p.state[service]
				if c.id != id {
					continue
				}
				started := "0001-01-01T00:00:00Z"
				if !c.started.IsZero() {
					started = c.started.UTC().Format(time.RFC3339Nano)
				}
				var fields []string
				for _, field := range []any{service, "False", c.running, c.status, c.exit, started} {
					raw, _ := json.Marshal(field)
					fields = append(fields, string(raw))
				}
				lines += strings.Join(fields, "\t") + "\n"
			}
		}
		return lines, nil
	}
	p.mu.Lock()
	p.calls = append(p.calls, append([]string(nil), argv...))
	p.mu.Unlock()
	if len(argv) < 3 || argv[1] != "-p" || argv[2] != testProject {
		return "no such project\n", errors.New("exit status 1")
	}
	for i, arg := range argv {
		switch arg {
		case "up":
			return p.up()
		case "stop":
			for _, service := range argv[i+1:] {
				p.halt(service, 0)
			}
			return "", nil
		}
	}
	return "unknown docker compose command\n", errors.New("exit status 1")
}

func (p *fakeProject) up() (string, error) {
	failed := func(step string, code int) (string, error) {
		return fmt.Sprintf(" Container %s-%s-1  Started\nservice %q didn't complete successfully: exit %d\n", testProject, step, step, code),
			errors.New("exit status 1")
	}
	p.start("netns")
	if code := p.place(); code != 0 {
		return failed("place", code)
	}
	if p.start("agentgateway") {
		p.gateway.restart()
		if p.gateway.isDown() {
			p.halt("agentgateway", 1)
		}
	}
	if code := p.confirm(); code != 0 {
		return failed("confirm", code)
	}
	p.start("front")
	return " Container " + testProject + "-front-1  Started\n", nil
}

// start 把一个没在跑的容器起起来，返回 true；本来就在跑的不动。
func (p *fakeProject) start(service string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	c := p.state[service]
	if c.running {
		return false
	}
	c.running, c.status, c.exit, c.started = true, "running", 0, time.Now()
	return true
}

func (p *fakeProject) halt(service string, code int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if c := p.state[service]; c.running {
		c.running, c.status, c.exit = false, "exited", code
	}
}

// kill 让一个容器死掉。
func (p *fakeProject) kill(service string) { p.halt(service, 137) }

// never 让一个容器成为建了却从来没有启动过的。
func (p *fakeProject) never(service string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	c := p.state[service]
	c.running, c.status, c.exit, c.started = false, "created", 0, time.Time{}
}

func (p *fakeProject) running(service string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.state[service].running
}

// reachable 报告回读口够不够得着：网关在跑，并且接在 netns 现在的命名空间里。
func (p *fakeProject) reachable() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	holder, gateway := p.state["netns"], p.state["agentgateway"]
	return holder.running && gateway.running && !gateway.started.Before(holder.started)
}

// composed 是到现在跑过的 docker compose 命令，各取项目名和文件之后的那一段。
func (p *fakeProject) composed() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	var commands []string
	for _, argv := range p.calls {
		for i, arg := range argv {
			if arg == "up" || arg == "stop" {
				commands = append(commands, strings.Join(argv[i:], " "))
				break
			}
		}
	}
	return commands
}

// compose 让 fakeDocker 扮演这个池的 compose 项目：三个常驻的容器都在跑，池里的假网关跟着它的容器走。
func (h *harness) compose() *fakeProject {
	h.t.Helper()
	p := &fakeProject{gateway: h.pool, state: map[string]*fakeContainer{}}
	booted := time.Now().Add(-time.Minute)
	for i, service := range services {
		p.state[service] = &fakeContainer{
			id: strings.Repeat(string(rune('a'+i)), 64), running: true, status: "running", started: booted.Add(time.Duration(i) * time.Second),
		}
	}
	p.place = func() int { return run(context.Background(), h.placeArgs(), io.Discard, io.Discard, nil) }
	p.confirm = func() int { return run(context.Background(), h.reconcileArgs(), io.Discard, io.Discard, nil) }
	h.pool.mu.Lock()
	file := h.pool.file
	h.pool.file = func() string {
		if !p.reachable() {
			return ""
		}
		return file()
	}
	h.pool.mu.Unlock()
	h.docker.project = p
	return p
}

func (h *harness) keepArgs() []string {
	return []string{"keep", "--config-dir", h.poolDir, "--read-back", h.poolAddr, "--read-back-name", readBackName,
		"--tls-cert", h.publisher.CertFile, "--tls-key", h.publisher.KeyFile, "--tls-ca", h.ca.File(),
		"--settle", "20ms", "--timeout", h.timeout,
		"--interval", "20ms", "--reconcile-interval", "100ms", "--max-backoff", "200ms", "--compose-project", testProject}
}

// shared 是几个 goroutine 都能写、都能读的一块输出。
type shared struct {
	mu     sync.Mutex
	buffer bytes.Buffer
}

func (s *shared) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buffer.Write(p)
}

func (s *shared) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buffer.String()
}

// keeping 是一个在跑着的 keep。
type keeping struct {
	t              *testing.T
	stdout, stderr *shared
	cancel         context.CancelFunc
	exited         chan int
	read           int // 已经看过的行数
}

func (h *harness) keep(extra ...string) *keeping {
	h.t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	k := &keeping{t: h.t, stdout: &shared{}, stderr: &shared{}, cancel: cancel, exited: make(chan int, 1)}
	args := append(h.keepArgs(), extra...)
	go func() { k.exited <- run(ctx, args, k.stdout, k.stderr, h.docker.run) }()
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

// lines 是它到现在写的每一行。每一行都得是 tended 那种 JSON，不多不少。
func (k *keeping) lines() []tended {
	k.t.Helper()
	var all []tended
	for _, line := range strings.Split(k.stdout.String(), "\n") {
		if line == "" {
			continue
		}
		var one tended
		decoder := json.NewDecoder(strings.NewReader(line))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&one); err != nil {
			k.t.Fatalf("标准输出里有一行不是那种 JSON：%q（%v）", line, err)
		}
		if _, err := time.Parse(time.RFC3339, one.Time); err != nil {
			k.t.Fatalf("这一行的时刻是 %q", one.Time)
		}
		all = append(all, one)
	}
	return all
}

// next 等它写出下一行符合 want 的，返回那一行。在它之前的行都算看过了。
func (k *keeping) next(what string, want func(tended) bool) tended {
	k.t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for {
		all := k.lines()
		for k.read < len(all) {
			line := all[k.read]
			k.read++
			if want(line) {
				return line
			}
		}
		if time.Now().After(deadline) {
			k.t.Fatalf("没有等到%s。它写了：\n%s标准错误：%q", what, k.stdout.String(), k.stderr.String())
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// end 等它退出，返回退出码。stop 先叫停它。
func (k *keeping) end() int {
	k.t.Helper()
	select {
	case code := <-k.exited:
		k.exited <- code
		return code
	case <-time.After(30 * time.Second):
		k.t.Fatal("keep 没有退出")
		return -1
	}
}

func (k *keeping) stop() int {
	k.t.Helper()
	k.cancel()
	return k.end()
}

func acted(line tended) bool { return line.Action != "" }

// hold 像一次发布那样占着这个池，返回放开它的函数。正好撞上看守在对账的那一瞬间就再来一次。
func (h *harness) hold() func() {
	h.t.Helper()
	delivery, err := directory.New(h.poolDir, configFile)
	if err != nil {
		h.t.Fatal(err)
	}
	for attempt := 0; ; attempt++ {
		release, err := delivery.Hold(context.Background())
		if err == nil {
			return release
		}
		if !errors.Is(err, ports.ErrBusy) || attempt > 1000 {
			h.t.Fatal(err)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestKeepBringsADeadGatewayBackAndReconcilesWhileItRuns(t *testing.T) {
	h := newHarness(t)
	if r := h.publish(two); r.code != exitActive {
		t.Fatalf("发布：退出码 %d，%s%s", r.code, r.stdout, r.stderr)
	}
	project := h.compose()
	k := h.keep()

	// 开头报告一次：三个容器都在跑，账对得上。
	first := k.next("开头的那一行", func(tended) bool { return true })
	if first.Condition != "whole" || first.Why != "" || first.Busy || first.Action != "" || first.After != nil || first.Repaired ||
		first.StartError != "" || first.RetryInSeconds != 0 || first.Error != "" {
		t.Fatalf("%+v", first)
	}
	if first.Pool == nil || !first.Pool.Holder.Running || !first.Pool.Gateway.Running || !first.Pool.Front.Running ||
		first.Pool.Gateway.State != "running" || first.Pool.Gateway.Started == "" {
		t.Fatalf("%+v", first.Pool)
	}
	if first.Reconcile == nil || first.Reconcile.Outcome != "IN_SYNC" || first.Reconcile.Snapshot != id(two) || first.Reconcile.Replaced {
		t.Fatalf("%+v", first.Reconcile)
	}

	// 网关死了，死的时候目录里放着一份没人确认过、它也加载不了的文件。（布置的这一会儿占着池，看守不插手。）
	release := h.hold()
	project.kill("agentgateway")
	h.place(unloadable)
	release()

	back := k.next("把网关起回来的那一行", acted)
	if back.Action != "start" || back.Condition != "down" || !strings.Contains(back.Why, "the gateway is not running (exited (137))") ||
		!back.Repaired || back.StartError != "" || back.RetryInSeconds != 0 || back.Error != "" {
		t.Fatalf("%+v", back)
	}
	if back.Pool.Gateway.Running || back.Pool.Gateway.State != "exited (137)" || back.After == nil || !back.After.Gateway.Running {
		t.Fatalf("之前 %+v，之后 %+v", back.Pool, back.After)
	}
	// 它是经启动命令起来的：带着的是记录的那一份。另外两个容器没有被动过。
	if !reflect.DeepEqual(project.composed(), []string{"up -d"}) || h.inPlace() != two || h.pool.restarts != 1 {
		t.Fatalf("docker compose 命令 %v，目录里是 %q，网关启动过 %d 次", project.composed(), h.inPlace(), h.pool.restarts)
	}
	if back.After.Holder != back.Pool.Holder || back.After.Front != back.Pool.Front || back.After.Gateway.Started == back.Pool.Gateway.Started {
		t.Fatalf("之前 %+v，之后 %+v", back.Pool, back.After)
	}
	if back.Reconcile == nil || back.Reconcile.Outcome != "IN_SYNC" || back.Reconcile.Snapshot != id(two) {
		t.Fatalf("%+v", back.Reconcile)
	}

	// 池在跑着的时候有人绕过发布器写了这个文件：下一次对账收回去，不重启谁。
	h.place(one)
	restored := k.next("把文件收回去的那一行", func(line tended) bool { return line.Reconcile != nil && line.Reconcile.Outcome == "RESTORED" })
	if restored.Action != "" || restored.Condition != "whole" || !restored.Reconcile.Replaced || restored.Reconcile.Previous != id(one) ||
		restored.Reconcile.Snapshot != id(two) || !strings.Contains(restored.Reconcile.Reason, "was not the snapshot last confirmed") {
		t.Fatalf("%+v / %+v", restored, restored.Reconcile)
	}
	if h.inPlace() != two || h.pool.restarts != 1 || !reflect.DeepEqual(project.composed(), []string{"up -d"}) {
		t.Fatalf("目录里是 %q，网关启动过 %d 次，docker compose 命令 %v", h.inPlace(), h.pool.restarts, project.composed())
	}

	// 被叫停：以 0 结束，标准错误上什么都没有。
	if code := k.stop(); code != exitActive || k.stderr.String() != "" {
		t.Fatalf("退出码 %d，标准错误 %q", code, k.stderr.String())
	}
	if !h.pool.sawOnly(publisherID) || len(h.leftovers()) != 0 {
		t.Fatalf("池见到 %v，配置目录里另外留下了 %v", h.pool.peers, h.leftovers())
	}
}

func TestKeepStopsWhatIsAttachedToADeadNamespaceBeforeStarting(t *testing.T) {
	h := newHarness(t)
	if r := h.publish(two); r.code != exitActive {
		t.Fatalf("发布：退出码 %d，%s%s", r.code, r.stdout, r.stderr)
	}
	project := h.compose()
	k := h.keep()
	k.next("开头的那一行", func(line tended) bool { return line.Condition == "whole" })

	project.kill("netns")
	back := k.next("接回去的那一行", acted)
	if back.Action != "stop+start" || back.Condition != "orphaned" || !back.Repaired || back.StartError != "" || back.Error != "" ||
		!strings.Contains(back.Why, "the gateway is running but the container that holds its network namespace is not") {
		t.Fatalf("%+v", back)
	}
	// 先停前置代理和网关，再跑启动命令。三个都是新起的。
	if !reflect.DeepEqual(project.composed(), []string{"stop front agentgateway", "up -d"}) {
		t.Fatalf("docker compose 命令 %v", project.composed())
	}
	if back.After.Holder.Started == back.Pool.Holder.Started || back.After.Gateway.Started == back.Pool.Gateway.Started ||
		back.After.Front.Started == back.Pool.Front.Started || back.Reconcile == nil || back.Reconcile.Outcome != "IN_SYNC" {
		t.Fatalf("之前 %+v，之后 %+v，对账 %+v", back.Pool, back.After, back.Reconcile)
	}
	if code := k.stop(); code != exitActive {
		t.Fatalf("退出码 %d", code)
	}
}

func TestKeepLeavesThePoolAloneWhileAPublicationHoldsIt(t *testing.T) {
	h := newHarness(t)
	if r := h.publish(two); r.code != exitActive {
		t.Fatalf("发布：退出码 %d，%s%s", r.code, r.stdout, r.stderr)
	}
	project := h.compose()
	// 一次带重启的发布正占着这个池，网关是它停的。看守这时才启动。
	release := h.hold()
	project.kill("agentgateway")
	k := h.keep()

	busy := k.next("说池被占着的那一行", func(tended) bool { return true })
	if !busy.Busy || busy.Action != "" || busy.Condition != "down" || busy.Reconcile != nil || busy.Error != "" {
		t.Fatalf("%+v", busy)
	}
	time.Sleep(200 * time.Millisecond) // 十眼
	if len(project.composed()) != 0 || len(k.lines()) != 1 {
		t.Fatalf("池被占着时：docker compose 命令 %v，写了 %d 行", project.composed(), len(k.lines()))
	}

	// 那次发布放开了池，网关却没有起来：这时才动手。
	release()
	back := k.next("把网关起回来的那一行", acted)
	if back.Action != "start" || back.Busy || !back.Repaired || !reflect.DeepEqual(project.composed(), []string{"up -d"}) {
		t.Fatalf("%+v，docker compose 命令 %v", back, project.composed())
	}
	if code := k.stop(); code != exitActive {
		t.Fatalf("退出码 %d", code)
	}
}

// 还没有记录的池：启动命令每次都卡在对账那一步。看守越试越稀；发布了第一份之后，它自己把前置代理打开。
func TestKeepRetriesLessAndLessOftenUntilThePoolCanOpen(t *testing.T) {
	h := newHarness(t)
	project := h.compose()
	project.never("front")
	k := h.keep()

	var retries []float64
	for len(retries) < 5 {
		attempt := k.next("又一次没成的启动", acted)
		if attempt.Action != "start" || attempt.Repaired || attempt.Condition != "down" || attempt.Pool.Front.State != "created" ||
			attempt.Pool.Front.Started != "" || !strings.Contains(attempt.Why, "the front proxy is not running (created)") {
			t.Fatalf("%+v", attempt)
		}
		if attempt.StartError != `container: docker compose up -d: exit status 1: service "confirm" didn't complete successfully: exit 3` ||
			attempt.Reconcile == nil || attempt.Reconcile.Outcome != "UNCONFIRMED" {
			t.Fatalf("%+v / %+v", attempt, attempt.Reconcile)
		}
		retries = append(retries, attempt.RetryInSeconds)
	}
	// 间隔 20 毫秒：之后隔 40、80、160 毫秒，再往后是最长的 200 毫秒。
	if !reflect.DeepEqual(retries, []float64{0.04, 0.08, 0.16, 0.2, 0.2}) {
		t.Fatalf("各次之后的等待是 %v 秒", retries)
	}
	if project.running("front") || h.inPlace() != one {
		t.Fatalf("前置代理在跑：%t，目录里是 %q", project.running("front"), h.inPlace())
	}

	// 发布第一份。正好撞上看守在对账的那一瞬间时，发布器说池被占着，什么都没动：再来一次。
	published := false
	for attempt := 0; attempt < 100 && !published; attempt++ {
		r := h.publish(one)
		switch {
		case r.code == exitActive:
			published = true
		case r.code != exitError || !strings.Contains(r.stderr, "another publication"):
			t.Fatalf("发布：退出码 %d，%s%s", r.code, r.stdout, r.stderr)
		}
	}
	if !published {
		t.Fatal("发布一直撞上看守")
	}
	opened := k.next("把前置代理打开的那一行", func(line tended) bool { return line.Repaired })
	if opened.Action != "start" || opened.StartError != "" || opened.RetryInSeconds != 0 || !opened.After.Front.Running ||
		opened.Reconcile == nil || opened.Reconcile.Outcome != "IN_SYNC" || !project.running("front") {
		t.Fatalf("%+v", opened)
	}
	if code := k.stop(); code != exitActive {
		t.Fatalf("退出码 %d", code)
	}
}

func TestKeepPassesTheComposeFilesToTheCommandsItRuns(t *testing.T) {
	h := newHarness(t)
	if r := h.publish(two); r.code != exitActive {
		t.Fatalf("发布：退出码 %d，%s%s", r.code, r.stdout, r.stderr)
	}
	project := h.compose()
	project.kill("front")
	// 变量文件是真的有：keep 启动时要核对它。里面的变量本进程的环境里也有，值相同（由 systemd 启动时就是这样）。
	variables := filepath.Join(t.TempDir(), "pool.env")
	if err := os.WriteFile(variables, []byte("# 一个池的设置\nPOOL_DIR=/srv/pool\nREADBACK_PORT=8443\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("POOL_DIR", "/srv/pool")
	k := h.keep("--compose-file", "compose.yml", "--compose-file", "more.yml", "--compose-env-file", variables)
	k.next("把前置代理起回来的那一行", func(line tended) bool { return line.Repaired })
	if code := k.stop(); code != exitActive {
		t.Fatalf("退出码 %d", code)
	}
	project.mu.Lock()
	defer project.mu.Unlock()
	if want := [][]string{{"compose", "-p", testProject, "--env-file", variables, "-f", "compose.yml", "-f", "more.yml", "up", "-d"}}; !reflect.DeepEqual(project.calls, want) {
		t.Fatalf("docker compose 命令 %q", project.calls)
	}
}

// keep 把自己的环境原样交给 docker compose，docker compose 先用环境里的变量。变量文件里有它和 systemd
// 读法不同的行，或者环境里同名的变量是另一个值，这一次 docker compose 拿到的设置就与启动这个池时的不同。
func TestKeepDoesNotStartWithAnEnvFileThatWouldChangeWhatDockerComposeSees(t *testing.T) {
	h := newHarness(t)
	if r := h.publish(two); r.code != exitActive {
		t.Fatalf("发布：退出码 %d，%s%s", r.code, r.stdout, r.stderr)
	}
	h.compose().kill("agentgateway")
	asked, commands := h.pool.asked(), len(h.docker.commands) // 那次发布做过的不算
	write := func(directory, name, content string) string {
		path := filepath.Join(directory, name)
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		return path
	}
	directory := t.TempDir()
	commented := write(directory, "commented.env", "READBACK_PORT=8443\nCALLERS_LISTEN=10.0.0.5:8080 # 办公网\n")
	plain := write(directory, "plain.env", "READBACK_PORT=8443\nCALLERS_LISTEN=10.0.0.5:8080\n")
	refused := func(what string, code int, says string, extra ...string) {
		t.Helper()
		r := h.run(append(h.keepArgs(), extra...))
		if r.code != code || r.stdout != "" || !strings.Contains(r.stderr, says) || strings.Contains(r.stderr, "10.0.0.5") {
			t.Errorf("%s：退出码 %d，标准输出 %q，标准错误 %q", what, r.code, r.stdout, r.stderr)
		}
	}

	// 值后面跟着注释：systemd 把注释也算进值里。退出码是 2：再起一次也一样。
	refused("变量文件里有一行两边读法不同", exitUsage, "gateway-control: container: env file "+commented+", line 2: only NAME=value lines are accepted",
		"--compose-env-file", commented)
	// 排在前面的文件没有毛病，后面的那个有。
	refused("第二个变量文件里有这样的行", exitUsage, commented+", line 2: ", "--compose-env-file", plain, "--compose-env-file", commented)
	// 文件没有毛病，环境里同名的变量却是另一个值。
	t.Setenv("CALLERS_LISTEN", "0.0.0.0:8080")
	refused("环境里的值与文件里的不同", exitUsage, plain+", line 2: CALLERS_LISTEN has another value in the environment of this command",
		"--compose-env-file", plain)
	// 给了却读不到：这不是写错了，退出码 1。
	refused("变量文件读不到", exitError, "gateway-control: container: env file: ", "--compose-env-file", filepath.Join(directory, "missing.env"))
	// 不给变量文件：docker compose 读的是当前目录里的 .env，核对的也是它。
	t.Chdir(directory)
	write(directory, ".env", "CALLERS_LISTEN='10.0.0.5:8080'\n")
	refused("当前目录里的 .env 有这样的行", exitUsage, "gateway-control: container: env file .env, line 1: ")

	if h.inPlace() != two || len(h.docker.commands) != commands || h.pool.asked() != asked {
		t.Fatalf("不该做任何事：目录里是 %q，docker 命令 %v，池被问过 %d 次（之前 %d 次）", h.inPlace(), h.docker.commands[commands:], h.pool.asked(), asked)
	}

	// 环境与文件一致之后照常启动，把网关起回来。
	t.Setenv("CALLERS_LISTEN", "10.0.0.5:8080")
	k := h.keep("--compose-env-file", plain)
	back := k.next("把网关起回来的那一行", acted)
	if back.Action != "start" || !back.Repaired || back.StartError != "" {
		t.Fatalf("%+v", back)
	}
	if code := k.stop(); code != exitActive {
		t.Fatalf("退出码 %d", code)
	}
}

func TestKeepDoesNotStartWhenItCannotHoldThePool(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root 不受目录权限的限制")
	}
	h := newHarness(t)
	project := h.compose()
	project.kill("agentgateway")
	// 配置目录写不了：占不了这个池。（换了账号来跑也是在这一步被挡下，见 directory 的测试。）
	if err := os.Chmod(h.poolDir, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(h.poolDir, 0o755) })

	k := h.keep()
	if code := k.end(); code != exitError || k.stdout.String() != "" || !strings.Contains(k.stderr.String(), "permission denied") {
		t.Fatalf("退出码 %d，标准输出 %q，标准错误 %q", code, k.stdout.String(), k.stderr.String())
	}
	if len(h.docker.commands) != 0 || len(h.pool.peers) != 0 {
		t.Fatalf("docker 命令 %v，池见到 %v", h.docker.commands, h.pool.peers)
	}
}

func TestUsageOfKeep(t *testing.T) {
	h := newHarness(t)
	h.compose().kill("agentgateway")
	with := func(extra ...string) []string { return append(h.keepArgs(), extra...) }
	for _, c := range []struct {
		name string
		args []string
		says string
	}{
		{"不认识的子命令", []string{"watch"}, "usage: gateway-control publish|restart|reconcile|place|keep [flags]"},
		{"keep 只有子命令", []string{"keep"}, "missing required flags: --config-dir, --read-back, --read-back-name, --tls-ca, --tls-cert, --tls-key\n"},
		{"keep 不要快照", with("--snapshot", h.snapshot(two)), "flag provided but not defined: -snapshot"},
		{"keep 不要容器的名字", with("--container", gatewayContainer), "flag provided but not defined: -container"},
		{"keep 多余的参数", with("now"), `unexpected argument "now"`},
		{"keep 的间隔为零", with("--interval", "0s"), "--interval and --reconcile-interval must be positive"},
		{"keep 的对账间隔是负的", with("--reconcile-interval", "-1s"), "--interval and --reconcile-interval must be positive"},
		{"keep 最长的等待比间隔还短", with("--max-backoff", "1ms"), "--max-backoff must not be shorter than --interval"},
		{"keep 的命令时限为零", with("--compose-timeout", "0s"), "--compose-timeout must be positive"},
		{"keep 的间隔不是时长", with("--interval", "often"), "invalid value"},
		{"keep 要帮助", []string{"keep", "--help"}, "-compose-file"},
	} {
		r := h.run(c.args)
		if r.code != exitUsage || r.stdout != "" || !strings.Contains(r.stderr, c.says) {
			t.Errorf("%s：退出码 %d，标准输出 %q，标准错误 %q", c.name, r.code, r.stdout, r.stderr)
		}
	}
	// 装不起来的：退出码 1，同样什么都不做。
	for _, c := range []struct {
		name string
		args []string
		says string
	}{
		{"项目名不是 compose 认的", with("--compose-project", "Not A Name"), "compose project name"},
		{"配置目录不存在", replaced(h.keepArgs(), "--config-dir", filepath.Join(h.poolDir, "missing")), "directory:"},
		{"证书读不到", replaced(h.keepArgs(), "--tls-cert", filepath.Join(h.poolDir, "missing.crt")), "read-back of the pool"},
	} {
		r := h.run(c.args)
		if r.code != exitError || r.stdout != "" || !strings.Contains(r.stderr, c.says) {
			t.Errorf("%s：退出码 %d，标准输出 %q，标准错误 %q", c.name, r.code, r.stdout, r.stderr)
		}
	}
	if h.inPlace() != one || len(h.docker.commands) != 0 || len(h.pool.peers) != 0 {
		t.Fatalf("不该做任何事：目录里是 %q，docker 命令 %v，池见到 %v", h.inPlace(), h.docker.commands, h.pool.peers)
	}

	// 不给的那些：5 秒看一眼，一分钟对一次账，最长隔 5 分钟；项目名是 compose.yml 里写的那个，
	// 文件由 docker compose 自己在当前目录里找。
	o, err := parse("keep", h.reconcileArgs()[1:], io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if o.pace != application.DefaultPace() || o.pace.Interval != 5*time.Second || o.pace.Reconcile != time.Minute || o.pace.MaxBackoff != 5*time.Minute {
		t.Fatalf("%+v", o.pace)
	}
	if o.composeProject != "idp-gateway-pool" || len(o.composeFiles) != 0 || len(o.composeEnvFiles) != 0 || o.composeTimeout != 3*time.Minute {
		t.Fatalf("%+v", o)
	}
}
