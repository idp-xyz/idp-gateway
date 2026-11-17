package container

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"go.idp.xyz/idp-gateway/internal/gatewayconfig/domain"
)

// fakeCompose 扮演 docker 命令行：ps 和 inspect 答事先给好的，compose 的命令只记下来。
type fakeCompose struct {
	ps, inspect, composed         string
	psErr, inspectErr, composeErr error
	block                         bool // compose 的命令一直不返回，直到它的 ctx 到期
	commands                      [][]string
	deadlines                     []time.Duration // 每条命令的 ctx 还剩多久；没有期限的是 -1
}

func (d *fakeCompose) run(ctx context.Context, _ []string, argv ...string) (string, error) {
	d.commands = append(d.commands, argv)
	remaining := time.Duration(-1)
	if at, ok := ctx.Deadline(); ok {
		remaining = time.Until(at).Round(time.Second)
	}
	d.deadlines = append(d.deadlines, remaining)
	if err := ctx.Err(); err != nil {
		return "", err
	}
	switch argv[0] {
	case "ps":
		return d.ps, d.psErr
	case "inspect":
		return d.inspect, d.inspectErr
	case "compose":
		if d.block {
			<-ctx.Done()
			return "", ctx.Err()
		}
		return d.composed, d.composeErr
	}
	return "", errors.New("unexpected docker command")
}

func id(n int) string { return fmt.Sprintf("%064x", n) }

// described 是 docker inspect 按 memberFormat 答的一行。
func described(service, oneOff string, running bool, status string, exitCode int, startedAt string) string {
	fields := []any{service, oneOff, running, status, exitCode, startedAt}
	parts := make([]string, len(fields))
	for i, field := range fields {
		raw, err := json.Marshal(field)
		if err != nil {
			panic(err)
		}
		parts[i] = string(raw)
	}
	return strings.Join(parts, "\t") + "\n"
}

const (
	never  = "0001-01-01T00:00:00Z"
	booted = "2026-11-12T09:00:00.100200300Z"
)

func at(stamp string) time.Time {
	parsed, err := time.Parse(time.RFC3339Nano, stamp)
	if err != nil {
		panic(err)
	}
	return parsed
}

// whole 是一个五个容器都在的池：三个常驻的在跑，两步跑完退出了。
func whole() *fakeCompose {
	return &fakeCompose{
		ps: id(1) + "\n" + id(2) + "\n" + id(3) + "\n" + id(4) + "\n" + id(5) + "\n",
		inspect: described("front", "False", true, "running", 0, "2026-11-12T09:00:02.5Z") +
			described("confirm", "False", false, "exited", 0, "2026-11-12T09:00:02Z") +
			described("agentgateway", "False", true, "running", 0, "2026-11-12T09:00:01Z") +
			described("place", "False", false, "exited", 0, "2026-11-12T09:00:00.2Z") +
			described("netns", "False", true, "running", 0, booted),
	}
}

func openPool(t *testing.T, docker *fakeCompose) *Pool {
	t.Helper()
	pool, err := NewPool(PoolConfig{Project: "idp-gateway-pool", Timeout: 3 * time.Minute, Docker: docker.run})
	if err != nil {
		t.Fatal(err)
	}
	return pool
}

func TestMembersAreTheThreeLongRunningContainersOfTheProject(t *testing.T) {
	docker := whole()
	members, err := openPool(t, docker).Members(ctx)
	if err != nil {
		t.Fatal(err)
	}
	want := domain.Members{
		Holder:  domain.Member{Running: true, Started: at(booted), State: "running"},
		Gateway: domain.Member{Running: true, Started: at("2026-11-12T09:00:01Z"), State: "running"},
		Front:   domain.Member{Running: true, Started: at("2026-11-12T09:00:02.5Z"), State: "running"},
	}
	if members != want {
		t.Fatalf("%+v", members)
	}
	if condition, why := members.Condition(); condition != domain.ConditionWhole {
		t.Fatalf("%s：%s", condition, why)
	}
	// 先按项目名列出容器，再一次问清它们。
	if len(docker.commands) != 2 ||
		!reflect.DeepEqual(docker.commands[0], []string{"ps", "-a", "-q", "--no-trunc", "--filter", "label=com.docker.compose.project=idp-gateway-pool"}) ||
		!reflect.DeepEqual(docker.commands[1], []string{"inspect", "-f", memberFormat, id(1), id(2), id(3), id(4), id(5)}) {
		t.Fatalf("docker 命令是 %q", docker.commands)
	}
	// 看一眼有期限：docker 不答话时不会一直等下去。
	if docker.deadlines[0] != 30*time.Second || docker.deadlines[1] != 30*time.Second {
		t.Fatalf("两条命令的期限是 %v", docker.deadlines)
	}
	// 问的每一项各是一个 JSON，之间是制表符。
	if strings.Count(memberFormat, "\t") != 5 || !strings.Contains(memberFormat, `"com.docker.compose.service"`) || !strings.Contains(memberFormat, ".State.StartedAt") {
		t.Fatalf("%q", memberFormat)
	}
}

func TestMembersReportWhatBecameOfEachContainer(t *testing.T) {
	for name, c := range map[string]struct {
		line string
		want domain.Member
	}{
		"被杀掉的": {described("agentgateway", "False", false, "exited", 137, "2026-11-12T09:00:01Z"),
			domain.Member{Started: at("2026-11-12T09:00:01Z"), State: "exited (137)"}},
		"自己退出的": {described("agentgateway", "False", false, "exited", 1, "2026-11-12T09:00:01Z"),
			domain.Member{Started: at("2026-11-12T09:00:01Z"), State: "exited (1)"}},
		"建了却从来没有启动过的": {described("agentgateway", "False", false, "created", 0, never),
			domain.Member{State: "created"}},
		"暂停着的算在跑": {described("agentgateway", "False", true, "paused", 0, "2026-11-12T09:00:01Z"),
			domain.Member{Running: true, Started: at("2026-11-12T09:00:01Z"), State: "paused"}},
		"没有这个容器": {"", domain.Member{}},
	} {
		docker := &fakeCompose{ps: id(1) + "\n" + id(2) + "\n",
			inspect: described("netns", "False", true, "running", 0, booted) + c.line}
		if c.line == "" {
			docker.ps = id(1) + "\n"
		}
		members, err := openPool(t, docker).Members(ctx)
		if err != nil || members.Gateway != c.want {
			t.Errorf("%s：%+v，%v", name, members.Gateway, err)
		}
		if c.want.Started.IsZero() != (c.line == "" || strings.Contains(c.line, never)) {
			t.Errorf("%s：启动时刻 %s", name, members.Gateway.Started)
		}
		if !members.Holder.Running || members.Front != (domain.Member{}) {
			t.Errorf("%s：%+v", name, members)
		}
	}
}

func TestAProjectWithoutContainersHasNoMembers(t *testing.T) {
	docker := &fakeCompose{ps: "\n"}
	members, err := openPool(t, docker).Members(ctx)
	if err != nil || members != (domain.Members{}) || len(docker.commands) != 1 {
		t.Fatalf("%+v，%v，docker 命令是 %q", members, err, docker.commands)
	}
	if condition, _ := members.Condition(); condition != domain.ConditionDown {
		t.Fatalf("%s", condition)
	}
}

func TestMembersIgnoreWhatIsNotOneOfTheThree(t *testing.T) {
	docker := whole()
	// 命令行的警告混在输出里；项目里还有别的服务；有人用 docker compose run 临时起过一个网关。
	docker.ps = "WARNING: Error loading config file: /home/svc/.docker/config.json: permission denied\n" + docker.ps + id(6) + "\n" + id(7) + "\n"
	docker.inspect = "WARNING: Error loading config file: /home/svc/.docker/config.json: permission denied\n" + docker.inspect +
		described("echo", "False", true, "running", 0, "2026-11-12T08:00:00Z") +
		described("agentgateway", "True", false, "exited", 1, "2026-11-12T08:30:00Z")
	members, err := openPool(t, docker).Members(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !members.Gateway.Running || members.Gateway.Started != at("2026-11-12T09:00:01Z") {
		t.Fatalf("%+v", members.Gateway)
	}
	if got := docker.commands[1]; len(got) != 3+7 || got[len(got)-1] != id(7) {
		t.Fatalf("docker 命令是 %q", got)
	}
}

func TestMembersRefuseToGuess(t *testing.T) {
	failed := errors.New("exit status 1")
	for name, c := range map[string]struct {
		spoil func(*fakeCompose)
		says  string
	}{
		"docker 够不着": {func(d *fakeCompose) {
			d.ps, d.psErr = "Cannot connect to the Docker daemon at unix:///var/run/docker.sock. Is the docker daemon running?\n", failed
		}, "docker ps: exit status 1: Cannot connect to the Docker daemon"},
		"列出来的容器转眼被删了": {func(d *fakeCompose) {
			d.inspect, d.inspectErr = d.inspect+"Error response from daemon: No such object: "+id(2)+"\n", failed
		}, "docker inspect: exit status 1: Error response from daemon: No such object"},
		"一个服务有两个容器": {func(d *fakeCompose) {
			d.ps += id(6) + "\n"
			d.inspect += described("agentgateway", "False", true, "running", 0, "2026-11-12T09:30:00Z")
		}, "more than one container for service agentgateway"},
		"答的行数比问的容器少": {func(d *fakeCompose) { d.ps += id(6) + "\n" }, "described 5 of the 6 containers"},
		"一行里的项数不对":   {func(d *fakeCompose) { d.inspect += `"front"` + "\t" + `"False"` + "\n" }, "something unexpected"},
		"有一项不是该有的样子": {func(d *fakeCompose) {
			d.inspect = strings.Replace(d.inspect, "true", `"yes"`, 1)
		}, "something unexpected"},
		"启动时刻读不出来": {func(d *fakeCompose) {
			d.inspect = strings.Replace(d.inspect, booted, "this morning", 1)
		}, "something unexpected"},
	} {
		docker := whole()
		c.spoil(docker)
		members, err := openPool(t, docker).Members(ctx)
		if err == nil || !strings.Contains(err.Error(), c.says) || members != (domain.Members{}) {
			t.Errorf("%s：%+v，%v", name, members, err)
		}
	}
}

func TestALookEndsWhenTheCallerIsToldToStop(t *testing.T) {
	docker := whole()
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := openPool(t, docker).Members(cancelled); err == nil || len(docker.commands) != 1 {
		t.Fatalf("%v，docker 命令是 %q", err, docker.commands)
	}
}

func TestStartIsTheComposeCommandThatStartsThePool(t *testing.T) {
	// 什么文件都不给：docker compose 自己在当前目录里找，与手工在那里跑的是同一条命令，只多了项目名。
	docker := whole()
	pool := openPool(t, docker)
	if err := pool.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if err := pool.StopDependents(ctx); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(docker.commands, [][]string{
		{"compose", "-p", "idp-gateway-pool", "up", "-d"},
		{"compose", "-p", "idp-gateway-pool", "stop", "front", "agentgateway"},
	}) {
		t.Fatalf("docker 命令是 %q", docker.commands)
	}
	if docker.deadlines[0] != 3*time.Minute || docker.deadlines[1] != 3*time.Minute {
		t.Fatalf("两条命令的期限是 %v", docker.deadlines)
	}

	// 给了文件：变量文件在前，compose 文件在后，各按给的先后。
	docker = whole()
	pool, err := NewPool(PoolConfig{Project: "idp-gateway-compose", Timeout: time.Minute, Docker: docker.run,
		Files: []string{"deploy/compose/compose.yml", "tests/echo.yml"}, EnvFiles: []string{"/pool/pool.env", "/pool/more.env"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := pool.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if err := pool.StopDependents(ctx); err != nil {
		t.Fatal(err)
	}
	prefix := []string{"compose", "-p", "idp-gateway-compose", "--env-file", "/pool/pool.env", "--env-file", "/pool/more.env",
		"-f", "deploy/compose/compose.yml", "-f", "tests/echo.yml"}
	if !reflect.DeepEqual(docker.commands, [][]string{
		append(append([]string{}, prefix...), "up", "-d"),
		append(append([]string{}, prefix...), "stop", "front", "agentgateway"),
	}) {
		t.Fatalf("docker 命令是 %q", docker.commands)
	}
	// 看容器按的也是这个项目名。
	if _, err := pool.Members(ctx); err != nil || docker.commands[2][len(docker.commands[2])-1] != "label=com.docker.compose.project=idp-gateway-compose" {
		t.Fatalf("%v，docker 命令是 %q", err, docker.commands[2])
	}
}

func TestTheServiceNamesAreTheOnesTheStopCommandUses(t *testing.T) {
	if HolderService != "netns" || GatewayService != "agentgateway" || FrontService != "front" || DefaultProject != "idp-gateway-pool" {
		t.Fatalf("%s %s %s %s", HolderService, GatewayService, FrontService, DefaultProject)
	}
}

func TestStartAndStopAreNotCancelledHalfway(t *testing.T) {
	// 调用的人已经被叫停：命令照样发出去，照样等它做完。
	docker := whole()
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	pool := openPool(t, docker)
	if err := pool.Start(cancelled); err != nil {
		t.Fatal(err)
	}
	if err := pool.StopDependents(cancelled); err != nil || len(docker.commands) != 2 {
		t.Fatalf("%v，docker 命令是 %q", err, docker.commands)
	}

	// 有一步没有通过：说出 docker compose 最后说的那一行。
	docker = whole()
	docker.composed = " Container idp-gateway-pool-place-1  Started\n" + `service "confirm" didn't complete successfully: exit 3` + "\n"
	docker.composeErr = errors.New("exit status 1")
	err := openPool(t, docker).Start(ctx)
	if err == nil || err.Error() != `container: docker compose up -d: exit status 1: service "confirm" didn't complete successfully: exit 3` {
		t.Fatalf("得到 %v", err)
	}
	err = openPool(t, docker).StopDependents(ctx)
	if err == nil || !strings.HasPrefix(err.Error(), "container: docker compose stop front agentgateway: exit status 1: ") {
		t.Fatalf("得到 %v", err)
	}

	// 到时了它还没有返回。
	docker = whole()
	docker.block = true
	pool, err = NewPool(PoolConfig{Project: "idp-gateway-pool", Timeout: 50 * time.Millisecond, Docker: docker.run})
	if err != nil {
		t.Fatal(err)
	}
	if err := pool.Start(ctx); err == nil || err.Error() != "container: docker compose up -d did not return within 50ms" {
		t.Fatalf("得到 %v", err)
	}
}

func TestNewPoolRefusesUnusableConfiguration(t *testing.T) {
	good := PoolConfig{Project: "idp-gateway-pool", Timeout: time.Minute}
	if _, err := NewPool(good); err != nil {
		t.Fatal(err)
	}
	for name, spoil := range map[string]func(*PoolConfig){
		"没有项目名":      func(c *PoolConfig) { c.Project = "" },
		"项目名里有大写":    func(c *PoolConfig) { c.Project = "Pool" },
		"项目名像一个参数":   func(c *PoolConfig) { c.Project = "-p" },
		"项目名里有空格":    func(c *PoolConfig) { c.Project = "a b" },
		"项目名里有等号":    func(c *PoolConfig) { c.Project = "a=b" },
		"文件名是空的":     func(c *PoolConfig) { c.Files = []string{"compose.yml", ""} },
		"文件名像一个参数":   func(c *PoolConfig) { c.Files = []string{"--project-directory"} },
		"变量文件名像一个参数": func(c *PoolConfig) { c.EnvFiles = []string{"-f"} },
		"没有时限":       func(c *PoolConfig) { c.Timeout = 0 },
		"时限是负的":      func(c *PoolConfig) { c.Timeout = -time.Second },
	} {
		bad := good
		spoil(&bad)
		if _, err := NewPool(bad); err == nil {
			t.Errorf("%s：被接受了", name)
		}
	}
}

// envFile 写一个变量文件，返回它的路径。
func envFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "pool.env")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// unset 是一个什么变量都没有的环境。
func unset(string) (string, bool) { return "", false }

func TestEnvFilesAreAcceptedWhenSystemdAndDockerComposeReadThemAlike(t *testing.T) {
	// deploy/compose/.env.example 填好之后的样子。
	filled := "# 一个池的设置\n\nCALLERS_LISTEN=10.0.0.5:8080\nREADBACK_PORT=8443\nREADBACK_NAME=readback.gateway.idp.test\n" +
		"POOL_DIR=/srv/idp-gateway/pool\nGATEWAY_USER=10101:10101\n  # 缩进的注释\n\t\n" +
		"GATEWAY_IMAGE=cr.agentgateway.dev/agentgateway@sha256:60216aafb03d37f94e952ff3d51d2f630a65b10ecaebdc0a864882f92610c45b\n" +
		"EMPTY=\nlower_case=a=b,c;d%e\nPOOL_NAME=华东一号\n"
	if err := CheckEnvFiles([]string{envFile(t, filled)}, unset); err != nil {
		t.Fatal(err)
	}
	// 末尾没有换行，或者整个文件是空的，都行。
	for _, content := range []string{"A=1", ""} {
		if err := CheckEnvFiles([]string{envFile(t, content)}, unset); err != nil {
			t.Fatalf("%q：%v", content, err)
		}
	}
}

func TestEnvFilesAreRefusedWhenALineReadsDifferently(t *testing.T) {
	for name, line := range map[string]string{
		"值后面跟着注释":    "CALLERS_LISTEN=10.0.0.5:8080 # 办公网",
		"值里有空格":      "POOL_DIR=/srv/my pool",
		"值的末尾有空格":    "POOL_DIR=/srv/pool ",
		"带双引号":       `POOL_DIR="/srv/pool"`,
		"带单引号":       "POOL_DIR='/srv/pool'",
		"引用另一个变量":    "POOL_DIR=${HOME}/pool",
		"值里有 $":      "READBACK_NAME=a$b",
		"值里有 #":      "READBACK_NAME=a#b",
		"值里有反斜杠":     `POOL_DIR=C:\pool`,
		"值里有反引号":     "POOL_DIR=`pwd`",
		"行尾是回车":      "POOL_DIR=/srv/pool\r",
		"export 开头":  "export POOL_DIR=/srv/pool",
		"名字前面有空格":    " POOL_DIR=/srv/pool",
		"等号前面有空格":    "POOL_DIR =/srv/pool",
		"等号后面有空格":    "POOL_DIR= /srv/pool",
		"用冒号":        "POOL_DIR: /srv/pool",
		"只有名字":       "POOL_DIR",
		"名字以数字开头":    "1POOL=/srv/pool",
		"名字里有连字符":    "POOL-DIR=/srv/pool",
		"分号开头的注释":    "; systemd 当它是注释，docker compose 不是",
		"值里有制表符":     "POOL_DIR=/srv/\tpool",
		"值不是 UTF-8":  "POOL_DIR=/srv/\xff",
		"值里有不间断空格":   "POOL_DIR=/srv/\u00a0pool",
		"值里有控制字符":    "POOL_DIR=/srv/\x1bpool",
		"没有名字":       "=/srv/pool",
		"行尾的反斜杠（续行）": "POOL_DIR=/srv/\\",
	} {
		path := envFile(t, "# 第一行\nREADBACK_PORT=8443\n\n"+line+"\nREADBACK_NAME=readback.gateway.idp.test\n")
		err := CheckEnvFiles([]string{path}, unset)
		if !errors.Is(err, ErrEnvFile) {
			t.Errorf("%s：得到 %v", name, err)
			continue
		}
		// 说出是哪个文件的哪一行；那一行的内容不写出来。
		want := "container: env file " + path + ", line 4: only NAME=value lines are accepted, with no whitespace, quotes, $, # or backslash in them: " +
			"systemd and docker compose read other lines differently"
		if err.Error() != want {
			t.Errorf("%s：%v", name, err)
		}
	}
}

func TestTheEnvironmentMustAgreeWithTheEnvFiles(t *testing.T) {
	first := envFile(t, "POOL_DIR=/srv/pool\nREADBACK_PORT=8443\nPOOL_DIR=/srv/pool-b\n")
	second := envFile(t, "CONFIRM_TIMEOUT=60s\nREADBACK_PORT=9443\n")
	environment := func(values map[string]string) func(string) (string, bool) {
		return func(name string) (string, bool) {
			value, set := values[name]
			return value, set
		}
	}
	// 一个名字出现几次时，算数的是最后那一次：同一个文件里靠后的，几个文件里靠后的那个文件的。
	// 环境里没有的不管；环境里另有别的变量也不管。
	agreeing := map[string]string{"POOL_DIR": "/srv/pool-b", "READBACK_PORT": "9443", "HOME": "/home/idp-gateway"}
	if err := CheckEnvFiles([]string{first, second}, environment(agreeing)); err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]struct {
		values map[string]string
		says   string
	}{
		"环境里是另一个值": {map[string]string{"CONFIRM_TIMEOUT": "10s"},
			second + ", line 1: CONFIRM_TIMEOUT has another value in the environment of this command, and docker compose would use that one"},
		"环境里是文件里靠前的那个值": {map[string]string{"POOL_DIR": "/srv/pool"}, first + ", line 3: POOL_DIR has another value"},
		"环境里是前一个文件的值":   {map[string]string{"READBACK_PORT": "8443"}, second + ", line 2: READBACK_PORT has another value"},
		"环境里是空的":        {map[string]string{"CONFIRM_TIMEOUT": ""}, second + ", line 1: CONFIRM_TIMEOUT has another value"},
	} {
		err := CheckEnvFiles([]string{first, second}, environment(c.values))
		if !errors.Is(err, ErrEnvFile) || !strings.Contains(err.Error(), c.says) {
			t.Errorf("%s：得到 %v", name, err)
			continue
		}
		// 两边的值都不写出来。
		message := strings.NewReplacer(first, "", second, "").Replace(err.Error())
		for _, value := range []string{"/srv/pool", "8443", "9443", "60s", "10s"} {
			if strings.Contains(message, value) {
				t.Errorf("%s：错误里带着值 %q：%v", name, value, err)
			}
		}
	}
}

func TestWithoutEnvFilesTheOneInTheCurrentDirectoryIsChecked(t *testing.T) {
	// 不给变量文件时 docker compose 读的是当前目录里的 .env。没有这个文件：没有可核对的。
	directory := t.TempDir()
	t.Chdir(directory)
	if err := CheckEnvFiles(nil, unset); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, ".env"), []byte("POOL_DIR=/srv/pool # 池\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := CheckEnvFiles(nil, unset); !errors.Is(err, ErrEnvFile) || !strings.Contains(err.Error(), "env file .env, line 1: ") {
		t.Fatalf("得到 %v", err)
	}
	// 给了变量文件：docker compose 不再读当前目录里的那个，这里也不看它。
	if err := CheckEnvFiles([]string{envFile(t, "POOL_DIR=/srv/pool\n")}, unset); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, ".env"), []byte("POOL_DIR=/srv/pool\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := CheckEnvFiles(nil, unset); err != nil {
		t.Fatal(err)
	}
}

func TestAnEnvFileThatCannotBeReadIsNotTheSameMistake(t *testing.T) {
	// 给了却读不到：docker compose 到时也读不到它。这不是文件写得不对，可能过一会儿就读得到了。
	err := CheckEnvFiles([]string{filepath.Join(t.TempDir(), "missing.env")}, unset)
	if err == nil || errors.Is(err, ErrEnvFile) || !strings.Contains(err.Error(), "container: env file: ") {
		t.Fatalf("得到 %v", err)
	}
}
