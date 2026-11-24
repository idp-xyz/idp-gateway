package container

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"go.idp.xyz/idp-gateway/internal/gatewayconfig/domain"
)

// scripted 扮演 docker 命令行：按命令的头一个词（network、compose 再加一个词）答事先给好的，并记下每一条。
type scripted struct {
	answers   map[string]string
	errs      map[string]error
	commands  [][]string
	deadlines []time.Duration
	cancelled []bool
}

func (d *scripted) run(ctx context.Context, _ []string, argv ...string) (string, error) {
	d.commands = append(d.commands, argv)
	remaining := time.Duration(-1)
	if at, ok := ctx.Deadline(); ok {
		remaining = time.Until(at).Round(time.Second)
	}
	d.deadlines = append(d.deadlines, remaining)
	d.cancelled = append(d.cancelled, ctx.Err() != nil)
	key := argv[0]
	if key == "network" {
		key = "network " + argv[1]
	}
	if key == "compose" {
		for _, word := range []string{"config", "run", "up", "stop"} {
			if contains(argv, word) {
				key = "compose " + word
			}
		}
	}
	return d.answers[key], d.errs[key]
}

func contains(argv []string, word string) bool {
	for _, arg := range argv {
		if arg == word {
			return true
		}
	}
	return false
}

// inspected 是 docker inspect 按 servicesFormat 答的一行。networks 是 网络 ID -> 地址。
func inspected(name, service, oneOff string, running bool, status string, exitCode int, networks map[string]string) string {
	attached := map[string]map[string]string{}
	for network, address := range networks {
		attached["net-"+network[:4]] = map[string]string{"NetworkID": network, "IPAddress": address, "Gateway": "", "MacAddress": ""}
	}
	fields := []any{"/" + name, service, oneOff, running, status, exitCode, attached}
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

var (
	ownNetwork   = strings.Repeat("ab", 32)
	otherNetwork = strings.Repeat("cd", 32) // 别的项目的网络（比如本机 Gatekeeper 的那个，external）
)

func tendedProject() *scripted {
	ids := ""
	for n := 1; n <= 7; n++ {
		ids += id(n) + "\n"
	}
	return &scripted{answers: map[string]string{
		"ps": ids,
		"inspect": inspected("pool-netns-1", "netns", "False", true, "running", 0, map[string]string{ownNetwork: "172.30.0.2"}) +
			inspected("pool-gateway-authz-2", "gateway-authz", "False", true, "running", 0, map[string]string{ownNetwork: "172.30.0.6", otherNetwork: "172.19.0.8"}) +
			inspected("pool-gateway-authz-1", "gateway-authz", "False", true, "running", 0, map[string]string{ownNetwork: "172.30.0.5", otherNetwork: "172.19.0.7"}) +
			inspected("pool-authz-state-1", "authz-state", "False", false, "exited", 137, map[string]string{ownNetwork: ""}) +
			inspected("pool-egress-run-0a1b", "egress", "True", true, "running", 0, map[string]string{}) +
			// docker compose run 临时起的一个 gateway-authz：不是池里的。
			inspected("pool-gateway-authz-run-3c4d", "gateway-authz", "True", true, "running", 0, map[string]string{ownNetwork: "172.30.0.9"}) +
			inspected("pool-place-1", "place", "False", false, "exited", 0, map[string]string{}),
		"network ls": "WARNING: Error loading config file\n" + ownNetwork + "\n",
	}, errs: map[string]error{}}
}

func tendedPool(t *testing.T, docker *scripted) *Pool {
	t.Helper()
	pool, err := NewPool(PoolConfig{Project: "idp-gateway-pool", Timeout: 3 * time.Minute, Docker: docker.run,
		Files: []string{"compose.yml", "coordinators.yml"}, EnvFiles: []string{"/pool/pool.env"}})
	if err != nil {
		t.Fatal(err)
	}
	return pool
}

func TestServicesAreEveryContainerOfTheTendedServices(t *testing.T) {
	docker := tendedProject()
	services, err := tendedPool(t, docker).Services(ctx, []string{"gateway-authz", "authz-state", "sf-token-coordinator"})
	if err != nil {
		t.Fatal(err)
	}
	want := []domain.Service{
		// 两个副本，按名字排；地址只有这个项目的网络上的那一个。临时起的那个不算。
		{Name: "gateway-authz", Replicas: []domain.Replica{
			{Name: "pool-gateway-authz-1", Running: true, State: "running", Addresses: []string{"172.30.0.5"}},
			{Name: "pool-gateway-authz-2", Running: true, State: "running", Addresses: []string{"172.30.0.6"}},
		}},
		// 死了的：带着退出码，没有地址。
		{Name: "authz-state", Replicas: []domain.Replica{{Name: "pool-authz-state-1", State: "exited (137)"}}},
		// 一个容器都没有。
		{Name: "sf-token-coordinator"},
	}
	if !reflect.DeepEqual(services, want) {
		t.Fatalf("%+v", services)
	}
	// 先按项目名列出容器，一次问清它们，再列出项目的网络；都有期限。
	if len(docker.commands) != 3 ||
		!reflect.DeepEqual(docker.commands[0], []string{"ps", "-a", "-q", "--no-trunc", "--filter", "label=com.docker.compose.project=idp-gateway-pool"}) ||
		!reflect.DeepEqual(docker.commands[1][:3], []string{"inspect", "-f", servicesFormat}) || len(docker.commands[1]) != 3+7 ||
		!reflect.DeepEqual(docker.commands[2], []string{"network", "ls", "-q", "--no-trunc", "--filter", "label=com.docker.compose.project=idp-gateway-pool"}) {
		t.Fatalf("docker 命令是 %q", docker.commands)
	}
	for i, remaining := range docker.deadlines {
		if remaining != 30*time.Second {
			t.Fatalf("第 %d 条命令的期限是 %v", i+1, remaining)
		}
	}
	if strings.Count(servicesFormat, "\t") != 6 || !strings.Contains(servicesFormat, "{{json .NetworkSettings.Networks}}") || !strings.Contains(servicesFormat, `"com.docker.compose.oneoff"`) {
		t.Fatalf("%q", servicesFormat)
	}
}

func TestServicesOfAProjectWithoutContainersHaveNone(t *testing.T) {
	docker := &scripted{answers: map[string]string{"ps": "\n"}}
	services, err := tendedPool(t, docker).Services(ctx, []string{"gateway-authz"})
	if err != nil || !reflect.DeepEqual(services, []domain.Service{{Name: "gateway-authz"}}) || len(docker.commands) != 1 {
		t.Fatalf("%+v，%v，docker 命令是 %q", services, err, docker.commands)
	}
}

func TestServicesRefuseToGuess(t *testing.T) {
	failed := errors.New("exit status 1")
	for name, c := range map[string]struct {
		spoil func(*scripted)
		says  string
	}{
		"docker 够不着": {func(d *scripted) { d.answers["ps"], d.errs["ps"] = "Cannot connect to the Docker daemon\n", failed },
			"container: docker ps: exit status 1: Cannot connect to the Docker daemon"},
		"列出来的容器转眼被删了": {func(d *scripted) { d.errs["inspect"] = failed }, "container: docker inspect: exit status 1"},
		"网络列不出来": {func(d *scripted) { d.answers["network ls"], d.errs["network ls"] = "permission denied\n", failed },
			"container: docker network ls: exit status 1: permission denied"},
		"答的行数比问的容器少": {func(d *scripted) { d.answers["ps"] += id(8) + "\n" }, "described 7 of the 8 containers"},
		"一行里的项数不对":   {func(d *scripted) { d.answers["inspect"] += `"/x"` + "\t" + `"gateway-authz"` + "\n" }, "something unexpected"},
		"网络那一项不是 JSON 对象": {func(d *scripted) {
			d.answers["inspect"] = strings.Replace(d.answers["inspect"], `{"net-`, `["net-`, 1)
		}, "something unexpected"},
	} {
		docker := tendedProject()
		c.spoil(docker)
		services, err := tendedPool(t, docker).Services(ctx, []string{"gateway-authz"})
		if err == nil || !strings.Contains(err.Error(), c.says) || services != nil {
			t.Errorf("%s：%+v，%v", name, services, err)
		}
	}
}

func TestForgetIsTheEgressStepRunOnceMoreWithForget(t *testing.T) {
	docker := tendedProject()
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	// 叫停了也照样发出去：forget 开始之后，后面还要接着停网关、起网关。
	if err := tendedPool(t, docker).Forget(cancelled); err != nil {
		t.Fatal(err)
	}
	want := []string{"compose", "-p", "idp-gateway-pool", "--env-file", "/pool/pool.env", "-f", "compose.yml", "-f", "coordinators.yml",
		"run", "--rm", "--no-deps", "egress", "forget"}
	if len(docker.commands) != 1 || !reflect.DeepEqual(docker.commands[0], want) || docker.deadlines[0] != 3*time.Minute || docker.cancelled[0] {
		t.Fatalf("docker 命令是 %q，期限 %v，被叫停 %v", docker.commands, docker.deadlines, docker.cancelled)
	}
	if EgressService != "egress" {
		t.Fatal(EgressService)
	}
	docker.answers["compose run"] = "pin-egress: cannot read /work/config/config.yaml\n"
	docker.errs["compose run"] = errors.New("exit status 1")
	err := tendedPool(t, docker).Forget(ctx)
	if err == nil || err.Error() != "container: docker compose run --rm --no-deps egress forget: exit status 1: pin-egress: cannot read /work/config/config.yaml" {
		t.Fatalf("得到 %v", err)
	}
}

func TestDeclaredIsWhatTheComposeFilesName(t *testing.T) {
	docker := &scripted{answers: map[string]string{
		"compose config": "time=\"2026-11-24T09:00:00Z\" level=warning msg=\"a warning\"\nnetns\nplace\negress\nagentgateway\nconfirm\nfront\negress-watch\ngateway-authz\nauthz-state\n",
	}, errs: map[string]error{}}
	declared, err := tendedPool(t, docker).Declared(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(declared, []string{"netns", "place", "egress", "agentgateway", "confirm", "front", "egress-watch", "gateway-authz", "authz-state"}) {
		t.Fatalf("%q", declared)
	}
	want := []string{"compose", "-p", "idp-gateway-pool", "--env-file", "/pool/pool.env", "-f", "compose.yml", "-f", "coordinators.yml", "config", "--services"}
	if !reflect.DeepEqual(docker.commands, [][]string{want}) || docker.deadlines[0] != 30*time.Second {
		t.Fatalf("docker 命令是 %q，期限 %v", docker.commands, docker.deadlines)
	}
	// 文件里缺变量、文件不在：docker compose 说的最后一句交回去。
	docker.answers["compose config"] = "error while interpolating services.gateway-authz.command.[]: required variable GATEWAY_AUTHZ_USER is missing a value: see gateway-authz.env.example\n"
	docker.errs["compose config"] = errors.New("exit status 15")
	if _, err := tendedPool(t, docker).Declared(ctx); err == nil || !strings.HasPrefix(err.Error(), "container: docker compose config --services: exit status 15: error while interpolating") {
		t.Fatalf("得到 %v", err)
	}
}

func TestCheckTendedTakesOnlyServicesTheKeeperDoesNotAlreadyLookAt(t *testing.T) {
	if err := CheckTended([]string{"gateway-authz", "provider-signer", "signer", "sf-token-coordinator", "authz-state", "egress-watch", "a.b_c-1"}); err != nil {
		t.Fatal(err)
	}
	if err := CheckTended(nil); err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]struct {
		names []string
		says  string
	}{
		"空的":        {[]string{""}, `"": not a compose service name`},
		"像一个参数":     {[]string{"-f"}, "not a compose service name"},
		"有空格":       {[]string{"gateway authz"}, "not a compose service name"},
		"有斜杠":       {[]string{"a/b"}, "not a compose service name"},
		"太长":        {[]string{strings.Repeat("a", 129)}, "not a compose service name"},
		"占着命名空间的那个": {[]string{"netns"}, "the keeper always looks at netns, agentgateway and front"},
		"网关":        {[]string{"agentgateway"}, "always looks at"},
		"前置代理":      {[]string{"front"}, "always looks at"},
		"place":     {[]string{"place"}, "a step that runs to completion and exits (place, egress, confirm, signer-egress)"},
		"egress":    {[]string{"egress"}, "a step that runs to completion"},
		"confirm":   {[]string{"confirm"}, "a step that runs to completion"},
		"签名器的出口那一步": {[]string{"signer-egress"}, "a step that runs to completion"},
		"给了两次":      {[]string{"gateway-authz", "authz-state", "gateway-authz"}, `"gateway-authz": given more than once`},
	} {
		err := CheckTended(c.names)
		if !errors.Is(err, ErrTend) || !strings.Contains(err.Error(), c.says) {
			t.Errorf("%s：%v", name, err)
		}
	}
}
