package container

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

var ctx = context.Background()

// fakeDocker 扮演 docker 命令行：inspect 答事先给好的一行，别的命令只记下来。
type fakeDocker struct {
	inspect    string
	inspectErr error
	restartErr error
	block      bool // restart 一直不返回，直到它的 ctx 到期
	commands   [][]string
	deadline   time.Duration // restart 那条命令的 ctx 还剩多久
}

func (d *fakeDocker) run(ctx context.Context, _ []string, argv ...string) (string, error) {
	d.commands = append(d.commands, argv)
	switch argv[0] {
	case "inspect":
		return d.inspect, d.inspectErr
	case "restart":
		if err := ctx.Err(); err != nil {
			return "", err
		}
		if at, ok := ctx.Deadline(); ok {
			d.deadline = time.Until(at).Round(time.Second)
		}
		if d.block {
			<-ctx.Done()
			return "", ctx.Err()
		}
		if d.restartErr != nil {
			return "Error response from daemon: No such container: gateway\n", d.restartErr
		}
		return argv[len(argv)-1] + "\n", nil
	}
	return "", errors.New("unexpected docker command")
}

func open(t *testing.T, inspect string, stop time.Duration) (*Container, *fakeDocker, string) {
	t.Helper()
	dir := t.TempDir()
	docker := &fakeDocker{inspect: strings.ReplaceAll(inspect, "$DIR", dir)}
	c, err := New(Config{Name: "pool-gateway", ConfigDirectory: dir, Mount: "/work/config", StopTimeout: stop, Docker: docker.run})
	if err != nil {
		t.Fatal(err)
	}
	return c, docker, dir
}

const mounted = `true 60 [{"Type":"bind","Source":"/somewhere/tls","Destination":"/work/tls","RW":false},{"Type":"bind","Source":"$DIR","Destination":"/work/config","RW":false}]` + "\n"

func TestVerifyAcceptsTheContainerThatMountsThisConfigurationDirectory(t *testing.T) {
	c, docker, dir := open(t, mounted, 0)
	if err := c.Verify(ctx); err != nil {
		t.Fatal(err)
	}
	if len(docker.commands) != 1 || docker.commands[0][0] != "inspect" || docker.commands[0][len(docker.commands[0])-1] != "pool-gateway" {
		t.Fatalf("docker 命令是 %v", docker.commands)
	}

	// 经符号链接指到同一个目录的也算。
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(dir, link); err != nil {
		t.Fatal(err)
	}
	linked, err := New(Config{Name: "pool-gateway", ConfigDirectory: link, Mount: "/work/config", Docker: docker.run})
	if err != nil {
		t.Fatal(err)
	}
	if err := linked.Verify(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyRefusesAnyOtherContainer(t *testing.T) {
	for name, c := range map[string]struct{ inspect, says string }{
		"挂的是别的目录":    {`true null [{"Type":"bind","Source":"/another/pool/config","Destination":"/work/config"}]`, "/another/pool/config"},
		"那个位置上什么都没挂": {`true null [{"Type":"bind","Source":"$DIR","Destination":"/etc/front"}]`, "nothing mounted at /work/config"},
		"没有挂载":       {`true null []`, "nothing mounted at /work/config"},
		"挂的是卷不是目录":   {`true null [{"Type":"volume","Source":"$DIR","Destination":"/work/config"}]`, "not the configuration directory"},
		"没有在跑":       {strings.Replace(mounted, "true", "false", 1), "is not running"},
		"答的不是预期的东西":  {"something else entirely", "unexpected"},
		"答的是空的":      {"", "unexpected"},
	} {
		container, _, _ := open(t, c.inspect, 0)
		if err := container.Verify(ctx); err == nil || !strings.Contains(err.Error(), c.says) {
			t.Errorf("%s：得到 %v", name, err)
		}
	}
	container, docker, _ := open(t, "Error response from daemon: No such object: pool-gateway\n", 0)
	docker.inspectErr = errors.New("exit status 1")
	if err := container.Verify(ctx); err == nil || !strings.Contains(err.Error(), "No such object") {
		t.Fatalf("得到 %v", err)
	}
}

func TestRestartLeavesTheStopTimeoutToTheContainerUnlessToldOtherwise(t *testing.T) {
	// 不指定：命令里不带时限；等它的时间按容器自己设的 60 秒，再加 30 秒。
	c, docker, _ := open(t, mounted, 0)
	if err := c.Verify(ctx); err != nil {
		t.Fatal(err)
	}
	if err := c.Restart(ctx); err != nil {
		t.Fatal(err)
	}
	if got := docker.commands[len(docker.commands)-1]; !reflect.DeepEqual(got, []string{"restart", "pool-gateway"}) || docker.deadline != 90*time.Second {
		t.Fatalf("命令是 %v，最多等 %s", got, docker.deadline)
	}

	// 容器自己没有设：docker 用 10 秒。
	c, docker, _ = open(t, strings.Replace(mounted, "true 60", "true null", 1), 0)
	if err := c.Verify(ctx); err != nil {
		t.Fatal(err)
	}
	if err := c.Restart(ctx); err != nil || docker.deadline != 40*time.Second {
		t.Fatalf("%v，最多等 %s", err, docker.deadline)
	}

	// 指定了：带在命令里。
	c, docker, _ = open(t, mounted, 45*time.Second)
	if err := c.Restart(ctx); err != nil {
		t.Fatal(err)
	}
	if got := docker.commands[len(docker.commands)-1]; !reflect.DeepEqual(got, []string{"restart", "-t", "45", "pool-gateway"}) || docker.deadline != 75*time.Second {
		t.Fatalf("命令是 %v，最多等 %s", got, docker.deadline)
	}
}

func TestRestartIsNotCancelledHalfway(t *testing.T) {
	// 调用的人已经被叫停：命令照样发出去，照样等它做完。
	c, docker, _ := open(t, mounted, 0)
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if err := c.Restart(cancelled); err != nil || len(docker.commands) != 1 {
		t.Fatalf("%v，docker 命令是 %v", err, docker.commands)
	}

	// docker 说不行。
	c, docker, _ = open(t, mounted, 0)
	docker.restartErr = errors.New("exit status 1")
	if err := c.Restart(ctx); err == nil || !strings.Contains(err.Error(), "No such container") {
		t.Fatalf("得到 %v", err)
	}

	// 等到头了它还没有返回。
	c, docker, _ = open(t, mounted, time.Second)
	c.grace = 50 * time.Millisecond
	docker.block = true
	if err := c.Restart(ctx); err == nil || !strings.Contains(err.Error(), "did not return within") {
		t.Fatalf("得到 %v", err)
	}
}

func TestNewRefusesUnusableConfiguration(t *testing.T) {
	dir := t.TempDir()
	good := Config{Name: "pool-gateway", ConfigDirectory: dir, Mount: "/work/config"}
	if _, err := New(good); err != nil {
		t.Fatal(err)
	}
	for name, spoil := range map[string]func(*Config){
		"没有名字":      func(c *Config) { c.Name = "" },
		"名字像一个参数":   func(c *Config) { c.Name = "--all" },
		"名字里有空格":    func(c *Config) { c.Name = "a b" },
		"挂载点不是绝对路径": func(c *Config) { c.Mount = "work/config" },
		"停止时限不是整秒":  func(c *Config) { c.StopTimeout = 1500 * time.Millisecond },
		"停止时限是负的":   func(c *Config) { c.StopTimeout = -time.Second },
	} {
		bad := good
		spoil(&bad)
		if _, err := New(bad); err == nil {
			t.Errorf("%s：被接受了", name)
		}
	}
}
