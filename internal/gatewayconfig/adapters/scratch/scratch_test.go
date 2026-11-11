package scratch

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"go.idp.xyz/idp-gateway/internal/gatewayconfig/domain"
	"go.idp.xyz/idp-gateway/internal/gatewayconfig/ports"
)

const image = "cr.agentgateway.dev/agentgateway@sha256:60216aafb03d37f94e952ff3d51d2f630a65b10ecaebdc0a864882f92610c45b"

// fakeDocker 记下每一次 docker 命令，按表回答。
type fakeDocker struct {
	t        *testing.T
	calls    [][]string
	env      [][]string
	runErr   error
	states   []string // 依次回答 inspect；用完之后一直答最后一个
	logs     string
	sawFile  string // run 的那一刻，挂进去的目录里的配置文件
	mounted  string
	lastLive bool // 最后一次 rm 时 ctx 是否还活着
	onState  func()
}

func (f *fakeDocker) run(ctx context.Context, env []string, argv ...string) (string, error) {
	f.calls = append(f.calls, argv)
	f.env = append(f.env, env)
	switch argv[0] {
	case "rm":
		f.lastLive = ctx.Err() == nil
		return "", nil
	case "run":
		for i, arg := range argv {
			if arg == "-v" && strings.HasSuffix(argv[i+1], ":"+ConfigMount+":ro") {
				f.mounted = strings.TrimSuffix(argv[i+1], ":"+ConfigMount+":ro")
				content, err := os.ReadFile(filepath.Join(f.mounted, ConfigFile))
				if err != nil {
					f.t.Errorf("起容器时候选配置不在挂载的目录里：%v", err)
				}
				f.sawFile = string(content)
			}
		}
		if f.runErr != nil {
			return "docker: Error response from daemon: port is already allocated.\n", f.runErr
		}
		return "0123456789ab\n", nil
	case "inspect":
		if f.onState != nil {
			f.onState()
		}
		state := f.states[0]
		if len(f.states) > 1 {
			f.states = f.states[1:]
		}
		return state + "\n", nil
	case "logs":
		return f.logs, nil
	}
	f.t.Errorf("没有预料到的 docker 命令：%v", argv)
	return "", errors.New("unexpected")
}

// readBack 先失败几次，然后读到。
type readBack struct {
	failures int
	calls    int
}

func (r *readBack) Observe(context.Context) (domain.Observation, error) {
	r.calls++
	if r.calls <= r.failures {
		return domain.Observation{}, errors.New("connection refused")
	}
	return domain.Observation{Digest: "digest-of-the-candidate", Synchronized: true, StorageMode: domain.StorageReadOnly}, nil
}

func staging(t *testing.T, reader ports.ReadBack, fake *fakeDocker) (*Staging, Config) {
	t.Helper()
	fake.t = t
	config := Config{Image: image, Name: "idp-gateway-scratch", TLSDirectory: t.TempDir(), WorkDirectory: t.TempDir(),
		Publish: "127.0.0.1:27618", ContainerPort: 8443, User: "1000:1000", ReadBack: reader, StartTimeout: 300 * time.Millisecond,
		Docker: fake.run}
	s, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	s.pause = time.Millisecond
	return s, config
}

func snapshot(t *testing.T) domain.Snapshot {
	t.Helper()
	snapshot, err := domain.NewSnapshot([]byte("routes: []\n"))
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}

// leftBehind 检查临时容器被删了、候选配置的目录也没有留下。
func leftBehind(t *testing.T, fake *fakeDocker, config Config) {
	t.Helper()
	last := fake.calls[len(fake.calls)-1]
	if !reflect.DeepEqual(last, []string{"rm", "-f", config.Name}) || !fake.lastLive {
		t.Errorf("最后一条命令是 %v（ctx 活着=%t），应该是删掉临时容器", last, fake.lastLive)
	}
	if entries, err := os.ReadDir(config.WorkDirectory); err != nil || len(entries) != 0 {
		t.Errorf("候选配置的目录留下了 %v（err=%v）", entries, err)
	}
}

func TestLoadStartsTheImageOnTheCandidateAndReadsItBack(t *testing.T) {
	fake, reader := &fakeDocker{states: []string{"true 0"}}, &readBack{failures: 2}
	s, config := staging(t, reader, fake)

	observed, err := s.Load(context.Background(), snapshot(t))
	if err != nil {
		t.Fatal(err)
	}
	if observed.Digest != "digest-of-the-candidate" || reader.calls != 3 {
		t.Fatalf("%+v，读了 %d 次", observed, reader.calls)
	}
	if fake.sawFile != "routes: []\n" || !strings.HasPrefix(fake.mounted, config.WorkDirectory+string(filepath.Separator)) {
		t.Fatalf("起容器时的候选配置是 %q，在 %s", fake.sawFile, fake.mounted)
	}
	want := []string{"run", "-d", "--name", "idp-gateway-scratch",
		"--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
		"--user", "1000:1000",
		"-p", "127.0.0.1:27618:8443",
		"-v", fake.mounted + ":/work/config:ro",
		"-v", config.TLSDirectory + ":/work/tls:ro",
		"-w", "/work",
		"-e", "SESSION_KEY",
		image, "-f", "config/config.yaml"}
	if !reflect.DeepEqual(fake.calls[0], []string{"rm", "-f", config.Name}) || !reflect.DeepEqual(fake.calls[1], want) {
		t.Fatalf("前两条命令是\n%v\n%v", fake.calls[0], fake.calls[1])
	}
	// 会话密钥经环境传进去，是 64 个十六进制字符，命令行参数里没有它。
	env := fake.env[1]
	if len(env) != 1 || !strings.HasPrefix(env[0], "SESSION_KEY=") || len(env[0]) != len("SESSION_KEY=")+64 {
		t.Fatalf("环境是 %v", env)
	}
	if strings.Contains(strings.Join(fake.calls[1], " "), strings.TrimPrefix(env[0], "SESSION_KEY=")) {
		t.Fatal("会话密钥出现在了命令行参数里")
	}
	leftBehind(t, fake, config)
}

func TestAGatewayThatExitsOnTheCandidateIsARejection(t *testing.T) {
	fake := &fakeDocker{states: []string{"false 1"},
		logs: "2026-11-11T12:00:00Z info starting\nError: routes[2]: unknown field `notAFieldOfARoute` at line 45 column 3\n"}
	s, config := staging(t, &readBack{failures: 1 << 30}, fake)

	_, err := s.Load(context.Background(), snapshot(t))
	var rejected *ports.RejectedError
	if !errors.As(err, &rejected) || rejected.Reason != "routes[2]: unknown field `notAFieldOfARoute` at line 45 column 3" {
		t.Fatalf("得到 %v", err)
	}
	leftBehind(t, fake, config)
}

// 网关给的原因是日志里以 "Error: " 开头的那一行，不一定是最后一行。前两段是锁定的镜像退出前
// 写到标准错误上的原文：配置引用了一个不存在的文件，和配置引用了一个没有的环境变量。
func TestTheReasonIsWhatTheGatewaySaid(t *testing.T) {
	const (
		missingFile = "Error: routes[1]: read resource file /work/tls/missing.crt at line 35 column 3\n"
		noVariable  = "Error: error looking key 'UNDEFINED_VAR_X' up: environment variable not found\n\nCaused by:\n    environment variable not found\n"
		ready       = "2026-11-11T12:30:14.718293Z\tinfo\tagent_core::readiness\tTask 'state manager' complete (15.302577ms), marking server ready\t\n"
	)
	for logs, want := range map[string]string{
		missingFile: "routes[1]: read resource file /work/tls/missing.crt at line 35 column 3",
		noVariable:  "error looking key 'UNDEFINED_VAR_X' up: environment variable not found",
		// 标准输出上的日志排在它前面还是后面都一样。
		ready + missingFile: "routes[1]: read resource file /work/tls/missing.crt at line 35 column 3",
		missingFile + ready: "routes[1]: read resource file /work/tls/missing.crt at line 35 column 3",
		"Error: an earlier attempt\ninfo retrying\nError: the last one\n": "the last one",
		// 没有这样的行：取最后一行。
		"thread 'main' panicked\nnote: run with RUST_BACKTRACE=1\n": "note: run with RUST_BACKTRACE=1",
		"": "",
	} {
		fake := &fakeDocker{states: []string{"false 1"}, logs: logs}
		s, _ := staging(t, &readBack{failures: 1 << 30}, fake)
		_, err := s.Load(context.Background(), snapshot(t))
		var rejected *ports.RejectedError
		if !errors.As(err, &rejected) || rejected.Reason != want {
			t.Errorf("日志 %q：得到 %v，原因应该是 %q", logs, err, want)
		}
	}
}

func TestWhatIsNotARejectionIsNotReportedAsOne(t *testing.T) {
	var rejected *ports.RejectedError
	for name, c := range map[string]struct {
		fake   *fakeDocker
		reader *readBack
		want   string
	}{
		"容器起不来":        {&fakeDocker{runErr: errors.New("exit status 125"), states: []string{"true 0"}}, &readBack{}, "port is already allocated"},
		"网关以 0 退出":     {&fakeDocker{states: []string{"false 0"}, logs: "bye\n"}, &readBack{failures: 1 << 30}, "exited with code 0"},
		"网关在跑，回读口一直没答": {&fakeDocker{states: []string{"true 0"}}, &readBack{failures: 1 << 30}, "did not answer on its read-back listener"},
	} {
		s, config := staging(t, c.reader, c.fake)
		_, err := s.Load(context.Background(), snapshot(t))
		if err == nil || errors.As(err, &rejected) || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s：得到 %v", name, err)
		}
		leftBehind(t, c.fake, config)
	}

	// 没有内容的快照：不碰 docker。
	fake := &fakeDocker{states: []string{"true 0"}}
	s, _ := staging(t, &readBack{}, fake)
	if _, err := s.Load(context.Background(), domain.Snapshot{}); err == nil || len(fake.calls) != 0 {
		t.Fatalf("得到 %v，docker 命令 %v", err, fake.calls)
	}
}

func TestCancellationStillRemovesTheContainer(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fake := &fakeDocker{states: []string{"true 0"}}
	fake.onState = cancel // 容器起来之后、第一次看它的状态时被取消
	s, config := staging(t, &readBack{failures: 1 << 30}, fake)

	if _, err := s.Load(ctx, snapshot(t)); !errors.Is(err, context.Canceled) {
		t.Fatalf("得到 %v", err)
	}
	leftBehind(t, fake, config)
}

func TestNewRefusesAnUnsafeOrIncompleteConfiguration(t *testing.T) {
	good := Config{Image: image, Name: "scratch", TLSDirectory: t.TempDir(), WorkDirectory: t.TempDir(),
		Publish: "127.0.0.1:27618", ContainerPort: 8443, ReadBack: &readBack{}}
	s, err := New(good)
	if err != nil {
		t.Fatal(err)
	}
	if s.config.User == "" || s.config.StartTimeout != 20*time.Second || s.docker == nil {
		t.Fatalf("默认值：%+v", s.config)
	}
	file := filepath.Join(t.TempDir(), "a-file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*Config){
		"镜像按标签引用":       func(c *Config) { c.Image = "cr.agentgateway.dev/agentgateway:v1.7.0" },
		"镜像的摘要不完整":      func(c *Config) { c.Image = "cr.agentgateway.dev/agentgateway@sha256:6021" },
		"镜像只有摘要":        func(c *Config) { c.Image = strings.TrimPrefix(image, "cr.agentgateway.dev/agentgateway") },
		"回读口映射到所有网卡":    func(c *Config) { c.Publish = "0.0.0.0:27618" },
		"回读口映射到一个外部地址":  func(c *Config) { c.Publish = "192.0.2.10:27618" },
		"回读口的地址是主机名":    func(c *Config) { c.Publish = "localhost:27618" },
		"回读口的地址没有端口":    func(c *Config) { c.Publish = "127.0.0.1" },
		"容器里的端口为零":      func(c *Config) { c.ContainerPort = 0 },
		"容器没有名字":        func(c *Config) { c.Name = "" },
		"容器的名字像一个选项":    func(c *Config) { c.Name = "--privileged" },
		"证书目录是相对路径":     func(c *Config) { c.TLSDirectory = "." }, // 这个目录是有的，只是 docker 不认相对路径
		"放候选配置的地方是相对路径": func(c *Config) { c.WorkDirectory = "." },
		"证书目录不存在":       func(c *Config) { c.TLSDirectory = filepath.Join(c.TLSDirectory, "missing") },
		"放候选配置的地方是一个文件": func(c *Config) { c.WorkDirectory = file },
		"没有回读":          func(c *Config) { c.ReadBack = nil },
	} {
		config := good
		change(&config)
		if _, err := New(config); err == nil {
			t.Errorf("%s：被接受了", name)
		}
	}
}

// 离线加载用的容器，布局必须和池里的网关容器相同。compose 套件的 compose.yml 是目前唯一写着
// 池的布局的地方；deploy/compose 建起来之后，这里改成对着它核对。
func TestTheLayoutIsTheOneThePoolUses(t *testing.T) {
	raw, err := os.ReadFile("../../../../tests/integration/compose/compose.yml")
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range []string{
		"working_dir: " + WorkingDirectory,
		`command: ["-f", "` + ConfigArgument + `"]`,
		`/pool/config:` + ConfigMount + `:ro"`,
		`/pool/tls:` + TLSMount + `:ro"`,
	} {
		if strings.Count(string(raw), line) != 1 {
			t.Errorf("compose.yml 里没有恰好一处 %s", line)
		}
	}
	if ConfigArgument != strings.TrimPrefix(ConfigMount, WorkingDirectory+"/")+"/"+ConfigFile {
		t.Errorf("%s 不是 %s 里的 %s", ConfigArgument, ConfigMount, ConfigFile)
	}
}
