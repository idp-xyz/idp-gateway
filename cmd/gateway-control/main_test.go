package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"go.idp.xyz/idp-gateway/internal/gatewayconfig/adapters/directory"
	"go.idp.xyz/idp-gateway/internal/gatewayconfig/application"
	"go.idp.xyz/idp-gateway/internal/platform/workloadtls"
	"go.idp.xyz/idp-gateway/internal/platform/workloadtls/tlstest"
)

const (
	image        = "cr.agentgateway.dev/agentgateway@sha256:60216aafb03d37f94e952ff3d51d2f630a65b10ecaebdc0a864882f92610c45b"
	readBackName = "readback.gateway.idp.test"
	publisherID  = "spiffe://idp.test/gateway-control/publisher"
	configFile   = "config.yaml"

	// 假网关把配置文件原样当成它的 /config_dump，所以这里的"配置"直接写成 dump 的样子。
	one          = `{"config":{"terminationMaxDeadline":"45s"},"routes":["one"]}`
	two          = `{"config":{"terminationMaxDeadline":"45s"},"routes":["one","two"]}`
	unloadable   = `{"config":{"terminationMaxDeadline":"45s"},"routes":["one",{"notAFieldOfARoute":true}]}`
	needsRestart = `{"config":{"terminationMaxDeadline":"90s"},"routes":["one","two"]}`
	// 离线加载得了、池里的网关加载不了的：比如引用了一个只有离线加载那边才有的文件。
	onlyOffline = `{"config":{"terminationMaxDeadline":"45s"},"routes":["one","needs-a-file-the-pool-lacks"]}`
	// 池里的网关读到它之后，回读口再也不回答。
	silences = `{"config":{"terminationMaxDeadline":"45s"},"routes":["one","silences-the-read-back"]}`

	// 与 two 只差启动设置；与它启动设置相同、路由不同的另一份；要重启、池里却加载不了的一份。
	sameSettings      = `{"config":{"terminationMaxDeadline":"90s"},"routes":["one","two","three"]}`
	restartUnloadable = `{"config":{"terminationMaxDeadline":"120s"},"routes":["one","needs-a-file-the-pool-lacks"]}`

	gatewayContainer = "idp-gateway-test-pool-gateway"
	recordFile       = "." + configFile + ".confirmed"

	loadError = "routes[1]: unknown field `notAFieldOfARoute` at line 1 column 70"
)

// fakeGateway 是一个假的网关回读口。每次被问到，它先把 file() 指着的文件"重载"一遍；
// 加载不了的文件它报告加载失败，继续跑之前的那一份。
type fakeGateway struct {
	mu       sync.Mutex
	file     func() string // 空串表示这个网关没有在跑
	refuses  []string      // 内容里有这些词的文件，这个网关加载不了
	fragile  bool          // 读到 silences 那样的文件之后，回读口再也不回答
	running  string
	failure  string
	silenced bool
	peers    map[string]bool
	// keepsStartup：config 段只在启动时读，之后换文件不跟着变（池里的网关）。
	// 为假时每次都跟着文件走：临时网关每次都是新起的。
	keepsStartup bool
	startup      json.RawMessage // 启动时读到的 config 段
	down         bool            // 重启时拿到的是一份加载不了的文件：没有起来
	restarts     int
	requests     int // 回读口被问过几次
}

// restart 让网关从现在的文件重新启动。文件加载不了，它就起不来。
func (g *fakeGateway) restart() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.restarts++
	g.startup, g.running, g.failure, g.down = nil, "", "", false
	content, err := os.ReadFile(g.file())
	if err != nil {
		g.down = true
		return
	}
	for _, word := range g.refuses {
		if strings.Contains(string(content), word) {
			g.down = true
		}
	}
}

func (g *fakeGateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.requests++
	g.peers[workloadtls.PeerIdentity(r.TLS)] = true
	path := g.file()
	if path == "" || g.down {
		http.Error(w, "not running", http.StatusServiceUnavailable)
		return
	}
	if content, err := os.ReadFile(path); err == nil {
		g.load(string(content))
	}
	if g.silenced {
		http.Error(w, "broken", http.StatusInternalServerError)
		return
	}
	switch r.URL.Path {
	case "/config_dump":
		_, _ = io.WriteString(w, g.running)
	case "/api/runtime":
		reload := map[string]any{"synchronized": g.failure == "", "lastError": nil}
		if g.failure != "" {
			reload["lastError"] = g.failure
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"build":        map[string]any{"version": "1.7.0", "gitRevision": "26f5aebe99a36a037fe54f8080a608aca5547e15"},
			"ui":           map[string]any{"gatewayMode": "standalone", "configStoreMode": "readOnly"},
			"configReload": reload,
		})
	default:
		http.NotFound(w, r)
	}
}

func (g *fakeGateway) load(content string) {
	if g.fragile && strings.Contains(content, "silences-the-read-back") {
		g.silenced = true
	}
	for _, word := range g.refuses {
		if strings.Contains(content, word) {
			g.failure = loadError
			return
		}
	}
	if g.keepsStartup {
		var document map[string]json.RawMessage
		if err := json.Unmarshal([]byte(content), &document); err == nil {
			if g.startup == nil {
				g.startup = document["config"]
			}
			document["config"] = g.startup
			if rewritten, err := json.Marshal(document); err == nil {
				content = string(rewritten)
			}
		}
	}
	g.running, g.failure = content, ""
}

// setting 是网关报告的启动设置里的那一项。
func (g *fakeGateway) setting() string {
	g.mu.Lock()
	defer g.mu.Unlock()
	var document struct {
		Config map[string]string `json:"config"`
	}
	_ = json.Unmarshal([]byte(g.running), &document)
	return document.Config["terminationMaxDeadline"]
}

// asked 是回读口到现在被问过几次。
func (g *fakeGateway) asked() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.requests
}

func (g *fakeGateway) sawOnly(identity string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.peers) == 1 && g.peers[identity]
}

// fakeDocker 扮演 docker 命令行：记下候选配置挂在哪里，网关加载不了的候选配置让"容器"退出。
type fakeDocker struct {
	mu        sync.Mutex
	candidate string
	commands  []string
	runErr    error
	// 池里的网关容器：它挂着哪个目录，重启它时叫谁。
	mounted string
	gateway *fakeGateway
	// restarted 是最近一条 docker restart 的全部参数。
	restarted []string
}

func (d *fakeDocker) run(_ context.Context, _ []string, argv ...string) (string, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.commands = append(d.commands, argv[0])
	switch argv[0] {
	case "rm":
		d.candidate = ""
	case "run":
		if d.runErr != nil {
			return "docker: Error response from daemon: port is already allocated.\n", d.runErr
		}
		for i, arg := range argv {
			if arg == "-v" && strings.HasSuffix(argv[i+1], ":/work/config:ro") {
				d.candidate = strings.TrimSuffix(argv[i+1], ":/work/config:ro")
			}
		}
	case "restart":
		if argv[len(argv)-1] != gatewayContainer {
			return "Error response from daemon: No such container: " + argv[len(argv)-1] + "\n", errors.New("exit status 1")
		}
		d.restarted = append([]string(nil), argv...)
		d.gateway.restart()
	case "inspect":
		if strings.Contains(argv[2], ".Mounts") { // 问的是池里的网关容器
			if argv[len(argv)-1] != gatewayContainer {
				return "Error response from daemon: No such object: " + argv[len(argv)-1] + "\n", errors.New("exit status 1")
			}
			return `true 60 [{"Type":"bind","Source":"` + d.mounted + `","Destination":"/work/config","RW":false}]` + "\n", nil
		}
		content, _ := os.ReadFile(filepath.Join(d.candidate, configFile))
		if strings.Contains(string(content), "notAFieldOfARoute") {
			return "false 1\n", nil
		}
		return "true 0\n", nil
	case "logs":
		return "info starting\nError: " + loadError + "\n", nil
	}
	return "", nil
}

func (d *fakeDocker) file() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.candidate == "" {
		return ""
	}
	return filepath.Join(d.candidate, configFile)
}

func (d *fakeDocker) last() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.commands) == 0 {
		return ""
	}
	return d.commands[len(d.commands)-1]
}

type harness struct {
	t         *testing.T
	ca        *tlstest.CA
	publisher tlstest.Leaf
	poolDir   string
	workDir   string
	tlsDir    string
	snapshots string
	pool      *fakeGateway
	scratch   *fakeGateway
	docker    *fakeDocker
	poolAddr  string
	stageAddr string
	timeout   string
}

// serve 起一个要客户端证书的回读口，返回它的地址。
func serve(t *testing.T, ca *tlstest.CA, name string, gateway *fakeGateway) string {
	t.Helper()
	leaf := ca.Issue("readback-"+name, nil, readBackName)
	config, err := workloadtls.ServerConfig(leaf.CertFile, leaf.KeyFile, ca.File())
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	gateway.peers = map[string]bool{}
	server := &http.Server{Handler: gateway, TLSConfig: config, ReadTimeout: 5 * time.Second, ErrorLog: log.New(io.Discard, "", 0)}
	go func() { _ = server.ServeTLS(listener, "", "") }()
	t.Cleanup(func() { _ = server.Close() })
	return listener.Addr().String()
}

// newHarness 布置一个池：配置目录里放着 one，池里的假网关在跑它。
func newHarness(t *testing.T) *harness {
	t.Helper()
	ca := tlstest.NewCA(t, "workload CA")
	h := &harness{
		t: t, ca: ca, publisher: ca.Issue("publisher", []string{publisherID}),
		poolDir: t.TempDir(), workDir: t.TempDir(), tlsDir: t.TempDir(), snapshots: t.TempDir(),
		docker: &fakeDocker{}, timeout: "3s",
	}
	h.place(one)
	h.pool = &fakeGateway{
		file:    func() string { return filepath.Join(h.poolDir, configFile) },
		refuses: []string{"notAFieldOfARoute", "needs-a-file-the-pool-lacks"},
		fragile: true, keepsStartup: true,
	}
	h.docker.mounted, h.docker.gateway = h.poolDir, h.pool
	h.scratch = &fakeGateway{file: h.docker.file}
	h.poolAddr = serve(t, ca, "pool", h.pool)
	h.stageAddr = serve(t, ca, "scratch", h.scratch)
	return h
}

// place 绕过发布器，直接往池的配置目录里放一个文件。
func (h *harness) place(content string) {
	h.t.Helper()
	if err := os.WriteFile(filepath.Join(h.poolDir, configFile), []byte(content), 0o644); err != nil {
		h.t.Fatal(err)
	}
}

func (h *harness) inPlace() string {
	h.t.Helper()
	content, err := os.ReadFile(filepath.Join(h.poolDir, configFile))
	if err != nil {
		h.t.Fatal(err)
	}
	return string(content)
}

// leftovers 列出配置目录里除配置文件、锁文件和记录之外的东西，和放候选配置的目录里的东西。
func (h *harness) leftovers() []string {
	h.t.Helper()
	var names []string
	for _, dir := range []string{h.poolDir, h.workDir} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			h.t.Fatal(err)
		}
		for _, entry := range entries {
			if name := entry.Name(); name != configFile && name != "."+configFile+".lock" && name != recordFile {
				names = append(names, name)
			}
		}
	}
	return names
}

func (h *harness) snapshot(content string) string {
	h.t.Helper()
	path := filepath.Join(h.snapshots, "snapshot-"+id(content)[:12]+".json")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		h.t.Fatal(err)
	}
	return path
}

func (h *harness) args(snapshot string) []string {
	return []string{"publish", "--snapshot", snapshot, "--config-dir", h.poolDir, "--image", image,
		"--read-back", h.poolAddr, "--read-back-name", readBackName,
		"--tls-cert", h.publisher.CertFile, "--tls-key", h.publisher.KeyFile, "--tls-ca", h.ca.File(),
		"--staging-publish", h.stageAddr, "--staging-container-port", "8443",
		"--staging-tls-dir", h.tlsDir, "--staging-work-dir", h.workDir, "--staging-name", "idp-gateway-test-scratch",
		"--staging-timeout", "10s", "--settle", "20ms", "--timeout", h.timeout}
}

// replaced 把 args 里某个参数的值换掉。
func replaced(args []string, flag, value string) []string {
	changed := append([]string(nil), args...)
	for i := range changed {
		if changed[i] == flag {
			changed[i+1] = value
		}
	}
	return changed
}

type result struct {
	code   int
	stdout string
	stderr string
	report outcome
}

func (h *harness) run(args []string) result {
	h.t.Helper()
	var stdout, stderr bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	r := result{code: run(ctx, args, &stdout, &stderr, h.docker.run)}
	r.stdout, r.stderr = stdout.String(), stderr.String()
	if r.stdout != "" {
		if err := json.Unmarshal(stdout.Bytes(), &r.report); err != nil {
			h.t.Fatalf("标准输出不是 JSON：%q", r.stdout)
		}
	}
	return r
}

func (h *harness) publish(content string) result {
	h.t.Helper()
	return h.run(h.args(h.snapshot(content)))
}

// restartArgs 是 restart 的参数：与 publish 的相同，另外指出池里的网关容器。snapshot 为空时不给快照。
func (h *harness) restartArgs(snapshot string) []string {
	args := []string{"restart", "--container", gatewayContainer}
	if snapshot != "" {
		args = append(args, "--snapshot", snapshot)
	}
	return append(args, h.args("-")[3:]...)
}

func (h *harness) restart(content string) result {
	h.t.Helper()
	return h.run(h.restartArgs(h.snapshot(content)))
}

func (h *harness) reconcileArgs() []string {
	return []string{"reconcile", "--config-dir", h.poolDir, "--read-back", h.poolAddr, "--read-back-name", readBackName,
		"--tls-cert", h.publisher.CertFile, "--tls-key", h.publisher.KeyFile, "--tls-ca", h.ca.File(),
		"--settle", "20ms", "--timeout", h.timeout}
}

func (h *harness) reconcile() result {
	h.t.Helper()
	return h.run(h.reconcileArgs())
}

// placeArgs 是 place 命令的参数：只有配置目录。（harness.place 是另一回事：测试绕过发布器直接放文件。）
func (h *harness) placeArgs() []string {
	return []string{"place", "--config-dir", h.poolDir}
}

// count 数某条 docker 命令被叫过几次。
func (d *fakeDocker) count(command string) int {
	d.mu.Lock()
	defer d.mu.Unlock()
	n := 0
	for _, name := range d.commands {
		if name == command {
			n++
		}
	}
	return n
}

func id(content string) string {
	sum := sha256.Sum256([]byte(content))
	return hex.EncodeToString(sum[:])
}

func TestPublishesASnapshotAndReportsIt(t *testing.T) {
	h := newHarness(t)

	r := h.publish(two)
	if r.code != exitActive || r.stderr != "" {
		t.Fatalf("退出码 %d，标准错误 %q，标准输出 %s", r.code, r.stderr, r.stdout)
	}
	if h.inPlace() != two || len(h.leftovers()) != 0 {
		t.Fatalf("配置目录里是 %q，另外留下了 %v", h.inPlace(), h.leftovers())
	}
	got := r.report
	if got.Outcome != "ACTIVE" || got.Reason != "" || !got.Replaced || got.Snapshot != id(two) || got.Previous != id(one) {
		t.Fatalf("%+v", got)
	}
	if got.Observed == nil || got.ExpectedDigest == "" || got.Observed.Digest != got.ExpectedDigest || !got.Observed.Synchronized ||
		got.Observed.StorageMode != "readOnly" || got.Observed.Version != "1.7.0" || len(got.Restart) != 0 {
		t.Fatalf("%+v / %+v", got, got.Observed)
	}
	// 输出里的名字是给别的程序读的，不随 Go 里的名字变。
	var raw map[string]any
	if err := json.Unmarshal([]byte(r.stdout), &raw); err != nil {
		t.Fatal(err)
	}
	var keys []string
	for key := range raw {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	if want := []string{"expected_digest", "observed", "outcome", "previous", "reason", "replaced", "restart", "restarted", "snapshot"}; !reflect.DeepEqual(keys, want) {
		t.Fatalf("输出的键是 %v", keys)
	}
	if restart, ok := raw["restart"].([]any); !ok || len(restart) != 0 {
		t.Fatalf("restart 应该是空数组，得到 %v", raw["restart"])
	}
	// 两个回读口见到的都只有发布器的证书；离线加载用的容器最后被删了。
	if !h.pool.sawOnly(publisherID) || !h.scratch.sawOnly(publisherID) || h.docker.last() != "rm" {
		t.Fatalf("池见到 %v，临时网关见到 %v，最后一条 docker 命令是 %q", h.pool.peers, h.scratch.peers, h.docker.last())
	}

	// 再发布一次同一份：已经在生效，不再写。
	before, err := os.Stat(filepath.Join(h.poolDir, configFile))
	if err != nil {
		t.Fatal(err)
	}
	again := h.publish(two)
	after, err := os.Stat(filepath.Join(h.poolDir, configFile))
	if err != nil {
		t.Fatal(err)
	}
	if again.code != exitActive || again.report.Outcome != "ACTIVE" || again.report.Replaced || again.report.Previous != id(two) || !os.SameFile(before, after) {
		t.Fatalf("退出码 %d，%+v", again.code, again.report)
	}
}

func TestWhatIsNotPublishedLeavesThePoolAlone(t *testing.T) {
	h := newHarness(t)

	refused := h.publish(unloadable)
	if refused.code != exitNotDone || refused.report.Outcome != "REFUSED" || refused.report.Reason != loadError ||
		refused.report.Replaced || refused.report.Observed != nil || refused.report.ExpectedDigest != "" {
		t.Fatalf("加载不了的：退出码 %d，%s%s", refused.code, refused.stdout, refused.stderr)
	}
	if !strings.Contains(refused.stdout, `"observed": null`) {
		t.Fatalf("没有读过池时 observed 应该是 null：%s", refused.stdout)
	}

	// 带环境变量的：不用起容器就拒绝。
	commands := len(h.docker.commands)
	environment := h.publish(`{"config":{"terminationMaxDeadline":"45s"},"routes":["one","tenant-$HOSTNAME"]}`)
	if environment.code != exitNotDone || environment.report.Outcome != "REFUSED" || !strings.Contains(environment.report.Reason, "($HOSTNAME)") ||
		environment.report.Replaced || len(h.docker.commands) != commands {
		t.Fatalf("带环境变量的：退出码 %d，%s%s", environment.code, environment.stdout, environment.stderr)
	}

	restart := h.publish(needsRestart)
	if restart.code != exitNotDone || restart.report.Outcome != "RESTART_REQUIRED" || restart.report.Replaced ||
		!reflect.DeepEqual(restart.report.Restart, []string{"terminationMaxDeadline"}) || restart.report.Observed == nil {
		t.Fatalf("要重启的：退出码 %d，%s%s", restart.code, restart.stdout, restart.stderr)
	}
	if h.inPlace() != one || len(h.leftovers()) != 0 {
		t.Fatalf("配置目录里是 %q，另外留下了 %v", h.inPlace(), h.leftovers())
	}

	// 有人绕过发布器，往目录里放了一个网关加载不了的文件：池不在已知的状态，先不动它。
	h.place(unloadable)
	unclean := h.publish(two)
	if unclean.code != exitNotDone || unclean.report.Outcome != "POOL_NOT_READY" || unclean.report.Replaced ||
		!strings.Contains(unclean.report.Reason, loadError) || unclean.report.Observed == nil || unclean.report.Observed.Synchronized {
		t.Fatalf("池不干净：退出码 %d，%s%s", unclean.code, unclean.stdout, unclean.stderr)
	}
	if h.inPlace() != unloadable || len(h.leftovers()) != 0 {
		t.Fatalf("配置目录里是 %q，另外留下了 %v", h.inPlace(), h.leftovers())
	}
}

func TestASnapshotThatDoesNotTakeEffectIsTakenBack(t *testing.T) {
	h := newHarness(t)

	restored := h.publish(onlyOffline)
	got := restored.report
	if restored.code != exitRestored || got.Outcome != "RESTORED" || !got.Replaced || !strings.Contains(got.Reason, loadError) ||
		got.Snapshot != id(onlyOffline) || got.Previous != id(one) {
		t.Fatalf("退出码 %d，%s%s", restored.code, restored.stdout, restored.stderr)
	}
	// 上一份回到了目录里，网关报告它在跑的是上一份，上一次加载是成功的。
	if h.inPlace() != one || len(h.leftovers()) != 0 {
		t.Fatalf("配置目录里是 %q，另外留下了 %v", h.inPlace(), h.leftovers())
	}
	if got.Observed == nil || !got.Observed.Synchronized || got.Observed.Digest == got.ExpectedDigest || got.Observed.Digest == "" {
		t.Fatalf("%+v", got.Observed)
	}
	// 之后照常能发布。
	if next := h.publish(two); next.code != exitActive || h.inPlace() != two {
		t.Fatalf("之后的发布：退出码 %d，%s%s", next.code, next.stdout, next.stderr)
	}

	// 换上去之后回读口再也不回答：上一份放回去了，但确认不了。
	h.timeout = "300ms"
	unknown := h.publish(silences)
	if unknown.code != exitUnknown || unknown.report.Outcome != "UNKNOWN" || !unknown.report.Replaced ||
		!strings.Contains(unknown.report.Reason, "put back but not confirmed") {
		t.Fatalf("退出码 %d，%s%s", unknown.code, unknown.stdout, unknown.stderr)
	}
	if h.inPlace() != two || len(h.leftovers()) != 0 {
		t.Fatalf("配置目录里是 %q，另外留下了 %v", h.inPlace(), h.leftovers())
	}
}

func TestTheScratchGatewayCanHaveItsOwnCertificates(t *testing.T) {
	h := newHarness(t)
	// 离线加载那边用另一套 CA、另一个名字、另一张发布器证书。
	const stagingName, stagingID = "readback.staging.idp.test", "spiffe://idp.test/gateway-control/staging"
	other := tlstest.NewCA(t, "staging CA")
	leaf := other.Issue("staging-readback", nil, stagingName)
	config, err := workloadtls.ServerConfig(leaf.CertFile, leaf.KeyFile, other.File())
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	scratch := &fakeGateway{file: h.docker.file, peers: map[string]bool{}}
	server := &http.Server{Handler: scratch, TLSConfig: config, ReadTimeout: 5 * time.Second, ErrorLog: log.New(io.Discard, "", 0)}
	go func() { _ = server.ServeTLS(listener, "", "") }()
	t.Cleanup(func() { _ = server.Close() })
	client := other.Issue("staging-publisher", []string{stagingID})

	args := append(replaced(h.args(h.snapshot(two)), "--staging-publish", listener.Addr().String()),
		"--staging-read-back-name", stagingName,
		"--staging-tls-cert", client.CertFile, "--staging-tls-key", client.KeyFile, "--staging-tls-ca", other.File())
	r := h.run(args)
	if r.code != exitActive || r.report.Outcome != "ACTIVE" || h.inPlace() != two {
		t.Fatalf("退出码 %d，%s%s", r.code, r.stdout, r.stderr)
	}
	if !scratch.sawOnly(stagingID) || !h.pool.sawOnly(publisherID) || len(h.scratch.peers) != 0 {
		t.Fatalf("临时网关见到 %v，池见到 %v", scratch.peers, h.pool.peers)
	}

	// 只换了地址、没换证书时，池的那一套在这个临时网关上通不过：没有发布。
	mismatched := h.run(replaced(replaced(h.args(h.snapshot(one)), "--staging-publish", listener.Addr().String()), "--staging-timeout", "300ms"))
	if mismatched.code != exitError || mismatched.stdout != "" || !strings.Contains(mismatched.stderr, "did not answer on its read-back listener within 300ms") || h.inPlace() != two {
		t.Fatalf("退出码 %d，%s%s", mismatched.code, mismatched.stdout, mismatched.stderr)
	}
}

func TestFailsBeforeTouchingThePool(t *testing.T) {
	h := newHarness(t)
	good := h.args(h.snapshot(two))
	empty := filepath.Join(h.snapshots, "empty.json")
	if err := os.WriteFile(empty, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	// 一个没有人在听的回环地址。
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	nobody := listener.Addr().String()
	_ = listener.Close()

	cases := []struct {
		name string
		args []string
		says string
	}{
		{"快照文件不存在", replaced(good, "--snapshot", filepath.Join(h.snapshots, "missing.json")), "missing.json"},
		{"快照文件是空的", replaced(good, "--snapshot", empty), "empty.json"},
		{"配置目录不存在", replaced(good, "--config-dir", filepath.Join(h.poolDir, "missing")), "directory:"},
		{"镜像按标签引用", replaced(good, "--image", "cr.agentgateway.dev/agentgateway:v1.7.0"), "not referenced by digest"},
		{"临时网关的回读口映射到所有网卡", replaced(good, "--staging-publish", "0.0.0.0:27618"), "loopback"},
		{"放候选配置的目录是相对路径", replaced(good, "--staging-work-dir", "work"), "absolute path"},
		{"发布器的证书不存在", replaced(good, "--tls-cert", filepath.Join(h.snapshots, "missing.crt")), "read-back of the pool"},
		{"证书与私钥不配对", replaced(good, "--tls-key", h.ca.Issue("someone-else", nil).KeyFile), "read-back of the pool"},
		{"回读口的地址没有端口", replaced(good, "--read-back", "127.0.0.1"), "read-back of the pool"},
		{"等的时限比沉淀期短", replaced(good, "--timeout", "10ms"), "unusable timing"},
		{"池的回读口没有人在听", replaced(good, "--read-back", nobody), "read-back before publishing"},
		{"池的回读口不是这个名字", append(replaced(good, "--read-back-name", "other.idp.test"), "--staging-read-back-name", readBackName), "read-back before publishing"},
		{"临时网关的回读口不是这个名字", append(replaced(good, "--staging-timeout", "300ms"), "--staging-read-back-name", "other.idp.test"), "did not answer on its read-back listener within 300ms"},
	}
	for _, c := range cases {
		r := h.run(c.args)
		if r.code != exitError || r.stdout != "" || !strings.Contains(r.stderr, c.says) || !strings.HasPrefix(r.stderr, "gateway-control: ") {
			t.Errorf("%s：退出码 %d，标准输出 %q，标准错误 %q", c.name, r.code, r.stdout, r.stderr)
		}
		if h.inPlace() != one || len(h.leftovers()) != 0 {
			t.Fatalf("%s：配置目录里是 %q，另外留下了 %v", c.name, h.inPlace(), h.leftovers())
		}
	}

	// 起不了离线加载用的容器。
	h.docker.runErr = errors.New("exit status 125")
	if r := h.run(good); r.code != exitError || r.stdout != "" || !strings.Contains(r.stderr, "port is already allocated") || h.inPlace() != one {
		t.Errorf("容器起不来：退出码 %d，%q %q", r.code, r.stdout, r.stderr)
	}
	h.docker.runErr = nil

	// 另一次发布正拿着这个池。
	delivery, err := directory.New(h.poolDir, configFile)
	if err != nil {
		t.Fatal(err)
	}
	release, err := delivery.Hold(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	busy := h.run(good)
	release()
	if busy.code != exitError || busy.stdout != "" || !strings.Contains(busy.stderr, "another publication") || h.inPlace() != one {
		t.Errorf("池被占着：退出码 %d，%q %q", busy.code, busy.stdout, busy.stderr)
	}
	// 放开之后同一条命令成功：上面各条挡下它的不是别的原因。
	if r := h.run(good); r.code != exitActive || h.inPlace() != two {
		t.Fatalf("对照：退出码 %d，%s%s", r.code, r.stdout, r.stderr)
	}
}

func TestUsage(t *testing.T) {
	h := newHarness(t)
	good := h.args(h.snapshot(two))
	without := func(flag string) []string {
		var args []string
		for i := 1; i < len(good); i += 2 {
			if good[i] != flag {
				args = append(args, good[i], good[i+1])
			}
		}
		return append([]string{"publish"}, args...)
	}
	cases := []struct {
		name string
		args []string
		says string
	}{
		{"没有参数", nil, "usage: gateway-control publish"},
		{"不认识的子命令", []string{"apply"}, "usage: gateway-control publish"},
		{"子命令之前有参数", append([]string{"--snapshot"}, good...), "usage: gateway-control publish"},
		{"只有子命令", []string{"publish"}, "missing required flags: --config-dir, --image, --read-back, --read-back-name, --snapshot, " +
			"--staging-name, --staging-publish, --staging-tls-dir, --staging-work-dir, --tls-ca, --tls-cert, --tls-key, --staging-container-port"},
		{"没有快照", without("--snapshot"), "missing required flags: --snapshot\n"},
		{"没有镜像", without("--image"), "missing required flags: --image\n"},
		{"没有容器里的端口", without("--staging-container-port"), "missing required flags: --staging-container-port\n"},
		{"多余的参数", append(append([]string(nil), good...), "now"), `unexpected argument "now"`},
		{"不认识的参数", append(append([]string(nil), good...), "--force"), "flag provided but not defined: -force"},
		{"时限不是时长", replaced(good, "--timeout", "soon"), "invalid value"},
		{"等临时网关的时限为零", replaced(good, "--staging-timeout", "0s"), "--staging-timeout must be positive"},
		{"临时网关的证书只给了一半", append(append([]string(nil), good...), "--staging-tls-cert", h.publisher.CertFile), "go together"},
		{"要帮助", []string{"publish", "--help"}, "-staging-container-port"},
	}
	for _, c := range cases {
		r := h.run(c.args)
		if r.code != exitUsage || r.stdout != "" || !strings.Contains(r.stderr, c.says) {
			t.Errorf("%s：退出码 %d，标准输出 %q，标准错误 %q", c.name, r.code, r.stdout, r.stderr)
		}
	}
	if h.inPlace() != one || len(h.docker.commands) != 0 || len(h.pool.peers) != 0 {
		t.Fatalf("用法不对时不该做任何事：目录里是 %q，docker 命令 %v，池见到 %v", h.inPlace(), h.docker.commands, h.pool.peers)
	}
}

func TestExitCodesSayWhatStateThePoolIsIn(t *testing.T) {
	want := map[application.Outcome]int{
		application.OutcomeActive:          0,
		application.OutcomeRefused:         3,
		application.OutcomeRestartRequired: 3,
		application.OutcomePoolNotReady:    3,
		application.OutcomeRestored:        4,
		application.OutcomeUnknown:         5,
		application.OutcomeInSync:          0,
		application.OutcomeUnconfirmed:     3,
		application.OutcomeRestartPending:  6,
		application.OutcomeInPlace:         0,
		application.OutcomeNoRecord:        0,
		// 这里不认识的结局不当成成功，也不当成"池没有被碰过"。
		"SOMETHING_NEW": 5,
		"":              5,
	}
	for outcome, code := range want {
		if got := exitCode(outcome); got != code {
			t.Errorf("%q 的退出码是 %d，应该是 %d", outcome, got, code)
		}
	}
}

// 对账：池和记录对不上时，把最后一次得到确认的那一份放回去。它不用 docker。
func TestReconcilePutsTheConfirmedSnapshotBack(t *testing.T) {
	h := newHarness(t)

	// 这个池上还没有确认过任何发布：没有可对的。
	none := h.reconcile()
	if none.code != exitNotDone || none.report.Outcome != "UNCONFIRMED" || none.report.Replaced || none.report.Snapshot != "" ||
		none.report.Previous != id(one) || none.report.Observed == nil || h.inPlace() != one {
		t.Fatalf("没有记录：退出码 %d，%s%s", none.code, none.stdout, none.stderr)
	}

	if r := h.publish(two); r.code != exitActive {
		t.Fatalf("发布：退出码 %d，%s%s", r.code, r.stdout, r.stderr)
	}
	before, err := os.Stat(filepath.Join(h.poolDir, configFile))
	if err != nil {
		t.Fatal(err)
	}
	same := h.reconcile()
	after, err := os.Stat(filepath.Join(h.poolDir, configFile))
	if err != nil {
		t.Fatal(err)
	}
	if same.code != exitActive || same.report.Outcome != "IN_SYNC" || same.report.Replaced || same.report.Reason != "" ||
		same.report.Snapshot != id(two) || same.report.Previous != id(two) || !os.SameFile(before, after) {
		t.Fatalf("对得上：退出码 %d，%s%s", same.code, same.stdout, same.stderr)
	}
	if same.report.Observed == nil || same.report.ExpectedDigest == "" || same.report.Observed.Digest != same.report.ExpectedDigest {
		t.Fatalf("%+v / %+v", same.report, same.report.Observed)
	}

	// 发布器把文件换上去之后死了（这里由测试直接放一份网关加载得了的文件）：放在那里的没有人确认过。
	h.place(one)
	blocked := h.publish(sameSettings)
	if blocked.code != exitNotDone || blocked.report.Outcome != "POOL_NOT_READY" || !strings.Contains(blocked.report.Reason, "reconcile") || h.inPlace() != one {
		t.Fatalf("没对账就发布：退出码 %d，%s%s", blocked.code, blocked.stdout, blocked.stderr)
	}
	commands := len(h.docker.commands)
	restored := h.reconcile()
	if restored.code != exitRestored || restored.report.Outcome != "RESTORED" || !restored.report.Replaced || restored.report.Restarted ||
		restored.report.Snapshot != id(two) || restored.report.Previous != id(one) || !strings.Contains(restored.report.Reason, "was not the snapshot last confirmed") {
		t.Fatalf("收回去：退出码 %d，%s%s", restored.code, restored.stdout, restored.stderr)
	}
	if h.inPlace() != two || len(h.leftovers()) != 0 || len(h.docker.commands) != commands ||
		restored.report.Observed == nil || restored.report.Observed.Digest != restored.report.ExpectedDigest || !restored.report.Observed.Synchronized {
		t.Fatalf("配置目录里是 %q，另外留下了 %v，docker 命令 %v", h.inPlace(), h.leftovers(), h.docker.commands[commands:])
	}

	// 有人放了一份网关加载不了的文件。
	h.place(unloadable)
	if r := h.reconcile(); r.code != exitRestored || !strings.Contains(r.report.Reason, loadError) || h.inPlace() != two {
		t.Fatalf("坏文件：退出码 %d，%s%s", r.code, r.stdout, r.stderr)
	}
	// 收拾好之后照常能发布。
	if r := h.publish(sameSettings); r.code != exitNotDone || r.report.Outcome != "RESTART_REQUIRED" {
		t.Fatalf("之后的发布：退出码 %d，%s%s", r.code, r.stdout, r.stderr)
	}
	if r := h.publish(one); r.code != exitActive || h.inPlace() != one {
		t.Fatalf("之后的发布：退出码 %d，%s%s", r.code, r.stdout, r.stderr)
	}

	// 记录读不成样子：报错，什么都不做。
	record := filepath.Join(h.poolDir, recordFile)
	intact, err := os.ReadFile(record)
	if err != nil {
		t.Fatal(err)
	}
	h.place(two)
	if err := os.WriteFile(record, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if r := h.reconcile(); r.code != exitError || r.stdout != "" || !strings.Contains(r.stderr, "damaged") || h.inPlace() != two {
		t.Fatalf("记录坏了：退出码 %d，%q %q", r.code, r.stdout, r.stderr)
	}
	if r := h.publish(two); r.code != exitError || r.stdout != "" || !strings.Contains(r.stderr, "damaged") || h.inPlace() != two {
		t.Fatalf("记录坏了时发布：退出码 %d，%q %q", r.code, r.stdout, r.stderr)
	}
	if err := os.WriteFile(record, intact, 0o600); err != nil {
		t.Fatal(err)
	}

	// 网关读不到：文件照样放回去，但确认不了。
	h.place(silences)
	h.timeout = "300ms"
	if r := h.reconcile(); r.code != exitUnknown || r.report.Outcome != "UNKNOWN" || !r.report.Replaced || h.inPlace() != one ||
		!strings.Contains(r.report.Reason, "put back but not confirmed") {
		t.Fatalf("读不到网关：退出码 %d，%s%s", r.code, r.stdout, r.stderr)
	}
}

// 发布器换上文件之后死了，没来得及记下来（这里由测试直接放那个文件）。同一份再发布一次就补完了，
// 不用先收回去。
func TestPublishingWhatWasLeftInPlaceCompletesIt(t *testing.T) {
	h := newHarness(t)
	if r := h.publish(two); r.code != exitActive {
		t.Fatalf("发布：退出码 %d，%s%s", r.code, r.stdout, r.stderr)
	}
	h.place(one)

	// 带重启的发布不认它：先对账。
	blocked := h.restart(needsRestart)
	if blocked.code != exitNotDone || blocked.report.Outcome != "POOL_NOT_READY" || !strings.Contains(blocked.report.Reason, "reconcile") ||
		blocked.report.Replaced || blocked.report.Restarted || h.pool.restarts != 0 || h.inPlace() != one {
		t.Fatalf("带重启的发布：退出码 %d，%s%s", blocked.code, blocked.stdout, blocked.stderr)
	}

	before, err := os.Stat(filepath.Join(h.poolDir, configFile))
	if err != nil {
		t.Fatal(err)
	}
	done := h.publish(one)
	after, err := os.Stat(filepath.Join(h.poolDir, configFile))
	if err != nil {
		t.Fatal(err)
	}
	if done.code != exitActive || done.report.Outcome != "ACTIVE" || done.report.Replaced || done.report.Snapshot != id(one) || done.report.Previous != id(one) ||
		!os.SameFile(before, after) || len(h.leftovers()) != 0 {
		t.Fatalf("补完：退出码 %d，%s%s", done.code, done.stdout, done.stderr)
	}
	// 记录跟上了：对得上，之后照常能发布。
	if r := h.reconcile(); r.code != exitActive || r.report.Outcome != "IN_SYNC" || r.report.Snapshot != id(one) {
		t.Fatalf("之后对账：退出码 %d，%s%s", r.code, r.stdout, r.stderr)
	}
	if r := h.publish(two); r.code != exitActive || !r.report.Replaced || h.inPlace() != two {
		t.Fatalf("之后的发布：退出码 %d，%s%s", r.code, r.stdout, r.stderr)
	}
}

// 记录文件里有启动设置的名字，没有它们的值。
func TestTheRecordDoesNotCarryStartupSettingValues(t *testing.T) {
	h := newHarness(t)
	const marked = `{"config":{"terminationMaxDeadline":"45s","sessionEncoder":"not-to-be-copied"},"routes":["one"]}`
	h.place(marked)
	if r := h.publish(marked); r.code != exitActive || r.report.Replaced {
		t.Fatalf("发布：退出码 %d，%s%s", r.code, r.stdout, r.stderr)
	}
	raw, err := os.ReadFile(filepath.Join(h.poolDir, recordFile))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"sessionEncoder"`) || !strings.Contains(string(raw), `"terminationMaxDeadline"`) || strings.Contains(string(raw), "not-to-be-copied") {
		t.Fatalf("记录文件是\n%s", raw)
	}
	info, err := os.Stat(filepath.Join(h.poolDir, recordFile))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("权限 %v（err=%v）", info.Mode().Perm(), err)
	}
}

// 带重启的发布：先换文件，网关加载得了再重启。
func TestRestartPublishesWhatNeedsARestart(t *testing.T) {
	h := newHarness(t)
	if r := h.publish(two); r.code != exitActive {
		t.Fatalf("发布：退出码 %d，%s%s", r.code, r.stdout, r.stderr)
	}

	done := h.restart(needsRestart)
	got := done.report
	if done.code != exitActive || got.Outcome != "ACTIVE" || !got.Replaced || !got.Restarted || !reflect.DeepEqual(got.Restart, []string{"terminationMaxDeadline"}) ||
		got.Snapshot != id(needsRestart) || got.Previous != id(two) {
		t.Fatalf("退出码 %d，%s%s", done.code, done.stdout, done.stderr)
	}
	if h.inPlace() != needsRestart || len(h.leftovers()) != 0 || h.pool.restarts != 1 || h.pool.setting() != "90s" || h.docker.count("restart") != 1 {
		t.Fatalf("配置目录里是 %q，另外留下了 %v，重启了 %d 次，设置是 %q", h.inPlace(), h.leftovers(), h.pool.restarts, h.pool.setting())
	}
	// 没有给 --stop-timeout：命令里不带 -t，docker 用容器自己设的停止时限。
	if !reflect.DeepEqual(h.docker.restarted, []string{"restart", gatewayContainer}) {
		t.Fatalf("docker 命令是 %v", h.docker.restarted)
	}
	// 记录跟上了：对得上。
	if r := h.reconcile(); r.code != exitActive || r.report.Outcome != "IN_SYNC" || r.report.Snapshot != id(needsRestart) {
		t.Fatalf("重启之后对账：退出码 %d，%s%s", r.code, r.stdout, r.stderr)
	}

	// 用不着重启的不重启。
	refused := h.restart(sameSettings)
	if refused.code != exitNotDone || refused.report.Outcome != "REFUSED" || !strings.Contains(refused.report.Reason, "nothing to restart") ||
		refused.report.Replaced || refused.report.Restarted || h.pool.restarts != 1 || h.inPlace() != needsRestart {
		t.Fatalf("用不着重启：退出码 %d，%s%s", refused.code, refused.stdout, refused.stderr)
	}

	// 池里加载不了的：在重启之前就收回去了。
	restored := h.restart(restartUnloadable)
	if restored.code != exitRestored || restored.report.Outcome != "RESTORED" || !restored.report.Replaced || restored.report.Restarted ||
		!strings.Contains(restored.report.Reason, loadError) || h.pool.restarts != 1 || h.inPlace() != needsRestart {
		t.Fatalf("池里加载不了：退出码 %d，%s%s", restored.code, restored.stdout, restored.stderr)
	}

	// 那个容器不是这个池的网关：不动。
	other := h.run(replaced(h.restartArgs(h.snapshot(two)), "--container", "someone-elses-container"))
	if other.code != exitError || other.stdout != "" || !strings.Contains(other.stderr, "No such object") || h.pool.restarts != 1 || h.inPlace() != needsRestart {
		t.Fatalf("别人的容器：退出码 %d，%q %q", other.code, other.stdout, other.stderr)
	}
	h.docker.mounted = filepath.Join(h.poolDir, "another-pool")
	elsewhere := h.restart(two)
	h.docker.mounted = h.poolDir
	if elsewhere.code != exitError || !strings.Contains(elsewhere.stderr, "not the configuration directory of this pool") || h.pool.restarts != 1 || h.inPlace() != needsRestart {
		t.Fatalf("挂着别的目录的容器：退出码 %d，%q %q", elsewhere.code, elsewhere.stdout, elsewhere.stderr)
	}
}

// 有人带着另一份文件重启过网关：对账把文件放回去，启动设置还差一次重启；restart 不给快照就是做这件事。
func TestRestartWithoutASnapshotUsesTheConfirmedOne(t *testing.T) {
	h := newHarness(t)

	// 这个池上还没有确认过任何发布：不给快照就不知道用哪一份。
	if r := h.run(h.restartArgs("")); r.code != exitError || r.stdout != "" || !strings.Contains(r.stderr, "no --snapshot was given") || h.pool.restarts != 0 {
		t.Fatalf("没有记录：退出码 %d，%q %q", r.code, r.stdout, r.stderr)
	}
	if r := h.publish(two); r.code != exitActive {
		t.Fatalf("发布：退出码 %d，%s%s", r.code, r.stdout, r.stderr)
	}
	h.place(needsRestart)
	h.pool.restart()

	pending := h.reconcile()
	if pending.code != exitRestartPending || pending.report.Outcome != "RESTART_PENDING" || !pending.report.Replaced || pending.report.Restarted ||
		!reflect.DeepEqual(pending.report.Restart, []string{"terminationMaxDeadline"}) || h.inPlace() != two || h.pool.setting() != "90s" {
		t.Fatalf("对账：退出码 %d，%s%s（设置 %q）", pending.code, pending.stdout, pending.stderr, h.pool.setting())
	}
	done := h.run(h.restartArgs(""))
	if done.code != exitActive || done.report.Outcome != "ACTIVE" || done.report.Replaced || !done.report.Restarted || done.report.Snapshot != id(two) ||
		h.inPlace() != two || h.pool.setting() != "45s" || h.pool.restarts != 2 {
		t.Fatalf("重启：退出码 %d，%s%s（设置 %q）", done.code, done.stdout, done.stderr, h.pool.setting())
	}
	if r := h.reconcile(); r.code != exitActive || r.report.Outcome != "IN_SYNC" {
		t.Fatalf("之后对账：退出码 %d，%s%s", r.code, r.stdout, r.stderr)
	}
}

// 网关启动之前把确认过的那一份放到位。place 只碰配置目录：不读网关，不用 docker。
func TestPlacePutsTheConfirmedSnapshotInPlaceBeforeTheGatewayStarts(t *testing.T) {
	h := newHarness(t)
	config := filepath.Join(h.poolDir, configFile)

	// 这个池上还没有确认过任何发布：没有可放的，什么都不写；网关可以启动。
	none := h.run(h.placeArgs())
	if none.code != exitActive || none.report.Outcome != "NO_RECORD" || none.report.Replaced || none.report.Snapshot != "" ||
		none.report.Previous != id(one) || none.report.Observed != nil || none.report.Reason == "" || h.inPlace() != one {
		t.Fatalf("没有记录：退出码 %d，%s%s", none.code, none.stdout, none.stderr)
	}

	published := h.publish(two)
	if published.code != exitActive {
		t.Fatalf("发布：退出码 %d，%s%s", published.code, published.stdout, published.stderr)
	}
	asked, commands := h.pool.asked(), len(h.docker.commands)
	before, err := os.Stat(config)
	if err != nil {
		t.Fatal(err)
	}
	same := h.run(h.placeArgs())
	after, err := os.Stat(config)
	if err != nil {
		t.Fatal(err)
	}
	if same.code != exitActive || same.report.Outcome != "IN_PLACE" || same.report.Replaced || same.report.Reason != "" ||
		same.report.Snapshot != id(two) || same.report.Previous != id(two) || same.report.Observed != nil || !os.SameFile(before, after) {
		t.Fatalf("已经在那里：退出码 %d，%s%s", same.code, same.stdout, same.stderr)
	}
	if same.report.ExpectedDigest == "" || same.report.ExpectedDigest != published.report.ExpectedDigest {
		t.Fatalf("期望摘要 %q，发布时是 %q", same.report.ExpectedDigest, published.report.ExpectedDigest)
	}

	// 放在那里的不是记录的那一份：不管它是什么，放回去。
	for _, c := range []struct {
		name     string
		spoil    func() error
		previous string
		says     string
	}{
		{"没做完的发布留下的一份", func() error { h.place(one); return nil }, id(one), "was not the snapshot last confirmed on this pool"},
		{"一份网关加载不了的文件", func() error { h.place(unloadable); return nil }, id(unloadable), "was not the snapshot last confirmed on this pool"},
		{"文件不见了", func() error { return os.Remove(config) }, "", "there was no configuration file in place"},
		{"一个空文件", func() error { h.place(""); return nil }, "", "could not be read as a configuration"},
	} {
		if err := c.spoil(); err != nil {
			t.Fatal(err)
		}
		r := h.run(h.placeArgs())
		if r.code != exitActive || r.report.Outcome != "IN_PLACE" || !r.report.Replaced || r.report.Restarted || r.report.Observed != nil ||
			r.report.Snapshot != id(two) || r.report.Previous != c.previous || !strings.Contains(r.report.Reason, c.says) {
			t.Errorf("%s：退出码 %d，%s%s", c.name, r.code, r.stdout, r.stderr)
		}
		info, err := os.Stat(config)
		if err != nil || info.Mode().Perm() != 0o644 || h.inPlace() != two || len(h.leftovers()) != 0 {
			t.Fatalf("%s：配置目录里是 %q（err=%v），另外留下了 %v", c.name, h.inPlace(), err, h.leftovers())
		}
	}
	if h.pool.asked() != asked || len(h.docker.commands) != commands {
		t.Fatalf("place 不读网关，不用 docker：网关被问了 %d 次，docker 命令 %v", h.pool.asked()-asked, h.docker.commands[commands:])
	}
	// 网关读到的是放回去的那一份：对账对得上。
	if r := h.reconcile(); r.code != exitActive || r.report.Outcome != "IN_SYNC" || r.report.Snapshot != id(two) {
		t.Fatalf("之后对账：退出码 %d，%s%s", r.code, r.stdout, r.stderr)
	}

	// 下面三种情况它什么都不做，退出码 1：这时不该启动网关。
	h.place(one)
	delivery, err := directory.New(h.poolDir, configFile)
	if err != nil {
		t.Fatal(err)
	}
	release, err := delivery.Hold(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	busy := h.run(h.placeArgs())
	release()
	if busy.code != exitError || busy.stdout != "" || !strings.Contains(busy.stderr, "another publication") || h.inPlace() != one {
		t.Fatalf("池被占着：退出码 %d，%q %q", busy.code, busy.stdout, busy.stderr)
	}
	record := filepath.Join(h.poolDir, recordFile)
	intact, err := os.ReadFile(record)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(record, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if r := h.run(h.placeArgs()); r.code != exitError || r.stdout != "" || !strings.Contains(r.stderr, "damaged") || h.inPlace() != one {
		t.Fatalf("记录坏了：退出码 %d，%q %q", r.code, r.stdout, r.stderr)
	}
	if err := os.WriteFile(record, intact, 0o600); err != nil {
		t.Fatal(err)
	}
	if r := h.run([]string{"place", "--config-dir", filepath.Join(h.poolDir, "missing")}); r.code != exitError || r.stdout != "" || !strings.Contains(r.stderr, "directory:") {
		t.Fatalf("配置目录不存在：退出码 %d，%q %q", r.code, r.stdout, r.stderr)
	}
	// 对照：锁放开、记录修好之后，同一条命令把那一份放回去了。
	if r := h.run(h.placeArgs()); r.code != exitActive || r.report.Outcome != "IN_PLACE" || !r.report.Replaced || h.inPlace() != two {
		t.Fatalf("对照：退出码 %d，%s%s", r.code, r.stdout, r.stderr)
	}
}

func TestUsageOfRestartReconcileAndPlace(t *testing.T) {
	h := newHarness(t)
	restart := h.restartArgs(h.snapshot(needsRestart))
	cases := []struct {
		name string
		args []string
		says string
	}{
		{"reconcile 只有子命令", []string{"reconcile"}, "missing required flags: --config-dir, --read-back, --read-back-name, --tls-ca, --tls-cert, --tls-key\n"},
		{"reconcile 不要快照", append(h.reconcileArgs(), "--snapshot", h.snapshot(two)), "flag provided but not defined: -snapshot"},
		{"reconcile 不要容器", append(h.reconcileArgs(), "--container", gatewayContainer), "flag provided but not defined: -container"},
		{"reconcile 多余的参数", append(h.reconcileArgs(), "now"), `unexpected argument "now"`},
		{"reconcile 要帮助", []string{"reconcile", "--help"}, "-read-back-name"},
		{"restart 没有容器", append([]string{"restart"}, restart[3:]...), "missing required flags: --container\n"},
		{"restart 的停止时限不是整秒", append(append([]string(nil), restart...), "--stop-timeout", "1500ms"), "--stop-timeout must be a whole number of seconds"},
		{"restart 的停止时限是负的", append(append([]string(nil), restart...), "--stop-timeout", "-5s"), "--stop-timeout must be a whole number of seconds"},
		{"publish 不要容器", append(h.args(h.snapshot(two)), "--container", gatewayContainer), "flag provided but not defined: -container"},
		{"restart 要帮助", []string{"restart", "--help"}, "-stop-timeout"},
		{"place 只有子命令", []string{"place"}, "missing required flags: --config-dir\n"},
		{"place 不要回读口", append(h.placeArgs(), "--read-back", h.poolAddr), "flag provided but not defined: -read-back"},
		{"place 不要时限", append(h.placeArgs(), "--timeout", "3s"), "flag provided but not defined: -timeout"},
		{"place 不要快照", append(h.placeArgs(), "--snapshot", h.snapshot(two)), "flag provided but not defined: -snapshot"},
		{"place 多余的参数", append(h.placeArgs(), "now"), `unexpected argument "now"`},
		{"place 要帮助", []string{"place", "--help"}, "-config-dir"},
	}
	for _, c := range cases {
		r := h.run(c.args)
		if r.code != exitUsage || r.stdout != "" || !strings.Contains(r.stderr, c.says) {
			t.Errorf("%s：退出码 %d，标准输出 %q，标准错误 %q", c.name, r.code, r.stdout, r.stderr)
		}
	}
	if h.inPlace() != one || len(h.docker.commands) != 0 || len(h.pool.peers) != 0 || h.pool.restarts != 0 {
		t.Fatalf("用法不对时不该做任何事：目录里是 %q，docker 命令 %v，池见到 %v", h.inPlace(), h.docker.commands, h.pool.peers)
	}

	// 停止时限带在 docker 的命令里。
	if r := h.run(append(append([]string(nil), restart...), "--stop-timeout", "45s")); r.code != exitActive || h.pool.restarts != 1 ||
		!reflect.DeepEqual(h.docker.restarted, []string{"restart", "-t", "45", gatewayContainer}) {
		t.Fatalf("带停止时限：退出码 %d，docker 命令 %v，%s%s", r.code, h.docker.restarted, r.stdout, r.stderr)
	}
}
