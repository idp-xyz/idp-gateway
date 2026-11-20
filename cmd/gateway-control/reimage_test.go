package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const imageNext = "cr.agentgateway.dev/agentgateway@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func envText(reference string) string {
	return "# pool\nPOOL_DIR=/srv/idp\nGATEWAY_IMAGE=" + reference +
		"\nFRONT_IMAGE=public.ecr.aws/nginx/nginx-unprivileged:stable-alpine@sha256:c3fc8fa482be50ef709c6438eb1bc98d50dbfe5a9b48be90711b8814f4dfd701\n"
}

func (h *harness) writeEnv(content string) string {
	h.t.Helper()
	path := filepath.Join(h.t.TempDir(), "pool.env")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		h.t.Fatal(err)
	}
	return path
}

func (h *harness) composeFile() string {
	return filepath.Join(h.workDir, "compose.yml")
}

func (h *harness) reimageArgs(envFile, reference string) []string {
	return []string{"reimage",
		"--image", reference,
		"--container", gatewayContainer,
		"--config-dir", h.poolDir,
		"--mount", "/work/config",
		"--compose-file", h.composeFile(),
		"--compose-env-file", envFile,
		"--service", "agentgateway",
		"--read-back", h.poolAddr,
		"--read-back-name", readBackName,
		"--tls-cert", h.publisher.CertFile,
		"--tls-key", h.publisher.KeyFile,
		"--tls-ca", h.ca.File(),
		"--settle", "20ms",
		"--timeout", h.timeout,
	}
}

func (d *fakeDocker) called() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.commands)
}

func (d *fakeDocker) reimageCalls() (argv [][]string, env [][]string, fromFile []string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, call := range d.composed {
		argv = append(argv, append([]string(nil), call...))
	}
	for _, call := range d.composeEnv {
		env = append(env, append([]string(nil), call...))
	}
	fromFile = append([]string(nil), d.composeFile...)
	return argv, env, fromFile
}

func gatewayImageInFile(argv []string) string {
	var path string
	for i := 0; i+1 < len(argv); i++ {
		if argv[i] == "--env-file" {
			path = argv[i+1]
		}
	}
	if path == "" {
		return ""
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	var value string
	for _, line := range strings.Split(string(content), "\n") {
		name, current, ok := strings.Cut(line, "=")
		if ok && name == "GATEWAY_IMAGE" {
			value = current
		}
	}
	return value
}

type reimageRun struct {
	code           int
	stdout, stderr string
	line           reimageLine
}

func (h *harness) runReimage(args []string) reimageRun {
	h.t.Helper()
	var stdout, stderr bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	got := reimageRun{code: run(ctx, args, &stdout, &stderr, h.docker.run)}
	got.stdout, got.stderr = stdout.String(), stderr.String()
	if got.stdout != "" {
		if strings.Count(got.stdout, "\n") != 1 || !strings.HasSuffix(got.stdout, "\n") {
			h.t.Fatalf("标准输出不是一行 JSON：%q", got.stdout)
		}
		if err := json.Unmarshal(stdout.Bytes(), &got.line); err != nil {
			h.t.Fatalf("标准输出不是 JSON：%q", got.stdout)
		}
	}
	return got
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(content)
}

func composeArgv(h *harness, envFile string) []string {
	return []string{"compose", "-f", h.composeFile(), "--env-file", envFile, "up", "-d", "--no-deps", "--force-recreate", "agentgateway"}
}

func TestReimageRefusesATagAndDoesNotCallDocker(t *testing.T) {
	h := newHarness(t)
	envFile := h.writeEnv(envText(image))
	before := readFile(t, envFile)

	r := h.runReimage(h.reimageArgs(envFile, "cr.agentgateway.dev/agentgateway:v1.7.0"))
	if r.code != exitError || r.stdout != "" || !strings.Contains(r.stderr, "not referenced by digest") || !strings.HasPrefix(r.stderr, "gateway-control: ") {
		t.Fatalf("退出码 %d，标准输出 %q，标准错误 %q", r.code, r.stdout, r.stderr)
	}
	if h.docker.called() != 0 || readFile(t, envFile) != before {
		t.Fatalf("docker 被叫了 %d 次，变量文件是 %q", h.docker.called(), readFile(t, envFile))
	}

	// 同一条规则也拒绝不完整的摘要，同样不碰 docker。
	short := h.runReimage(h.reimageArgs(envFile, "cr.agentgateway.dev/agentgateway@sha256:6021"))
	if short.code != exitError || short.stdout != "" || !strings.Contains(short.stderr, "not referenced by digest") || h.docker.called() != 0 {
		t.Fatalf("不完整的摘要：退出码 %d，%q %q，docker %d 次", short.code, short.stdout, short.stderr, h.docker.called())
	}
}

func TestReimageLeavesTheSameDigestUntouched(t *testing.T) {
	h := newHarness(t)
	h.docker.imageRef = image
	envFile := h.writeEnv(envText(image))
	before := readFile(t, envFile)

	r := h.runReimage(h.reimageArgs(envFile, image))
	argv, _, _ := h.docker.reimageCalls()
	if r.code != exitActive || r.stderr != "" || r.line.Outcome != "UNCHANGED" || r.line.Previous != image || r.line.Image != image {
		t.Fatalf("退出码 %d，%+v，标准错误 %q", r.code, r.line, r.stderr)
	}
	if len(argv) != 0 || h.docker.count("compose") != 0 || readFile(t, envFile) != before {
		t.Fatalf("compose %v，变量文件是 %q", argv, readFile(t, envFile))
	}
}

func TestReimageRecreatesTheServiceWhenTheDigestChanges(t *testing.T) {
	h := newHarness(t)
	h.docker.imageRef = image
	envFile := h.writeEnv(envText(image))

	r := h.runReimage(h.reimageArgs(envFile, imageNext))
	argv, env, fromFile := h.docker.reimageCalls()
	if r.code != exitActive || r.stderr != "" || r.line.Outcome != "ACTIVE" || r.line.Previous != image || r.line.Image != imageNext {
		t.Fatalf("退出码 %d，%+v，标准错误 %q，标准输出 %q", r.code, r.line, r.stderr, r.stdout)
	}
	if len(argv) != 1 || !reflectSlice(argv[0], composeArgv(h, envFile)) || len(env) != 1 || !reflectSlice(env[0], []string{"GATEWAY_IMAGE=" + imageNext}) {
		t.Fatalf("compose 参数 %v，环境 %v", argv, env)
	}
	if len(fromFile) != 1 || fromFile[0] != imageNext || readFile(t, envFile) != envText(imageNext) {
		t.Fatalf("重建时文件里是 %v，事后是 %q", fromFile, readFile(t, envFile))
	}
	if strings.Contains(strings.Join(argv[0], " "), " down") {
		t.Fatalf("命令里有 down：%v", argv[0])
	}
}

func TestReimageRestoresThePreviousImageWhenReadBackFails(t *testing.T) {
	h := newHarness(t)
	h.docker.imageRef = image
	h.pool.mu.Lock()
	h.pool.down = true
	h.pool.mu.Unlock()
	envFile := h.writeEnv(envText(image))
	args := replaced(h.reimageArgs(envFile, imageNext), "--timeout", "350ms")

	r := h.runReimage(args)
	argv, env, fromFile := h.docker.reimageCalls()
	if r.code != exitRestored || r.stderr != "" || r.line.Outcome != "RESTORED" || r.line.Previous != image || r.line.Image != imageNext {
		t.Fatalf("退出码 %d，%+v，标准错误 %q，标准输出 %q", r.code, r.line, r.stderr, r.stdout)
	}
	if len(argv) != 2 || !reflectSlice(argv[0], composeArgv(h, envFile)) || !reflectSlice(argv[1], composeArgv(h, envFile)) {
		t.Fatalf("compose 参数 %v", argv)
	}
	if len(env) != 2 || !reflectSlice(env[0], []string{"GATEWAY_IMAGE=" + imageNext}) || !reflectSlice(env[1], []string{"GATEWAY_IMAGE=" + image}) {
		t.Fatalf("传给 compose 的环境 %v", env)
	}
	if !reflectSlice(fromFile, []string{imageNext, image}) || readFile(t, envFile) != envText(image) {
		t.Fatalf("两次重建时文件里是 %v，事后是 %q", fromFile, readFile(t, envFile))
	}
}

func TestReimageRefusesAContainerThatDoesNotMountThisPool(t *testing.T) {
	h := newHarness(t)
	h.docker.imageRef = image
	h.docker.mountSource = "/not/this/pool"
	envFile := h.writeEnv(envText(image))
	before := readFile(t, envFile)

	r := h.runReimage(h.reimageArgs(envFile, imageNext))
	argv, _, _ := h.docker.reimageCalls()
	if r.code == 0 || r.stdout != "" || !strings.Contains(r.stderr, "not the configuration directory") || !strings.HasPrefix(r.stderr, "gateway-control: ") {
		t.Fatalf("退出码 %d，标准输出 %q，标准错误 %q", r.code, r.stdout, r.stderr)
	}
	if len(argv) != 0 || h.docker.count("inspect") == 0 || readFile(t, envFile) != before {
		t.Fatalf("compose %v，inspect %d 次，变量文件是 %q", argv, h.docker.count("inspect"), readFile(t, envFile))
	}
}

func TestReimageRefusesAnEnvFileWithoutGatewayImage(t *testing.T) {
	h := newHarness(t)
	h.docker.imageRef = image
	envFile := h.writeEnv("# GATEWAY_IMAGE is mentioned only in a comment\nPOOL_DIR=/srv/idp\n")
	before := readFile(t, envFile)

	r := h.runReimage(h.reimageArgs(envFile, imageNext))
	argv, _, _ := h.docker.reimageCalls()
	if r.code != exitError || r.stdout != "" || !strings.Contains(r.stderr, "GATEWAY_IMAGE is not set") {
		t.Fatalf("退出码 %d，标准输出 %q，标准错误 %q", r.code, r.stdout, r.stderr)
	}
	if len(argv) != 0 || readFile(t, envFile) != before {
		t.Fatalf("compose %v，变量文件是 %q", argv, readFile(t, envFile))
	}
}

func reflectSlice(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}
