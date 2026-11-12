//go:build unix

package container

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

// fakeDockerEnv 让这个测试程序扮演 docker 命令行：只报告自己在哪个进程组里。
const fakeDockerEnv = "IDP_GATEWAY_TEST_FAKE_DOCKER"

func TestMain(m *testing.M) {
	if os.Getenv(fakeDockerEnv) == "1" {
		fmt.Println(os.Getpid(), syscall.Getpgrp(), strings.Join(os.Args[1:], " "))
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// 终端上的 Ctrl-C 发给整个前台进程组。docker 命令行不在发布器的那个组里，重启做到一半才不会被它打断。
func TestTheDockerCommandLineRunsInItsOwnProcessGroup(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	bin := t.TempDir()
	if err := os.Symlink(self, filepath.Join(bin, "docker")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin)

	output, err := docker(ctx, []string{fakeDockerEnv + "=1"}, "restart", "pool-gateway")
	if err != nil {
		t.Fatalf("%v：%s", err, output)
	}
	fields := strings.SplitN(strings.TrimSpace(output), " ", 3)
	if len(fields) != 3 || fields[2] != "restart pool-gateway" {
		t.Fatalf("假的 docker 说 %q", output)
	}
	pid, _ := strconv.Atoi(fields[0])
	group, _ := strconv.Atoi(fields[1])
	if pid == 0 || group != pid || group == syscall.Getpgrp() {
		t.Fatalf("docker 命令行的进程号 %d，进程组 %d；这个进程的进程组 %d", pid, group, syscall.Getpgrp())
	}
}
