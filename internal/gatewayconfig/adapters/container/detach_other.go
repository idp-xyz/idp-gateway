//go:build !unix

package container

import "os/exec"

// detach 在没有进程组的系统上什么都不做。网关只在 Linux 上部署，这里只为了让别的系统上也编译得过。
func detach(*exec.Cmd) {}
