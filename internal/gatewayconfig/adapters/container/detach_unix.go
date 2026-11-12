//go:build unix

package container

import (
	"os/exec"
	"syscall"
)

// detach 让这条命令自成一个进程组。终端上的 Ctrl-C 是发给整个前台进程组的：docker 命令行和发布器
// 在同一个组里的话，重启做到一半它就跟着退出了。发布器会把这当成重启失败，把上一份放回去再重启一次，
// 而第一次重启其实还在进行。
func detach(command *exec.Cmd) {
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}
