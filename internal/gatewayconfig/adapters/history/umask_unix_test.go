//go:build unix

package history

import "syscall"

// setUmask 换掉进程的 umask，返回原来的。
func setUmask(mask int) int { return syscall.Umask(mask) }
