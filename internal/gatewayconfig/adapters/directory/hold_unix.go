//go:build unix

package directory

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"go.idp.xyz/idp-gateway/internal/gatewayconfig/ports"
)

// euid 是这个进程以谁的身份运行。测试里换掉它。
var euid = os.Geteuid

// Hold 用目录里的一个锁文件取得独占权。占着它的进程退出时（包括崩溃），内核会放开这把锁。
// 只对同一台机器上的进程有效。
//
// 只有目录的属主占得了它。锁文件和记录的权限都是 0600：换一个账号来写（比如 root），
// 属主之后就读不了它们，这个池再也发布不了、启动不了。所以别的账号在这里就被挡下，什么都不写。
func (d *Directory) Hold(context.Context) (func(), error) {
	info, err := os.Stat(d.dir)
	if err != nil {
		return nil, fmt.Errorf("directory: %w", err)
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); ok && int(stat.Uid) != euid() {
		return nil, fmt.Errorf("directory: %s belongs to uid %d and this process runs as uid %d: "+
			"what it writes there could not be read by the owner afterwards; run it as the owner of that directory", d.dir, stat.Uid, euid())
	}
	lock, err := os.OpenFile(filepath.Join(d.dir, "."+d.name+".lock"), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("directory: %w", err)
	}
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = lock.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, ports.ErrBusy
		}
		return nil, fmt.Errorf("directory: lock: %w", err)
	}
	return func() {
		_ = syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
		_ = lock.Close()
	}, nil
}
