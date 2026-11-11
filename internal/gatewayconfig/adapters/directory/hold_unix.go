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

// Hold 用目录里的一个锁文件取得独占权。占着它的进程退出时（包括崩溃），内核会放开这把锁。
// 只对同一台机器上的进程有效。
func (d *Directory) Hold(context.Context) (func(), error) {
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
