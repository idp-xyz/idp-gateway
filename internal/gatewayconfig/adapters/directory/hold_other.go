//go:build !unix

package directory

import (
	"context"
	"errors"
)

// Hold 在没有 flock 的系统上不可用。网关只在 Linux 上部署，这里只为了让别的系统上也编译得过。
func (d *Directory) Hold(context.Context) (func(), error) {
	return nil, errors.New("directory: exclusive access to the configuration directory is not implemented on this operating system")
}
