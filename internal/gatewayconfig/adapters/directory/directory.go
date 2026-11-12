// Package directory 是单机上的下发：网关容器挂载的那个目录里的配置文件
// （docs/adr/ADR-0010.md 第 10 条）。
//
// 挂进容器的必须是这个目录，不是配置文件本身：这里换文件靠改名，只挂文件的话容器里看到的
// 一直是旧的那一个（tests/integration/compose 的 SH-05）。
//
// 目录里除了配置文件，还有发布器自己的两个文件：一把锁，和"最后一次得到确认的是哪一份"的记录。
package directory

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"go.idp.xyz/idp-gateway/internal/gatewayconfig/domain"
)

const (
	// fileMode 是配置文件的权限。网关容器里的用户不一定是写文件的这个用户，所以其他人可读；
	// 配置里没有密钥，证书、私钥和凭证都在别处（ADR-0010 第 3 条）。
	fileMode fs.FileMode = 0o644
	// recordMode 是记录的权限。读它的只有发布器。
	recordMode fs.FileMode = 0o600
)

// Directory 是一个池的配置目录里的那个配置文件。
type Directory struct {
	dir  string
	name string
}

// New 指定目录和配置文件的名字。目录必须已经存在。
func New(dir, name string) (*Directory, error) {
	if name == "" || name != filepath.Base(name) || name == "." || name == ".." {
		return nil, fmt.Errorf("directory: %q is not a plain file name", name)
	}
	info, err := os.Stat(dir)
	if err != nil {
		return nil, fmt.Errorf("directory: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("directory: %s is not a directory", dir)
	}
	return &Directory{dir: dir, name: name}, nil
}

func (d *Directory) path() string { return filepath.Join(d.dir, d.name) }

// Current 返回现在放在那里的配置文件。
func (d *Directory) Current(context.Context) (domain.Snapshot, bool, error) {
	content, err := os.ReadFile(d.path())
	if errors.Is(err, fs.ErrNotExist) {
		return domain.Snapshot{}, false, nil
	}
	if err != nil {
		return domain.Snapshot{}, false, fmt.Errorf("directory: %w", err)
	}
	snapshot, err := domain.NewSnapshot(content)
	if err != nil {
		return domain.Snapshot{}, false, fmt.Errorf("directory: %s: %w", d.path(), err)
	}
	return snapshot, true, nil
}

// Put 在同一个目录里写一个临时文件，落盘，再改名盖掉配置文件，最后把目录落盘。
// 改名是原子的：读这个文件的人看到的要么是旧的整份，要么是新的整份。
//
// 调用的人要占着这个目录（Hold）：动手之前，这里先把以前的发布器死在半路留下的临时文件清掉。
func (d *Directory) Put(_ context.Context, snapshot domain.Snapshot) error {
	if snapshot.IsZero() {
		return errors.New("directory: nothing to put")
	}
	d.sweep()
	return d.replace(d.name, "."+d.name+"."+snapshot.ShortID()+".tmp", snapshot.Content(), fileMode)
}

// sweep 删掉留在目录里的临时文件。清不掉的不算错：它们不碍事，下一次再清。
func (d *Directory) sweep() {
	stale, err := filepath.Glob(filepath.Join(d.dir, "."+d.name+".*.tmp"))
	if err != nil {
		return
	}
	for _, path := range stale {
		_ = os.Remove(path)
	}
}

// replace 把目录里名叫 name 的文件整份换成 content：写临时文件，落盘，改名，目录落盘。
func (d *Directory) replace(name, temporaryName string, content []byte, mode fs.FileMode) (err error) {
	temporary := filepath.Join(d.dir, temporaryName)
	defer func() {
		if err != nil {
			_ = os.Remove(temporary)
			err = fmt.Errorf("directory: %w", err)
		}
	}()
	file, err := os.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	if _, err = file.Write(content); err == nil {
		err = file.Chmod(mode) // 不受 umask 影响
	}
	if err == nil {
		err = file.Sync()
	}
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err = os.Rename(temporary, filepath.Join(d.dir, name)); err != nil {
		return err
	}
	return syncDirectory(d.dir)
}

func syncDirectory(dir string) error {
	entry, err := os.Open(dir)
	if err != nil {
		return err
	}
	err = entry.Sync()
	if closeErr := entry.Close(); err == nil {
		err = closeErr
	}
	return err
}
