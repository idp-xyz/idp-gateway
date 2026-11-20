// Package filestore 把 JWKS 写成本机的一个文件。写入是整份替换：临时文件、权限、刷盘、改名、
// 再刷目录。读者要么看到原来的那一份，要么看到新的那一份，看不到写了一半的内容。
package filestore

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"go.idp.xyz/idp-gateway/internal/jwkssync/ports"
)

// Store 实现 ports.Store。
type Store struct {
	path string
	mode fs.FileMode
}

var _ ports.Store = (*Store)(nil)

// New 核对路径和权限。权限只接受 0600 和 0644：前者只给本机同一个用户，后者给同机的网关容器读。
func New(path string, mode fs.FileMode) (*Store, error) {
	if path == "" {
		return nil, errors.New("jwks file: path is required")
	}
	if mode != 0o600 && mode != 0o644 {
		return nil, errors.New("jwks file: mode must be 0600 or 0644")
	}
	return &Store{path: path, mode: mode}, nil
}

// Read 读整份文件。还不存在时 exists 为 false，这不是错误。
func (s *Store) Read() ([]byte, bool, error) {
	data, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("jwks file: %w", err)
	}
	return data, true, nil
}

// Write 原子替换 path。临时文件放在同一目录，这样改名不跨文件系统。
// 权限用 Chmod 设，不受进程 umask 影响。改名成功之后再刷目录；目录刷不掉时文件已经可见，
// 仍然返回错误，调用方可以再读一次确认。
func (s *Store) Write(data []byte) error {
	dir := filepath.Dir(s.path)
	file, err := os.CreateTemp(dir, ".jwks-*.tmp")
	if err != nil {
		return fmt.Errorf("jwks file: %w", err)
	}
	temporary := file.Name()
	done := false
	defer func() {
		if !done {
			_ = os.Remove(temporary)
		}
	}()
	if _, err = file.Write(data); err != nil {
		_ = file.Close()
		return fmt.Errorf("jwks file: %w", err)
	}
	if err = file.Chmod(s.mode); err != nil {
		_ = file.Close()
		return fmt.Errorf("jwks file: %w", err)
	}
	if err = file.Sync(); err != nil {
		_ = file.Close()
		return fmt.Errorf("jwks file: %w", err)
	}
	if err = file.Close(); err != nil {
		return fmt.Errorf("jwks file: %w", err)
	}
	if err = os.Rename(temporary, s.path); err != nil {
		return fmt.Errorf("jwks file: %w", err)
	}
	done = true
	if err = syncDirectory(dir); err != nil {
		return fmt.Errorf("jwks file: %w", err)
	}
	return nil
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
