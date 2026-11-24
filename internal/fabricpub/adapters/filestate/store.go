// Package filestate 把发布状态放在一个已经存在的目录里。
//
// 目录必须是 0700，不能是符号链接，本进程不替敲错的路径建目录。
// 状态文件是 0600：临时文件、fsync、原子改名、再刷目录。锁是同一目录里的 flock。
package filestate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"go.idp.xyz/idp-gateway/internal/fabricpub/ports"
)

const (
	lockName  = ".fabric.lock"
	stateName = "state.json"
	fileMode  = fs.FileMode(0o600)
	dirMode   = fs.FileMode(0o700)
)

// Store 是一个 --state-dir。
type Store struct {
	dir   string
	lock  string
	state string
}

// Open 打开状态目录。目录必须已经存在，权限正好是 0700，且不是符号链接。
func Open(dir string) (*Store, error) {
	info, err := os.Lstat(dir)
	if err != nil {
		return nil, fmt.Errorf("fabric state: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("fabric state: the state directory is a symlink")
	}
	if !info.IsDir() {
		return nil, errors.New("fabric state: the state path is not a directory")
	}
	if info.Mode().Perm() != dirMode {
		return nil, fmt.Errorf("fabric state: directory mode is %o, want 0700", info.Mode().Perm())
	}
	return &Store{dir: dir, lock: filepath.Join(dir, lockName), state: filepath.Join(dir, stateName)}, nil
}

// Load 读取状态。文件还不存在时返回空状态，不创建它。
func (s *Store) Load(context.Context) (ports.State, error) {
	info, err := os.Lstat(s.state)
	if errors.Is(err, fs.ErrNotExist) {
		state := ports.State{}
		state.Normalize()
		return state, nil
	}
	if err != nil {
		return ports.State{}, fmt.Errorf("fabric state: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return ports.State{}, errors.New("fabric state: state.json must be a regular file")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return ports.State{}, errors.New("fabric state: state.json is readable by the group or others")
	}
	raw, err := os.ReadFile(s.state)
	if err != nil {
		return ports.State{}, fmt.Errorf("fabric state: %w", err)
	}
	var state ports.State
	if err := json.Unmarshal(raw, &state); err != nil {
		return ports.State{}, fmt.Errorf("fabric state: %s is not valid JSON: %w", s.state, err)
	}
	state.Normalize()
	return state, nil
}

// Save 原子写上整份状态。
func (s *Store) Save(_ context.Context, state ports.State) error {
	if err := s.recheckDir(); err != nil {
		return err
	}
	body, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	body = append(body, '\n')
	return replaceFile(s.dir, s.state, body, fileMode)
}

func (s *Store) recheckDir() error {
	info, err := os.Lstat(s.dir)
	if err != nil {
		return fmt.Errorf("fabric state: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm() != dirMode {
		return errors.New("fabric state: the state directory is no longer a private directory")
	}
	return nil
}

func replaceFile(dir, path string, content []byte, mode fs.FileMode) (err error) {
	file, err := os.CreateTemp(dir, ".state-*.tmp")
	if err != nil {
		return fmt.Errorf("fabric state: %w", err)
	}
	tmp := file.Name()
	defer func() {
		if err != nil {
			_ = os.Remove(tmp)
		}
	}()
	if err = file.Chmod(mode); err != nil {
		_ = file.Close()
		return fmt.Errorf("fabric state: %w", err)
	}
	if _, err = file.Write(content); err != nil {
		_ = file.Close()
		return fmt.Errorf("fabric state: %w", err)
	}
	if err = file.Sync(); err != nil {
		_ = file.Close()
		return fmt.Errorf("fabric state: %w", err)
	}
	if err = file.Close(); err != nil {
		return fmt.Errorf("fabric state: %w", err)
	}
	if err = os.Rename(tmp, path); err != nil {
		return fmt.Errorf("fabric state: %w", err)
	}
	if err = syncDir(dir); err != nil {
		return fmt.Errorf("fabric state: %w", err)
	}
	return nil
}

func syncDir(dir string) error {
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
