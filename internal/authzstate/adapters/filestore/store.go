// Package filestore 把撤销/封禁文档写在一个 0600 的普通文件里。父目录必须已经存在。
// 配额桶不进这个文件。错误文字里没有文件正文。
package filestore

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"go.idp.xyz/idp-gateway/internal/authzstate/domain"
)

const maxFileBytes = 1 << 20

// Store 是 --state-file 指向的那一个文件。
type Store struct {
	path string
}

type document struct {
	Epoch    *uint64           `json:"epoch"`
	Accounts map[string]*entry `json:"revoked_accounts"`
	Banned   map[string]*entry `json:"banned_operations"`
}

type entry struct {
	At     *string `json:"at"`
	By     string  `json:"by"`
	Reason string  `json:"reason"`
}

// Open 打开状态文件。文件不存在时创建一份空的 0600 文件（代次 0，两张表都是空的）。
// 已经存在时必须是普通文件（拒绝符号链接），权限 0600 或更严（拒绝 group/other 位），并且是合法文档。
func Open(path string) (*Store, error) {
	parent := filepath.Dir(path)
	info, err := os.Stat(parent)
	if err != nil {
		return nil, errors.New("authz state file: parent directory is missing")
	}
	if !info.IsDir() {
		return nil, errors.New("authz state file: parent path is not a directory")
	}
	if err := ensureFile(path); err != nil {
		return nil, err
	}
	store := &Store{path: path}
	if _, err := store.Load(); err != nil {
		return nil, err
	}
	return store, nil
}

// Load 读出整份快照。
func (s *Store) Load() (domain.Snapshot, error) {
	if err := checkExisting(s.path); err != nil {
		return domain.Snapshot{}, err
	}
	file, err := os.Open(s.path)
	if err != nil {
		return domain.Snapshot{}, errors.New("authz state file: cannot read")
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, maxFileBytes+1))
	if err != nil {
		return domain.Snapshot{}, errors.New("authz state file: cannot read")
	}
	if len(raw) > maxFileBytes {
		return domain.Snapshot{}, errors.New("authz state file: not valid JSON")
	}
	return decode(raw)
}

// Save 原子替换文件：同目录临时文件、0600、写入、刷盘、关闭、改名、再刷目录。
func (s *Store) Save(snap domain.Snapshot) error {
	if err := checkExisting(s.path); err != nil {
		return err
	}
	body, err := encode(snap)
	if err != nil {
		return err
	}
	return replaceFile(filepath.Dir(s.path), s.path, body)
}

// Encode 把快照写成和 filestore 撤销文件相同的 JSON 形状。
func Encode(snap domain.Snapshot) ([]byte, error) {
	body, err := encode(snap)
	if err != nil {
		return nil, err
	}
	if len(body) > 0 && body[len(body)-1] == '\n' {
		body = body[:len(body)-1]
	}
	return body, nil
}

func ensureFile(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return createEmpty(path)
	}
	if err != nil {
		return errors.New("authz state file: cannot inspect")
	}
	return rejectUnsafe(info)
}

func checkExisting(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return errors.New("authz state file: cannot inspect")
	}
	return rejectUnsafe(info)
}

func rejectUnsafe(info os.FileInfo) error {
	if info.Mode()&os.ModeSymlink != 0 {
		return errors.New("authz state file: refusing a symlink")
	}
	if !info.Mode().IsRegular() {
		return errors.New("authz state file: not a regular file")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("authz state file: mode %04o is readable by group or others; want 0600 or stricter", info.Mode().Perm())
	}
	return nil
}

func createEmpty(path string) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return errors.New("authz state file: cannot create")
	}
	ok := false
	defer func() {
		if !ok {
			_ = file.Close()
			_ = os.Remove(path)
		}
	}()
	if err := file.Chmod(0o600); err != nil {
		return errors.New("authz state file: cannot set mode")
	}
	if _, err := file.Write(emptyDocument()); err != nil {
		return errors.New("authz state file: cannot create")
	}
	if err := file.Sync(); err != nil {
		return errors.New("authz state file: cannot create")
	}
	if err := file.Close(); err != nil {
		return errors.New("authz state file: cannot create")
	}
	ok = true
	if err := syncDir(filepath.Dir(path)); err != nil {
		return errors.New("authz state file: cannot create")
	}
	return nil
}

func emptyDocument() []byte {
	return []byte("{\"epoch\":0,\"revoked_accounts\":{},\"banned_operations\":{}}\n")
}

func decode(raw []byte) (domain.Snapshot, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var doc document
	if err := dec.Decode(&doc); err != nil {
		return domain.Snapshot{}, errors.New("authz state file: not valid JSON")
	}
	if _, err := dec.Token(); err != io.EOF {
		return domain.Snapshot{}, errors.New("authz state file: not valid JSON")
	}
	if doc.Epoch == nil || doc.Accounts == nil {
		return domain.Snapshot{}, errors.New("authz state file: not valid JSON")
	}
	accounts, err := decodeEntries(doc.Accounts)
	if err != nil {
		return domain.Snapshot{}, err
	}
	bans, err := decodeEntries(doc.Banned)
	if err != nil {
		return domain.Snapshot{}, err
	}
	return domain.Snapshot{Epoch: *doc.Epoch, Accounts: accounts, Bans: bans}, nil
}

func decodeEntries(raw map[string]*entry) (map[string]domain.Entry, error) {
	out := make(map[string]domain.Entry, len(raw))
	for name, row := range raw {
		if name == "" || row == nil || row.At == nil {
			return nil, errors.New("authz state file: not valid JSON")
		}
		at, err := time.Parse(time.RFC3339, *row.At)
		if err != nil {
			return nil, errors.New("authz state file: not valid JSON")
		}
		out[name] = domain.Entry{At: at.UTC(), By: row.By, Reason: row.Reason}
	}
	return out, nil
}

func encode(snap domain.Snapshot) ([]byte, error) {
	doc := document{
		Epoch:    &snap.Epoch,
		Accounts: make(map[string]*entry, len(snap.Accounts)),
		Banned:   make(map[string]*entry, len(snap.Bans)),
	}
	if err := fillEntries(doc.Accounts, snap.Accounts); err != nil {
		return nil, err
	}
	if err := fillEntries(doc.Banned, snap.Bans); err != nil {
		return nil, err
	}
	body, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, errors.New("authz state file: cannot encode")
	}
	return append(body, '\n'), nil
}

func fillEntries(dst map[string]*entry, src map[string]domain.Entry) error {
	for name, row := range src {
		if name == "" {
			return errors.New("authz state file: cannot encode")
		}
		at := row.At.UTC().Format(time.RFC3339)
		dst[name] = &entry{At: &at, By: row.By, Reason: row.Reason}
	}
	return nil
}

func replaceFile(dir, path string, content []byte) (err error) {
	file, err := os.CreateTemp(dir, ".authz-state-*.tmp")
	if err != nil {
		return errors.New("authz state file: cannot write")
	}
	tmp := file.Name()
	defer func() {
		if err != nil {
			_ = os.Remove(tmp)
		}
	}()
	if err = file.Chmod(0o600); err != nil {
		_ = file.Close()
		return errors.New("authz state file: cannot write")
	}
	if _, err = file.Write(content); err != nil {
		_ = file.Close()
		return errors.New("authz state file: cannot write")
	}
	if err = file.Sync(); err != nil {
		_ = file.Close()
		return errors.New("authz state file: cannot write")
	}
	if err = file.Close(); err != nil {
		return errors.New("authz state file: cannot write")
	}
	if err = os.Rename(tmp, path); err != nil {
		return errors.New("authz state file: cannot write")
	}
	if err = syncDir(dir); err != nil {
		return errors.New("authz state file: cannot write")
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
