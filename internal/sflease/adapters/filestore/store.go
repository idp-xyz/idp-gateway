// Package filestore 把租约写在一个 0600 的普通文件里。父目录必须已经存在。
// 令牌只出现在文件正文里，不出现在错误文字里。
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

	"go.idp.xyz/idp-gateway/internal/sflease/domain"
)

const fileVersion = 1

// Store 是 --lease-file 指向的那一个文件。
type Store struct {
	path string
}

type fileDocument struct {
	Version int                  `json:"version"`
	Leases  map[string]fileLease `json:"leases"`
}

type fileLease struct {
	Token     string `json:"token"`
	ExpiresAt string `json:"expires_at"`
	Lifetime  int64  `json:"lifetime_ns"`
}

// Open 打开租约文件。文件不存在时创建一份空的 0600 文件。
// 已经存在时必须是普通文件（拒绝符号链接），权限 0600 或更严（拒绝 group/other 位），并且是合法的第 1 版 JSON。
func Open(path string) (*Store, error) {
	parent := filepath.Dir(path)
	info, err := os.Stat(parent)
	if err != nil {
		return nil, fmt.Errorf("sf lease file: parent directory: %w", err)
	}
	if !info.IsDir() {
		return nil, errors.New("sf lease file: parent path is not a directory")
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

// Load 读出尚未过期的租约。过期条目丢掉，不因此拒绝启动。
func (s *Store) Load() (map[string]domain.LeaseRecord, error) {
	if err := checkExisting(s.path); err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(s.path)
	if err != nil {
		return nil, errors.New("sf lease file: cannot read")
	}
	records, err := decode(raw, time.Now())
	if err != nil {
		return nil, err
	}
	return records, nil
}

// Save 原子替换文件：同目录临时文件、0600、写入、刷盘、关闭、改名、再刷目录。
// 已经过期的条目不写回去。
func (s *Store) Save(records map[string]domain.LeaseRecord) error {
	if err := checkExisting(s.path); err != nil {
		return err
	}
	body, err := encode(records, time.Now())
	if err != nil {
		return err
	}
	return replaceFile(filepath.Dir(s.path), s.path, body)
}

func ensureFile(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return createEmpty(path)
	}
	if err != nil {
		return errors.New("sf lease file: cannot inspect")
	}
	return rejectUnsafe(info)
}

func checkExisting(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return errors.New("sf lease file: cannot inspect")
	}
	return rejectUnsafe(info)
}

func rejectUnsafe(info os.FileInfo) error {
	if info.Mode()&os.ModeSymlink != 0 {
		return errors.New("sf lease file: refusing a symlink")
	}
	if !info.Mode().IsRegular() {
		return errors.New("sf lease file: not a regular file")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("sf lease file: mode %04o is readable by group or others; want 0600 or stricter", info.Mode().Perm())
	}
	return nil
}

func createEmpty(path string) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return errors.New("sf lease file: cannot create")
	}
	tmpOK := false
	defer func() {
		if !tmpOK {
			_ = file.Close()
			_ = os.Remove(path)
		}
	}()
	if err := file.Chmod(0o600); err != nil {
		return errors.New("sf lease file: cannot set mode")
	}
	if _, err := file.Write(emptyDocument()); err != nil {
		return errors.New("sf lease file: cannot create")
	}
	if err := file.Sync(); err != nil {
		return errors.New("sf lease file: cannot create")
	}
	if err := file.Close(); err != nil {
		return errors.New("sf lease file: cannot create")
	}
	tmpOK = true
	if err := syncDir(filepath.Dir(path)); err != nil {
		return errors.New("sf lease file: cannot create")
	}
	return nil
}

func emptyDocument() []byte {
	return []byte("{\"version\":1,\"leases\":{}}\n")
}

func decode(raw []byte, now time.Time) (map[string]domain.LeaseRecord, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	// 先解到 RawMessage，错误只说“不是合法 JSON”，不把文件正文（里面有令牌）带出去。
	var header struct {
		Version *int                        `json:"version"`
		Leases  *map[string]json.RawMessage `json:"leases"`
	}
	if err := dec.Decode(&header); err != nil {
		return nil, errors.New("sf lease file: not valid JSON")
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("sf lease file: not valid JSON")
	}
	if header.Version == nil || *header.Version != fileVersion || header.Leases == nil {
		return nil, errors.New("sf lease file: not valid JSON")
	}
	out := make(map[string]domain.LeaseRecord, len(*header.Leases))
	for key, rawLease := range *header.Leases {
		if err := domain.ValidateLeaseKey(key); err != nil {
			return nil, errors.New("sf lease file: not valid JSON")
		}
		rec, ok := decodeLease(key, rawLease)
		if !ok {
			return nil, errors.New("sf lease file: not valid JSON")
		}
		if !rec.ExpiresAt.After(now) {
			continue
		}
		out[key] = rec
	}
	return out, nil
}

func decodeLease(key string, raw json.RawMessage) (domain.LeaseRecord, bool) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var row struct {
		Token     *string `json:"token"`
		ExpiresAt *string `json:"expires_at"`
		Lifetime  *int64  `json:"lifetime_ns"`
	}
	if err := dec.Decode(&row); err != nil {
		return domain.LeaseRecord{}, false
	}
	if _, err := dec.Token(); err != io.EOF {
		return domain.LeaseRecord{}, false
	}
	if row.Token == nil || row.ExpiresAt == nil || row.Lifetime == nil || *row.Lifetime <= 0 {
		return domain.LeaseRecord{}, false
	}
	if err := domain.ValidateToken(*row.Token); err != nil {
		return domain.LeaseRecord{}, false
	}
	expires, err := time.Parse(time.RFC3339Nano, *row.ExpiresAt)
	if err != nil {
		return domain.LeaseRecord{}, false
	}
	return domain.LeaseRecord{
		LeaseKey: key, Token: domain.NewSecret(*row.Token),
		ExpiresAt: expires, Lifetime: time.Duration(*row.Lifetime),
	}, true
}

func encode(records map[string]domain.LeaseRecord, now time.Time) ([]byte, error) {
	doc := fileDocument{Version: fileVersion, Leases: map[string]fileLease{}}
	for key, rec := range records {
		if err := domain.ValidateLeaseKey(key); err != nil {
			return nil, errors.New("sf lease file: cannot encode")
		}
		if !rec.ExpiresAt.After(now) {
			continue
		}
		token := rec.Token.Reveal()
		if err := domain.ValidateToken(token); err != nil {
			return nil, errors.New("sf lease file: cannot encode")
		}
		doc.Leases[key] = fileLease{
			Token:     token,
			ExpiresAt: rec.ExpiresAt.UTC().Format(time.RFC3339Nano),
			Lifetime:  int64(rec.Lifetime),
		}
	}
	body, err := json.Marshal(doc)
	if err != nil {
		// json 的错误可能夹着字段值。不往外传。
		return nil, errors.New("sf lease file: cannot encode")
	}
	return append(body, '\n'), nil
}

func replaceFile(dir, path string, content []byte) (err error) {
	file, err := os.CreateTemp(dir, ".lease-*.tmp")
	if err != nil {
		return errors.New("sf lease file: cannot write")
	}
	tmp := file.Name()
	defer func() {
		if err != nil {
			_ = os.Remove(tmp)
		}
	}()
	if err = file.Chmod(0o600); err != nil {
		_ = file.Close()
		return errors.New("sf lease file: cannot write")
	}
	if _, err = file.Write(content); err != nil {
		_ = file.Close()
		return errors.New("sf lease file: cannot write")
	}
	if err = file.Sync(); err != nil {
		_ = file.Close()
		return errors.New("sf lease file: cannot write")
	}
	if err = file.Close(); err != nil {
		return errors.New("sf lease file: cannot write")
	}
	if err = os.Rename(tmp, path); err != nil {
		return errors.New("sf lease file: cannot write")
	}
	if err = syncDir(dir); err != nil {
		return errors.New("sf lease file: cannot write")
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
