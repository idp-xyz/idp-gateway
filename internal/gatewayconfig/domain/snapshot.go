// Package domain 是配置发布的规则：一份快照是什么，网关报告的运行配置怎么算摘要，
// 什么样的观察说明一份快照已经在网关上生效（docs/adr/ADR-0010.md 第 6、10 条）。
// 这里不做 I/O，也不知道快照是怎么送到网关那里的。
package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
)

// Snapshot 是要下发给一个池的一份网关配置。内容定下来就不再变；它的名字是内容的摘要，
// 内容不同，名字就不同。
type Snapshot struct {
	id      string
	content []byte
}

// NewSnapshot 把一份配置的内容包成快照。空内容不是一份配置。
func NewSnapshot(content []byte) (Snapshot, error) {
	if len(content) == 0 {
		return Snapshot{}, errors.New("gatewayconfig: a snapshot cannot be empty")
	}
	sum := sha256.Sum256(content)
	return Snapshot{id: hex.EncodeToString(sum[:]), content: append([]byte(nil), content...)}, nil
}

// ID 是内容的 SHA-256（十六进制）。
func (s Snapshot) ID() string { return s.id }

// ShortID 是 ID 的前 12 位，用在文件名这类给人看的地方。
func (s Snapshot) ShortID() string {
	if len(s.id) < 12 {
		return s.id
	}
	return s.id[:12]
}

// Content 返回内容的一份副本：拿到它的人改不了快照。
func (s Snapshot) Content() []byte { return append([]byte(nil), s.content...) }

// IsZero 报告这是不是一个没有内容的零值。
func (s Snapshot) IsZero() bool { return s.id == "" }
