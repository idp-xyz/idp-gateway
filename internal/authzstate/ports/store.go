// Package ports 是撤销协调器的端口。存储只认快照，不认识 HTTP，也不保存配额桶。
package ports

import "go.idp.xyz/idp-gateway/internal/authzstate/domain"

// Store 持久化撤销/封禁文档。Load 在进程启动时读一遍；Save 在对外发布之前写完。
// 错误里不得出现请求正文。配额桶不进这个端口：它们只在内存里，重启之后是满的。
type Store interface {
	Load() (domain.Snapshot, error)
	Save(domain.Snapshot) error
}
