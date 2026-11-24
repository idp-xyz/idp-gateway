// Package ports 是租约协调器的端口。存储只认指纹键和已经包好的令牌，不认识 HTTP。
package ports

import "go.idp.xyz/idp-gateway/internal/sflease/domain"

// Store 持久化租约。Load 在进程启动时读一遍；Save 在提交成功对外发布之前写完。
// 返回的 map 归调用方。错误里不得出现令牌原文。
type Store interface {
	Load() (map[string]domain.LeaseRecord, error)
	Save(records map[string]domain.LeaseRecord) error
}
