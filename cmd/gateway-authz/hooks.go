package main

import (
	"log/slog"

	"go.idp.xyz/idp-gateway/internal/egressauthz/adapters/filestore"
	"go.idp.xyz/idp-gateway/internal/egressauthz/adapters/httpapi"
	"go.idp.xyz/idp-gateway/internal/egressauthz/adapters/memory"
)

// seams 是 install 能碰到的全部东西。
//
// install 有两个实现，由构建标签二选一：默认构建（hooks_off.go）什么都不装；带
// acceptance 标签的构建（hooks_on.go）装上黑盒验收用的控制接口。验收构建不是产品，
// 不得部署。
type seams struct {
	listen  string
	callers httpapi.Callers
	// 撤销表是这两个里的一个，另一个是 nil：没有给 --revocations 时在内存里，给了就在文件里。
	revocationsInMemory *memory.Revocations
	revocationsInFile   *filestore.Revocations
	logger              *slog.Logger
}
