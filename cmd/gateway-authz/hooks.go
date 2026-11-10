package main

import (
	"log/slog"

	"go.idp.xyz/idp-gateway/internal/egressauthz/adapters/httpapi"
	"go.idp.xyz/idp-gateway/internal/egressauthz/adapters/memory"
)

// seams 是 install 能碰到的全部东西。
//
// install 有两个实现，由构建标签二选一：默认构建（hooks_off.go）什么都不装；带
// acceptance 标签的构建（hooks_on.go）装上黑盒验收用的控制接口。验收构建不是产品，
// 不得部署。
type seams struct {
	listen      string
	callers     httpapi.Callers
	revocations *memory.Revocations
	logger      *slog.Logger
}
