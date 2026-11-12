// Package ports 是配置发布对外部的要求：发布之前在哪里试着加载一份快照，快照怎么送到一个池的
// 网关那里，网关在跑什么从哪里读，网关进程怎么重启。
//
// 这几样都是对着一个池说的。平台不同，实现不同；第一期是单机上的 docker compose
// （docs/adr/ADR-0010.md 第 10 条）。
package ports

import (
	"context"
	"errors"

	"go.idp.xyz/idp-gateway/internal/gatewayconfig/domain"
)

// ErrBusy 表示这个池此刻有另一次发布在进行。
var ErrBusy = errors.New("gatewayconfig: another publication to this pool is in progress")

// RejectedError 表示网关加载不了这份快照：它拿这份文件启动不起来。
type RejectedError struct {
	// Reason 是网关自己说的原因。
	Reason string
}

func (e *RejectedError) Error() string {
	return "gatewayconfig: the gateway cannot load the snapshot: " + e.Reason
}

// Staging 在发布之前离线加载一份快照：用要部署的那个镜像另起一个网关，不接流量，不碰任何池。
type Staging interface {
	// Load 返回那个网关加载这份快照之后报告的运行配置，发布时拿它当期望值。
	// 网关加载不了这份快照时返回 *RejectedError；别的错误表示这一步没做成，说明不了快照的好坏。
	Load(ctx context.Context, snapshot domain.Snapshot) (domain.Observation, error)
}

// Delivery 是一个池的网关读配置的地方。往那里写的只有发布器。
type Delivery interface {
	// Hold 取得往那里写的独占权，直到调用返回的函数为止。已经被占着时返回 ErrBusy，不等。
	Hold(ctx context.Context) (release func(), err error)
	// Current 返回现在放在那里的内容；那里还什么都没有时 ok 为假。
	Current(ctx context.Context) (snapshot domain.Snapshot, ok bool, err error)
	// Put 把那里的内容整份换成这份快照。网关读到的要么是换之前的整份，要么是这一份，
	// 不会是写了一半的。返回错误时不保证是哪一份。
	Put(ctx context.Context, snapshot domain.Snapshot) error
	// Confirmed 返回这个池上最后一次得到确认的发布；还没有过时 ok 为假。
	// 记录读得到却不成样子时返回错误：这时既不能当它没有，也不能照着它做。
	Confirmed(ctx context.Context) (confirmation domain.Confirmation, ok bool, err error)
	// Confirm 记下这份快照已经在这个池上得到确认，盖掉上一条。记录和配置放在一起：
	// 发布器中途死了，下一个占到这个池的从它知道该放回哪一份。
	Confirm(ctx context.Context, confirmation domain.Confirmation) error
}

// ReadBack 读一个池里的网关此刻在跑什么。
type ReadBack interface {
	// Observe 返回错误表示这一次没有读到：网关够不着，或答的不是预期的东西。
	Observe(ctx context.Context) (domain.Observation, error)
}

// Process 是一个池里的网关进程。
type Process interface {
	// Verify 报告它管的是不是读这个池的配置的那个网关；不是时返回错误。它不改变任何东西。
	Verify(ctx context.Context) error
	// Restart 让网关停下再起来。返回时新的进程已经被启动，但不保证它起得来：那要经回读口看。
	// 停下之前在途的请求有多久做完，由池的部署决定。开始之后不随 ctx 取消。
	Restart(ctx context.Context) error
}
