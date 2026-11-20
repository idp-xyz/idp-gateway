package application

import (
	"context"
	"errors"

	"go.idp.xyz/idp-gateway/internal/gatewayconfig/domain"
	"go.idp.xyz/idp-gateway/internal/gatewayconfig/ports"
)

// ReimageResult 是一次换镜像做了什么。Previous 是动手之前容器在跑的镜像引用，
// Image 是调用者要换成的那一个。两个都是原文，不另作解释。
type ReimageResult struct {
	Outcome  Outcome
	Previous string
	Image    string
}

// Reimager 把一个池的网关换成另一个按摘要引用的镜像（ADR-0010 第 10 条「要重启网关的变更」）。
// 它不改配置文件，所以回读不必等摘要变化：镜像换了，文件没有。等的方式与重启之后等网关起来相同。
type Reimager struct {
	watch
	images ports.ImageSwap
}

// NewReimager 构造换镜像的这一层。它不在这里碰 docker。
func NewReimager(images ports.ImageSwap, readBack ports.ReadBack, timing Timing) (*Reimager, error) {
	if images == nil || readBack == nil {
		return nil, errors.New("gatewayconfig: the gateway image and read-back are both required")
	}
	if err := timing.check(); err != nil {
		return nil, err
	}
	return &Reimager{watch: newWatch(readBack, timing), images: images}, nil
}

// Reimage 把池指到 want。want 必须按摘要引用。
//
// 容器现在跑的已经是 want：UNCHANGED，不重建。否则记下原来的引用，改 GATEWAY_IMAGE，
// 只重建那一个服务，再等回读口看到网关起来。重建或回读没有成，把原来的引用写回去再重建一次：
// 旧镜像回来了是 RESTORED，第二次重建也没有成是 UNKNOWN。
//
// 返回错误表示还没有改过变量文件，也没有重建。一旦开始改，就不随 ctx 取消：
// 停在半路会留下一个没人确认的镜像。
func (r *Reimager) Reimage(ctx context.Context, want string) (ReimageResult, error) {
	if err := domain.ImageReference(want); err != nil {
		return ReimageResult{}, err
	}
	current, err := r.images.Current(ctx)
	if err != nil {
		return ReimageResult{}, err
	}
	if current == want {
		return ReimageResult{Outcome: OutcomeUnchanged, Previous: current, Image: want}, nil
	}
	steady := context.WithoutCancel(ctx)
	if err := r.images.PointAt(steady, want); err != nil {
		if !errors.Is(err, ports.ErrImageRecreate) {
			// 变量文件没有改成 want（没有这一项，或这一行写不进去）。没有重建。
			return ReimageResult{}, err
		}
		return r.restore(steady, current, want), nil
	}
	if _, ok, _ := r.await(steady, readBackUp, false); ok {
		return ReimageResult{Outcome: OutcomeActive, Previous: current, Image: want}, nil
	}
	return r.restore(steady, current, want), nil
}

// readBackUp 等的是网关经回读口答得上话，并且配置加载成功、存储只读。
// 不比摘要：换的是镜像，配置文件没有变，另一个构建报出的摘要可以不同。
func readBackUp(seen domain.Observation) (bool, string) {
	if seen.Digest == "" || !seen.Synchronized || seen.StorageMode != domain.StorageReadOnly {
		return false, "the gateway is not up"
	}
	return true, ""
}

// restore 把原来的镜像引用写回去再重建一次。第二次没有成就是 UNKNOWN，不再试第三次。
func (r *Reimager) restore(ctx context.Context, previous, want string) ReimageResult {
	result := ReimageResult{Outcome: OutcomeUnknown, Previous: previous, Image: want}
	if err := r.images.PointAt(ctx, previous); err != nil {
		return result
	}
	result.Outcome = OutcomeRestored
	return result
}
