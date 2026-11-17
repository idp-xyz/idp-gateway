package domain

import (
	"strings"
	"time"
)

// Member 是单机上一个池里的一个常驻容器此刻的样子。
type Member struct {
	// Running 报告它是不是在跑。
	Running bool
	// Started 是它这一次启动的时刻；没有这个容器、或者它从来没有启动过时是零值。
	Started time.Time
	// State 给人看：容器现在的状态，退出了的带着退出码。没有这个容器时为空。
	State string
}

// Members 是单机上一个池里常驻的三个容器（docs/adr/ADR-0010.md 第 10 条）。
type Members struct {
	// Holder 只占着网络命名空间和本机上的端口。Gateway 和 Front 是接在它里面的两个：
	// 网关，和对外收业务请求的前置代理。
	Holder, Gateway, Front Member
}

// Condition 是这三个容器合起来的样子。
type Condition string

const (
	// ConditionWhole：三个都在跑，后两个接在第一个现在的命名空间里。
	ConditionWhole Condition = "whole"
	// ConditionDown：有没在跑的。把它们起起来就行，在跑的不用动。
	ConditionDown Condition = "down"
	// ConditionOrphaned：后两个里有在跑的，接着的却是一个已经不在了的命名空间：占着命名空间的那个
	// 停了，或者在它们之后重新启动过。它们还在跑，却谁也连不到；只把没在跑的起起来修不好，
	// 要先把它们停下。
	ConditionOrphaned Condition = "orphaned"
)

// Condition 报告三个容器合起来是什么样子，和依据。
func (m Members) Condition() (Condition, string) {
	named := []struct {
		name string
		Member
	}{
		{"the container that holds the network namespace", m.Holder},
		{"the gateway", m.Gateway},
		{"the front proxy", m.Front},
	}
	var orphaned, down []string
	for _, member := range named[1:] {
		switch {
		case !member.Running:
		case !m.Holder.Running:
			orphaned = append(orphaned, member.name+" is running but the container that holds its network namespace is not")
		case member.Started.Before(m.Holder.Started):
			// 接在命名空间里的容器启动时，占着命名空间的那个一定已经在跑：比它启动得还早的，
			// 接着的是它上一次的命名空间。
			orphaned = append(orphaned, member.name+" started before the container that holds its network namespace did, so it is attached to a namespace that is gone")
		}
	}
	if len(orphaned) > 0 {
		return ConditionOrphaned, strings.Join(orphaned, "; ")
	}
	for _, member := range named {
		if !member.Running {
			state := member.State
			if state == "" {
				state = "there is no such container"
			}
			down = append(down, member.name+" is not running ("+state+")")
		}
	}
	if len(down) > 0 {
		return ConditionDown, strings.Join(down, "; ")
	}
	return ConditionWhole, ""
}
