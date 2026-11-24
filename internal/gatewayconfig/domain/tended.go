package domain

import (
	"sort"
	"strings"
)

// Replica 是看守另外照看的一个服务（docs/adr/ADR-0024.md）的一个容器此刻的样子。
type Replica struct {
	// Name 是容器的名字。
	Name string
	// Running 报告它是不是在跑。
	Running bool
	// State 给人看：容器现在的状态，退出了的带着退出码。
	State string
	// Addresses 是它在这个池的 compose 项目的网络上的 IPv4 地址，排好序。没在跑的容器没有地址。
	Addresses []string
}

// Service 是看守另外照看的一个服务：常驻三个之外、叠加文件里的那些（gateway-authz、签名器、两个协调器）。
// 一个服务可以有几个容器（--scale、deploy.replicas）。
type Service struct {
	// Name 是 compose 文件里的服务名。
	Name string
	// Pinned：网关经出口规则（pin-egress.sh）按名字连它。这样的服务换了地址，网关那边要跟上。
	Pinned bool
	// Replicas 是它的容器（docker compose run 临时起的不算）；一个都没有时为空。
	Replicas []Replica
}

// Running 报告这个服务有容器，并且每一个都在跑。
func (s Service) Running() bool {
	if len(s.Replicas) == 0 {
		return false
	}
	for _, replica := range s.Replicas {
		if !replica.Running {
			return false
		}
	}
	return true
}

// Addresses 是它的各个容器的地址合在一起，去掉重复，排好序。
func (s Service) Addresses() []string {
	seen := map[string]bool{}
	var all []string
	for _, replica := range s.Replicas {
		for _, address := range replica.Addresses {
			if !seen[address] {
				seen[address] = true
				all = append(all, address)
			}
		}
	}
	sort.Strings(all)
	return all
}

// Down 说明这几个服务里哪几个不是每个容器都在跑：一个容器都没有的，和没在跑的容器各自的状态。都在跑时为空。
func Down(services []Service) string {
	var down []string
	for _, service := range services {
		if len(service.Replicas) == 0 {
			down = append(down, service.Name+" has no container")
			continue
		}
		for _, replica := range service.Replicas {
			if !replica.Running {
				state := replica.State
				if state == "" {
					state = "unknown"
				}
				down = append(down, service.Name+": "+replica.Name+" is not running ("+state+")")
			}
		}
	}
	return strings.Join(down, "; ")
}
