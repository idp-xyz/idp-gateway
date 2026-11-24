package telemetry

import (
	"errors"
	"strings"
	"testing"
	"time"

	"go.idp.xyz/idp-gateway/internal/gatewayconfig/application"
	"go.idp.xyz/idp-gateway/internal/gatewayconfig/domain"
)

func tendedServices(authzState bool) []domain.Service {
	state := domain.Replica{Name: "pool-authz-state-1", State: "exited (137)"}
	if authzState {
		state = domain.Replica{Name: "pool-authz-state-1", Running: true, State: "running", Addresses: []string{"172.30.0.4"}}
	}
	return []domain.Service{
		{Name: "gateway-authz", Pinned: true, Replicas: []domain.Replica{
			{Name: "pool-gateway-authz-1", Running: true, State: "running", Addresses: []string{"172.30.0.5"}},
			{Name: "pool-gateway-authz-2", Running: true, State: "running", Addresses: []string{"172.30.0.6"}},
		}},
		{Name: "authz-state", Replicas: []domain.Replica{state}},
	}
}

// 不给 Tend：一样都不多（golden 文件的那个测试也是这样看的）。
func TestWithoutTendedServicesThereIsNothingAboutThem(t *testing.T) {
	m := New("idp-gateway-pool", application.DefaultPace(), started)
	tending := looked(three())
	tending.Services = tendedServices(false)
	m.Observe(tending, after(5*time.Second))
	if text := string(m.Text()); strings.Contains(text, "tended") || strings.Contains(text, "repins") || strings.Contains(text, "unfollowed") {
		t.Fatalf("%s", text)
	}
}

func TestTheTendedServicesAndTheRepinsAreCounted(t *testing.T) {
	m := New("idp-gateway-pool", application.DefaultPace(), started).Tend([]string{"gateway-authz", "authz-state"}, []string{"gateway-authz"})
	read := func() map[string]string { return samples(t, string(m.Text())) }
	authz := `idp_gateway_pool_tended_running{service="gateway-authz",pinned="true"}`
	state := `idp_gateway_pool_tended_running{service="authz-state",pinned="false"}`

	// 还没有看过一眼：都不算在跑。
	if found := read(); found[authz] != "0" || found[state] != "0" || found["idp_gateway_pool_repins_total"] != "0" || found["idp_gateway_pool_unfollowed_addresses"] != "0" {
		t.Fatalf("%v", found)
	}

	// authz-state 死了；看守跑了启动命令，它起来了：给出来的是动手之后的样子。
	down := looked(three())
	down.Services = tendedServices(false)
	whole := three()
	down.Started, down.After, down.ServicesAfter = true, &whole, tendedServices(true)
	m.Observe(down, after(5*time.Second))
	if found := read(); found[authz] != "1" || found[state] != "1" || found["idp_gateway_pool_starts_total"] != "1" {
		t.Fatalf("%v", found)
	}

	// 一次发布占着池，gateway-authz 有了一个新地址：这一眼没动手，指标说有一个地址网关还没跟上。
	moved := looked(three())
	moved.Services, moved.Moved, moved.Busy = tendedServices(true), []string{"gateway-authz 172.30.0.9"}, true
	m.Observe(moved, after(10*time.Second))
	if found := read(); found["idp_gateway_pool_unfollowed_addresses"] != "1" || found["idp_gateway_pool_repins_total"] != "0" || found["idp_gateway_pool_busy"] != "1" {
		t.Fatalf("%v", found)
	}

	// forget 没成：数了一次，地址还是没跟上；这一眼的样子是不知道。
	failed := looked(three())
	failed.Services, failed.Moved, failed.Forgot, failed.Err = tendedServices(true), []string{"gateway-authz 172.30.0.9"}, true, errors.New("pool: forget")
	m.Observe(failed, after(15*time.Second))
	if found := read(); found["idp_gateway_pool_unfollowed_addresses"] != "1" || found["idp_gateway_pool_repins_total"] != "1" || found[authz] != "0" {
		t.Fatalf("%v", found)
	}

	// 这一次成了：forget、停、起。
	done := looked(three())
	done.Services, done.Moved, done.Forgot, done.Stopped, done.Started = tendedServices(true), []string{"gateway-authz 172.30.0.9"}, true, true, true
	done.After, done.ServicesAfter = &whole, tendedServices(true)
	m.Observe(done, after(20*time.Second))
	if found := read(); found["idp_gateway_pool_unfollowed_addresses"] != "0" || found["idp_gateway_pool_repins_total"] != "2" ||
		found["idp_gateway_pool_starts_total"] != "2" || found[authz] != "1" || found[state] != "1" {
		t.Fatalf("%v", found)
	}

	// 这一眼没看成。
	m.Observe(application.Tending{Err: errors.New("pool: docker ps: exit status 1")}, after(25*time.Second))
	if found := read(); found[authz] != "0" || found[state] != "0" {
		t.Fatalf("%v", found)
	}
}
