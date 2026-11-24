package domain

import (
	"reflect"
	"testing"
)

func TestWhetherATendedServiceRuns(t *testing.T) {
	up := func(name string, addresses ...string) Replica {
		return Replica{Name: name, Running: true, State: "running", Addresses: addresses}
	}
	killed := Replica{Name: "pool-gateway-authz-2", State: "exited (137)"}
	for name, c := range map[string]struct {
		service Service
		running bool
		down    string
	}{
		"两个容器都在跑":  {Service{Name: "gateway-authz", Replicas: []Replica{up("a", "10.0.0.2"), up("b", "10.0.0.3")}}, true, ""},
		"两个里死了一个":  {Service{Name: "gateway-authz", Replicas: []Replica{up("a", "10.0.0.2"), killed}}, false, "gateway-authz: pool-gateway-authz-2 is not running (exited (137))"},
		"一个容器都没有":  {Service{Name: "authz-state"}, false, "authz-state has no container"},
		"说不出状态的那个": {Service{Name: "signer", Replicas: []Replica{{Name: "pool-signer-1"}}}, false, "signer: pool-signer-1 is not running (unknown)"},
	} {
		if got := c.service.Running(); got != c.running {
			t.Errorf("%s：Running 是 %t", name, got)
		}
		if got := Down([]Service{c.service}); got != c.down {
			t.Errorf("%s：Down 是 %q", name, got)
		}
	}
	// 几个服务一起说，按给的先后，分号隔开。
	both := Down([]Service{{Name: "authz-state"}, {Name: "gateway-authz", Replicas: []Replica{killed, up("a")}}})
	if both != "authz-state has no container; gateway-authz: pool-gateway-authz-2 is not running (exited (137))" {
		t.Fatalf("%q", both)
	}
	if Down(nil) != "" {
		t.Fatal("没有照看的服务时有话说")
	}
}

func TestTheAddressesOfAServiceAreTheOnesOfAllItsContainers(t *testing.T) {
	service := Service{Name: "gateway-authz", Replicas: []Replica{
		{Name: "b", Running: true, Addresses: []string{"10.0.0.9", "10.0.0.3"}},
		{Name: "a", Running: true, Addresses: []string{"10.0.0.3"}},
		{Name: "c", State: "exited (0)"},
	}}
	if got := service.Addresses(); !reflect.DeepEqual(got, []string{"10.0.0.3", "10.0.0.9"}) {
		t.Fatalf("%v", got)
	}
	if got := (Service{Name: "x"}).Addresses(); len(got) != 0 {
		t.Fatalf("%v", got)
	}
}
