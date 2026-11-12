package domain

import (
	"reflect"
	"strings"
	"testing"
)

func confirmedSnapshot(t *testing.T) Snapshot {
	t.Helper()
	snapshot, err := NewSnapshot([]byte("routes: [a]\n"))
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}

// confirming 是一次说明快照在生效的观察。
func confirming() Observation {
	return Observation{Digest: "digest-a", Synchronized: true, StorageMode: StorageReadOnly, Version: "1.7.0", Revision: "26f5aebe",
		Settings: Settings{"terminationMaxDeadline": `"45s"`, "sessionEncoder": `{"key":"not-to-be-copied"}`, "dns": `"here"`, "numWorkerThreads": "4"}}
}

func TestOnlyAnObservationThatConfirmsMakesAConfirmation(t *testing.T) {
	snapshot := confirmedSnapshot(t)
	for _, build := range []func(Snapshot, Observation) (Confirmation, error){ConfirmedBy, FoundInPlace} {
		confirmation, err := build(snapshot, confirming())
		if err != nil || confirmation.IsZero() || confirmation.Snapshot.ID() != snapshot.ID() ||
			confirmation.Digest != "digest-a" || confirmation.Version != "1.7.0" || confirmation.Revision != "26f5aebe" {
			t.Fatalf("%+v（%v）", confirmation, err)
		}
		for name, spoil := range map[string]func(*Snapshot, *Observation){
			"没有快照":    func(s *Snapshot, _ *Observation) { *s = Snapshot{} },
			"没有摘要":    func(_ *Snapshot, o *Observation) { o.Digest = "" },
			"上一次加载失败": func(_ *Snapshot, o *Observation) { o.Synchronized = false },
			"存储不是只读":  func(_ *Snapshot, o *Observation) { o.StorageMode = "file" },
			"读不到版本":   func(_ *Snapshot, o *Observation) { o.Version = "" },
			"读不到提交":   func(_ *Snapshot, o *Observation) { o.Revision = "" },
		} {
			badSnapshot, badObservation := snapshot, confirming()
			spoil(&badSnapshot, &badObservation)
			if got, err := build(badSnapshot, badObservation); err == nil || !got.IsZero() {
				t.Errorf("%s：得到了一条确认 %+v", name, got)
			}
		}
	}
	if !(Confirmation{}).IsZero() {
		t.Fatal("零值不是空的")
	}
}

func TestAConfirmationHoldsWhileTheGatewayReportsTheSameThing(t *testing.T) {
	seen := confirming()
	confirmation, err := ConfirmedBy(confirmedSnapshot(t), seen)
	if err != nil {
		t.Fatal(err)
	}
	if !confirmation.Holds(seen) || !confirmation.SameBuild(seen) || len(confirmation.PendingRestart(seen)) != 0 {
		t.Fatal("确认时的那次观察自己对不上")
	}
	for name, c := range map[string]struct {
		change    func(*Observation)
		sameBuild bool
	}{
		"摘要不同":    {func(o *Observation) { o.Digest = "digest-b" }, true},
		"上一次加载失败": {func(o *Observation) { o.Synchronized = false }, true},
		"存储不是只读":  {func(o *Observation) { o.StorageMode = "file" }, true},
		"换了版本":    {func(o *Observation) { o.Version = "1.8.0" }, false},
		"换了提交":    {func(o *Observation) { o.Revision = "0000000" }, false},
		"读不到版本":   {func(o *Observation) { o.Version = "" }, false},
	} {
		now := confirming()
		c.change(&now)
		if confirmation.Holds(now) || confirmation.SameBuild(now) != c.sameBuild {
			t.Errorf("%s：Holds=%t，SameBuild=%t", name, confirmation.Holds(now), confirmation.SameBuild(now))
		}
	}
}

// 启动设置另外比：它们不同不妨碍运行配置对得上，但说明网关要重启。
func TestStartupSettingsAreComparedByFingerprint(t *testing.T) {
	confirmation, err := ConfirmedBy(confirmedSnapshot(t), confirming())
	if err != nil {
		t.Fatal(err)
	}
	// 记下的只有指纹：值不在里面，随环境变的项也不在里面。
	if len(confirmation.Startup) != 2 {
		t.Fatalf("记下了 %v", confirmation.Startup)
	}
	for name, print := range confirmation.Startup {
		if len(print) != 64 || strings.Contains(print, "not-to-be-copied") || strings.Contains(print, "45s") || name == "dns" || name == "numWorkerThreads" {
			t.Fatalf("%s 记成了 %q", name, print)
		}
	}

	now := confirming()
	now.Settings = Settings{
		"terminationMaxDeadline": `"46s"`,                      // 变了
		"sessionEncoder":         `{"key":"not-to-be-copied"}`, // 没变
		"dns":                    `"elsewhere"`,                // 随环境变的不算
		"tracing":                `null`,                       // 多出来的
		"adminAddr":              `"localhost:15000"`,          // 也是多出来的
	}
	// 报出来的按名字排好了序，不随哪一项是变了的、哪一项是多出来的而变。
	if !confirmation.Holds(now) || !reflect.DeepEqual(confirmation.PendingRestart(now), []string{"adminAddr", "terminationMaxDeadline", "tracing"}) {
		t.Fatalf("Holds=%t，PendingRestart=%v", confirmation.Holds(now), confirmation.PendingRestart(now))
	}
	// 少了一项也算。
	now.Settings = Settings{"terminationMaxDeadline": `"45s"`}
	if got := confirmation.PendingRestart(now); !reflect.DeepEqual(got, []string{"sessionEncoder"}) {
		t.Fatalf("PendingRestart=%v", got)
	}
}

// 接手来的记录不知道那份文件给出的启动设置是什么：它不说"要重启"。
func TestAnAdoptedConfirmationSaysNothingAboutStartupSettings(t *testing.T) {
	found, err := FoundInPlace(confirmedSnapshot(t), confirming())
	if err != nil {
		t.Fatal(err)
	}
	if !found.Adopted || found.Startup != nil {
		t.Fatalf("%+v", found)
	}
	now := confirming()
	now.Settings = Settings{"terminationMaxDeadline": `"46s"`}
	if !found.Holds(now) || found.PendingRestart(now) != nil {
		t.Fatalf("Holds=%t，PendingRestart=%v", found.Holds(now), found.PendingRestart(now))
	}
}

func TestConfirmationsThatSayTheSameThingAreEqual(t *testing.T) {
	snapshot := confirmedSnapshot(t)
	confirmation, err := ConfirmedBy(snapshot, confirming())
	if err != nil {
		t.Fatal(err)
	}
	// 随环境变的项不同，不算不同。
	elsewhere := confirming()
	elsewhere.Settings["dns"], elsewhere.Settings["numWorkerThreads"] = `"elsewhere"`, "8"
	same, err := ConfirmedBy(snapshot, elsewhere)
	if err != nil || !confirmation.Equal(same) || !same.Equal(confirmation) {
		t.Fatalf("只差随环境变的项：Equal=%t（%v）", confirmation.Equal(same), err)
	}

	other, err := NewSnapshot([]byte("routes: [a, b]\n"))
	if err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*Snapshot, *Observation){
		"另一份快照":  func(s *Snapshot, _ *Observation) { *s = other },
		"摘要不同":   func(_ *Snapshot, o *Observation) { o.Digest = "digest-b" },
		"版本不同":   func(_ *Snapshot, o *Observation) { o.Version = "1.8.0" },
		"提交不同":   func(_ *Snapshot, o *Observation) { o.Revision = "0000000" },
		"一项设置变了": func(_ *Snapshot, o *Observation) { o.Settings["terminationMaxDeadline"] = `"46s"` },
		"多了一项设置": func(_ *Snapshot, o *Observation) { o.Settings["tracing"] = "null" },
		"少了一项设置": func(_ *Snapshot, o *Observation) { delete(o.Settings, "sessionEncoder") },
		"换了一项设置": func(_ *Snapshot, o *Observation) {
			delete(o.Settings, "sessionEncoder")
			o.Settings["tracing"] = "null"
		},
	} {
		changedSnapshot, changedObservation := snapshot, confirming()
		change(&changedSnapshot, &changedObservation)
		different, err := ConfirmedBy(changedSnapshot, changedObservation)
		if err != nil || confirmation.Equal(different) || different.Equal(confirmation) {
			t.Errorf("%s：仍然算相同（%v）", name, err)
		}
	}
	// 接手来的和确认过的不是一回事。
	found, err := FoundInPlace(snapshot, confirming())
	if err != nil || confirmation.Equal(found) || found.Equal(confirmation) || !found.Equal(found) {
		t.Fatalf("接手来的与确认过的算相同（%v）", err)
	}
	// 网关没有一项可记的启动设置时也分得出来：两边都没有指纹，差的只有"接手来的"这一点。
	bare := confirming()
	bare.Settings = Settings{"dns": `"here"`}
	confirmedBare, err := ConfirmedBy(snapshot, bare)
	if err != nil {
		t.Fatal(err)
	}
	foundBare, err := FoundInPlace(snapshot, bare)
	if err != nil || len(confirmedBare.Startup) != 0 || confirmedBare.Equal(foundBare) || foundBare.Equal(confirmedBare) {
		t.Fatalf("没有可记的启动设置时，接手来的与确认过的算相同（%v）", err)
	}
}
