package domain

import (
	"testing"
)

func TestSnapshotIsNamedAfterItsContent(t *testing.T) {
	snapshot, err := NewSnapshot([]byte("abc"))
	if err != nil {
		t.Fatal(err)
	}
	// SHA-256("abc")，FIPS 180-2 的例子。
	if snapshot.ID() != "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" || snapshot.ShortID() != "ba7816bf8f01" {
		t.Fatalf("%s / %s", snapshot.ID(), snapshot.ShortID())
	}
	same, _ := NewSnapshot([]byte("abc"))
	other, _ := NewSnapshot([]byte("abd"))
	if same.ID() != snapshot.ID() || other.ID() == snapshot.ID() {
		t.Fatal("同样的内容名字应该相同，不同的内容名字应该不同")
	}
	if snapshot.IsZero() || !(Snapshot{}).IsZero() || (Snapshot{}).ShortID() != "" {
		t.Fatal("IsZero")
	}
}

func TestSnapshotContentCannotBeChangedFromOutside(t *testing.T) {
	source := []byte("routes: []")
	snapshot, err := NewSnapshot(source)
	if err != nil {
		t.Fatal(err)
	}
	source[0] = 'X' // 交进去的那块内存之后被改了
	handed := snapshot.Content()
	handed[1] = 'Y' // 拿出来的那份被改了
	if got := string(snapshot.Content()); got != "routes: []" {
		t.Fatalf("快照的内容变成了 %q", got)
	}
}

func TestEmptyContentIsNotASnapshot(t *testing.T) {
	for _, content := range [][]byte{nil, {}} {
		if snapshot, err := NewSnapshot(content); err == nil {
			t.Fatalf("空内容得到了快照 %s", snapshot.ID())
		}
	}
}

func TestObservationConfirms(t *testing.T) {
	staged := Observation{Digest: "d1", Synchronized: true, StorageMode: StorageReadOnly}
	good := Observation{Digest: "d1", Synchronized: true, StorageMode: StorageReadOnly}
	if !good.Confirms(staged) {
		t.Fatal("摘要相同、加载成功、存储只读，却不算生效")
	}
	// 启动设置不同不影响这一条：它由 Settings.Differing 另外判断。
	withOtherSettings := good
	withOtherSettings.Settings = Settings{"terminationMaxDeadline": `"46s"`}
	if !withOtherSettings.Confirms(staged) {
		t.Fatal("启动设置不该在这里比")
	}
	for name, observed := range map[string]Observation{
		"在跑的是另一份":  {Digest: "d0", Synchronized: true, StorageMode: StorageReadOnly},
		"上一次加载失败":  {Digest: "d1", Synchronized: false, LastError: "routes[2]: unknown field", StorageMode: StorageReadOnly},
		"存储不是只读":   {Digest: "d1", Synchronized: true, StorageMode: "file"},
		"没有报告存储模式": {Digest: "d1", Synchronized: true},
		"什么都没读到":   {},
	} {
		if observed.Confirms(staged) {
			t.Errorf("%s：被算成了生效", name)
		}
	}
	// 没有期望值时什么观察都不算数：两个空摘要相等不说明任何事。
	if (Observation{Synchronized: true, StorageMode: StorageReadOnly}).Confirms(Observation{}) {
		t.Fatal("空的期望值被确认了")
	}
}
