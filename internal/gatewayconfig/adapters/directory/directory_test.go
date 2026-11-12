//go:build unix

package directory

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"go.idp.xyz/idp-gateway/internal/gatewayconfig/domain"
	"go.idp.xyz/idp-gateway/internal/gatewayconfig/ports"
)

var ctx = context.Background()

func snap(t *testing.T, content string) domain.Snapshot {
	t.Helper()
	snapshot, err := domain.NewSnapshot([]byte(content))
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func open(t *testing.T) (*Directory, string) {
	t.Helper()
	dir := t.TempDir()
	directory, err := New(dir, "config.yaml")
	if err != nil {
		t.Fatal(err)
	}
	return directory, dir
}

func names(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var found []string
	for _, entry := range entries {
		found = append(found, entry.Name())
	}
	return found
}

func TestPutThenCurrent(t *testing.T) {
	directory, dir := open(t)
	if _, ok, err := directory.Current(ctx); ok || err != nil {
		t.Fatalf("空目录：ok=%t err=%v", ok, err)
	}
	if err := directory.Put(ctx, domain.Snapshot{}); err == nil {
		t.Fatal("没有内容的快照被放进去了")
	}
	// 写文件的进程把 umask 收得很紧时，配置文件仍是别人可读的：网关容器里的用户不一定是它。
	previous := syscall.Umask(0o077)
	defer syscall.Umask(previous)

	one, two := snap(t, "routes: [a]\n"), snap(t, "routes: [a, b]\n")
	for _, snapshot := range []domain.Snapshot{one, two, one} {
		if err := directory.Put(ctx, snapshot); err != nil {
			t.Fatal(err)
		}
		current, ok, err := directory.Current(ctx)
		if err != nil || !ok || current.ID() != snapshot.ID() {
			t.Fatalf("放进去的是 %s，读出来的是 %s（ok=%t err=%v）", snapshot.ShortID(), current.ShortID(), ok, err)
		}
	}
	// 目录里只有配置文件：临时文件没有留下。
	if found := names(t, dir); len(found) != 1 || found[0] != "config.yaml" {
		t.Fatalf("目录里有 %v", found)
	}
	info, err := os.Stat(filepath.Join(dir, "config.yaml"))
	if err != nil || info.Mode().Perm() != 0o644 {
		t.Fatalf("权限 %v（err=%v）", info.Mode().Perm(), err)
	}
}

// 换文件是换上另一个文件，不是改写原来那个：已经打开旧文件的人读到的仍是旧的整份。
// 网关的监视和"只挂单个文件就看不到"（SH-05）都系于这一点。
func TestPutReplacesTheFileInsteadOfRewritingIt(t *testing.T) {
	directory, dir := open(t)
	if err := directory.Put(ctx, snap(t, "the first one")); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "config.yaml")
	reader, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}

	if err := directory.Put(ctx, snap(t, "the second one, which is longer")); err != nil {
		t.Fatal(err)
	}
	old, err := io.ReadAll(reader)
	if err != nil || string(old) != "the first one" {
		t.Fatalf("旧文件的读者读到了 %q（err=%v）", old, err)
	}
	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if before.Sys().(*syscall.Stat_t).Ino == after.Sys().(*syscall.Stat_t).Ino {
		t.Fatal("还是原来那个文件：是就地改写，不是改名替换")
	}
}

func TestCurrentRefusesAnEmptyFile(t *testing.T) {
	directory, dir := open(t)
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if snapshot, ok, err := directory.Current(ctx); err == nil {
		t.Fatalf("空文件被当成了快照 %s（ok=%t）", snapshot.ID(), ok)
	}
}

func TestAFailedPutLeavesThePreviousFile(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root 不受目录权限限制")
	}
	directory, dir := open(t)
	if err := directory.Put(ctx, snap(t, "kept")); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	if err := directory.Put(ctx, snap(t, "never written")); err == nil {
		t.Fatal("目录不可写，Put 却成功了")
	}
	current, ok, err := directory.Current(ctx)
	if err != nil || !ok || string(current.Content()) != "kept" {
		t.Fatalf("原来的文件变成了 %q（ok=%t err=%v）", current.Content(), ok, err)
	}
}

// 临时文件写好了、改名却没成（这里是因为配置文件的位置上是一个目录）：临时文件不留在目录里。
// 留下的话，它会一直待在网关容器挂载的那个目录里。
func TestAPutThatFailsAtTheRenameLeavesNoTemporaryFile(t *testing.T) {
	directory, dir := open(t)
	if err := os.Mkdir(filepath.Join(dir, "config.yaml"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := directory.Put(ctx, snap(t, "cannot replace a directory")); err == nil {
		t.Fatal("配置文件的位置上是一个目录，Put 却成功了")
	}
	if found := names(t, dir); len(found) != 1 || found[0] != "config.yaml" {
		t.Fatalf("目录里留下了 %v", found)
	}
}

func TestHoldIsExclusive(t *testing.T) {
	directory, dir := open(t)
	release, err := directory.Hold(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// 同一个目录的另一个发布器（另一个进程也是这样）。
	other, err := New(dir, "config.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := other.Hold(ctx); !errors.Is(err, ports.ErrBusy) {
		t.Fatalf("第二次占用得到 %v", err)
	}
	if _, err := directory.Hold(ctx); !errors.Is(err, ports.ErrBusy) {
		t.Fatalf("同一个对象再占一次得到 %v", err)
	}
	release()
	again, err := other.Hold(ctx)
	if err != nil {
		t.Fatalf("放开之后占不到：%v", err)
	}
	again()

	// 锁文件不是配置文件，占用也不碰配置文件。
	if _, ok, err := directory.Current(ctx); ok || err != nil {
		t.Fatalf("占用之后目录里多出了配置文件：ok=%t err=%v", ok, err)
	}
	for _, name := range names(t, dir) {
		if !strings.HasPrefix(name, ".") {
			t.Fatalf("目录里多出了 %s", name)
		}
	}
}

func TestNewRefusesWhatIsNotADirectoryAndAPlainName(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "a-file")
	if err := os.WriteFile(file, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	for name, args := range map[string][2]string{
		"目录不存在":   {filepath.Join(dir, "missing"), "config.yaml"},
		"不是目录":    {file, "config.yaml"},
		"名字为空":    {dir, ""},
		"名字带目录":   {dir, "sub/config.yaml"},
		"名字指向上一级": {dir, ".."},
	} {
		if _, err := New(args[0], args[1]); err == nil {
			t.Errorf("%s：被接受了", name)
		}
	}
}

// observed 是确认一份内容时网关报告的。启动设置里有一项的值不该被抄到别处。
func observed(digest string) domain.Observation {
	return domain.Observation{
		Digest: digest, Synchronized: true, StorageMode: domain.StorageReadOnly, Version: "1.7.0", Revision: "26f5aebe",
		Settings: domain.Settings{"terminationMaxDeadline": `"45s"`, "sessionEncoder": `{"key":"not-to-be-copied"}`, "dns": `{"servers":["10.0.0.1"]}`},
	}
}

// confirmation 是一条记录：这份内容得到了确认，当时网关报告的是这些。
func confirmation(t *testing.T, content, digest string) domain.Confirmation {
	t.Helper()
	confirmed, err := domain.ConfirmedBy(snap(t, content), observed(digest))
	if err != nil {
		t.Fatal(err)
	}
	return confirmed
}

func TestConfirmThenConfirmed(t *testing.T) {
	directory, dir := open(t)
	if _, ok, err := directory.Confirmed(ctx); ok || err != nil {
		t.Fatalf("还没有记录：ok=%t err=%v", ok, err)
	}
	previous := syscall.Umask(0o022)
	defer syscall.Umask(previous)
	path := filepath.Join(dir, ".config.yaml.confirmed")

	// 内容原样带着，包括不是 UTF-8 的字节。
	first, second := confirmation(t, "routes: [a]\n\xff\x00", "digest-a"), confirmation(t, "routes: [a, b]\n", "digest-b")
	for _, wanted := range []domain.Confirmation{first, second} {
		if err := directory.Confirm(ctx, wanted); err != nil {
			t.Fatal(err)
		}
		got, ok, err := directory.Confirmed(ctx)
		if err != nil || !ok {
			t.Fatalf("ok=%t err=%v", ok, err)
		}
		if got.Snapshot.ID() != wanted.Snapshot.ID() || string(got.Snapshot.Content()) != string(wanted.Snapshot.Content()) {
			t.Fatalf("记下的是 %q，读出来的是 %q", wanted.Snapshot.Content(), got.Snapshot.Content())
		}
		// 读出来的和记下的是同一条；拿当时的那次观察去对，对得上，启动设置一项不差。
		if !got.Equal(wanted) || !got.Holds(observed(wanted.Digest)) || len(got.PendingRestart(observed(wanted.Digest))) != 0 || len(got.Startup) != 2 {
			t.Fatalf("读出来的是 %+v", got)
		}
		// 启动设置变了一项，读出来的记录看得出是哪一项。
		restarted := observed(wanted.Digest)
		restarted.Settings["terminationMaxDeadline"] = `"46s"`
		if pending := got.PendingRestart(restarted); len(pending) != 1 || pending[0] != "terminationMaxDeadline" {
			t.Fatalf("PendingRestart=%v", pending)
		}
		// 文件里有启动设置的名字，没有它们的值。
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(raw), `"sessionEncoder"`) || strings.Contains(string(raw), "not-to-be-copied") || strings.Contains(string(raw), "45s") ||
			strings.Contains(string(raw), "10.0.0.1") || !strings.Contains(string(raw), `"format": 1`) {
			t.Fatalf("记录文件是\n%s", raw)
		}
	}
	// 目录里多出来的只有记录这一个文件，只有属主能读；记录不是配置文件，Current 看不到它。
	if found := names(t, dir); len(found) != 1 || found[0] != ".config.yaml.confirmed" {
		t.Fatalf("目录里有 %v", found)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("权限 %v（err=%v）", info.Mode().Perm(), err)
	}
	if _, ok, err := directory.Current(ctx); ok || err != nil {
		t.Fatalf("记录被当成了配置文件：ok=%t err=%v", ok, err)
	}

	// 接手来的记录：没有启动设置，读出来仍是接手来的。
	found, err := domain.FoundInPlace(snap(t, "routes: [a]\n"), observed("digest-a"))
	if err != nil {
		t.Fatal(err)
	}
	if err := directory.Confirm(ctx, found); err != nil {
		t.Fatal(err)
	}
	got, ok, err := directory.Confirmed(ctx)
	if err != nil || !ok || !got.Adopted || got.Startup != nil || !got.Equal(found) || !got.Holds(observed("digest-a")) {
		t.Fatalf("读出来的是 %+v（ok=%t err=%v）", got, ok, err)
	}
	raw, err := os.ReadFile(path)
	if err != nil || !strings.Contains(string(raw), `"adopted": true`) || !strings.Contains(string(raw), `"startup": null`) {
		t.Fatalf("记录文件是\n%s（err=%v）", raw, err)
	}
	// 交进来的那一条说是接手来的、却带着启动设置：不照抄，文件里仍然没有。
	found.Startup = map[string]string{"terminationMaxDeadline": "0123456789abcdef"}
	if err := directory.Confirm(ctx, found); err != nil {
		t.Fatal(err)
	}
	raw, err = os.ReadFile(path)
	if err != nil || !strings.Contains(string(raw), `"startup": null`) || strings.Contains(string(raw), "0123456789abcdef") {
		t.Fatalf("记录文件是\n%s（err=%v）", raw, err)
	}
}

func TestConfirmRefusesWhatIsNotAConfirmation(t *testing.T) {
	directory, dir := open(t)
	good := confirmation(t, "routes: [a]\n", "digest-a")
	for name, spoil := range map[string]func(*domain.Confirmation){
		"没有快照":   func(c *domain.Confirmation) { c.Snapshot = domain.Snapshot{} },
		"没有摘要":   func(c *domain.Confirmation) { c.Digest = "" },
		"没有版本":   func(c *domain.Confirmation) { c.Version = "" },
		"没有提交":   func(c *domain.Confirmation) { c.Revision = "" },
		"没有启动设置": func(c *domain.Confirmation) { c.Startup = nil },
	} {
		bad := good
		spoil(&bad)
		if err := directory.Confirm(ctx, bad); err == nil {
			t.Errorf("%s：被记下了", name)
		}
	}
	if found := names(t, dir); len(found) != 0 {
		t.Fatalf("目录里有 %v", found)
	}
}

// 记录读得到却不成样子：报错，不当成"没有记录"。
func TestADamagedRecordIsAnError(t *testing.T) {
	directory, dir := open(t)
	if err := directory.Confirm(ctx, confirmation(t, "routes: [a]\n", "digest-a")); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, ".config.yaml.confirmed")
	intact, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	other := snap(t, "routes: [a]\n").ID()
	startup := string(intact[strings.Index(string(intact), `"startup": {`):strings.Index(string(intact), `"adopted"`)])
	for name, c := range map[string]struct{ damaged, says string }{
		"截断了":       {string(intact[:len(intact)/2]), "damaged"},
		"是空的":       {"", "damaged"},
		"内容与名字对不上":  {strings.Replace(string(intact), other, snap(t, "something else").ID(), 1), "damaged"},
		"没有内容":      {`{"format":1,"snapshot":"` + other + `","digest":"digest-a","version":"1.7.0","revision":"26f5aebe","startup":{}}`, "damaged"},
		"没有网关报告的摘要": {strings.Replace(string(intact), `"digest-a"`, `""`, 1), "damaged"},
		"没有网关的版本":   {strings.Replace(string(intact), `"1.7.0"`, `""`, 1), "damaged"},
		"没有网关的提交":   {strings.Replace(string(intact), `"26f5aebe"`, `""`, 1), "damaged"},
		"没有启动设置":    {strings.Replace(string(intact), startup, `"startup": null,`+"\n  ", 1), "damaged"},
		"是更新的格式":    {strings.Replace(string(intact), `"format": 1`, `"format": 2`, 1), "is in format 2; this version reads format 1"},
		"没有写格式":     {strings.Replace(string(intact), `"format": 1,`, ``, 1), "is in format 0"},
	} {
		if c.damaged == string(intact) {
			t.Fatalf("%s：没有改动到记录", name)
		}
		if err := os.WriteFile(path, []byte(c.damaged), 0o600); err != nil {
			t.Fatal(err)
		}
		if got, ok, err := directory.Confirmed(ctx); err == nil || ok || !strings.Contains(err.Error(), c.says) || !got.IsZero() {
			t.Errorf("%s：ok=%t err=%v（%+v）", name, ok, err, got)
		}
	}
	// 写回原样就又读得出来：上面各条挡下它的是内容。
	if err := os.WriteFile(path, intact, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := directory.Confirmed(ctx); !ok || err != nil {
		t.Fatalf("ok=%t err=%v", ok, err)
	}

	// 记录在那里却读不了（这里它的位置上是一个目录）：也不当成"没有记录"。
	directory, dir = open(t)
	if err := os.Mkdir(filepath.Join(dir, ".config.yaml.confirmed"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := directory.Confirmed(ctx); err == nil || ok {
		t.Fatalf("ok=%t err=%v", ok, err)
	}
}

// 以前的发布器死在半路，留下的临时文件：下一次换文件时清掉。锁、记录和别的文件不动。
func TestPutSweepsTemporaryFilesLeftBehind(t *testing.T) {
	directory, dir := open(t)
	if err := directory.Confirm(ctx, confirmation(t, "routes: [a]\n", "digest-a")); err != nil {
		t.Fatal(err)
	}
	release, err := directory.Hold(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	for _, name := range []string{".config.yaml.0123456789ab.tmp", ".config.yaml.confirmed.tmp", "notes.tmp", ".other.yaml.0123456789ab.tmp"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("left behind"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := directory.Put(ctx, snap(t, "routes: [a, b]\n")); err != nil {
		t.Fatal(err)
	}
	want := []string{".config.yaml.confirmed", ".config.yaml.lock", ".other.yaml.0123456789ab.tmp", "config.yaml", "notes.tmp"}
	if found := names(t, dir); strings.Join(found, " ") != strings.Join(want, " ") {
		t.Fatalf("目录里有 %v", found)
	}
}
