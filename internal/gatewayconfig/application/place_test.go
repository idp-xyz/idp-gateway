package application

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"go.idp.xyz/idp-gateway/internal/gatewayconfig/domain"
	"go.idp.xyz/idp-gateway/internal/gatewayconfig/ports"
)

// notRunning 让这个池的网关没有在跑：就位是在网关启动之前做的。Place 拿到的只有下发这一样，
// 回读口它本来也读不了。
func (p *pool) notRunning() *pool {
	p.down = true
	return p
}

func place(t *testing.T, p *pool) Result {
	t.Helper()
	result, err := Place(context.Background(), p)
	if err != nil {
		t.Fatalf("Place: %v", err)
	}
	if p.held {
		t.Error("就位返回之后还占着这个池")
	}
	if p.staged != 0 || p.restarts != 0 || len(p.confirms) != 0 || p.elapsed() != 0 {
		t.Errorf("就位不做离线加载、不重启、不改记录、不等：离线加载 %d 次，重启 %d 次，记了 %v，等了 %s", p.staged, p.restarts, p.confirms, p.elapsed())
	}
	if !reflect.DeepEqual(result.Observed, domain.Observation{}) {
		t.Errorf("就位不读网关，却带着一次观察：%+v", result.Observed)
	}
	return result
}

func TestTheConfirmedSnapshotAlreadyInPlaceIsLeftAlone(t *testing.T) {
	p := newPool(t, "one", threeSnapshots).confirmed("one").notRunning()
	result := place(t, p)
	if result.Outcome != OutcomeInPlace || result.Replaced || result.Reason != "" || len(p.puts) != 0 {
		t.Fatalf("%+v，写了 %v", result, p.puts)
	}
	if result.Snapshot != snap(t, "one").ID() || result.Previous != snap(t, "one").ID() || result.Expected != "digest-one" {
		t.Fatalf("%+v", result)
	}
}

// 网关启动之前，放在那里的不是确认过的那一份：不管它是什么，放回去。
func TestWhateverIsNotTheConfirmedSnapshotIsPutBackBeforeTheGatewayStarts(t *testing.T) {
	for name, c := range map[string]struct {
		spoil    func(*pool)
		says     string
		previous string
	}{
		"没做完的发布留下的一份（网关加载得了）": {func(*pool) {}, "what was in place (" + snap(t, "two").ShortID() + ") was not the snapshot last confirmed on this pool", snap(t, "two").ID()},
		"一份网关加载不了的文件": {func(p *pool) {
			broken := snap(p.t, "broken")
			p.file = &broken
		}, "was not the snapshot last confirmed on this pool", snap(t, "broken").ID()},
		"文件不见了": {func(p *pool) { p.file = nil }, "there was no configuration file in place", ""},
		"放在那里的读不成一份配置（空文件）": {func(p *pool) { p.currentErr = errors.New("a snapshot cannot be empty") },
			"what was in place could not be read as a configuration (a snapshot cannot be empty)", ""},
	} {
		p := newPool(t, "two", threeSnapshots).confirmed("one").notRunning()
		c.spoil(p)
		result := place(t, p)
		if result.Outcome != OutcomeInPlace || !result.Replaced || !strings.Contains(result.Reason, c.says) {
			t.Errorf("%s：%+v", name, result)
		}
		if result.Previous != c.previous || result.Snapshot != snap(t, "one").ID() || result.Expected != "digest-one" {
			t.Errorf("%s：%+v", name, result)
		}
		if !reflect.DeepEqual(p.puts, []string{"one"}) || p.file == nil || string(p.file.Content()) != "one" {
			t.Errorf("%s：写了 %v", name, p.puts)
		}
		// 再来一次：已经在那里了，不再写。
		if again := place(t, p); again.Outcome != OutcomeInPlace || again.Replaced || again.Reason != "" || len(p.puts) != 1 {
			t.Errorf("%s，再来一次：%+v，写了 %v", name, again, p.puts)
		}
	}
}

// 接手来的记录（发布器第一次动这个池时放在那里的那一份）一样算数。
func TestAnAdoptedRecordIsPutBackToo(t *testing.T) {
	p := newPool(t, "two", threeSnapshots).adopted("one").notRunning()
	if result := place(t, p); result.Outcome != OutcomeInPlace || !result.Replaced || !reflect.DeepEqual(p.puts, []string{"one"}) {
		t.Fatalf("%+v，写了 %v", result, p.puts)
	}
}

// 这个池上还没有确认过任何发布：没有哪一份可放。网关从放在那里的文件启动，之后的对账不认它。
func TestWithoutARecordNothingIsPutInPlace(t *testing.T) {
	p := newPool(t, "one", threeSnapshots).notRunning()
	result := place(t, p)
	if result.Outcome != OutcomeNoRecord || result.Replaced || len(p.puts) != 0 || result.Snapshot != "" || result.Expected != "" {
		t.Fatalf("%+v，写了 %v", result, p.puts)
	}
	if result.Previous != snap(t, "one").ID() || !strings.Contains(result.Reason, "no publication has been confirmed on this pool yet") {
		t.Fatalf("%+v", result)
	}

	// 目录里连文件都没有。
	p = newPool(t, "", threeSnapshots).notRunning()
	if result := place(t, p); result.Outcome != OutcomeNoRecord || result.Replaced || len(p.puts) != 0 || result.Previous != "" {
		t.Fatalf("%+v，写了 %v", result, p.puts)
	}

	// 没有记录，放在那里的又读不出来：不能说网关可以启动。
	p = newPool(t, "one", threeSnapshots).notRunning()
	p.currentErr = errors.New("a snapshot cannot be empty")
	if _, err := Place(context.Background(), p); err == nil || !strings.Contains(err.Error(), "cannot be empty") || len(p.puts) != 0 || p.held {
		t.Fatalf("得到 %v，写了 %v", err, p.puts)
	}
}

func TestWhenTheConfirmedSnapshotCannotBePutInPlaceTheOutcomeIsUnknown(t *testing.T) {
	p := newPool(t, "two", threeSnapshots).confirmed("one").notRunning()
	p.failPut[1] = errors.New("disk full")
	result := place(t, p)
	if result.Outcome != OutcomeUnknown || !result.Replaced || string(p.file.Content()) != "two" ||
		!strings.Contains(result.Reason, "was not the snapshot last confirmed on this pool; putting the confirmed snapshot back failed: disk full") {
		t.Fatalf("%+v，目录里是 %s", result, p.file.Content())
	}
}

// cancelling 是一个正要往回放的时候被叫停的池。
type cancelling struct {
	*pool
	stop context.CancelFunc
}

func (c cancelling) Put(ctx context.Context, snapshot domain.Snapshot) error {
	c.stop()
	return c.pool.Put(ctx, snapshot)
}

func TestCancellationDoesNotStopPlacingHalfway(t *testing.T) {
	// 开始往回放之后被叫停：做完再返回。
	p := newPool(t, "two", threeSnapshots).confirmed("one").notRunning()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result, err := Place(ctx, cancelling{p, cancel})
	if err != nil || result.Outcome != OutcomeInPlace || !result.Replaced || string(p.file.Content()) != "one" || ctx.Err() == nil {
		t.Fatalf("%+v（%v），目录里是 %s", result, err, p.file.Content())
	}

	// 还没开始放就被叫停：不开始。
	p = newPool(t, "two", threeSnapshots).confirmed("one").notRunning()
	if _, err := Place(ctx, p); err == nil || !strings.Contains(err.Error(), "interrupted before") || len(p.puts) != 0 || string(p.file.Content()) != "two" || p.held {
		t.Fatalf("得到 %v，写了 %v", err, p.puts)
	}
	// 用不着放的时候，被叫停也照常回答。
	p = newPool(t, "one", threeSnapshots).confirmed("one").notRunning()
	if result, err := Place(ctx, p); err != nil || result.Outcome != OutcomeInPlace || result.Replaced {
		t.Fatalf("%+v（%v）", result, err)
	}
}

func TestPlaceFailsWithoutTouchingThePool(t *testing.T) {
	p := newPool(t, "two", threeSnapshots).confirmed("one").notRunning()
	p.held = true
	if _, err := Place(context.Background(), p); !errors.Is(err, ports.ErrBusy) {
		t.Fatalf("得到 %v", err)
	}
	p.held = false
	p.recordErr = errors.New("the record is damaged")
	if _, err := Place(context.Background(), p); err == nil || !strings.Contains(err.Error(), "damaged") {
		t.Fatalf("得到 %v", err)
	}
	if len(p.puts) != 0 || p.held || string(p.file.Content()) != "two" {
		t.Fatalf("写了 %v，held=%t", p.puts, p.held)
	}
	if _, err := Place(context.Background(), nil); err == nil {
		t.Error("没有下发：被接受了")
	}
}
