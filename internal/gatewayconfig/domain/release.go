package domain

import (
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// ReleaseState 是发布历史里记下来的状态：G03 第 3 节的状态机里发布器自己经手的那一段
// （docs/adr/ADR-0013.md 第 2 条）。
type ReleaseState string

const (
	// StateStaged：快照离线加载通过，这一次发布开始了。池还没有被动过。
	StateStaged ReleaseState = "STAGED"
	// StateApplying：正要动手。每一步（换文件、重启网关）之前各记一行，行上有步骤名。
	StateApplying ReleaseState = "APPLYING"
	// StateObserving：手动完了，等网关报告。这一行不是动手之前的一步，写不进去不拦发布。
	StateObserving ReleaseState = "OBSERVING"
	// StateActive：这份快照在池里的网关上生效，并且记成了池上最后一次确认的。
	StateActive ReleaseState = "ACTIVE"
	// StateFailed：没有生效。上一份已经放回去并得到确认（或者池原本就没有被这一次动过）。
	StateFailed ReleaseState = "FAILED"
	// StateUnknown：换上去了，没有生效，也没能确认放回去。等对账。
	StateUnknown ReleaseState = "UNKNOWN"
	// StateOvertaken：这一条没有结局，后来又有了更新的发布，对账把它收了尾：结局不明。
	// 它不是 FAILED：没有人知道它有没有生效过。
	StateOvertaken ReleaseState = "OVERTAKEN"
	// StateSuperseded 不写进历史：读的时候，同一个池上有更晚的一条 ACTIVE，这一条（ACTIVE 的）就是 SUPERSEDED。
	StateSuperseded ReleaseState = "SUPERSEDED"
)

// Settled 报告这个状态是不是一个结局：之后历史里不会再为这一条追加什么。
// UNKNOWN 不是：它在等对账。
func (s ReleaseState) Settled() bool {
	return s == StateActive || s == StateFailed || s == StateOvertaken
}

// Known 报告这是不是历史里会出现的状态。
func (s ReleaseState) Known() bool {
	switch s {
	case StateStaged, StateApplying, StateObserving, StateActive, StateFailed, StateUnknown, StateOvertaken:
		return true
	}
	return false
}

// 步骤名：APPLYING 的行上写它，说明接下来要做的是哪一步。别的行上的步骤名说明是谁写的这一行。
const (
	StepReplaceFile    = "replace-file"
	StepRestartGateway = "restart-gateway"
	StepReconcile      = "reconcile"
	StepRerun          = "publish-again"
)

// 限制。
const (
	// MaxNoteBytes 与撤销的原因同长。
	MaxNoteBytes = 512
	// MaxPoolBytes 是池的标识最长多少字节。
	MaxPoolBytes = 64
)

// ValidateNote 检查操作员的备注：可以为空，最长 MaxNoteBytes 字节，必须是 UTF-8，不许有控制字符。
func ValidateNote(note string) error {
	switch {
	case len(note) > MaxNoteBytes:
		return fmt.Errorf("the note is %d bytes long; at most %d are allowed", len(note), MaxNoteBytes)
	case !utf8.ValidString(note):
		return errors.New("the note is not valid UTF-8")
	}
	for _, r := range note {
		if unicode.IsControl(r) {
			return fmt.Errorf("the note contains the control character U+%04X; it must be one line of plain text", r)
		}
	}
	return nil
}

// ValidatePool 检查池的标识：1 到 MaxPoolBytes 个字符，只许字母、数字、点、下划线、连字符。
func ValidatePool(pool string) error {
	if pool == "" || len(pool) > MaxPoolBytes {
		return fmt.Errorf("the pool name must be 1 to %d characters", MaxPoolBytes)
	}
	for _, r := range pool {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '_' || r == '-') {
			return fmt.Errorf("the pool name %q has a character outside letters, digits, '.', '_' and '-'", pool)
		}
	}
	return nil
}

// Initiator 是谁发起的这一次发布。两项都是进程自己报的，没有别人核实。
type Initiator struct {
	// Workload 是发布器证书里唯一的那个 URI 身份；没有或者不止一个时为空。
	Workload string
	// Account 是跑这个进程的操作系统账号。
	Account string
}

// ReleaseStart 是开始一条发布记录时要交给历史的东西。
type ReleaseStart struct {
	// Snapshot 是要发布的；Previous 是动手之前放在那里的（没有时为零值）。两份的全文都由历史存下。
	Snapshot Snapshot
	Previous Snapshot
	// Expected 是离线加载得到的运行配置摘要。
	Expected string
	// Command 是哪个命令发起的：publish、restart 或 rollback。
	Command string
	// By 和 Note：谁发起的；操作员的备注，未经核实。
	By   Initiator
	Note string
	// RolledBackTo 是回滚时回到的那一条的编号；不是回滚时为 0。
	RolledBackTo uint64
	// At 是开始的时刻。
	At time.Time
}

// StepFacts 是结局那一行上带的事实：网关最后一次报告的，和需要重启时哪几项启动设置不同。
type StepFacts struct {
	Digest   string
	Version  string
	Revision string
	Restart  []string
}

// ReleaseStep 是一条发布记录的一步：一次状态变化。
type ReleaseStep struct {
	State ReleaseState
	// Name 是步骤名（见 Step 开头的常量），没有时为空。
	Name string
	// Reason 是原因；没有要说的时为空。
	Reason string
	At     time.Time
	// Facts 只在结局的那一行上有。
	Facts *StepFacts
}

// Release 是历史里的一条发布记录：开始时定下来的那些，和之后每一步。
type Release struct {
	// Number 是这个池里从 1 起单调增加的编号，由历史给。
	Number uint64
	Pool   string

	Snapshot     string
	Previous     string
	Expected     string
	Command      string
	By           Initiator
	Note         string
	RolledBackTo uint64
	// Supersedes 是开始时这个池上最后一条 ACTIVE 的编号；还没有过时为 0。
	Supersedes uint64
	// RouteIntent 留给将来：这份快照由哪个 RouteIntent 编译而来。现在永远为空
	// （开发计划第 4 节第 3 项）。
	RouteIntent string

	// Steps 按写入的先后。第一步总是 STAGED。
	Steps []ReleaseStep
	// SupersededBy 不是存下来的，是读的时候由 DeriveSuperseded 推出来的：更晚的那条 ACTIVE 的编号。
	SupersededBy uint64
}

// State 是最后一步的状态。
func (r Release) State() ReleaseState {
	if len(r.Steps) == 0 {
		return ""
	}
	return r.Steps[len(r.Steps)-1].State
}

// Settled 报告这一条有没有结局。
func (r Release) Settled() bool { return r.State().Settled() }

// StartedAt 是开始的时刻。
func (r Release) StartedAt() time.Time {
	if len(r.Steps) == 0 {
		return time.Time{}
	}
	return r.Steps[0].At
}

// FinishedAt 是结局的时刻；还没有结局时为零值。
func (r Release) FinishedAt() time.Time {
	if !r.Settled() {
		return time.Time{}
	}
	return r.Steps[len(r.Steps)-1].At
}

// ReachedActive 报告这一条有没有到过 ACTIVE：回滚只能回到这样的。
func (r Release) ReachedActive() bool {
	for _, step := range r.Steps {
		if step.State == StateActive {
			return true
		}
	}
	return false
}

// Replaced 和 Restarted 由步骤推出来：写过"换文件"、"重启网关"那一步的行，就是动过手。
func (r Release) Replaced() bool  { return r.did(StepReplaceFile) }
func (r Release) Restarted() bool { return r.did(StepRestartGateway) }

func (r Release) did(name string) bool {
	for _, step := range r.Steps {
		if step.State == StateApplying && step.Name == name {
			return true
		}
	}
	return false
}

// Facts 是结局那一行上的事实；没有时为 nil。
func (r Release) Facts() *StepFacts {
	for i := len(r.Steps) - 1; i >= 0; i-- {
		if r.Steps[i].Facts != nil {
			return r.Steps[i].Facts
		}
	}
	return nil
}

// Reason 是最后一个带原因的步骤的原因。
func (r Release) Reason() string {
	for i := len(r.Steps) - 1; i >= 0; i-- {
		if r.Steps[i].Reason != "" {
			return r.Steps[i].Reason
		}
	}
	return ""
}

// ShownState 是给人看的状态：ACTIVE 而后来有更晚的 ACTIVE 的，是 SUPERSEDED。
func (r Release) ShownState() ReleaseState {
	if r.State() == StateActive && r.SupersededBy != 0 {
		return StateSuperseded
	}
	return r.State()
}

// DeriveSuperseded 返回 releases 的一份副本，每一条 ACTIVE 的上面填好 SupersededBy：同一个池上
// 编号更大的最近那条 ACTIVE。releases 要按编号从小到大。
func DeriveSuperseded(releases []Release) []Release {
	derived := make([]Release, len(releases))
	copy(derived, releases)
	var next uint64 // 往回看时，目前见到的最小的 ACTIVE 编号
	for i := len(derived) - 1; i >= 0; i-- {
		if derived[i].State() != StateActive {
			continue
		}
		derived[i].SupersededBy = next
		next = derived[i].Number
	}
	return derived
}

// LastActive 返回编号最大的一条 ACTIVE 的；没有时 ok 为假。
func LastActive(releases []Release) (release Release, ok bool) {
	for i := len(releases) - 1; i >= 0; i-- {
		if releases[i].State() == StateActive {
			return releases[i], true
		}
	}
	return Release{}, false
}

// ShortSnapshot 缩短一个快照 ID，给人看。
func ShortSnapshot(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

// Describe 是一条记录的一句话，用在提示里。
func (r Release) Describe() string {
	return fmt.Sprintf("release %d (snapshot %s, %s)", r.Number, ShortSnapshot(r.Snapshot), strings.ToLower(string(r.State())))
}
