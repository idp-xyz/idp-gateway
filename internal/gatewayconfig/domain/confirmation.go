package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sort"
)

// Confirmation 是一个池上最后一次得到确认的发布：哪一份快照，确认它时池里的网关报告的是什么。
// 对账拿它当依据（ADR-0010 第 10 条）：池里该放着的、网关该在跑的，就是这一份。
type Confirmation struct {
	// Snapshot 是得到确认的那份快照，带着内容：对不上时要把它放回去。
	Snapshot Snapshot
	// Digest 是确认时网关报告的运行配置摘要；Version 和 Revision 是那个网关的构建。
	// 摘要里有网关的版本，所以只能拿同一个构建报告的来比。
	Digest   string
	Version  string
	Revision string
	// Startup 是确认时网关的启动设置，每一项只留值的指纹。对账只要知道它们变没变；而这些值
	// 有一部分取自网关进程的环境，不只取自快照，不该再抄一份到别处。随运行环境变的项不在里面。
	// Adopted 为真时没有这一项。
	Startup map[string]string
	// Adopted 为真表示这份快照不是发布器发布的，是它第一次动这个池时已经放在那里的。
	// 网关当时报告加载成功是看到了的；这份文件给出的启动设置是不是网关启动时的那一套，没有核对过。
	Adopted bool
}

// ConfirmedBy 由一次观察得出一条确认：observed 说明 snapshot 正在这个网关上生效。
// 观察说明不了这一点时返回错误。
func ConfirmedBy(snapshot Snapshot, observed Observation) (Confirmation, error) {
	confirmation, err := newConfirmation(snapshot, observed)
	if err != nil {
		return Confirmation{}, err
	}
	confirmation.Startup = observed.Settings.fingerprints()
	return confirmation, nil
}

// FoundInPlace 记下发布器第一次动一个池时看到的：放在那里的是 snapshot，网关报告的是 observed。
// 从这以后，发布器中途死了也知道该放回哪一份。
func FoundInPlace(snapshot Snapshot, observed Observation) (Confirmation, error) {
	confirmation, err := newConfirmation(snapshot, observed)
	if err != nil {
		return Confirmation{}, err
	}
	confirmation.Adopted = true
	return confirmation, nil
}

func newConfirmation(snapshot Snapshot, observed Observation) (Confirmation, error) {
	switch {
	case snapshot.IsZero():
		return Confirmation{}, errors.New("gatewayconfig: a confirmation needs the snapshot it confirms")
	case !observed.Confirms(observed):
		return Confirmation{}, errors.New("gatewayconfig: the gateway does not report a successful load with read-only storage, so it confirms nothing")
	case observed.Version == "" || observed.Revision == "":
		return Confirmation{}, errors.New("gatewayconfig: the gateway does not report its build, so its digest cannot be compared later")
	}
	return Confirmation{Snapshot: snapshot, Digest: observed.Digest, Version: observed.Version, Revision: observed.Revision}, nil
}

// fingerprints 返回每一项设置的值的指纹（SHA-256）；随运行环境变的项不算。
func (s Settings) fingerprints() map[string]string {
	prints := make(map[string]string, len(s))
	for name, value := range s {
		if !environmentDependent[name] {
			sum := sha256.Sum256([]byte(value))
			prints[name] = hex.EncodeToString(sum[:])
		}
	}
	return prints
}

// IsZero 报告这是不是一条空的记录。
func (c Confirmation) IsZero() bool { return c.Snapshot.IsZero() }

// SameBuild 报告 now 是不是出自做这次确认的那个网关构建。
func (c Confirmation) SameBuild(now Observation) bool {
	return now.SameBuild(Observation{Version: c.Version, Revision: c.Revision})
}

// Holds 报告 now 这次观察是否说明池里的网关在跑的仍是这份确认过的快照：同一个构建，运行配置的
// 摘要相同，上一次加载成功，存储只读。
//
// 构建要相同，是因为摘要里有网关的版本：换了构建，同一份快照的摘要也不同，两边没法比。
// 启动设置不在这里比，见 PendingRestart。
func (c Confirmation) Holds(now Observation) bool {
	return c.SameBuild(now) && now.Confirms(Observation{Digest: c.Digest})
}

// PendingRestart 返回网关此刻的启动设置里与确认时不同的项，按名字排序。不为空时，网关是带着别的
// 设置起来的，要重启才回得到确认过的样子。接手来的记录没有记启动设置，这里什么都不报告。
func (c Confirmation) PendingRestart(now Observation) []string {
	if c.Adopted {
		return nil
	}
	current := now.Settings.fingerprints()
	var names []string
	for name, print := range c.Startup {
		if theirs, ok := current[name]; !ok || theirs != print {
			names = append(names, name)
		}
	}
	for name := range current {
		if _, ok := c.Startup[name]; !ok {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names
}

// Equal 报告两条记录说的是不是同一件事。
func (c Confirmation) Equal(other Confirmation) bool {
	if c.Snapshot.ID() != other.Snapshot.ID() || c.Digest != other.Digest || c.Version != other.Version ||
		c.Revision != other.Revision || c.Adopted != other.Adopted || len(c.Startup) != len(other.Startup) {
		return false
	}
	for name, print := range c.Startup {
		if theirs, ok := other.Startup[name]; !ok || theirs != print {
			return false
		}
	}
	return true
}
