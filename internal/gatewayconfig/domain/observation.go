package domain

// StorageReadOnly 是网关报告的存储模式必须取的值：管理接口改不了运行配置，也不会把改动写回
// 配置文件（ADR-0010 第 4 条的 config.storage.mode: readOnly）。
const StorageReadOnly = "readOnly"

// Observation 是经回读口从一个网关读到的：它此刻在跑什么，上一次加载配置文件的结果如何。
type Observation struct {
	// Digest 是它的运行配置的摘要（PublishedDigest）。
	Digest string
	// Settings 是它启动时定下的设置。
	Settings Settings
	// Synchronized 为假表示它上一次加载配置文件失败了：在跑的仍是失败之前的那一份。
	Synchronized bool
	// LastError 是上一次加载失败的原因；加载成功时为空。
	LastError string
	// StorageMode 是它报告的存储模式。
	StorageMode string
	// Version 和 Revision 是它自报的版本和源码提交。
	Version  string
	Revision string
}

// Confirms 报告这次观察是否说明 staged 所代表的那份快照正在这个网关上生效：
// 运行配置的摘要相同，上一次加载成功，存储模式只读。staged 是发布之前用同一个镜像离线加载
// 这份快照时的观察。
//
// 启动设置不在这里比：它们不同时这份快照的其余部分照样生效，但要重启网关才算全部到位，
// 见 Settings.Differing。
func (o Observation) Confirms(staged Observation) bool {
	return staged.Digest != "" && o.Digest == staged.Digest && o.Synchronized && o.StorageMode == StorageReadOnly
}

// SameBuild 报告两次观察是不是出自同一个网关构建。读不到版本或提交的不算同一个。
// 运行配置的摘要里有网关的版本，所以换了构建，同一份快照的摘要也不同。
func (o Observation) SameBuild(other Observation) bool {
	return o.Version != "" && o.Revision != "" && o.Version == other.Version && o.Revision == other.Revision
}
