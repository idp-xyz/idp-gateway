package directory

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"go.idp.xyz/idp-gateway/internal/gatewayconfig/domain"
)

// recordFormat 是记录文件现在的格式。格式变得旧版本读不对时加一。
const recordFormat = 1

// record 是记录文件的内容：这个池上最后一次得到确认的那份快照，和确认它时网关报告的。
// 快照的内容整份带着，对不上时要把它放回去；它在文件里是 base64。
//
// 这是单机下发自己的东西，只说"这个目录里该放着哪一份"。它不是发布的记录：谁批准的、发布过哪些，
// 不在这里（G03 的发布状态还没有做）。
type record struct {
	Format int `json:"format"`
	// Snapshot 是内容的 SHA-256，读的时候拿它核对内容。
	Snapshot string `json:"snapshot"`
	Content  []byte `json:"content"`
	// Digest、Version、Revision 是确认时网关报告的运行配置摘要和构建。
	Digest   string `json:"digest"`
	Version  string `json:"version"`
	Revision string `json:"revision"`
	// Startup 是确认时网关的启动设置，每一项只有值的指纹，没有值。Adopted 为真时没有这一项：
	// 这份快照是发布器第一次动这个池时已经放在那里的。
	Startup map[string]string `json:"startup"`
	Adopted bool              `json:"adopted"`
	// ConfirmedAt 是记下的时刻，给人看的。
	ConfirmedAt string `json:"confirmed_at"`
}

func (d *Directory) recordName() string { return "." + d.name + ".confirmed" }

// Confirmed 读出记录。没有记录文件时 ok 为假；有却读不成样子时返回错误。
func (d *Directory) Confirmed(context.Context) (domain.Confirmation, bool, error) {
	none := domain.Confirmation{}
	path := filepath.Join(d.dir, d.recordName())
	raw, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return none, false, nil
	}
	if err != nil {
		return none, false, fmt.Errorf("directory: %w", err)
	}
	damaged := func(why string) (domain.Confirmation, bool, error) {
		return none, false, fmt.Errorf("directory: the record of the last confirmed snapshot (%s) is damaged: %s", path, why)
	}
	var stored record
	if err := json.Unmarshal(raw, &stored); err != nil {
		return damaged(err.Error())
	}
	if stored.Format != recordFormat {
		// 不认识的格式不猜：多半是更新的版本写的。
		return none, false, fmt.Errorf("directory: the record of the last confirmed snapshot (%s) is in format %d; this version reads format %d",
			path, stored.Format, recordFormat)
	}
	snapshot, err := domain.NewSnapshot(stored.Content)
	if err != nil {
		return damaged("it carries no snapshot")
	}
	if snapshot.ID() != stored.Snapshot {
		return damaged("the snapshot in it does not have the SHA-256 it is recorded under")
	}
	if stored.Digest == "" || stored.Version == "" || stored.Revision == "" {
		return damaged("it does not say what the gateway reported")
	}
	confirmation := domain.Confirmation{
		Snapshot: snapshot, Digest: stored.Digest, Version: stored.Version, Revision: stored.Revision, Adopted: stored.Adopted,
	}
	if !stored.Adopted {
		if stored.Startup == nil {
			return damaged("it does not say what startup settings the gateway had")
		}
		confirmation.Startup = stored.Startup
	}
	return confirmation, true, nil
}

// Confirm 把记录整份换成这一条，做法与换配置文件相同。
func (d *Directory) Confirm(_ context.Context, confirmation domain.Confirmation) error {
	if confirmation.IsZero() || confirmation.Digest == "" || confirmation.Version == "" || confirmation.Revision == "" {
		return errors.New("directory: a confirmation needs the snapshot and what the gateway reported")
	}
	if !confirmation.Adopted && confirmation.Startup == nil {
		return errors.New("directory: a confirmation needs the startup settings the gateway had")
	}
	stored := record{
		Format: recordFormat, Snapshot: confirmation.Snapshot.ID(), Content: confirmation.Snapshot.Content(),
		Digest: confirmation.Digest, Version: confirmation.Version, Revision: confirmation.Revision,
		Adopted: confirmation.Adopted, ConfirmedAt: time.Now().UTC().Format(time.RFC3339),
	}
	if !confirmation.Adopted {
		stored.Startup = confirmation.Startup
	}
	raw, err := json.MarshalIndent(stored, "", "  ")
	if err != nil {
		return fmt.Errorf("directory: %w", err)
	}
	return d.replace(d.recordName(), d.recordName()+".tmp", append(raw, '\n'), recordMode)
}
