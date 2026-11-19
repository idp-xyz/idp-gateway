package ports

import (
	"context"
	"errors"

	"go.idp.xyz/idp-gateway/internal/gatewayconfig/domain"
)

// 历史读不成时的几种错误。别的错误（目录不存在、写不进去）直接返回。
var (
	// ErrReleaseNotFound：历史里没有这个编号。
	ErrReleaseNotFound = errors.New("gatewayconfig: no such release in the history")
	// ErrSnapshotNotFound：历史里没有存过这个 ID 的快照。
	ErrSnapshotNotFound = errors.New("gatewayconfig: no such snapshot in the history")
	// ErrSnapshotDamaged：存下的快照与它的 SHA-256 对不上。
	ErrSnapshotDamaged = errors.New("gatewayconfig: a stored snapshot does not have the SHA-256 it is stored under")
	// ErrHistoryDamaged：历史读得到却不成样子。不猜，不跳过。
	ErrHistoryDamaged = errors.New("gatewayconfig: the release history is damaged")
)

// History 是一个池的发布历史（docs/adr/ADR-0013.md）：每次发布一条记录，一步一步追加，之前的不改。
// 端口上只有发布和快照，没有文件路径、行号这类只有某一种存储才有的东西。
//
// 写的方法（Begin、Advance）都发生在 Delivery.Hold 之内：同一个池同一时刻只有一个写入方。
// 读的方法（List、Get、Snapshot）不占锁。
type History interface {
	// Begin 开始一条新的发布记录：存下快照（和动手之前放着的那一份，还没有存过的话），给它下一个编号，
	// 写第一步 STAGED，落盘之后才返回。写不进去时返回错误，什么都不算开始了。
	Begin(ctx context.Context, start domain.ReleaseStart) (number uint64, err error)
	// Advance 给这一条追加一步，落盘之后才返回。写不进去时返回错误，这一步没有记下。
	Advance(ctx context.Context, number uint64, step domain.ReleaseStep) error
	// Snapshot 按 ID 取出存下的快照，取出时核对 SHA-256：对不上返回 ErrSnapshotDamaged。
	Snapshot(ctx context.Context, id string) (domain.Snapshot, error)
	// List 按编号从小到大返回这个池的全部发布记录（每一条带着它所有的步骤）。
	List(ctx context.Context) ([]domain.Release, error)
	// Get 返回一条记录和它的每一步；没有这个编号时返回 ErrReleaseNotFound。
	Get(ctx context.Context, number uint64) (domain.Release, error)
}
