package authzstate

import (
	"context"
	"errors"
	"log/slog"
	"slices"

	"go.idp.xyz/idp-gateway/internal/egressauthz/adapters/filestore"
	"go.idp.xyz/idp-gateway/internal/egressauthz/ports"
)

// Ledger 在协调器上读和改撤销表。每一次读都取一份新快照。
// 取不到、超时、401、5xx 或正文读不懂都是错误：调用方不得用旧快照放行。
// 本地文件只在启动和成功的改动之后被整份换成协调器的快照，不参与判定。
type Ledger struct {
	client *Client
	local  *filestore.Revocations
	log    *slog.Logger
}

// NewLedger 把 client 同时当作 ports.Revocations 和 ports.RevocationLedger。
// local 是 --revocations 指向的文件，用来留下启动时和改动后的镜像。
func NewLedger(client *Client, local *filestore.Revocations, logger *slog.Logger) *Ledger {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	return &Ledger{client: client, local: local, log: logger}
}

// Mirror 启动时调用：先取一份快照，再把它写进本地撤销文件。取不到就返回错误，调用方不得启动。
// 本地代次和协调器不同时，写下去的是协调器这一份。
func Mirror(ctx context.Context, client *Client, local *filestore.Revocations) error {
	snap, err := client.Snapshot(ctx)
	if err != nil {
		return err
	}
	return local.Adopt(snap.epoch, snap.accounts, snap.bans)
}

func (l *Ledger) State(ctx context.Context, accountID string) (bool, uint64, error) {
	snap, err := l.client.Snapshot(ctx)
	if err != nil {
		return false, 0, err
	}
	return revoked(snap, accountID), snap.epoch, nil
}

func (l *Ledger) View(ctx context.Context, accountID, operationID string) (bool, bool, uint64, error) {
	snap, err := l.client.Snapshot(ctx)
	if err != nil {
		return false, false, 0, err
	}
	return revoked(snap, accountID), banned(snap, operationID), snap.epoch, nil
}

func (l *Ledger) Epoch(ctx context.Context) (uint64, error) {
	snap, err := l.client.Snapshot(ctx)
	if err != nil {
		return 0, err
	}
	return snap.epoch, nil
}

func (l *Ledger) Revoke(ctx context.Context, accountID, by, reason string) (ports.RevocationChange, error) {
	if accountID == "" {
		return ports.RevocationChange{}, errors.New("revocations: no account given")
	}
	result, err := l.client.mutate(ctx, mutation{Action: "revoke", AccountID: accountID, By: by, Reason: reason})
	if err != nil {
		return ports.RevocationChange{}, err
	}
	l.mirror(ctx)
	return ports.RevocationChange{Changed: result.Changed, Revoked: result.Revoked, Epoch: result.Epoch}, nil
}

func (l *Ledger) Restore(ctx context.Context, accountID string) (ports.RevocationChange, error) {
	if accountID == "" {
		return ports.RevocationChange{}, errors.New("revocations: no account given")
	}
	result, err := l.client.mutate(ctx, mutation{Action: "restore", AccountID: accountID})
	if err != nil {
		return ports.RevocationChange{}, err
	}
	l.mirror(ctx)
	return ports.RevocationChange{Changed: result.Changed, Revoked: result.Revoked, Epoch: result.Epoch}, nil
}

func (l *Ledger) Revoked(ctx context.Context) ([]ports.RevokedAccount, uint64, error) {
	snap, err := l.client.Snapshot(ctx)
	if err != nil {
		return nil, 0, err
	}
	return snap.accounts, snap.epoch, nil
}

func (l *Ledger) Ban(ctx context.Context, operationID, by, reason string) (ports.BanChange, error) {
	if operationID == "" {
		return ports.BanChange{}, errors.New("revocations: no operation given")
	}
	result, err := l.client.mutate(ctx, mutation{Action: "ban", OperationID: operationID, By: by, Reason: reason})
	if err != nil {
		return ports.BanChange{}, err
	}
	l.mirror(ctx)
	return ports.BanChange{Changed: result.Changed, Banned: result.Banned, Epoch: result.Epoch}, nil
}

func (l *Ledger) Lift(ctx context.Context, operationID string) (ports.BanChange, error) {
	if operationID == "" {
		return ports.BanChange{}, errors.New("revocations: no operation given")
	}
	result, err := l.client.mutate(ctx, mutation{Action: "lift", OperationID: operationID})
	if err != nil {
		return ports.BanChange{}, err
	}
	l.mirror(ctx)
	return ports.BanChange{Changed: result.Changed, Banned: result.Banned, Epoch: result.Epoch}, nil
}

func (l *Ledger) Banned(ctx context.Context) ([]ports.BannedOperation, uint64, error) {
	snap, err := l.client.Snapshot(ctx)
	if err != nil {
		return nil, 0, err
	}
	return snap.bans, snap.epoch, nil
}

func (l *Ledger) mirror(ctx context.Context) {
	if l.local == nil {
		return
	}
	if err := Mirror(ctx, l.client, l.local); err != nil {
		l.log.Warn("authz state mirror failed", "cause", err.Error())
	}
}

func revoked(snap snapshot, accountID string) bool {
	for _, account := range snap.accounts {
		if account.AccountID == accountID {
			return true
		}
	}
	return false
}

func banned(snap snapshot, operationID string) bool {
	for _, ban := range snap.bans {
		if ban.OperationID == operationID {
			return true
		}
	}
	return false
}

func sortAccounts(accounts []ports.RevokedAccount) {
	slices.SortFunc(accounts, func(a, b ports.RevokedAccount) int {
		switch {
		case a.AccountID < b.AccountID:
			return -1
		case a.AccountID > b.AccountID:
			return 1
		default:
			return 0
		}
	})
}

func sortBans(bans []ports.BannedOperation) {
	slices.SortFunc(bans, func(a, b ports.BannedOperation) int {
		switch {
		case a.OperationID < b.OperationID:
			return -1
		case a.OperationID > b.OperationID:
			return 1
		default:
			return 0
		}
	})
}
