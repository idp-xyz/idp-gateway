package main

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"go.idp.xyz/idp-gateway/internal/fabricpub/ports"
	gapplication "go.idp.xyz/idp-gateway/internal/gatewayconfig/application"
	gdomain "go.idp.xyz/idp-gateway/internal/gatewayconfig/domain"
	gports "go.idp.xyz/idp-gateway/internal/gatewayconfig/ports"
)

// poolPublisher 把 fabricpub 的发布端口接到 gatewayconfig 的 Publish 和 Reconcile。
type poolPublisher struct {
	staging    gports.Staging
	publisher  *gapplication.Publisher
	reconciler *gapplication.Reconciler
}

func (p *poolPublisher) Stage(ctx context.Context, gatewayYAML []byte) (string, error) {
	snapshot, err := gdomain.NewSnapshot(gatewayYAML)
	if err != nil {
		return "", err
	}
	observed, err := p.staging.Load(ctx, snapshot)
	if err != nil {
		var rejected *gports.RejectedError
		if errors.As(err, &rejected) {
			return "", fmt.Errorf("%w: offline load refused", ports.ErrRefused)
		}
		return "", err
	}
	if observed.Digest == "" || !observed.Synchronized || observed.StorageMode != gdomain.StorageReadOnly {
		return "", fmt.Errorf("%w: offline load did not confirm a read-only configuration", ports.ErrRefused)
	}
	return observed.Digest, nil
}

func (p *poolPublisher) Publish(ctx context.Context, gatewayYAML []byte, _ string) (ports.PublishOutcome, error) {
	snapshot, err := gdomain.NewSnapshot(gatewayYAML)
	if err != nil {
		return ports.PublishOutcome{}, err
	}
	result, err := p.publisher.Publish(ctx, snapshot)
	if errors.Is(err, gports.ErrBusy) {
		return ports.PublishOutcome{Busy: true, Reason: oneLine(result.Reason)}, fmt.Errorf("%w", ports.ErrBusy)
	}
	return publishOutcome(result), err
}

func (p *poolPublisher) Reconcile(ctx context.Context) (ports.ReconcileOutcome, error) {
	result, err := p.reconciler.Reconcile(ctx)
	if errors.Is(err, gports.ErrBusy) {
		return ports.ReconcileOutcome{}, fmt.Errorf("%w", ports.ErrBusy)
	}
	return ports.ReconcileOutcome{
		Outcome:        string(result.Outcome),
		DesiredDigest:  result.Expected,
		ObservedDigest: result.Observed.Digest,
		Replaced:       result.Replaced,
		Reason:         oneLine(result.Reason),
	}, err
}

func publishOutcome(result gapplication.Result) ports.PublishOutcome {
	return ports.PublishOutcome{
		Outcome:        string(result.Outcome),
		DesiredDigest:  result.Expected,
		ObservedDigest: result.Observed.Digest,
		Replaced:       result.Replaced,
		Reason:         oneLine(result.Reason),
	}
}

func oneLine(text string) string {
	text = strings.Join(strings.Fields(text), " ")
	if len(text) > 180 {
		text = text[:180]
	}
	return text
}
