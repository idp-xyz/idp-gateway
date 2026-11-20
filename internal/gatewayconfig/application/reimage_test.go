package application

import (
	"context"
	"errors"
	"testing"
	"time"

	"go.idp.xyz/idp-gateway/internal/gatewayconfig/domain"
	"go.idp.xyz/idp-gateway/internal/gatewayconfig/ports"
)

const (
	runningImage = "cr.agentgateway.dev/agentgateway@sha256:60216aafb03d37f94e952ff3d51d2f630a65b10ecaebdc0a864882f92610c45b"
	nextImage    = "cr.agentgateway.dev/agentgateway@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

type swapFake struct {
	current string
	failAt  int // 第几次 PointAt 返回 ErrImageRecreate；0 表示都不失败
	plain   error
	calls   []string
}

func (s *swapFake) Current(context.Context) (string, error) { return s.current, nil }

func (s *swapFake) PointAt(_ context.Context, reference string) error {
	s.calls = append(s.calls, reference)
	if s.plain != nil && len(s.calls) == 1 {
		return s.plain
	}
	if s.failAt == len(s.calls) {
		return ports.ErrImageRecreate
	}
	return nil
}

type readFake struct{ err error }

func (r readFake) Observe(context.Context) (domain.Observation, error) {
	if r.err != nil {
		return domain.Observation{}, r.err
	}
	return domain.Observation{Digest: "abc", Synchronized: true, StorageMode: domain.StorageReadOnly}, nil
}

func newReimage(t *testing.T, images *swapFake, read ports.ReadBack) *Reimager {
	t.Helper()
	reimager, err := NewReimager(images, read, Timing{Settle: 0, Timeout: 3 * time.Millisecond, Interval: time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	var now time.Time
	reimager.now = func() time.Time { return now }
	reimager.sleep = func(context.Context, time.Duration) error {
		now = now.Add(time.Millisecond)
		return nil
	}
	return reimager
}

func TestReimageReportsUnchangedWithoutRecreating(t *testing.T) {
	images := &swapFake{current: runningImage}
	result, err := newReimage(t, images, readFake{}).Reimage(context.Background(), runningImage)
	if err != nil || result.Outcome != OutcomeUnchanged || result.Previous != runningImage || result.Image != runningImage || len(images.calls) != 0 {
		t.Fatalf("%+v %v，调用 %v", result, err, images.calls)
	}
}

func TestReimageRestoresWhenTheSecondRecreateFails(t *testing.T) {
	images := &swapFake{current: runningImage, failAt: 2}
	result, err := newReimage(t, images, readFake{err: errors.New("readback: down")}).Reimage(context.Background(), nextImage)
	if err != nil || result.Outcome != OutcomeUnknown || result.Previous != runningImage || result.Image != nextImage {
		t.Fatalf("%+v %v", result, err)
	}
	if len(images.calls) != 2 || images.calls[0] != nextImage || images.calls[1] != runningImage {
		t.Fatalf("调用 %v", images.calls)
	}
}

func TestReimageDoesNotRecreateWhenTheEnvFileHasNoImage(t *testing.T) {
	images := &swapFake{current: runningImage, plain: errors.New("container: env file pool.env: GATEWAY_IMAGE is not set")}
	result, err := newReimage(t, images, readFake{}).Reimage(context.Background(), nextImage)
	if err == nil || result.Outcome != "" || len(images.calls) != 1 {
		t.Fatalf("%+v %v，调用 %v", result, err, images.calls)
	}
}
