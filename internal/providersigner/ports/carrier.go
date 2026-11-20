// Package ports 是 provider-signer 的用例对外要的东西：向承运商发一次请求。
package ports

import (
	"context"
	"errors"
)

// CarrierRequest 是发给承运商的一次调用里，除 URL 之外所有可变的东西。URL、方法和
// Content-Type 是适配器自己的常量，调用方的任何东西都进不到这里。
type CarrierRequest struct {
	MsgType string
	Lang    string
	AppKey  Secret
	Token   Secret
	// Timestamp 是 Unix 毫秒的十进制写法。
	Timestamp string
	Nonce     string
	Signature string
	// Ciphertext 是请求正文的全部：不包 JSON，没有引号，没有换行。
	Ciphertext string
}

// CarrierResponse 是承运商的答复。只有 Status 为 200 时才读正文：别的状态下 Body 为 nil，
// 承运商的正文被丢弃。
type CarrierResponse struct {
	Status int
	Body   []byte
}

// 调用没有得到答复时的三种错误。它们是哨兵值，不带底层错误的文字：底层错误可能带着 URL
// 或承运商的文字，不进日志，也不进答复。
var (
	// ErrTimeout 是整次交换超过了时限。
	ErrTimeout = errors.New("carrier did not answer in time")
	// ErrUnreachable 是连不上、握手失败或连接中途断了。
	ErrUnreachable = errors.New("carrier could not be reached")
	// ErrAnswerTooLarge 是状态 200 的答复正文超过了上限。
	ErrAnswerTooLarge = errors.New("carrier answer is larger than the limit")
)

// Carrier 向承运商发一次请求，不重试：写操作超时或断连，结果是未知，重放可能做两次。
type Carrier interface {
	Send(ctx context.Context, request CarrierRequest) (CarrierResponse, error)
}
