// Package application 是 provider-signer 的用例：给定一个操作、调用方的 Authorization 头和明文正文，
// 加密、签名、向承运商发一次请求、解密应答，得出要答给网关的东西（docs/adr/ADR-0014.md 第 3 条）。
package application

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strconv"
	"time"

	"go.idp.xyz/idp-gateway/internal/providersigner/domain"
	"go.idp.xyz/idp-gateway/internal/providersigner/ports"
)

// statusOK 是承运商唯一被接受的 HTTP 状态，也是网关得到成功答复时的状态。
const statusOK = 200

// Settings 是部署时定的常量，都不取自请求。
type Settings struct {
	// Lang 是请求头 lang 的值，取 domain.ValidLanguage 认可的值之一。
	Lang string
	// MaxRequestBytes 是接受的请求正文的上限（字节）。
	MaxRequestBytes int64
}

// Service 是用例。
type Service struct {
	carrier  ports.Carrier
	settings Settings
	now      func() time.Time
	random   io.Reader
}

// Option 改变 Service 的默认依赖。给测试注入时钟和随机源用。
type Option func(*Service)

// WithClock 换掉时钟（默认 time.Now）：它只用来取请求头 timestamp。
func WithClock(now func() time.Time) Option { return func(s *Service) { s.now = now } }

// WithRandom 换掉随机源（默认 crypto/rand）：随机数和明文开头的 16 个随机字符都从它取。
func WithRandom(random io.Reader) Option { return func(s *Service) { s.random = random } }

// New 构造 Service。设置不合法时返回错误。
func New(carrier ports.Carrier, settings Settings, options ...Option) (*Service, error) {
	switch {
	case carrier == nil:
		return nil, errors.New("carrier is required")
	case !domain.ValidLanguage(settings.Lang):
		return nil, errors.New("lang is not one of the values the carrier accepts")
	case settings.MaxRequestBytes <= 0:
		return nil, errors.New("request size limit must be greater than zero")
	}
	service := &Service{carrier: carrier, settings: settings, now: time.Now, random: rand.Reader}
	for _, option := range options {
		option(service)
	}
	return service, nil
}

// Call 是一次要处理的请求，适配器在核对完调用方身份、操作、查询串和 Content-Type 之后交来。
type Call struct {
	Operation domain.Operation
	// Authorization 是请求里所有的 Authorization 头的值，必须恰好一个。
	Authorization []string
	// Body 在核对完凭证之后才读，最多读 MaxRequestBytes+1 字节。
	Body io.Reader
}

// Result 是要答给网关的东西，以及写进日志的几个数。
type Result struct {
	Status int
	// Body 是答复的 JSON。
	Body []byte
	// Outcome 是日志里的 outcome：错误码，或 domain 的三种结局。
	Outcome string
	// CarrierStatus 是承运商答的 HTTP 状态；没有联系承运商或没有得到答复时为 0。
	CarrierStatus int
	// APIResultCode 是承运商信封里的 apiResultCode，HasAPIResultCode 为真时才有意义。
	APIResultCode    int64
	HasAPIResultCode bool
	// RequestBytes 是从请求正文里读到的字节数（最多 MaxRequestBytes+1）；正文没有读时为 0。
	RequestBytes int
}

// fail 把 r 变成一个错误答复。只有 carrier_status 这一种错误把承运商的状态写进答复，别的错误不写。
func (r Result) fail(f Failure) Result {
	shown := 0
	if f == CarrierStatus {
		shown = r.CarrierStatus
	}
	r.Status, r.Body, r.Outcome = f.Status, f.body(shown), f.Code
	return r
}

// Handle 依次做下面这些事，第一个不成的就答，后面的都不做，承运商也不会被联系：
// 凭证、正文、构造请求、发送、读应答。
func (s *Service) Handle(ctx context.Context, call Call) Result {
	// 第 5 步：凭证。恰好一个 Authorization 头。
	if len(call.Authorization) != 1 {
		return Result{}.fail(CredentialMalformed)
	}
	credential, err := domain.ParseCredential(call.Authorization[0])
	if err != nil {
		return Result{}.fail(CredentialMalformed)
	}

	// 第 6 步：正文。最多读 MaxRequestBytes+1 字节，必须恰好是一个 JSON 对象，逐字节原样加密。
	body, err := readBody(call.Body, s.settings.MaxRequestBytes)
	result := Result{RequestBytes: len(body)}
	switch {
	case int64(len(body)) > s.settings.MaxRequestBytes:
		return result.fail(RequestTooLarge)
	case err != nil, !domain.IsJSONObject(body):
		return result.fail(BodyNotJSONObject)
	}

	// 第 7 步：构造承运商的请求。随机源出错就不发。
	timestamp := strconv.FormatInt(s.now().UnixMilli(), 10)
	nonce, err := s.nonce()
	if err != nil {
		return result.fail(Internal)
	}
	ciphertext, err := domain.Encrypt(credential.Key(), credential.AppKey(), body, s.random)
	if err != nil {
		return result.fail(Internal)
	}

	// 第 8 步：发送，一次，不重试。
	response, err := s.carrier.Send(ctx, ports.CarrierRequest{
		MsgType:    call.Operation.MsgType,
		Lang:       s.settings.Lang,
		AppKey:     ports.NewSecret(credential.AppKey()),
		Token:      ports.NewSecret(credential.Token()),
		Timestamp:  timestamp,
		Nonce:      nonce,
		Signature:  domain.Sign(credential.Token(), timestamp, nonce, ciphertext),
		Ciphertext: ciphertext,
	})

	// 第 9 步：结局。
	switch {
	case errors.Is(err, ports.ErrTimeout):
		return result.fail(CarrierTimeout)
	case errors.Is(err, ports.ErrAnswerTooLarge):
		result.CarrierStatus = statusOK
		return result.fail(CarrierAnswerUnreadable)
	case err != nil:
		return result.fail(CarrierUnreachable)
	}
	result.CarrierStatus = response.Status
	if response.Status != statusOK {
		return result.fail(CarrierStatus)
	}
	answer, err := domain.OpenAnswer(response.Body, credential.Key(), credential.AppKey())
	result.APIResultCode, result.HasAPIResultCode = answer.Code, answer.CodeKnown
	if err != nil {
		return result.fail(CarrierAnswerUnreadable)
	}
	result.Status, result.Body, result.Outcome = statusOK, answer.Body, answer.Outcome
	return result
}

// nonce 是请求头 nonce：16 个随机字节写成 32 个小写十六进制字符。
func (s *Service) nonce() (string, error) {
	var raw [16]byte
	if _, err := io.ReadFull(s.random, raw[:]); err != nil {
		return "", fmt.Errorf("random source: %w", err)
	}
	return hex.EncodeToString(raw[:]), nil
}

// readBody 最多读 limit+1 字节：多于 limit 就是太大。body 为 nil 时当作空正文。
func readBody(body io.Reader, limit int64) ([]byte, error) {
	if body == nil {
		return nil, nil
	}
	return io.ReadAll(io.LimitReader(body, limit+1))
}
