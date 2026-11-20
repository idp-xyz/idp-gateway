package sfopenapi

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"syscall"
)

// exchangeCause 把一次 HTTP 交换的错误归成一个词。
// 只看类型和 errno，用 errors.As 和 errors.Is 穿过 *url.Error 和 *net.OpError，不看错误的文字：
// 文字里有请求地址，地址的查询串里有应用密钥。返回的词也不从错误的字符串里来。
//
// 顺序，先对上的算：
//  1. *net.DNSError：IsNotFound 是 dns_not_found，否则 IsTimeout 是 dns_timeout，其余是 dns_other。
//     一次查找既是 DNS 错误又是超时（IsTimeout，或链上还有 context 的截止时间），仍算 DNS。
//  2. ECONNREFUSED 是 refused，ECONNRESET 是 reset，ENETUNREACH 或 EHOSTUNREACH 是 no_route。
//  3. io.EOF 或 io.ErrUnexpectedEOF 是 closed：对端在应答之前或应答中途把连接关了。
//  4. TLS 握手或证书校验失败是 tls，只认标准库导出的类型（见 tlsFailure）。
//  5. 超时：*net.OpError 的 Op 是 dial 时是 dial_timeout，其余（包括 context 到了截止时间）是 response_timeout。
//     判定与 request 把 c.http.Do 的错误记成 timeout 的条件相同，见 timedOut。
//     因此 ETIMEDOUT 也算超时：syscall.Errno.Timeout 对 ETIMEDOUT、EAGAIN、EWOULDBLOCK 为真。
//  6. 以上都不是，是 other。
func exchangeCause(err error) string {
	var dns *net.DNSError
	if errors.As(err, &dns) {
		switch {
		case dns.IsNotFound:
			return "dns_not_found"
		case dns.IsTimeout:
			return "dns_timeout"
		default:
			return "dns_other"
		}
	}
	switch {
	case errors.Is(err, syscall.ECONNREFUSED):
		return "refused"
	case errors.Is(err, syscall.ECONNRESET):
		return "reset"
	case errors.Is(err, syscall.ENETUNREACH), errors.Is(err, syscall.EHOSTUNREACH):
		return "no_route"
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		return "closed"
	}
	if tlsFailure(err) {
		return "tls"
	}
	if timedOut(err) {
		var op *net.OpError
		if errors.As(err, &op) && op.Op == "dial" {
			return "dial_timeout"
		}
		return "response_timeout"
	}
	return "other"
}

// timedOut 报告这次交换是不是超时。request 把 c.http.Do 的错误分成 timeout 和 unreachable 时用的就是这一条：
// 链上有 context 的截止时间，或者链上第一个带 Timeout 方法的错误（*url.Error、*net.OpError）返回真。
func timedOut(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var timeout interface{ Timeout() bool }
	return errors.As(err, &timeout) && timeout.Timeout()
}

// tlsFailure 报告这是不是 TLS 握手或证书校验失败。只认标准库导出的类型。
// crypto/tls 在普通握手里返回的 alert 是包内未导出的类型，这里认不出，归 other。
func tlsFailure(err error) bool {
	var verify *tls.CertificateVerificationError
	var record tls.RecordHeaderError
	var alert tls.AlertError
	var ech *tls.ECHRejectionError
	var unknown x509.UnknownAuthorityError
	var invalid x509.CertificateInvalidError
	var host x509.HostnameError
	var roots x509.SystemRootsError
	var constraint x509.ConstraintViolationError
	var insecure x509.InsecureAlgorithmError
	return errors.As(err, &verify) || errors.As(err, &record) || errors.As(err, &alert) || errors.As(err, &ech) ||
		errors.As(err, &unknown) || errors.As(err, &invalid) || errors.As(err, &host) || errors.As(err, &roots) ||
		errors.As(err, &constraint) || errors.As(err, &insecure)
}
