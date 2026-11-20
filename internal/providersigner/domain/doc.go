// Package domain 是 provider-signer 的纯规则（docs/adr/ADR-0014.md）：承运商（顺丰国际）要求的
// 正文加密、解密与签名，Authorization 头里凭证的解析，写死的操作表，以及承运商应答信封的读取与改写。
//
// 这里不做 I/O，不认识 HTTP，不写日志。随机源由调用方传入，所以固定的随机源能复现固定的密文。
package domain
