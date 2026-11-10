// Package workloadtls 是工作负载之间双向 TLS 的服务端一侧：要求对端出示由指定 CA 签发的
// 证书，并从已验证的证书里取出对端身份。
//
// 身份是证书 subjectAltName 里的 URI（SPIFFE 风格）。这里不接 SPIFFE Workload API，
// 证书和 CA 在启动时从文件读一次，没有轮换，也不查吊销。
package workloadtls

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
)

// ServerConfig 构造要求并验证客户端证书的服务端 TLS 配置。没有证书、或证书不是
// clientCAFile 里的 CA 签发的对端，握手不会完成。
func ServerConfig(certFile, keyFile, clientCAFile string) (*tls.Config, error) {
	certificate, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("server certificate: %w", err)
	}
	pem, err := os.ReadFile(clientCAFile)
	if err != nil {
		return nil, fmt.Errorf("client CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, errors.New("client CA: no certificate found in " + clientCAFile)
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{certificate},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pool,
	}, nil
}

// PeerIdentity 返回对端已验证证书里的 URI 身份。证书里没有 URI、或有不止一个时返回空串：
// 身份必须无歧义。state 为 nil（连接不是 TLS）时同样返回空串。
func PeerIdentity(state *tls.ConnectionState) string {
	if state == nil || len(state.VerifiedChains) == 0 || len(state.VerifiedChains[0]) == 0 {
		return ""
	}
	leaf := state.VerifiedChains[0][0]
	if len(leaf.URIs) != 1 {
		return ""
	}
	return leaf.URIs[0].String()
}
