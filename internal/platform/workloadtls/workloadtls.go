// Package workloadtls 是工作负载之间的双向 TLS。服务端一侧：要求对端出示由指定 CA 签发的
// 证书，并从已验证的证书里取出对端身份。客户端一侧：出示自己的证书，按指定的 CA 和名字验证服务端。
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
	pool, err := caPool("client CA", clientCAFile)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{certificate},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pool,
	}, nil
}

// ClientConfig 构造出示客户端证书的客户端 TLS 配置。服务端的证书必须由 serverCAFile 里的 CA 签发，
// 并且是给 serverName 这个名字的；系统自带的根证书不被信任。
func ClientConfig(certFile, keyFile, serverCAFile, serverName string) (*tls.Config, error) {
	if serverName == "" {
		return nil, errors.New("server name: the name to verify the server certificate for is required")
	}
	certificate, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("client certificate: %w", err)
	}
	pool, err := caPool("server CA", serverCAFile)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{certificate},
		RootCAs:      pool,
		ServerName:   serverName,
	}, nil
}

func caPool(what, file string) (*x509.CertPool, error) {
	pem, err := os.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", what, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, errors.New(what + ": no certificate found in " + file)
	}
	return pool, nil
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
