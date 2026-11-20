// Package workloadtls 是工作负载之间的双向 TLS。服务端一侧：要求对端出示由指定 CA 签发的
// 证书，并从已验证的证书里取出对端身份。客户端一侧：出示自己的证书，按指定的 CA 和名字验证服务端。
//
// 身份是证书 subjectAltName 里的 URI（SPIFFE 风格）。这里不接 SPIFFE Workload API，
// 证书和 CA 在启动时从文件读一次，没有轮换，也不查吊销。
// IssuePublisherCert 把新叶子写到文件里给下一次进程读，不在这个进程里重载。
package workloadtls

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
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

// CertificateIdentity 返回证书文件（PEM）里第一张证书的 URI 身份，取法与 PeerIdentity 相同：
// 证书里没有 URI、或有不止一个时返回空串，身份必须无歧义。文件读不了、不是证书时返回错误。
// 它不验证证书：调用的人拿这个证书去握过手了，这里只是读出它自称的身份。
func CertificateIdentity(certFile string) (string, error) {
	raw, err := os.ReadFile(certFile)
	if err != nil {
		return "", fmt.Errorf("certificate: %w", err)
	}
	for {
		var block *pem.Block
		block, raw = pem.Decode(raw)
		if block == nil {
			return "", errors.New("certificate: no certificate found in " + certFile)
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		leaf, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return "", fmt.Errorf("certificate: %w", err)
		}
		if len(leaf.URIs) != 1 {
			return "", nil
		}
		return leaf.URIs[0].String(), nil
	}
}
