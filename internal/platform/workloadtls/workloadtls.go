// Package workloadtls 是工作负载之间的双向 TLS。服务端一侧：要求对端出示由指定 CA 签发的
// 证书，并从已验证的证书里取出对端身份。客户端一侧：出示自己的证书，按指定的 CA 和名字验证服务端。
//
// 身份是证书 subjectAltName 里的 URI（SPIFFE 风格）。这里不接 SPIFFE Workload API，也不查 CRL 或 OCSP。
// 证书和 CA 在启动时读入。之后每次新建 TLS 握手再看文件：inode、修改时间、大小或权限变了就重读。
// 证书和私钥分两次换完、文件被删、或写进坏的 PEM 时，保留上一份有效材料，不放行没有证书的连接。
// 已经握完手的连接不因文件替换被断开。新材料只对之后新建的握手生效。
package workloadtls

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"os"
)

// ServerConfig 构造要求并验证客户端证书的服务端 TLS 配置。没有证书、或证书不是
// clientCAFile 里的 CA 签发的对端，握手不会完成。证书和 CA 文件后来被替换时，下一次握手用新的。
func ServerConfig(certFile, keyFile, clientCAFile string) (*tls.Config, error) {
	return ServerConfigWithLogger(certFile, keyFile, clientCAFile, nil)
}

// ServerConfigWithLogger 与 ServerConfig 相同。logger 记录热重载和读失败；为 nil 时不写日志。
// 日志只有路径和错误类别，没有私钥或证书正文。
func ServerConfigWithLogger(certFile, keyFile, clientCAFile string, logger *slog.Logger) (*tls.Config, error) {
	logger = discardLogger(logger)
	keys, err := newKeyPairReloader(certFile, keyFile, logger)
	if err != nil {
		return nil, fmt.Errorf("server certificate: %w", err)
	}
	clientCA, err := newCAReloader("client CA", clientCAFile, logger)
	if err != nil {
		return nil, err
	}
	cfg := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{keys.initial()},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientCA.initial(),
	}
	// 返回的配置换成这份，叶子和客户端 CA 都是这次握手时的文件。NextProtos 跟原配置走，
	// http.Server 启动时往原配置上加的 h2 不会丢。
	cfg.GetConfigForClient = func(*tls.ClientHelloInfo) (*tls.Config, error) {
		return &tls.Config{
			MinVersion:   tls.VersionTLS12,
			Certificates: []tls.Certificate{keys.current()},
			ClientAuth:   tls.RequireAndVerifyClientCert,
			ClientCAs:    clientCA.current(),
			NextProtos:   append([]string(nil), cfg.NextProtos...),
		}, nil
	}
	return cfg, nil
}

// ClientConfig 构造出示客户端证书的客户端 TLS 配置。服务端的证书必须由 serverCAFile 里的 CA 签发，
// 并且是给 serverName 这个名字的；系统自带的根证书不被信任。证书和 CA 文件后来被替换时，下一次连接用新的。
func ClientConfig(certFile, keyFile, serverCAFile, serverName string) (*tls.Config, error) {
	return ClientConfigWithLogger(certFile, keyFile, serverCAFile, serverName, nil)
}

// ClientConfigWithLogger 与 ClientConfig 相同。logger 为 nil 时不写日志。
func ClientConfigWithLogger(certFile, keyFile, serverCAFile, serverName string, logger *slog.Logger) (*tls.Config, error) {
	if serverName == "" {
		return nil, errors.New("server name: the name to verify the server certificate for is required")
	}
	logger = discardLogger(logger)
	keys, err := newKeyPairReloader(certFile, keyFile, logger)
	if err != nil {
		return nil, fmt.Errorf("client certificate: %w", err)
	}
	serverCA, err := newCAReloader("server CA", serverCAFile, logger)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{keys.initial()},
		RootCAs:      serverCA.initial(),
		ServerName:   serverName,
		// 默认校验只认构造时那一个 RootCAs。CA 文件换了就会在 VerifyConnection 之前失败。
		// 所以跳过默认校验，由 VerifyConnection 用此刻的 CA 池做完整校验。ServerName 为空、
		// 没有证书、链或名字或 ExtKeyUsageServerAuth 不对，一律拒绝。系统根证书不参与。
		InsecureSkipVerify: true,
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			cert := keys.current()
			return &cert, nil
		},
		VerifyConnection: func(cs tls.ConnectionState) error {
			return verifyServer(cs, serverCA.current())
		},
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
