package workloadtls

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"sync"
)

// maxPEMBytes 是一次读证书、私钥或 CA 的上限。再大就拒绝，避免把内存吃满。
const maxPEMBytes = 4 << 20

var (
	errPEMTooLarge   = errors.New("too large")
	errNoCertificate = errors.New("no certificate")
	errRejected      = errors.New("rejected")
)

// stamp 是上一次尝试（成功或失败）看到的文件状态。失败也要记住：
// 同一份坏文件下一次握手不再读、不再记日志；证书和私钥分两次替换时，
// 先换的那一个已经记下来，后换的那一个一变就重新加载。
type stamp struct {
	ok   bool
	info os.FileInfo
	kind string
}

func statStamp(path string) stamp {
	info, err := os.Stat(path)
	if err != nil {
		return stamp{kind: errorCategory(err)}
	}
	return stamp{ok: true, info: info}
}

func stampsEqual(a, b stamp) bool {
	if a.ok != b.ok {
		return false
	}
	if !a.ok {
		return a.kind == b.kind
	}
	return os.SameFile(a.info, b.info) &&
		a.info.ModTime().Equal(b.info.ModTime()) &&
		a.info.Size() == b.info.Size() &&
		a.info.Mode() == b.info.Mode()
}

func errorCategory(err error) string {
	switch {
	case errors.Is(err, os.ErrNotExist):
		return "not found"
	case errors.Is(err, os.ErrPermission):
		return "permission denied"
	case errors.Is(err, errPEMTooLarge):
		return "too large"
	case errors.Is(err, errNoCertificate):
		return "no certificate"
	default:
		return "rejected"
	}
}

func readLimited(path string) ([]byte, os.FileInfo, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, info, errRejected
	}
	if info.Size() > maxPEMBytes {
		return nil, info, errPEMTooLarge
	}
	buf, err := io.ReadAll(io.LimitReader(file, maxPEMBytes+1))
	if err != nil {
		return nil, info, err
	}
	if int64(len(buf)) > maxPEMBytes {
		return nil, info, errPEMTooLarge
	}
	return buf, info, nil
}

func loadKeyPair(certFile, keyFile string) (tls.Certificate, stamp, stamp, error) {
	certPEM, certInfo, err := readLimited(certFile)
	if err != nil {
		return tls.Certificate{}, stamp{}, stamp{}, err
	}
	keyPEM, keyInfo, err := readLimited(keyFile)
	if err != nil {
		return tls.Certificate{}, stamp{}, stamp{}, err
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, stamp{}, stamp{}, err
	}
	if len(pair.Certificate) == 0 {
		return tls.Certificate{}, stamp{}, stamp{}, errNoCertificate
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return tls.Certificate{}, stamp{}, stamp{}, err
	}
	pair.Leaf = leaf
	return pair, stamp{ok: true, info: certInfo}, stamp{ok: true, info: keyInfo}, nil
}

func readCAPool(what, file string) (*x509.CertPool, stamp, error) {
	pemBytes, info, err := readLimited(file)
	if err != nil {
		return nil, stamp{}, fmt.Errorf("%s: %w", what, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBytes) {
		return nil, stamp{}, fmt.Errorf("%s: no certificate found in %s: %w", what, file, errNoCertificate)
	}
	return pool, stamp{ok: true, info: info}, nil
}

// keyPairReloader 盯着证书和私钥两个文件。坏的一对不会换上，上一对一直留着。
type keyPairReloader struct {
	certFile string
	keyFile  string
	logger   *slog.Logger

	mu       sync.Mutex
	cert     tls.Certificate
	certSeen stamp
	keySeen  stamp
}

func newKeyPairReloader(certFile, keyFile string, logger *slog.Logger) (*keyPairReloader, error) {
	cert, certSeen, keySeen, err := loadKeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	return &keyPairReloader{
		certFile: certFile,
		keyFile:  keyFile,
		logger:   logger,
		cert:     cert,
		certSeen: certSeen,
		keySeen:  keySeen,
	}, nil
}

func (r *keyPairReloader) initial() tls.Certificate {
	r.mu.Lock()
	defer r.mu.Unlock()
	return cloneCertificate(r.cert)
}

// current 返回此刻该用的证书。文件没变就用上一对。变了但读不成，记下这次看到的状态，
// 继续用上一对，并且同一状态只记一条日志。日志只有路径和类别，没有私钥或 PEM。
func (r *keyPairReloader) current() tls.Certificate {
	r.mu.Lock()
	defer r.mu.Unlock()

	certSeen := statStamp(r.certFile)
	keySeen := statStamp(r.keyFile)
	if stampsEqual(r.certSeen, certSeen) && stampsEqual(r.keySeen, keySeen) {
		return cloneCertificate(r.cert)
	}
	cert, readCert, readKey, err := loadKeyPair(r.certFile, r.keyFile)
	if err != nil {
		// 记住这次看到的状态，包括读失败的那一次。不要清掉 r.cert。
		r.certSeen, r.keySeen = certSeen, keySeen
		r.logger.Error("workload tls material rejected; still using the last one that loaded",
			"kind", "certificate", "cert", r.certFile, "key", r.keyFile, "error", errorCategory(err))
		return cloneCertificate(r.cert)
	}
	r.cert = cert
	r.certSeen, r.keySeen = readCert, readKey
	r.logger.Info("workload tls material reloaded",
		"kind", "certificate", "cert", r.certFile, "key", r.keyFile)
	return cloneCertificate(r.cert)
}

func cloneCertificate(in tls.Certificate) tls.Certificate {
	out := in
	if in.Certificate != nil {
		out.Certificate = append([][]byte(nil), in.Certificate...)
	}
	return out
}

// caReloader 盯着一张 CA 文件。读不成就留着上一个池，不会换成空池。
type caReloader struct {
	what   string
	file   string
	logger *slog.Logger

	mu   sync.Mutex
	pool *x509.CertPool
	seen stamp
}

func newCAReloader(what, file string, logger *slog.Logger) (*caReloader, error) {
	pool, seen, err := readCAPool(what, file)
	if err != nil {
		return nil, err
	}
	return &caReloader{what: what, file: file, logger: logger, pool: pool, seen: seen}, nil
}

func (r *caReloader) initial() *x509.CertPool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.pool
}

func (r *caReloader) current() *x509.CertPool {
	r.mu.Lock()
	defer r.mu.Unlock()

	seen := statStamp(r.file)
	if stampsEqual(r.seen, seen) {
		return r.pool
	}
	pool, readSeen, err := readCAPool(r.what, r.file)
	if err != nil {
		r.seen = seen
		r.logger.Error("workload tls material rejected; still using the last one that loaded",
			"kind", "ca", "path", r.file, "error", errorCategory(err))
		return r.pool
	}
	r.pool = pool
	r.seen = readSeen
	r.logger.Info("workload tls material reloaded", "kind", "ca", "path", r.file)
	return r.pool
}

func discardLogger(logger *slog.Logger) *slog.Logger {
	if logger == nil {
		return slog.New(slog.DiscardHandler)
	}
	return logger
}

// verifyServer 在 InsecureSkipVerify 之后强制验证服务端。ServerName 为空、没有证书、
// 链或主机名或 ExtKeyUsageServerAuth 对不上当前 CA 池，都拒绝。
func verifyServer(cs tls.ConnectionState, pool *x509.CertPool) error {
	if cs.ServerName == "" {
		return errors.New("server name: the name to verify the server certificate for is required")
	}
	if len(cs.PeerCertificates) == 0 {
		return errors.New("server certificate: none presented")
	}
	if pool == nil {
		return errors.New("server CA: no certificate")
	}
	intermediates := x509.NewCertPool()
	for _, cert := range cs.PeerCertificates[1:] {
		intermediates.AddCert(cert)
	}
	if _, err := cs.PeerCertificates[0].Verify(x509.VerifyOptions{
		DNSName:       cs.ServerName,
		Intermediates: intermediates,
		Roots:         pool,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		return fmt.Errorf("server certificate: %w", err)
	}
	return nil
}
