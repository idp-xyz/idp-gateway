package filestore

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"sync"
	"time"

	"go.idp.xyz/idp-gateway/internal/egressauthz/domain"
)

// maxRateLimitBytes 是配额文件的上限。它在请求路径上被重读，不能把一份巨大的文件整个吞进来。
const maxRateLimitBytes = 1 << 20

// RateLimits 是从文件读入的配额表。
//
// 文件里没有秘密，0644 和 0600 都可以。启动时读不成就返回错误；之后文件被换掉则整份重读，
// 新文件读不成就继续用上一份，并记一条错误。同一份坏文件只记一次。换文件要写临时文件再改名。
type RateLimits struct {
	path   string
	logger *slog.Logger

	mu      sync.Mutex
	seen    os.FileInfo
	table   *domain.QuotaTable
	count   int
	version string
}

// LoadRateLimits 读配额文件。格式是 {"version","buckets":[...]}，不认识的字段拒绝，
// 规则交给 domain.ValidateQuotaRules。
func LoadRateLimits(path string, logger *slog.Logger) (*RateLimits, error) {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	loaded := &RateLimits{path: path, logger: logger}
	table, info, count, version, err := loaded.read()
	if err != nil {
		return nil, err
	}
	loaded.table, loaded.seen, loaded.count, loaded.version = table, info, count, version
	return loaded, nil
}

// Allow 实现 ports.RateLimiter。文件变了就先重读；重读失败时沿用上一份，不把这次请求判成没有结论。
// ctx 已经取消时不扣配额。
func (r *RateLimits) Allow(ctx context.Context, subject domain.RateLimitSubject) (bool, int, error) {
	if err := ctx.Err(); err != nil {
		return false, 0, err
	}
	allowed, retry := r.current().Allow(time.Now(), subject)
	return allowed, retry, nil
}

// Charges 返回此刻规则对 subject 的扣费清单，不扣本地桶。文件变了就先重读，重读失败时沿用上一份。
func (r *RateLimits) Charges(subject domain.RateLimitSubject) []domain.QuotaCharge {
	if r == nil {
		return nil
	}
	return r.current().Charges(subject)
}

// Len 返回最近一次读成的规则条数，供启动日志使用。
func (r *RateLimits) Len() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.count
}

// current 返回此刻该用的那张表。文件没变就用上一份。
func (r *RateLimits) current() *domain.QuotaTable {
	r.mu.Lock()
	defer r.mu.Unlock()

	info, err := os.Stat(r.path)
	if err != nil {
		if r.seen != nil {
			r.seen = nil
			r.logger.Error("rate limits file cannot be seen; still using the last one that loaded",
				"path", r.path, "error", err.Error(), "buckets", r.count)
		}
		return r.table
	}
	if r.seen != nil && sameFile(r.seen, info) {
		return r.table
	}
	table, read, count, version, err := r.read()
	if err != nil {
		r.seen = info
		r.logger.Error("rate limits file did not load; still using the last one that loaded",
			"path", r.path, "error", err.Error(), "buckets", r.count)
		return r.table
	}
	r.table, r.seen, r.count, r.version = table, read, count, version
	r.logger.Info("rate limits file loaded again", "path", r.path, "buckets", count, "version", version)
	return r.table
}

// read 读一遍文件。返回的 FileInfo 属于实际读到的那个文件。
func (r *RateLimits) read() (*domain.QuotaTable, os.FileInfo, int, string, error) {
	file, err := os.Open(r.path)
	if err != nil {
		return nil, nil, 0, "", fmt.Errorf("rate limits: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, nil, 0, "", fmt.Errorf("rate limits: %w", err)
	}
	raw, err := io.ReadAll(io.LimitReader(file, maxRateLimitBytes+1))
	if err != nil {
		return nil, nil, 0, "", fmt.Errorf("rate limits: %w", err)
	}
	if int64(len(raw)) > maxRateLimitBytes {
		return nil, nil, 0, "", fmt.Errorf("rate limits %s: file is larger than %d bytes", r.path, maxRateLimitBytes)
	}
	version, rules, err := parseRateLimits(raw)
	if err != nil {
		return nil, nil, 0, "", fmt.Errorf("rate limits %s: %w", r.path, err)
	}
	table, err := domain.NewQuotaTable(rules)
	if err != nil {
		return nil, nil, 0, "", fmt.Errorf("rate limits %s: %w", r.path, err)
	}
	return table, info, len(rules), version, nil
}

type rateLimitDocument struct {
	Version *string            `json:"version"`
	Buckets *[]rateLimitBucket `json:"buckets"`
}

type rateLimitBucket struct {
	ID            string   `json:"id"`
	ProviderID    string   `json:"provider_id"`
	OperationID   string   `json:"operation_id"`
	KeyDimensions []string `json:"key_dimensions"`
	MaxRequests   int      `json:"max_requests"`
	WindowSeconds int      `json:"window_seconds"`
	Burst         int      `json:"burst"`
}

func parseRateLimits(raw []byte) (string, []domain.QuotaRule, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var document rateLimitDocument
	if err := decoder.Decode(&document); err != nil {
		return "", nil, err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return "", nil, errors.New("unexpected data after the rate limit document")
	}
	if document.Version == nil || *document.Version == "" {
		return "", nil, errors.New("version is required")
	}
	if document.Buckets == nil {
		return "", nil, errors.New("buckets is required")
	}
	rules := make([]domain.QuotaRule, len(*document.Buckets))
	for i, bucket := range *document.Buckets {
		if bucket.ID == "" {
			return "", nil, errors.New("a bucket has an empty id")
		}
		rules[i] = domain.QuotaRule{
			ID:            bucket.ID,
			ProviderID:    bucket.ProviderID,
			OperationID:   bucket.OperationID,
			KeyDimensions: bucket.KeyDimensions,
			MaxRequests:   bucket.MaxRequests,
			WindowSeconds: bucket.WindowSeconds,
			Burst:         bucket.Burst,
		}
	}
	if err := domain.ValidateQuotaRules(rules); err != nil {
		return "", nil, err
	}
	return *document.Version, rules, nil
}
