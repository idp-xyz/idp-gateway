// Package revokerclient 是操作员一侧的客户端：对着一个 gateway-authz 的撤销接口（/v1/egress/revocations，
// docs/adr/ADR-0012.md、contracts/gatekeeper/openapi.yaml）发一次请求，把应答归成一个结局。
//
// 只走双向 TLS，出示撤销者自己的证书，按指定的 CA 和名字验证服务端；不跟随重定向，不用环境里的代理，
// 每次一条新连接，不重试。重发是调用方的决定：这个接口是幂等的，但"要不要再发一次"要由看到结局的人来定。
//
// 结局的意思：
//   - 状态码是确定的那几种（401、404、422、400）只看状态码，不读正文，也不把正文带出去；
//   - 500 要读正文才分得出是"撤销已生效但没有写下去"还是别的，读不懂就算 OutcomeUnknown；
//   - 没有拿到应答（连不上、TLS 建不起来、超时、中途断了），或者应答看不懂，都是 OutcomeUnknown：
//     请求可能到了，也可能没到，生效没生效不知道。
package revokerclient

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Path 是撤销接口的路径。
const Path = "/v1/egress/revocations"

// maxBody 是一个应答最多读多少。整张撤销表很小。
const maxBody = 4 << 20

// Outcome 是一次调用的结局。名字是稳定的，写进了命令的帮助和 ADR-0012。
type Outcome string

const (
	// OutcomeRevoked：撤销在 gateway-authz 上生效了（或本来就是撤销的，State.Changed 为 false），也写下去了。
	OutcomeRevoked Outcome = "REVOKED"
	// OutcomeLifted：撤销取消了（或本来就没有撤销）。
	OutcomeLifted Outcome = "LIFTED"
	// OutcomeListed：读到了整张表。
	OutcomeListed Outcome = "LISTED"
	// OutcomeRevokedNotWritten：账户现在被拒绝，但没有写进撤销文件，gateway-authz 重启之后就不是了。
	OutcomeRevokedNotWritten Outcome = "REVOKED_NOT_WRITTEN"
	// OutcomeLiftNotWritten：恢复没有写下去，所以没有恢复：账户仍然被撤销。
	OutcomeLiftNotWritten Outcome = "LIFT_NOT_WRITTEN"
	// OutcomeNotRevoker：401，出示的证书不是撤销者的。什么都没有变。
	OutcomeNotRevoker Outcome = "NOT_REVOKER"
	// OutcomeNoRevoker：404，这个 gateway-authz 没有配置撤销者。
	OutcomeNoRevoker Outcome = "NO_REVOKER_CONFIGURED"
	// OutcomeUnknownAccount：422，不认识的账户，多半是名字敲错了。什么都没有变。
	OutcomeUnknownAccount Outcome = "UNKNOWN_ACCOUNT"
	// OutcomeRefused：400，请求不合格式。什么都没有变。
	OutcomeRefused Outcome = "REQUEST_REFUSED"
	// OutcomeUnknown：不知道。请求可能到了也可能没到，生效没生效不知道。
	OutcomeUnknown Outcome = "UNKNOWN"
)

// State 是服务端说的、这次调用之后账户的状态。
type State struct {
	Revoked bool
	Changed bool
	Epoch   uint64
}

// Row 是撤销表里的一个账户。
type Row struct {
	AccountID string
	RevokedAt string
	RevokedBy string
	Reason    string
}

// Table 是整张撤销表。
type Table struct {
	Epoch uint64
	Rows  []Row
}

// Result 是一次调用的结果。State 在 REVOKED、LIFTED、REVOKED_NOT_WRITTEN 时有值（读到应答正文时
// LIFT_NOT_WRITTEN 也有），Table 在 LISTED 时有值。Status 是 HTTP 状态码，没有拿到应答时为 0。
// Detail 只在 UNKNOWN 时有值，说的是出了什么事；里面不会有应答正文。
type Result struct {
	Outcome Outcome
	Status  int
	Detail  string
	State   *State
	Table   *Table
}

// Config 说明撤销接口在哪里、怎么连。
type Config struct {
	// Address 是 gateway-authz 的 host:port。
	Address string
	// TLS 出示撤销者的证书，并按名字验证服务端的证书（workloadtls.ClientConfig）。
	TLS *tls.Config
	// Timeout 是一次请求最长多久，必须是正数。
	Timeout time.Duration
}

// Client 对着一个 gateway-authz 的撤销接口发请求。
type Client struct {
	address string
	host    string
	timeout time.Duration
	http    *http.Client
}

// New 构造客户端。它不在这里连接。
func New(config Config) (*Client, error) {
	if host, port, err := net.SplitHostPort(config.Address); err != nil || host == "" || port == "" {
		return nil, fmt.Errorf("revokerclient: address must be host:port, got %q", config.Address)
	}
	if config.TLS == nil || config.TLS.ServerName == "" || len(config.TLS.Certificates) == 0 || config.TLS.RootCAs == nil {
		return nil, errors.New("revokerclient: a TLS configuration with a client certificate, a CA and the server name is required")
	}
	if config.Timeout <= 0 {
		return nil, errors.New("revokerclient: the timeout must be positive")
	}
	return &Client{
		address: config.Address,
		host:    config.TLS.ServerName,
		timeout: config.Timeout,
		http: &http.Client{
			Timeout: config.Timeout,
			// 不用环境里的代理；每次一条新连接；不重试（http.Transport 对幂等请求会在连接复用失败时重发，关掉连接复用就没有这件事）。
			Transport: &http.Transport{TLSClientConfig: config.TLS.Clone(), DisableKeepAlives: true, Proxy: nil},
			// 撤销接口不该把人带到别处：3xx 当作"应答看不懂"，不去那个地址。
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}, nil
}

// 下面几个结构对着 contracts/gatekeeper/openapi.yaml 的 RevocationRequest、RevocationChange、RevocationState、
// RevokedAccount 写；tests/contracts 里有一条测试核对字段。收到的结构里必填的项用指针，为的是分清"没有给"和"给了零值"。

type revocationRequest struct {
	AccountID string `json:"account_id"`
	Revoked   bool   `json:"revoked"`
	Reason    string `json:"reason,omitempty"`
}

type revocationChange struct {
	AccountID       *string `json:"account_id"`
	Revoked         *bool   `json:"revoked"`
	Changed         *bool   `json:"changed"`
	RevocationEpoch *uint64 `json:"revocation_epoch"`
	Error           string  `json:"error,omitempty"`
}

type revocationState struct {
	RevocationEpoch *uint64          `json:"revocation_epoch"`
	RevokedAccounts []revokedAccount `json:"revoked_accounts"`
}

type revokedAccount struct {
	AccountID *string `json:"account_id"`
	RevokedAt *string `json:"revoked_at"`
	RevokedBy *string `json:"revoked_by"`
	Reason    *string `json:"reason"`
}

const (
	errorRevocationNotWritten  = "revocation_in_effect_but_not_written"
	errorRevocationsNotChanged = "revocations_not_changed"
)

// Revoke 撤销一个账户。原因不能为空。请求没有发出去（参数不合格）时返回错误；发出去之后不返回错误，
// 一切都在结局里。
func (c *Client) Revoke(ctx context.Context, account, reason string) (Result, error) {
	if account == "" {
		return Result{}, errors.New("revokerclient: no account given")
	}
	if strings.TrimSpace(reason) == "" {
		return Result{}, errors.New("revokerclient: a revocation needs a reason")
	}
	return c.change(ctx, revocationRequest{AccountID: account, Revoked: true, Reason: reason}), nil
}

// Restore 取消一个账户的撤销。
func (c *Client) Restore(ctx context.Context, account string) (Result, error) {
	if account == "" {
		return Result{}, errors.New("revokerclient: no account given")
	}
	return c.change(ctx, revocationRequest{AccountID: account, Revoked: false}), nil
}

// List 读整张撤销表。
func (c *Client) List(ctx context.Context) Result {
	status, body, err := c.do(ctx, http.MethodGet, nil, func(status int) bool { return status == http.StatusOK })
	if err != nil {
		return unknown(0, err.Error())
	}
	switch status {
	case http.StatusOK:
		var state revocationState
		if err := decodeOne(body, &state); err != nil || state.RevocationEpoch == nil || state.RevokedAccounts == nil {
			return unknown(status, "the answer to the read is not a revocation table")
		}
		table := &Table{Epoch: *state.RevocationEpoch, Rows: make([]Row, 0, len(state.RevokedAccounts))}
		for _, row := range state.RevokedAccounts {
			if row.AccountID == nil || row.RevokedAt == nil || row.RevokedBy == nil || row.Reason == nil {
				return unknown(status, "the answer to the read is not a revocation table")
			}
			table.Rows = append(table.Rows, Row{AccountID: *row.AccountID, RevokedAt: *row.RevokedAt, RevokedBy: *row.RevokedBy, Reason: *row.Reason})
		}
		return Result{Outcome: OutcomeListed, Status: status, Table: table}
	default:
		return c.byStatus(status)
	}
}

func (c *Client) change(ctx context.Context, request revocationRequest) Result {
	encoded, err := json.Marshal(request)
	if err != nil {
		return unknown(0, err.Error())
	}
	// 200 和 500 的正文要读；别的状态码只看状态码。
	status, body, err := c.do(ctx, http.MethodPost, encoded, func(status int) bool {
		return status == http.StatusOK || status == http.StatusInternalServerError
	})
	if err != nil {
		return unknown(0, err.Error())
	}
	switch status {
	case http.StatusOK:
		state, ok := understood(body, request)
		if !ok {
			return unknown(status, "the answer does not say what state the account is in")
		}
		outcome := OutcomeLifted
		if request.Revoked {
			outcome = OutcomeRevoked
		}
		return Result{Outcome: outcome, Status: status, State: state}
	case http.StatusInternalServerError:
		var change revocationChange
		if err := decodeOne(body, &change); err == nil {
			switch {
			case request.Revoked && change.Error == errorRevocationNotWritten:
				// 要紧的一种：不要求正文里别的项都在，认得出这个错误名就够了。
				result := Result{Outcome: OutcomeRevokedNotWritten, Status: status}
				if state, ok := understood(body, request); ok {
					result.State = state
				}
				return result
			case !request.Revoked && change.Error == errorRevocationsNotChanged:
				result := Result{Outcome: OutcomeLiftNotWritten, Status: status}
				if state, ok := understood(body, revocationRequest{AccountID: request.AccountID, Revoked: true}); ok {
					result.State = state
				}
				return result
			}
		}
		return unknown(status, "the answer is a server error that this command does not know")
	default:
		return c.byStatus(status)
	}
}

// byStatus 归那几个只看状态码的结局；别的状态码是"应答看不懂"，只报状态码。
func (c *Client) byStatus(status int) Result {
	switch status {
	case http.StatusUnauthorized:
		return Result{Outcome: OutcomeNotRevoker, Status: status}
	case http.StatusNotFound:
		return Result{Outcome: OutcomeNoRevoker, Status: status}
	case http.StatusUnprocessableEntity:
		return Result{Outcome: OutcomeUnknownAccount, Status: status}
	case http.StatusBadRequest:
		return Result{Outcome: OutcomeRefused, Status: status}
	}
	return unknown(status, fmt.Sprintf("the answer has the status %d, which this command does not know", status))
}

// understood 读 RevocationChange：账户和撤销与否要与请求的一致，三项必填的都在。
func understood(body []byte, request revocationRequest) (*State, bool) {
	var change revocationChange
	if err := decodeOne(body, &change); err != nil {
		return nil, false
	}
	if change.AccountID == nil || change.Revoked == nil || change.Changed == nil || change.RevocationEpoch == nil || *change.AccountID != request.AccountID {
		return nil, false
	}
	if *change.Revoked != request.Revoked {
		return nil, false
	}
	return &State{Revoked: *change.Revoked, Changed: *change.Changed, Epoch: *change.RevocationEpoch}, true
}

func decodeOne(body []byte, into any) error {
	decoder := json.NewDecoder(bytes.NewReader(body))
	if err := decoder.Decode(into); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return errors.New("unexpected data after the document")
	}
	return nil
}

func unknown(status int, detail string) Result {
	return Result{Outcome: OutcomeUnknown, Status: status, Detail: detail}
}

// do 发一次请求。readBody 说这个状态码的正文要不要读；不读的话 body 为 nil。拿不到应答、读正文时断了、
// 正文过长，都返回错误（"不知道"）。
func (c *Client) do(ctx context.Context, method string, payload []byte, readBody func(status int) bool) (int, []byte, error) {
	var reader io.Reader
	if payload != nil {
		reader = bytes.NewReader(payload)
	}
	request, err := http.NewRequestWithContext(ctx, method, "https://"+c.address+Path, reader)
	if err != nil {
		return 0, nil, errors.New("the request could not be built")
	}
	request.Host = c.host
	if payload != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	request.Header.Set("Accept", "application/json")
	response, err := c.http.Do(request)
	if err != nil {
		return 0, nil, c.describe(ctx, err)
	}
	defer response.Body.Close()
	if !readBody(response.StatusCode) {
		return response.StatusCode, nil, nil
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxBody+1))
	if err != nil {
		return 0, nil, c.describe(ctx, err)
	}
	if len(body) > maxBody {
		return 0, nil, errors.New("the answer is longer than this command reads")
	}
	return response.StatusCode, body, nil
}

// describe 说一句没有拿到应答是怎么回事。里面只有地址和错误，没有证书、私钥或应答正文。
func (c *Client) describe(ctx context.Context, err error) error {
	var urlError *url.Error
	if errors.As(err, &urlError) {
		err = urlError.Err
	}
	switch {
	case errors.Is(ctx.Err(), context.Canceled):
		return errors.New("interrupted before an answer came")
	case errors.Is(err, context.DeadlineExceeded), isTimeout(err):
		return fmt.Errorf("no answer from %s within %s", c.address, c.timeout)
	}
	return fmt.Errorf("no answer from %s: %w", c.address, err)
}

func isTimeout(err error) bool {
	var network net.Error
	return errors.As(err, &network) && network.Timeout()
}
