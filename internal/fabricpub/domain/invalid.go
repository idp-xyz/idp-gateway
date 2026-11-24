package domain

// Invalid 是信封、绑定或目录不合规则。调用方把它变成 HTTP 422，不落发布记录。
type Invalid struct {
	Code string
}

func (e *Invalid) Error() string {
	if e == nil || e.Code == "" {
		return "invalid"
	}
	return e.Code
}

func invalid(code string) error { return &Invalid{Code: code} }
