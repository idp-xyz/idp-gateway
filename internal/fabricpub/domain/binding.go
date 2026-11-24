package domain

// Binding 是 credential-binding.schema.json 的一条。里面没有密钥。
type Binding struct {
	BindingID               string
	ProviderID              string
	Environment             string
	AuthScheme              string
	AccountResolution       string
	GatewayWorkloadID       string
	AuthorizedCredentialRef string
	ScopeSet                []string
	Audience                string
	TokenTTLMaxSeconds      int
	HasTokenTTL             bool
	RequestSignerRef        string
	ApprovalRef             string
}

var bindingFields = map[string]struct{}{
	"binding_id": {}, "provider_id": {}, "environment": {}, "auth_scheme": {},
	"account_resolution": {}, "gateway_workload_id": {}, "authorized_credential_ref": {},
	"scope_set": {}, "audience": {}, "token_ttl_max_seconds": {}, "request_signer_ref": {},
	"approval_ref": {},
}

var authSchemes = map[string]struct{}{
	"API_KEY": {}, "OAUTH2_CLIENT_CREDENTIALS": {}, "OAUTH2_AUTHORIZATION_CODE": {},
	"HMAC_REQUEST_SIGNING": {}, "MTLS_CLIENT_CERT": {},
}

// ParseBindings 读取 --bindings 文件。文件可以是一个对象，或一个对象数组。
func ParseBindings(data []byte) ([]Binding, error) {
	doc, err := parseDocument(data)
	if err != nil {
		return nil, err
	}
	var items []any
	switch value := doc.Value.(type) {
	case map[string]any:
		items = []any{value}
	case []any:
		if len(value) == 0 {
			return nil, invalid("binding")
		}
		items = value
	default:
		return nil, invalid("binding")
	}
	out := make([]Binding, 0, len(items))
	seenRef := map[string]struct{}{}
	for _, item := range items {
		binding, err := parseBinding(item)
		if err != nil {
			return nil, err
		}
		if _, dup := seenRef[binding.AuthorizedCredentialRef]; dup {
			return nil, invalid("binding")
		}
		seenRef[binding.AuthorizedCredentialRef] = struct{}{}
		out = append(out, binding)
	}
	return out, nil
}

func parseBinding(value any) (Binding, error) {
	obj, ok := asObject(value)
	if !ok {
		return Binding{}, invalid("binding")
	}
	if err := unknownFields(obj, bindingFields); err != nil {
		return Binding{}, err
	}
	var b Binding
	var err error
	if b.BindingID, err = needString(obj, "binding_id"); err != nil || len(b.BindingID) < 6 {
		return Binding{}, invalid("binding")
	}
	if b.ProviderID, err = needString(obj, "provider_id"); err != nil || len(b.ProviderID) < 3 {
		return Binding{}, invalid("binding")
	}
	if b.Environment, err = needString(obj, "environment"); err != nil {
		return Binding{}, err
	}
	switch b.Environment {
	case "DEV", "TEST", "PROD":
	default:
		return Binding{}, invalid("binding")
	}
	if b.AuthScheme, err = needString(obj, "auth_scheme"); err != nil {
		return Binding{}, err
	}
	if _, ok := authSchemes[b.AuthScheme]; !ok {
		return Binding{}, invalid("binding")
	}
	if b.AccountResolution, err = needString(obj, "account_resolution"); err != nil || b.AccountResolution != "GATEKEEPER_AUTHORIZED_ACCOUNT" {
		return Binding{}, invalid("binding")
	}
	if b.GatewayWorkloadID, err = needString(obj, "gateway_workload_id"); err != nil || len(b.GatewayWorkloadID) < 3 {
		return Binding{}, invalid("binding")
	}
	if b.AuthorizedCredentialRef, err = needPattern(obj, "authorized_credential_ref", reCredential); err != nil {
		return Binding{}, err
	}
	if raw, ok := obj["scope_set"]; ok {
		items, ok := raw.([]any)
		if !ok {
			return Binding{}, invalid("binding")
		}
		seen := map[string]struct{}{}
		for _, item := range items {
			text, ok := asString(item)
			if !ok || text == "" || !plainText(text) {
				return Binding{}, invalid("binding")
			}
			if _, dup := seen[text]; dup {
				return Binding{}, invalid("binding")
			}
			seen[text] = struct{}{}
			b.ScopeSet = append(b.ScopeSet, text)
		}
	}
	if raw, ok := obj["audience"]; ok {
		audience, ok := asString(raw)
		if !ok || audience == "" || !plainText(audience) {
			return Binding{}, invalid("binding")
		}
		b.Audience = audience
	}
	if raw, ok := obj["token_ttl_max_seconds"]; ok {
		ttl, ok := asInt(raw)
		if !ok || ttl < 1 || ttl > 3600 {
			return Binding{}, invalid("binding")
		}
		b.TokenTTLMaxSeconds = ttl
		b.HasTokenTTL = true
	}
	if raw, ok := obj["request_signer_ref"]; ok {
		ref, ok := asString(raw)
		if !ok || !reSigner.MatchString(ref) {
			return Binding{}, invalid("binding")
		}
		b.RequestSignerRef = ref
	}
	if b.ApprovalRef, err = needString(obj, "approval_ref"); err != nil || len(b.ApprovalRef) < 4 {
		return Binding{}, invalid("binding")
	}
	return b, nil
}

// SelectBinding 按 authorized_credential_ref 精确找一条。没有或多于一条都拒绝。
func SelectBinding(bindings []Binding, ref string) (Binding, error) {
	var found Binding
	n := 0
	for _, binding := range bindings {
		if binding.AuthorizedCredentialRef == ref {
			found = binding
			n++
		}
	}
	if n != 1 {
		return Binding{}, invalid("binding")
	}
	return found, nil
}

const (
	schemeWanb   = "Hc-OweDeveloper "
	schemeSF     = "Sf-OpenApi "
	providerWanb = "wanbexpress"
	providerSF   = "sfintl"
)

// Matches 按 ADR-0020 第 5 条把绑定和 pool-base、意图对上。对不上是 422。
func (b Binding) Matches(in Intent, base PoolBase) error {
	if b.ProviderID != base.Provider.ProviderID || b.Environment != base.Pool.Environment ||
		b.AuthorizedCredentialRef != base.Provider.CredentialBindingRef || b.AuthorizedCredentialRef != in.CredentialBindingRef {
		return invalid("binding")
	}
	if b.Environment != in.Environment || b.ProviderID != in.ProviderID {
		return invalid("binding")
	}
	if b.AccountResolution != "GATEKEEPER_AUTHORIZED_ACCOUNT" || in.ProviderAccountStrategy != "GATEKEEPER_DECISION_BINDING" {
		return invalid("binding")
	}
	switch b.AuthScheme {
	case "OAUTH2_AUTHORIZATION_CODE":
		return invalid("binding")
	case "HMAC_REQUEST_SIGNING":
		if !reSigner.MatchString(b.RequestSignerRef) {
			return invalid("binding")
		}
	case "API_KEY", "OAUTH2_CLIENT_CREDENTIALS":
		if !reScheme.MatchString(base.Provider.CredentialScheme) {
			return invalid("binding")
		}
		if base.Provider.CredentialHeader != "" && base.Provider.CredentialQueryParameter != "" {
			return invalid("binding")
		}
	case "MTLS_CLIENT_CERT":
		if base.Provider.BackendTLS == nil || base.Provider.BackendTLS.Hostname == "" || in.UpstreamTLS != "VERIFY_REQUIRED" {
			return invalid("binding")
		}
	default:
		return invalid("binding")
	}
	switch base.Provider.CredentialScheme {
	case schemeWanb:
		if base.Provider.ProviderID != providerWanb || b.ProviderID != providerWanb {
			return invalid("binding")
		}
	case schemeSF:
		if base.Provider.ProviderID != providerSF || b.ProviderID != providerSF || !reSigner.MatchString(b.RequestSignerRef) {
			return invalid("binding")
		}
		if base.Provider.InternalBackendHost == "" || base.Provider.BackendTLS == nil || in.UpstreamTLS != "VERIFY_REQUIRED" {
			return invalid("binding")
		}
	}
	if base.Provider.ProviderID == providerWanb && base.Provider.CredentialScheme != schemeWanb {
		return invalid("binding")
	}
	if base.Provider.ProviderID == providerSF && base.Provider.CredentialScheme != schemeSF {
		return invalid("binding")
	}
	return nil
}

// CheckPublication 在落幂等键之前核对接绑。目录合并仍由 Merge 做。
func CheckPublication(env Envelope, base PoolBase, bindings []Binding) error {
	if env.TargetID == "" {
		return invalid("schema")
	}
	binding, err := SelectBinding(bindings, env.Intent.CredentialBindingRef)
	if err != nil {
		return err
	}
	return binding.Matches(env.Intent, base)
}
