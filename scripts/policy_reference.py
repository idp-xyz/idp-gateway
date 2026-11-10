"""Offline, minimal reference policy decision helper.

NOT a real authorization server. Verified identity must come from authentication
middleware in a real deployment. Never deploy this helper or trust caller fields.
"""
from __future__ import annotations
import re
from dataclasses import dataclass
from typing import Mapping, Any

# A path is canonical when it is /segment/segment... and every segment is made of
# unreserved characters and does not start with a dot. That leaves no percent sign (so no
# encoded or double-encoded dot, slash or NUL), no empty, "." or ".." segment, no trailing
# slash and no ";params". Anything else is denied rather than normalised: the PDP must not
# guess how the gateway or the provider will decode it. The PoC gateway route applies the
# same expression (poc/p1/agentgateway.poc.yaml); keep the two identical.
CANONICAL_PATH = re.compile(r'(?:/[A-Za-z0-9_~-][A-Za-z0-9._~-]*)+')


def is_canonical_path(path: Any) -> bool:
    return isinstance(path, str) and CANONICAL_PATH.fullmatch(path) is not None

@dataclass(frozen=True)
class TrustedPrincipal:
    service_id: str
    tenant_id: str
    verified: bool
    environment: str

@dataclass(frozen=True)
class EgressRequest:
    provider_id: str
    operation_id: str
    method: str
    path: str
    account_id: str
    environment: str
    target_override: str | None = None
    trusted_host_header: bool = False

@dataclass(frozen=True)
class Decision:
    result: str
    reason: str
    credential_binding_ref: str | None = None


def evaluate(policy: Mapping[str, Any], principal: TrustedPrincipal | None, request: EgressRequest) -> Decision:
    """Deterministic allowlist evaluation; non-authoritative mock of an AuthZ policy."""
    deny=lambda reason: Decision('DENY', reason)
    if principal is None or not principal.verified or not principal.service_id or not principal.tenant_id:
        return deny('UNAUTHENTICATED')
    if request.environment != principal.environment:
        return deny('ENVIRONMENT_MISMATCH')
    if request.target_override is not None or request.trusted_host_header:
        return deny('ARBITRARY_TARGET_DENIED')
    if not is_canonical_path(request.path):
        return deny('PATH_NOT_CANONICAL')
    if request.method not in {'GET','POST','PUT','PATCH','DELETE'}:
        return deny('METHOD_NOT_ALLOWED')
    for row in policy.get('registered_operations', []):
        match=(request.provider_id == row.get('provider_id') and request.operation_id==row.get('operation_id') and
               request.environment==row.get('environment') and request.method==row.get('method'))
        prefix=row.get('path_prefix')
        if not is_canonical_path(prefix):
            continue  # a row that does not name a canonical prefix authorises nothing
        path_matches=(request.path==prefix or request.path.startswith(prefix+'/'))
        if not(match and path_matches):
            continue
        if principal.tenant_id not in row.get('allowed_tenants',[]):
            return deny('TENANT_NOT_GRANTED')
        if principal.service_id not in row.get('allowed_service_ids',[]):
            return deny('SERVICE_NOT_GRANTED')
        if request.account_id not in row.get('accounts_by_tenant',{}).get(principal.tenant_id,[]):
            return deny('ACCOUNT_NOT_GRANTED')
        if not row.get('credential_binding_ref'):
            return deny('CREDENTIAL_BINDING_MISSING')
        return Decision('ALLOW','ACTIVE_ACCOUNT_GRANT', row['credential_binding_ref'])
    return deny('NO_MATCHING_ALLOWLIST_OPERATION')
