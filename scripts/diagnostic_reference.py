"""Safe-by-default OFFLINE diagnostic grant / sampling reference.

This is NOT a packet collector or production redactor. Real deployment must
validate byte-level capture order, transport encoding, data classification and
server-side authorization before any payload reaches storage or telemetry.
"""
from __future__ import annotations
from datetime import datetime, timezone

ALLOWED_HEADERS={'content-type','x-request-id','traceparent'}
MAX_WINDOW_SECONDS=900

def _utc(ts:str)->datetime:
    dt=datetime.fromisoformat(ts.replace('Z','+00:00'))
    if dt.tzinfo is None:raise ValueError('timezone required')
    return dt.astimezone(timezone.utc)

def authorize_capture(grant:dict, *, trusted_route:str, trusted_tenant:str, trusted_environment:str, now:datetime)->tuple[bool,str]:
    """Checks contextual constraints in addition to JSON Schema; does not verify identity signatures."""
    if not grant or grant.get('route_ref')!=trusted_route or grant.get('tenant_ref')!=trusted_tenant or grant.get('environment')!=trusted_environment:
        return False,'SCOPE_MISMATCH'
    if grant.get('requested_by')==grant.get('approved_by'):
        return False,'SEGREGATION_OF_DUTIES'
    try: start,end=_utc(grant['start_at']),_utc(grant['expires_at'])
    except (ValueError,KeyError,TypeError):return False,'INVALID_CAPTURE_TIMESTAMPS'
    if end<=start or (end-start).total_seconds()>MAX_WINDOW_SECONDS:
        return False,'WINDOW_EXCEEDED'
    if now.astimezone(timezone.utc)<start or now.astimezone(timezone.utc)>=end:
        return False,'OUTSIDE_APPROVED_WINDOW'
    if not (0<=grant.get('max_bytes_per_message',-1)<=65536):
        return False,'UNSAFE_LIMIT'
    return True,'APPROVED_BOUND_SCOPE'

def sanitize_headers(headers:dict[str,str])->dict[str,str]:
    """Strict allowlist; drop all unknown fields including authorization/PII/custom headers."""
    return {k.lower():v for k,v in headers.items() if k.lower() in ALLOWED_HEADERS and isinstance(v,str) and len(v)<256}

def sanitized_evidence(*, headers:dict[str,str], body:bytes|str|dict|None, capture_grant:dict|None=None)->dict:
    """No body is persisted even if grant exists: production schema-aware sanitization NOT implemented."""
    return {'sanitized_headers':sanitize_headers(headers),
            'body_status':'NOT_CAPTURED',
            'body_sample_sanitized':None,
            'capture_grant_present':bool(capture_grant),
            'production_payload_capture_enabled':False}
