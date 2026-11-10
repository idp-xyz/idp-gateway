"""Safe-by-default OFFLINE diagnostic grant / sampling reference.

This is NOT a packet collector or production redactor. Real deployment must
validate byte-level capture order, transport encoding, data classification and
server-side authorization before any payload reaches storage or telemetry.
"""
from __future__ import annotations
from datetime import datetime, timezone

# The only header names diagnostic evidence may carry. contracts/gateway/diagnostic-event.schema.json
# ($defs.sanitized_header_name) lists the same names; a contract test keeps the two equal.
ALLOWED_HEADERS={'content-type','x-request-id','x-correlation-id','x-provider-request-id','traceparent'}
MAX_WINDOW_SECONDS=900
MAX_BYTES_PER_MESSAGE=65536
UNOBSERVED_STATUSES={'NOT_SENT','NOT_OBSERVED'}
OBSERVATION_FIELDS=('http_status','grpc_status','sanitized_headers','body_sha256','body_sample_sanitized',
                    'bytes_observed','body_total_bytes','body_captured_bytes','content_type','provider_request_id_sanitized')

def _identity(value)->str:
    """Comparable form of an actor reference; '' when it does not name anyone."""
    return value.strip().casefold() if isinstance(value,str) else ''

def _utc(ts:str)->datetime:
    dt=datetime.fromisoformat(ts.replace('Z','+00:00'))
    if dt.tzinfo is None:raise ValueError('timezone required')
    return dt.astimezone(timezone.utc)

def authorize_capture(grant:dict, *, trusted_route:str, trusted_tenant:str, trusted_environment:str, now:datetime)->tuple[bool,str]:
    """Checks contextual constraints in addition to JSON Schema; does not verify identity signatures."""
    if not grant or grant.get('route_ref')!=trusted_route or grant.get('tenant_ref')!=trusted_tenant or grant.get('environment')!=trusted_environment:
        return False,'SCOPE_MISMATCH'
    requester,approver=_identity(grant.get('requested_by')),_identity(grant.get('approved_by'))
    if not requester or not approver:
        return False,'APPROVAL_IDENTITY_MISSING'
    if requester==approver:
        return False,'SEGREGATION_OF_DUTIES'
    try: start,end=_utc(grant['start_at']),_utc(grant['expires_at'])
    except (ValueError,KeyError,TypeError):return False,'INVALID_CAPTURE_TIMESTAMPS'
    if end<=start or (end-start).total_seconds()>MAX_WINDOW_SECONDS:
        return False,'WINDOW_EXCEEDED'
    if now.astimezone(timezone.utc)<start or now.astimezone(timezone.utc)>=end:
        return False,'OUTSIDE_APPROVED_WINDOW'
    limit=grant.get('max_bytes_per_message')
    if type(limit) is not int or not (0<=limit<=MAX_BYTES_PER_MESSAGE):  # bool, str, float: not a limit
        return False,'UNSAFE_LIMIT'
    return True,'APPROVED_BOUND_SCOPE'

def event_semantic_errors(event:dict)->list[str]:
    """Consistency rules for a diagnostic event that JSON Schema cannot (or can only partly) express.

    Run after schema validation. An empty list means consistent, not true: nothing here
    can tell whether the stages describe what really happened on the wire.
    """
    issues=[]
    stages=[s for s in event.get('stages',[]) if isinstance(s,dict)]
    names=[s.get('stage') for s in stages]
    if len(names)!=len(set(names)):
        issues.append('DUPLICATE_STAGE')
    if any(s.get('status') in UNOBSERVED_STATUSES and any(f in s for f in OBSERVATION_FIELDS) for s in stages):
        issues.append('UNOBSERVED_STAGE_HAS_OBSERVATIONS')
    by_name={s.get('stage'):s for s in stages}
    observed=lambda name: name in by_name and by_name[name].get('status') not in UNOBSERVED_STATUSES
    outcome=event.get('business_outcome')
    if outcome=='NOT_SENT' and (observed('EGRESS') or observed('UPSTREAM_RESPONSE')):
        issues.append('NOT_SENT_OUTCOME_WITH_UPSTREAM_EXCHANGE')
    if outcome=='SUCCESS' and not observed('UPSTREAM_RESPONSE'):
        issues.append('SUCCESS_OUTCOME_WITHOUT_UPSTREAM_RESPONSE')
    return sorted(set(issues))

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
