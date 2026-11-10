#!/usr/bin/env python3
"""OFFLINE, DENY-FIRST checks for IDP governance intent objects.

Not agentgateway native config, not network-aware and not a security perimeter.
Native schema, DNS re-resolution, wire protocols and operational policy enforcement
MUST be independently validated before deployment.
"""
from __future__ import annotations
import argparse, hashlib, ipaddress, itertools, json, re, sys
from pathlib import Path
from typing import Any
from jsonschema import Draft202012Validator, FormatChecker

ROOT=Path(__file__).resolve().parents[1]
# The canonical-path rule of the egress policy. The implementation that decides requests is
# internal/egressauthz/domain (CanonicalPathPattern); tests/contracts checks the two are the same.
CANONICAL_PATH=re.compile(r'(/[A-Za-z0-9_~-][A-Za-z0-9._~-]*)+')


def is_canonical_path(path:Any)->bool:
    return isinstance(path,str) and CANONICAL_PATH.fullmatch(path) is not None
# The upstream rule is an allowlist: an EGRESS intent passes only if it matches a row of the
# provider registry. In a deployment that registry is API Fabric's approved provider catalogue;
# offline it defaults to the example below. The reserved-name lists that follow are kept as a
# second, independent check and are not what makes a destination acceptable.
DEFAULT_PROVIDER_REGISTRY=ROOT/'contracts/gateway/policies/egress-policy.example.json'
RESERVED_SUFFIXES=('.internal','.local','.localhost','.test','.invalid','.onion','.home.arpa')
RESERVED_HOSTS={'localhost','metadata.google.internal','169.254.169.254','metadata.aws.internal'}
SENSITIVE_KEYS={'password','client_secret','secret_value','api_key','access_token','refresh_token','private_key','authorization','bearer_token'}
# G02 §5: one pool per traffic class and environment (ingress-prod, egress-test, ai-dev, ...).
POOL_NAME=re.compile(r'(ingress|egress|ai)-(dev|test|prod)(?:-[a-z0-9]+)*')


def load(path: Path)->Any:
    return json.loads(path.read_text(encoding='utf-8'))


def errors_for_schema(schema_file: str, data:Any)->list[str]:
    schema=load(ROOT/schema_file)
    return [f'{".".join(str(i) for i in error.path)}: {error.message}' for error in Draft202012Validator(schema,format_checker=FormatChecker()).iter_errors(data)]


def under(path:Any, prefix:Any)->bool:
    """Segment-wise prefix: /a/b is under /a, /ab is not."""
    return isinstance(path,str) and isinstance(prefix,str) and (prefix=='/' or path==prefix or path.startswith(prefix+'/'))


def registry_errors(intent:dict, registry:dict)->list[str]:
    """Why this EGRESS intent is not covered by the provider registry ([] when it is)."""
    rows=[r for r in (registry or {}).get('registered_operations',[]) if isinstance(r,dict)]
    rows=[r for r in rows if r.get('provider_id')==intent.get('provider_id') and r.get('environment')==intent.get('environment')]
    if not rows:
        return ['PROVIDER_NOT_REGISTERED']
    rows=[r for r in rows if r.get('upstream_hostname')==intent.get('upstream_hostname') and r.get('port')==intent.get('upstream_port')]
    if not rows:
        return ['UPSTREAM_NOT_REGISTERED_FOR_PROVIDER']
    rows=[r for r in rows if r.get('operation_id')==intent.get('operation_id') and is_canonical_path(r.get('path_prefix'))
          and under(intent.get('logical_path'),r.get('path_prefix'))]
    methods=intent.get('allowed_methods')
    if not rows or not isinstance(methods,list) or not methods or not set(map(str,methods))<={r.get('method') for r in rows}:
        return ['OPERATION_NOT_REGISTERED']
    if any(r.get('credential_binding_ref')!=intent.get('credential_binding_ref') for r in rows if r.get('method') in methods):
        return ['CREDENTIAL_BINDING_NOT_REGISTERED']
    return []


def safety_errors(intent:dict, registry:dict|None=None)->list[str]:
    issues=[]
    path=intent.get('logical_path')
    if path!='/' and not is_canonical_path(path):
        issues.append('NON_CANONICAL_LOGICAL_PATH')
    pool=POOL_NAME.fullmatch(str(intent.get('gateway_pool','')))
    if not pool or (pool[1].upper(),pool[2].upper())!=(intent.get('traffic_class'),intent.get('environment')):
        issues.append('POOL_CLASS_ENVIRONMENT_MISMATCH')
    if intent.get('traffic_class')=='EGRESS':
        issues.extend(registry_errors(intent,registry or {}))
        host=intent.get('upstream_hostname','').lower().rstrip('.')
        if not host or host in RESERVED_HOSTS or host.endswith(RESERVED_SUFFIXES):
            issues.append('UNAPPROVED_UPSTREAM_DOMAIN')
        if '@' in host or '%' in host or ':' in host:
            issues.append('UNSAFE_UPSTREAM_HOSTNAME')
        try:
            ipaddress.ip_address(host)
            issues.append('IP_LITERAL_UPSTREAM_DENIED')
        except ValueError: pass
        if intent.get('upstream_sni') and intent.get('upstream_sni') != intent.get('upstream_hostname'):
            issues.append('SNI_HOST_MISMATCH_REQUIRES_SIGNED_EXCEPTION')
        if intent.get('redirect_policy') != 'DENY':
            issues.append('REDIRECT_NOT_DENIED')
        if intent.get('upstream_tls') != 'VERIFY_REQUIRED':
            issues.append('TLS_VERIFICATION_MISSING')
        if not str(intent.get('credential_binding_ref','')).startswith('gatekeeper:'):
            issues.append('NO_GATEKEEPER_CREDENTIAL_REFERENCE')
    if intent.get('traffic_class')=='INGRESS':
        if intent.get('public_hostname') in RESERVED_HOSTS:
            issues.append('UNSAFE_PUBLIC_HOST')
    for key,value in intent.items():
        if key.lower() in SENSITIVE_KEYS and value:
            issues.append('CREDENTIAL_VALUE_IN_INTENT')
    return sorted(set(issues))


def prefix_overlaps(intents:list[dict])->list[dict]:
    """Two routes in the same pool where one path contains the other and a method is shared.

    Which one wins is then up to the routing engine, so it is rejected unless both intents
    state an explicit route_priority and the two differ.
    """
    errs=[]
    scope=lambda it:(it.get('environment'),it.get('gateway_pool'),it.get('traffic_class'),
                     it.get('public_hostname') if it.get('traffic_class')=='INGRESS' else '*')
    methods=lambda it:set(map(str,it.get('allowed_methods') or ['*']))
    explicit=lambda it:type(it.get('route_priority')) is int
    for a,b in itertools.combinations([it for it in intents if isinstance(it,dict)],2):
        pa,pb=a.get('logical_path'),b.get('logical_path')
        if scope(a)!=scope(b) or pa==pb or not (under(pa,pb) or under(pb,pa)):
            continue
        ma,mb=methods(a),methods(b)
        if not (ma&mb or '*' in ma or '*' in mb):
            continue
        if explicit(a) and explicit(b) and a['route_priority']!=b['route_priority']:
            continue
        errs.append({'code':'PREFIX_ROUTE_OVERLAP','first':a.get('intent_id'),'second':b.get('intent_id'),'paths':[pa,pb]})
    return errs


def conflicts(intents:list[dict])->list[dict]:
    errs=[]
    # Same route key twice. Nested prefixes are handled by prefix_overlaps(); regex routes
    # and the native engine's own precedence still have to be checked in a later gate.
    index={}
    for it in intents:
        methods=it.get('allowed_methods') or ['*']
        host=it.get('public_hostname') if it.get('traffic_class')=='INGRESS' else '*'
        for method in methods:
            key=(it.get('environment'),it.get('gateway_pool'),it.get('traffic_class'),host,it.get('logical_path'),method)
            prev=index.setdefault(key,it.get('intent_id'))
            if prev!=it.get('intent_id'):
                errs.append({'code':'EXACT_ROUTE_CONFLICT','first':prev,'second':it.get('intent_id'),'route_key':list(key)})
    return errs


def evaluate(intents:list[dict], registry:dict|None=None)->dict:
    """registry: provider registry document; None loads DEFAULT_PROVIDER_REGISTRY.

    An empty or missing registry registers nothing, so every EGRESS intent is rejected.
    """
    if registry is None:
        registry=load(DEFAULT_PROVIDER_REGISTRY) if DEFAULT_PROVIDER_REGISTRY.is_file() else {}
    canonical=lambda doc:json.dumps(doc,sort_keys=True,ensure_ascii=False,separators=(',',':')).encode()
    issues=[]
    for it in intents:
        if not isinstance(it,dict):
            issues.append({'intent_id':'UNKNOWN','reason':'INTENT_NOT_OBJECT'});continue
        bad=errors_for_schema('contracts/gateway/route-intent.schema.json',it)+safety_errors(it,registry)
        issues += [{'intent_id':it.get('intent_id','UNKNOWN'),'reason':b} for b in bad]
    issues.extend(conflicts([it for it in intents if isinstance(it,dict)]))
    issues.extend(prefix_overlaps(intents))
    return {'status':'REJECT' if issues else 'STATIC_PREFLIGHT_OK_NOT_DEPLOYABLE',
            'native_agentgateway_config_generated':False,
            'native_agentgateway_schema_validated':False,
            'network_dns_allowlist_validated':False,
            'intents_sha256':hashlib.sha256(canonical(intents)).hexdigest(),
            'provider_registry_sha256':hashlib.sha256(canonical(registry)).hexdigest(),
            'issue_count':len(issues),'issues':issues}


def main():
    ap=argparse.ArgumentParser(description='Offline IDP RouteIntent preflight (NOT native agentgateway validation)')
    ap.add_argument('file',type=Path,help='JSON intent object or array')
    ap.add_argument('--provider-registry',type=Path,
                    help=f'approved provider registry (default: {DEFAULT_PROVIDER_REGISTRY.relative_to(ROOT)})')
    ap.add_argument('--output',type=Path)
    a=ap.parse_args()
    doc=load(a.file)
    report=evaluate(doc if isinstance(doc,list) else [doc],load(a.provider_registry) if a.provider_registry else None)
    output=json.dumps(report,ensure_ascii=False,indent=2)
    if a.output:a.output.write_text(output+'\n',encoding='utf-8')
    else:print(output)
    return 0 if report['issue_count']==0 else 2
if __name__=='__main__':sys.exit(main())
