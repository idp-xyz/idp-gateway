#!/usr/bin/env python3
"""OFFLINE, DENY-FIRST checks for IDP governance intent objects.

Not agentgateway native config, not network-aware and not a security perimeter.
Native schema, DNS re-resolution, wire protocols and operational policy enforcement
MUST be independently validated before deployment.
"""
from __future__ import annotations
import argparse, hashlib, ipaddress, json, sys
from pathlib import Path
from typing import Any
from jsonschema import Draft202012Validator, FormatChecker

ROOT=Path(__file__).resolve().parents[1]
RESERVED_SUFFIXES=('.internal','.local','.localhost','.test','.invalid','.onion','.home.arpa')
RESERVED_HOSTS={'localhost','metadata.google.internal','169.254.169.254','metadata.aws.internal'}
SENSITIVE_KEYS={'password','client_secret','secret_value','api_key','access_token','refresh_token','private_key','authorization','bearer_token'}


def load(path: Path)->Any:
    return json.loads(path.read_text(encoding='utf-8'))


def errors_for_schema(schema_file: str, data:Any)->list[str]:
    schema=load(ROOT/schema_file)
    return [f'{".".join(str(i) for i in error.path)}: {error.message}' for error in Draft202012Validator(schema,format_checker=FormatChecker()).iter_errors(data)]


def safety_errors(intent:dict)->list[str]:
    issues=[]
    path=str(intent.get('logical_path',''))
    if any(bad in path.lower() for bad in ('%','..','//','\\')):
        issues.append('NON_CANONICAL_LOGICAL_PATH')
    if intent.get('traffic_class')=='EGRESS':
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


def conflicts(intents:list[dict])->list[dict]:
    errs=[]
    # Exact route key is intentionally conservative: prefix/regex ambiguities must
    # also be resolved by the native routing engine in a later gate.
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


def evaluate(intents:list[dict])->dict:
    issues=[]
    for it in intents:
        if not isinstance(it,dict):
            issues.append({'intent_id':'UNKNOWN','reason':'INTENT_NOT_OBJECT'});continue
        bad=errors_for_schema('contracts/gateway/route-intent.schema.json',it)+safety_errors(it)
        issues += [{'intent_id':it.get('intent_id','UNKNOWN'),'reason':b} for b in bad]
    issues.extend(conflicts(intents))
    data=json.dumps(intents,sort_keys=True,ensure_ascii=False,separators=(',',':')).encode()
    return {'status':'REJECT' if issues else 'STATIC_PREFLIGHT_OK_NOT_DEPLOYABLE',
            'native_agentgateway_config_generated':False,
            'native_agentgateway_schema_validated':False,
            'network_dns_allowlist_validated':False,
            'intents_sha256':hashlib.sha256(data).hexdigest(),
            'issue_count':len(issues),'issues':issues}


def main():
    ap=argparse.ArgumentParser(description='Offline IDP RouteIntent preflight (NOT native agentgateway validation)')
    ap.add_argument('file',type=Path,help='JSON intent object or array')
    ap.add_argument('--output',type=Path)
    a=ap.parse_args()
    doc=load(a.file)
    report=evaluate(doc if isinstance(doc,list) else [doc])
    output=json.dumps(report,ensure_ascii=False,indent=2)
    if a.output:a.output.write_text(output+'\n',encoding='utf-8')
    else:print(output)
    return 0 if report['issue_count']==0 else 2
if __name__=='__main__':sys.exit(main())
