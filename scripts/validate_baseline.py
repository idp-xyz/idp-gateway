#!/usr/bin/env python3
"""Validate the documentary/offline Gateway engineering baseline only.

It does NOT invoke an agentgateway binary, Gatekeeper, FedEx or a cluster.
It records genuine local evidence and keeps all runtime gates NOT_RUN.
"""
from __future__ import annotations
import csv, json, re, sys, traceback, hashlib, datetime
from pathlib import Path
import yaml
from jsonschema import Draft202012Validator, FormatChecker

R=Path(__file__).resolve().parents[1]
checks=[]
def check(key,fn):
 try:
  info=fn();checks.append({'check':key,'status':'PASS','detail':str(info or 'ok')})
 except Exception as e:
  checks.append({'check':key,'status':'FAIL','detail':f'{type(e).__name__}: {e}'})

def exists():
 expected=['README.md','governance/project-manifest.json','tests/acceptance_matrix.csv']
 expected += [f'docs/{t}' for t in ['G01_Requirements.md','G02_Architecture.md','G03_Routing_and_Configuration.md','G04_Identity_and_Security.md','G05_Engineering_and_Operations.md','G06_Testing_and_Acceptance.md']]
 expected += [f'decisions/ADR-{i:04d}.md' for i in range(1,8)]
 assert all((R/f).is_file() for f in expected),[f for f in expected if not(R/f).is_file()]
 return f'{len(expected)} required baseline files'
check('required_files',exists)

def markdown_links():
 files=list(R.rglob('*.md'));count=0
 pat=re.compile(r'(?<!\!)\[[^\]]+\]\(([^\s)]+)\)|!\[[^\]]*\]\(([^\s)]+)\)')
 for f in files:
  s=f.read_text(encoding='utf-8')
  for m in pat.finditer(s):
   u=m.group(1) or m.group(2)
   if u.startswith(('https://','http://','#','mailto:')):continue
   assert (f.parent/u.split('#',1)[0]).exists(),f'broken link {f} -> {u}'
   count+=1
 return f'{len(files)} Markdown files, {count} local links'
check('markdown_relative_links',markdown_links)

def html_links():
 from bs4 import BeautifulSoup
 files=list(R.rglob('*.html'));count=0
 for f in files:
  soup=BeautifulSoup(f.read_text(encoding='utf-8'),'html.parser')
  for tag in soup.find_all(['a','img','link','script']):
   u=tag.get('href') or tag.get('src') or ''
   if not u or u.startswith(('http://','https://','mailto:','data:','#','javascript:')):continue
   loc=u.split('#',1)[0].split('?',1)[0]
   assert (f.parent/loc).exists(),f'Broken HTML link {f.name}: {u}'
   count+=1
 return f'{len(files)} HTML pages, {count} local asset/href refs'
check('html_relative_links',html_links)

def json_and_schema():
 n=0
 for f in R.rglob('*.json'):
  x=json.loads(f.read_text(encoding='utf-8'));n+=1
  if f.name.endswith('.schema.json'):Draft202012Validator.check_schema(x)
 route=json.loads((R/'contracts/gateway/route-intent.schema.json').read_text())
 Draft202012Validator(route,format_checker=FormatChecker()).validate(json.loads((R/'contracts/gateway/route-intent.example.json').read_text()))
 dec=json.loads((R/'contracts/gatekeeper/authz-decision.schema.json').read_text())
 Draft202012Validator(dec,format_checker=FormatChecker()).validate(json.loads((R/'contracts/gatekeeper/authz-decision.example.json').read_text()))
 for path in ['contracts/gateway/route-intent.ingress.example.json','contracts/gateway/route-intent.ai.example.json']:
  Draft202012Validator(route,format_checker=FormatChecker()).validate(json.loads((R/path).read_text()))
 for path in ['gateway/policies/traffic-policy','gateway/policies/credential-binding','gateway/policies/diagnostic-capture','contracts/gateway/diagnostic-event']:
  schema=json.loads((R/(path+'.schema.json')).read_text());example=json.loads((R/(path+'.example.json')).read_text());Draft202012Validator(schema,format_checker=FormatChecker()).validate(example)
 for case in json.loads((R/'tests/contracts/invalid-route-intents.json').read_text()):
  assert not Draft202012Validator(route).is_valid(case['intent']),case['case']
 return f'{n} JSON files parsed; 6 additional example schemas and negative route samples validated'
check('json_schema_and_examples',json_and_schema)

def yaml_parse():
 fs=list(R.rglob('*.yaml'))+list(R.rglob('*.yml'))
 for f in fs:
  obj=yaml.safe_load(f.read_text(encoding='utf-8'));assert isinstance(obj,dict),f
 for f in R.rglob('*openapi.yaml'):
  o=yaml.safe_load(f.read_text(encoding='utf-8'));assert str(o.get('openapi')).startswith('3.1.')
 return f'{len(fs)} YAML syntax checks; no native agentgateway runtime/schema tests'
check('yaml_syntax_not_runtime',yaml_parse)

def matrix_coverage():
 with (R/'tests/acceptance_matrix.csv').open(encoding='utf-8-sig',newline='') as f:rows=list(csv.DictReader(f))
 ids=[r['case_id'] for r in rows];assert len(ids)==len(set(ids))
 coverage=set(r['requirement_id'] for r in rows)
 missing={f'GW-FR-{i:03d}' for i in range(1,51)}-coverage
 missing_nfr={f'GW-NFR-{i:02d}' for i in range(1,20)}-coverage
 assert not missing and not missing_nfr,(missing,missing_nfr)
 assert all(r['status']=='NOT_RUN' and not r['evidence_uri'] for r in rows)
 return f'{len(rows)} NOT_RUN scenarios, all 50 FR and 19 NFR referenced'
check('acceptance_coverage_not_run',matrix_coverage)

def safety_config():
 p=json.loads((R/'gateway/policies/egress-policy.example.json').read_text())
 assert p['default_decision']=='DENY' and p['allow_request_redirects'] is False and p['gateway_may_retry_non_idempotent'] is False
 assert p['enforce_tls_upstream'] is True
 for r in p['registered_operations']:
  assert r['upstream_hostname'].endswith('.example')
  assert not any(z in r for z in ['target_url','secret','token','authorization'])
  assert r['environment']=='TEST' and r['method'] in ['GET','POST','PUT','PATCH','DELETE']
 return 'demo policy: default deny, no redirects, no automatic write retries, reserved upstreams'
check('demo_policy_safety',safety_config)

def manifest_flags():
 m=json.loads((R/'governance/project-manifest.json').read_text())
 standard_schema=json.loads((R/'governance/standard-project-manifest.schema.json').read_text())
 Draft202012Validator(standard_schema,format_checker=FormatChecker()).validate(m)
 state=json.loads((R/'governance/design-status.json').read_text())
 assert m['adoption']['status']=='DRAFT' and m['adoption']['approved_by'] is None
 assert all(v.startswith('UNASSIGNED-') for v in m['owners'].values())
 assert all(v=='NOT_RUN' for v in state['gate_status'].values())
 assert all(v=='NOT_RUN' for v in state['runtime_verification'].values())
 assert 'AI' in [p['id'] for p in m['profiles']] and m['capabilities']['ai'] is True
 return 'official Manifest JSON Schema PASS; unresolved owners/other placeholders; gates NOT_RUN'
check('approval_and_gate_integrity',manifest_flags)

def ux_artifacts():
 prot=R/'portal/prototypes/gateway-operations.html'
 spec=R/'portal/spec/Gateway_Operations_UX_Spec_V1.0.md'
 screen=R/'portal/previews'
 assert prot.is_file() and spec.is_file()
 html=prot.read_text(encoding='utf-8')
 for name in ['overview','catalog','gateways','routes','backends','providers','policies','llm','llmsecurity','llmkeys','llmanalytics','mcp','mcpplay','a2a','traffic','releases','instances','tools']:
  assert f'data-page="{name}"' in html, name
 assert 'DEMO DATA · NOT LIVE' in html
 assert not any(s in html for s in ['fetch(', 'XMLHttpRequest(', 'WebSocket(', 'navigator.sendBeacon('])
 with (R/'tests/ux/acceptance_matrix.csv').open(encoding='utf-8-sig',newline='') as f:rows=list(csv.DictReader(f))
 assert len(rows)==75, len(rows)
 assert len({r['case_id'] for r in rows})==75
 assert {f'GW-UX-{i:03d}' for i in range(1,76)}=={r['requirement_id'] for r in rows}
 assert all(r['status']=='NOT_RUN' and not r['evidence_uri'] for r in rows)
 assert len(list(screen.glob('*.png')))>=10
 browser_evidence=(R/'tests/evidence/ux-prototype-browser-tests.txt').read_text(encoding='utf-8')
 assert '35 PASS, 0 FAIL' in browser_evidence
 added_evidence=(R/'tests/evidence/unified-console-browser-tests.txt').read_text(encoding='utf-8')
 assert 'PASS 46/46 checks' in added_evidence
 assert 'Browser PASS: 504 UNKNOWN' in (R/'tests/evidence/message-inspector-browser-tests.txt').read_text(encoding='utf-8')
 assert 'Message Inspector' in html and 'diagnosticEvidence' in html
 assert 'trafficGovernancePanel' in html and 'data-governance=\"quota\"' in html
 return '18-page unified offline mock; 75 UX formal cases NOT_RUN; original 35 + additional 46 local browser checks PASS; 12 preview PNGs'
check('gateway_operations_ux_mock',ux_artifacts)

def diagram_evidence():
 png=list((R/'diagrams').glob('*.png'));svg=list((R/'diagrams').glob('*.svg'))
 assert len(png)==4 and len(svg)==4
 return f'{len(svg)} SVG + {len(png)} PNG diagrams'
check('diagrams_exist',diagram_evidence)


def gap_evidence():
 from preflight_intents import evaluate
 with (R/'governance/gap-remediation-matrix.csv').open(encoding='utf-8-sig',newline='') as f:gaps=list(csv.DictReader(f))
 assert len(gaps)==15 and all(g['status']=='NOT_RUN' for g in gaps)
 assert all(g['priority'] in ['P0','P1','P2'] for g in gaps)
 with (R/'tests/acceptance_matrix.csv').open(encoding='utf-8-sig',newline='') as f:r=list(csv.DictReader(f))
 assert len(r)==95 and all(x['status']=='NOT_RUN' for x in r)
 with (R/'tests/protocol-compatibility.csv').open(encoding='utf-8-sig',newline='') as f:proto=list(csv.DictReader(f))
 assert len(proto)>=10 and all(x['status']=='NOT_RUN' for x in proto)
 with (R/'tests/operational-exercises.csv').open(encoding='utf-8-sig',newline='') as f:exercises=list(csv.DictReader(f))
 assert len(exercises)>=10 and all(x['status']=='NOT_RUN' for x in exercises)
 intents=[json.loads((R/('contracts/gateway/'+file)).read_text()) for file in ['route-intent.example.json','route-intent.ingress.example.json','route-intent.ai.example.json']]
 pres=evaluate(intents)
 assert pres['status']=='STATIC_PREFLIGHT_OK_NOT_DEPLOYABLE' and not pres['native_agentgateway_config_generated']
 assert not pres['native_agentgateway_schema_validated']
 assert 'NOT_RUN' in (R/'operations/incident-runbook.md').read_text()
 return f'{len(gaps)} gaps; {len(r)} runtime cases; {len(proto)} protocol scenarios; {len(exercises)} operational exercises, runtime NOT_RUN'
check('gap_remediation_offline_only',gap_evidence)

report={
 'title':'IDP Gateway V1.0 offline static validation',
 'executed_at_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),
 'python_version':sys.version.split()[0],
 'scope':'offline files, schemas, example data, traceability only',
 'checks':checks,
 'summary':{'pass':sum(c['status']=='PASS' for c in checks),'fail':sum(c['status']=='FAIL' for c in checks)},
 'gatekeeper_runtime':'NOT_RUN', 'agentgateway_runtime':'NOT_RUN', 'provider_sandbox':'NOT_RUN',
 'performance':'NOT_RUN','security_penetration':'NOT_RUN','formal_signoff':'NOT_RUN',
 'not_a_production_certification':True
}
p=R/'tests/evidence/static-validation.json';p.parent.mkdir(exist_ok=True,parents=True);p.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
for c in checks:print(f"{c['status']:4s} {c['check']}: {c['detail']}")
print('Offline checks:',report['summary'],'| Runtime: NOT_RUN')
raise SystemExit(1 if report['summary']['fail'] else 0)
