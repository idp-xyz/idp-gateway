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
sys.path.insert(0,str(R/'scripts'))
# Not part of the baseline: the virtualenv, git internals, per-run PoC scratch files.
SKIP_DIRS={'.venv','.git','.run','__pycache__','node_modules'}
def files(pattern):
 return sorted(f for f in R.rglob(pattern) if not SKIP_DIRS & set(f.relative_to(R).parts))
def matrix_rows(path):
 """A case may leave NOT_RUN only by pointing at evidence that exists in the repository."""
 with (R/path).open(encoding='utf-8-sig',newline='') as f:rows=list(csv.DictReader(f))
 for r in rows:
  uri=r.get('evidence_uri','')
  if r['status']=='NOT_RUN':
   assert not uri,f"{r['case_id']}: NOT_RUN case carries evidence_uri"
  else:
   assert r['status'] in ('PASS','FAIL','BLOCKED'),f"{r['case_id']}: unknown status {r['status']}"
   assert uri and '://' not in uri and (R/uri).is_file(),f"{r['case_id']}: status {r['status']} without evidence file in repository"
 return rows
def tally(rows):
 n={}
 for r in rows:n[r['status']]=n.get(r['status'],0)+1
 return ', '.join(f'{v} {k}' for k,v in sorted(n.items()))
checks=[]
def check(key,fn):
 try:
  info=fn();checks.append({'check':key,'status':'PASS','detail':str(info or 'ok')})
 except Exception as e:
  checks.append({'check':key,'status':'FAIL','detail':f'{type(e).__name__}: {e}'})

def exists():
 expected=['README.md','governance/project-manifest.json','tests/acceptance_matrix.csv']
 expected += [f'docs/{t}' for t in ['G01_Requirements.md','G02_Architecture.md','G03_Routing_and_Configuration.md','G04_Identity_and_Security.md','G05_Engineering_and_Operations.md','G06_Testing_and_Acceptance.md']]
 expected += [f'decisions/ADR-{i:04d}.md' for i in range(1,9)]
 assert all((R/f).is_file() for f in expected),[f for f in expected if not(R/f).is_file()]
 return f'{len(expected)} required baseline files'
check('required_files',exists)

def markdown_links():
 mds=files('*.md');count=0
 pat=re.compile(r'(?<!\!)\[[^\]]+\]\(([^\s)]+)\)|!\[[^\]]*\]\(([^\s)]+)\)')
 for f in mds:
  s=f.read_text(encoding='utf-8')
  for m in pat.finditer(s):
   u=m.group(1) or m.group(2)
   if u.startswith(('https://','http://','#','mailto:')):continue
   assert (f.parent/u.split('#',1)[0]).exists(),f'broken link {f} -> {u}'
   count+=1
 return f'{len(mds)} Markdown files, {count} local links'
check('markdown_relative_links',markdown_links)

def html_links():
 from bs4 import BeautifulSoup
 pages=files('*.html');count=0
 for f in pages:
  soup=BeautifulSoup(f.read_text(encoding='utf-8'),'html.parser')
  for tag in soup.find_all(['a','img','link','script']):
   u=tag.get('href') or tag.get('src') or ''
   if not u or u.startswith(('http://','https://','mailto:','data:','#','javascript:')):continue
   loc=u.split('#',1)[0].split('?',1)[0]
   assert (f.parent/loc).exists(),f'Broken HTML link {f.name}: {u}'
   count+=1
 return f'{len(pages)} HTML pages, {count} local asset/href refs'
check('html_relative_links',html_links)

def json_and_schema():
 n=0
 for f in files('*.json'):
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
 fs=files('*.yaml')+files('*.yml')
 for f in fs:
  obj=yaml.safe_load(f.read_text(encoding='utf-8'));assert isinstance(obj,dict),f
 for f in files('*openapi.yaml'):
  o=yaml.safe_load(f.read_text(encoding='utf-8'));assert str(o.get('openapi')).startswith('3.1.')
 return f'{len(fs)} YAML syntax checks; no native agentgateway runtime/schema tests'
check('yaml_syntax_not_runtime',yaml_parse)

def matrix_coverage():
 rows=matrix_rows('tests/acceptance_matrix.csv')
 ids=[r['case_id'] for r in rows];assert len(ids)==len(set(ids))
 coverage=set(r['requirement_id'] for r in rows)
 missing={f'GW-FR-{i:03d}' for i in range(1,51)}-coverage
 missing_nfr={f'GW-NFR-{i:02d}' for i in range(1,20)}-coverage
 assert not missing and not missing_nfr,(missing,missing_nfr)
 return f'{len(rows)} scenarios ({tally(rows)}), all 50 FR and 19 NFR referenced'
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
 rows=matrix_rows('tests/ux/acceptance_matrix.csv')
 assert len(rows)==75, len(rows)
 assert len({r['case_id'] for r in rows})==75
 assert {f'GW-UX-{i:03d}' for i in range(1,76)}=={r['requirement_id'] for r in rows}
 assert len(list(screen.glob('*.png')))>=10
 browser_evidence=(R/'tests/evidence/ux-prototype-browser-tests.txt').read_text(encoding='utf-8')
 assert '35 PASS, 0 FAIL' in browser_evidence
 added_evidence=(R/'tests/evidence/unified-console-browser-tests.txt').read_text(encoding='utf-8')
 assert 'PASS 46/46 checks' in added_evidence
 assert 'Browser PASS: 504 UNKNOWN' in (R/'tests/evidence/message-inspector-browser-tests.txt').read_text(encoding='utf-8')
 assert 'Message Inspector' in html and 'diagnosticEvidence' in html
 assert 'trafficGovernancePanel' in html and 'data-governance=\"quota\"' in html
 # The three browser-test texts above were produced by scripts that are not in this
 # repository; this check only confirms the texts are present, it cannot re-run them.
 return (f'18-page unified offline mock; 75 UX formal cases ({tally(rows)}); browser-check transcripts present '
         f'(35 + 46 checks claimed, generating scripts not in repository, not reproducible here); '
         f"{len(list(screen.glob('*.png')))} preview PNGs")
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
 r=matrix_rows('tests/acceptance_matrix.csv')
 assert len(r)==95
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

def poc_p1_evidence():
 """PoC evidence must describe the files that are in the repository now, and must not be
 passed off as acceptance. It is read here, not re-run: run poc/p1/run_poc.py for that."""
 ev=R/'poc/p1/evidence/p1-run.json'
 if not ev.is_file():return 'no PoC evidence file (PoC not run)'
 e=json.loads(ev.read_text(encoding='utf-8'))
 sha=lambda p:hashlib.sha256((R/p).read_bytes()).hexdigest()
 assert e['agentgateway']['config_sha256']==sha('poc/p1/agentgateway.poc.yaml'),'evidence is for another gateway config; re-run the PoC'
 assert e['policy_sha256']==sha('poc/p1/policy.poc.json'),'evidence is for another PoC policy; re-run the PoC'
 assert e['policy_reference_sha256']==sha('scripts/policy_reference.py'),'evidence is for another policy_reference.py; re-run the PoC'
 assert str(e['formal_acceptance']).startswith('NOT_RUN')
 s=e['summary'];results=[c['result'] for c in e['cases']]
 assert s['cases']==len(results) and s['pass']==results.count('PASS') and s['fail']==results.count('FAIL')
 failed=[c['id'] for c in e['cases'] if c['result']!='PASS']
 return (f"PoC evidence matches current config/policy: {s['pass']}/{s['cases']} cases PASS on agentgateway "
         f"{e['agentgateway']['version'].get('version')}; FAIL: {', '.join(failed) or 'none'}; not acceptance evidence")
check('poc_p1_evidence_current',poc_p1_evidence)

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
