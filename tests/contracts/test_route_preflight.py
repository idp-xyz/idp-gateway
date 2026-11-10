"""Offline reference contract tests; NOT real proxy/network/security validation."""
import copy,json,sys,unittest
from pathlib import Path
R=Path(__file__).resolve().parents[2];sys.path.insert(0,str(R/'scripts'))
from preflight_intents import evaluate,errors_for_schema

def load(path):return json.loads((R/path).read_text(encoding='utf-8'))
class RoutePreflightTests(unittest.TestCase):
 def setUp(self):self.e=load('contracts/gateway/route-intent.example.json');self.i=load('contracts/gateway/route-intent.ingress.example.json');self.ai=load('contracts/gateway/route-intent.ai.example.json')
 def test_three_classes_schema(self):
  for it in [self.e,self.i,self.ai]:self.assertEqual(errors_for_schema('contracts/gateway/route-intent.schema.json',it),[])
 def test_egress_preflight(self):self.assertEqual(evaluate([self.e])['issue_count'],0)
 def test_three_pools_no_collision(self):self.assertEqual(evaluate([self.e,self.i,self.ai])['issue_count'],0)
 def test_branch_negatives(self):
  for case in load('tests/contracts/invalid-route-intents.json'):
   with self.subTest(case=case['case']):self.assertTrue(errors_for_schema('contracts/gateway/route-intent.schema.json',case['intent']))
 def test_duplicate_route_conflict(self):
  other=copy.deepcopy(self.e);other['intent_id']='gwi-collision-002'
  result=evaluate([self.e,other]);self.assertTrue(any(i.get('code')=='EXACT_ROUTE_CONFLICT' for i in result['issues']))
 def test_unsafe_destination(self):
  for host in ['localhost','metadata.google.internal','internal.test','127.0.0.1','169.254.169.254','myservice.internal']:
   with self.subTest(host=host):
    it=copy.deepcopy(self.e);it['upstream_hostname']=host
    self.assertNotEqual(evaluate([it])['issue_count'],0)
 def test_noncanonical_logical_path(self):
  for x in ['/providers/%2e%2e/', '/providers/../', '/providers//api']:
   with self.subTest(path=x):
    it=copy.deepcopy(self.e);it['logical_path']=x;self.assertNotEqual(evaluate([it])['issue_count'],0)
 def test_egress_quota_must_be_account_scoped(self):
  p=load('contracts/gateway/policies/traffic-policy.example.json');p['quota_buckets'][0]['key_dimensions']=['tenant','operation']
  self.assertNotEqual(errors_for_schema('contracts/gateway/policies/traffic-policy.schema.json',p),[])
 def test_distributed_quota_fallback_explicit(self):
  p=load('contracts/gateway/policies/traffic-policy.example.json');p['quota_buckets'][0].pop('coordinator_failure')
  self.assertNotEqual(errors_for_schema('contracts/gateway/policies/traffic-policy.schema.json',p),[])
 def test_sni_mismatch(self):
  x=copy.deepcopy(self.e);x['upstream_sni']='evil.example';self.assertIn('SNI_HOST_MISMATCH_REQUIRES_SIGNED_EXCEPTION',[i['reason'] for i in evaluate([x])['issues']])
 def test_conflict_env_isolated(self):
  x=copy.deepcopy(self.e);x['intent_id']='gwi-same-route-prod';x['environment']='PROD'
  self.assertFalse(any(i.get('code')=='EXACT_ROUTE_CONFLICT' for i in evaluate([self.e,x])['issues']))
 def test_no_api_key_as_config(self):
  x=copy.deepcopy(self.e);x['api_key']='secret';self.assertNotEqual(evaluate([x])['issue_count'],0)
 def test_head_options_valid(self):
  x=copy.deepcopy(self.i);x['allowed_methods']=['HEAD','OPTIONS'];self.assertEqual(evaluate([x])['issue_count'],0)
 def test_traffic_schema(self):
  p=load('contracts/gateway/policies/traffic-policy.example.json');self.assertEqual(errors_for_schema('contracts/gateway/policies/traffic-policy.schema.json',p),[])
  p['retry_mode']='RETRY_ALL';self.assertNotEqual(errors_for_schema('contracts/gateway/policies/traffic-policy.schema.json',p),[])
 def test_diagnostic_capture_and_event_schema(self):
  for sch,ex in [('contracts/gateway/policies/diagnostic-capture.schema.json','contracts/gateway/policies/diagnostic-capture.example.json'),('contracts/gateway/diagnostic-event.schema.json','contracts/gateway/diagnostic-event.example.json'),('contracts/gateway/policies/credential-binding.schema.json','contracts/gateway/policies/credential-binding.example.json')]:
   with self.subTest(schema=sch):self.assertEqual(errors_for_schema(sch,load(ex)),[])
if __name__=='__main__':unittest.main()
