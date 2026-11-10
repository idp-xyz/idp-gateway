"""OFFLINE mock policy tests, not real Gateway/Gatekeeper integration tests."""
import json, unittest
from pathlib import Path
import sys
R=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(R/'scripts'))
from policy_reference import TrustedPrincipal,EgressRequest,evaluate

P=json.loads((R/'gateway/policies/egress-policy.example.json').read_text())

def principal(tenant='tenant-blue', service='parcel-service', verified=True, env='TEST'):
 return TrustedPrincipal(service_id=service,tenant_id=tenant,verified=verified,environment=env)

def req(account='account-blue', op='tracking.get', path='/providers/mockcarrier/v1/tracking/123',method='GET',env='TEST',**kw):
 return EgressRequest(provider_id='mockcarrier',operation_id=op,account_id=account,path=path,method=method,environment=env,**kw)

class PolicyReferenceTests(unittest.TestCase):
 def test_valid_mock_case(self):self.assertEqual(evaluate(P,principal(),req()).result,'ALLOW')
 def test_cross_tenant_account(self):self.assertEqual(evaluate(P,principal('tenant-green'),req()).result,'DENY')
 def test_own_tenant_account(self):self.assertEqual(evaluate(P,principal('tenant-green'),req('account-green')).result,'ALLOW')
 def test_unverified_caller(self):self.assertEqual(evaluate(P,principal(verified=False),req()).result,'DENY')
 def test_no_identity(self):self.assertEqual(evaluate(P,None,req()).result,'DENY')
 def test_unregistered_operation(self):self.assertEqual(evaluate(P,principal(),req(op='label.create')).result,'DENY')
 def test_bad_method(self):self.assertEqual(evaluate(P,principal(),req(method='POST')).result,'DENY')
 def test_wrong_environment(self):self.assertEqual(evaluate(P,principal(),req(env='PROD')).result,'DENY')
 def test_different_service(self):self.assertEqual(evaluate(P,principal(service='unknown-service'),req()).result,'DENY')
 def test_custom_target(self):self.assertEqual(evaluate(P,principal(),req(target_override='http://127.0.0.1/metadata')).result,'DENY')
 def test_encoded_slash(self):self.assertEqual(evaluate(P,principal(),req(path='/providers/mockcarrier/v1/tracking%2fadmin')).result,'DENY')
 def test_encoded_dot(self):self.assertEqual(evaluate(P,principal(),req(path='/providers/mockcarrier/v1/tracking/%2e%2e/')).result,'DENY')
 def test_prefix_collision(self):self.assertEqual(evaluate(P,principal(),req(path='/providers/mockcarrier/v1/tracking-admin')).result,'DENY')
 def test_untrusted_host_override(self):self.assertEqual(evaluate(P,principal(),req(trusted_host_header=True)).result,'DENY')
 def test_dot_segments(self):self.assertEqual(evaluate(P,principal(),req(path='/providers/mockcarrier/v1/tracking/../private')).result,'DENY')
 def test_no_credential_binding(self):
  clone=json.loads(json.dumps(P));clone['registered_operations'][0]['credential_binding_ref']='';self.assertEqual(evaluate(clone,principal(),req()).result,'DENY')
if __name__=='__main__':unittest.main()
