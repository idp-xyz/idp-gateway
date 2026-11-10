import copy,json,sys,unittest
from datetime import datetime,timezone
from pathlib import Path
R=Path(__file__).resolve().parents[2];sys.path.insert(0,str(R/'scripts'))
from diagnostic_reference import authorize_capture,sanitized_evidence,sanitize_headers
G=json.loads((R/'contracts/gateway/policies/diagnostic-capture.example.json').read_text())
NOW=datetime.fromisoformat('2026-11-10T08:05:00+00:00')
def approve(g):return authorize_capture(g,trusted_route='gwi-example-001',trusted_tenant='tenant-blue',trusted_environment='TEST',now=NOW)
class DiagnosticReferenceTests(unittest.TestCase):
 def test_valid_sample(self):self.assertEqual(approve(G),(True,'APPROVED_BOUND_SCOPE'))
 def test_cross_tenant_denied(self):
  self.assertFalse(authorize_capture(G,trusted_route='gwi-example-001',trusted_tenant='tenant-other',trusted_environment='TEST',now=NOW)[0])
 def test_self_approval_denied(self):
  x=copy.deepcopy(G);x['approved_by']=x['requested_by'];self.assertFalse(approve(x)[0])
 def test_expired_denied(self):self.assertFalse(authorize_capture(G,trusted_route='gwi-example-001',trusted_tenant='tenant-blue',trusted_environment='TEST',now=datetime(2026,11,10,9,0,tzinfo=timezone.utc))[0])
 def test_window_bound(self):
  x=copy.deepcopy(G);x['expires_at']='2026-11-10T08:30:00Z';self.assertEqual(approve(x)[1],'WINDOW_EXCEEDED')
 def test_token_header_dropped(self):
  x=sanitize_headers({'Authorization':'Bearer secret','Cookie':'jwt=secret','X-Api-Key':'secret','Content-Type':'application/json','X-Client-Id':'private','X-Request-ID':'r-42'})
  self.assertEqual(x,{'content-type':'application/json','x-request-id':'r-42'})
 def test_body_cannot_leak(self):
  out=sanitized_evidence(headers={'Authorization':'Bearer jwt'},body={'name':'Sensitive Person','address':'sensitive'},capture_grant=G)
  self.assertIsNone(out['body_sample_sanitized']);self.assertEqual(out['body_status'],'NOT_CAPTURED')
if __name__=='__main__':unittest.main()
