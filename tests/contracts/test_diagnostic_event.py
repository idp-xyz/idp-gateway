import copy,json,unittest
from pathlib import Path
from jsonschema import Draft202012Validator,ValidationError
R=Path(__file__).resolve().parents[2]
class DiagnosticEventContract(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.schema=json.loads((R/'contracts/gateway/diagnostic-event.schema.json').read_text())
  cls.validator=Draft202012Validator(cls.schema)
 def test_example_success_pair(self):
  e=json.loads((R/'contracts/gateway/diagnostic-event.paired-200.example.json').read_text())
  self.validator.validate(e)
  self.assertEqual([s['message_kind'] for s in e['stages']],['REQUEST','REQUEST','RESPONSE','RESPONSE'])
  self.assertEqual(len({s['hop'] for s in e['stages']}),2)
 def test_example_504_capture(self):
  e=json.loads((R/'contracts/gateway/diagnostic-event.example.json').read_text())
  self.validator.validate(e)
  self.assertEqual(e['business_outcome'],'UNKNOWN')
 def test_reject_raw_authorization_header_even_mixed_case(self):
  e=json.loads((R/'contracts/gateway/diagnostic-event.paired-200.example.json').read_text())
  for name in ['Authorization','authorization','AUTHORIZATION','X-API-KEY','Cookie','pROxy-authorization']:
   trial=copy.deepcopy(e);trial['stages'][0]['sanitized_headers'][name]='DO-NOT-STORE'
   with self.subTest(name=name):
    with self.assertRaises(ValidationError):self.validator.validate(trial)
 def test_http_status_range(self):
  e=json.loads((R/'contracts/gateway/diagnostic-event.paired-200.example.json').read_text());e['stages'][2]['http_status']=999
  with self.assertRaises(ValidationError):self.validator.validate(e)
if __name__=='__main__':unittest.main()
