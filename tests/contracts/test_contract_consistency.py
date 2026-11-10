"""The contracts must agree with each other and with what the PoC mock actually speaks.

These tests pin the four contradictions found in review so they cannot come back:
two definitions of the decision artefact, a publication API without the envelope G03 §4
describes, several release-state vocabularies, and a credential handle nobody can redeem.
OFFLINE contract tests; nothing here calls a Gatekeeper or a gateway.
"""
import ast, copy, json, re, unittest
from pathlib import Path
import yaml
from jsonschema import Draft202012Validator, FormatChecker

R = Path(__file__).resolve().parents[2]
text = lambda path: (R / path).read_text(encoding='utf-8')
GATEKEEPER = yaml.safe_load(text('contracts/gatekeeper/openapi.yaml'))
FABRIC = yaml.safe_load(text('contracts/fabric/route-publication-intent.openapi.yaml'))
DECISION_SCHEMA = json.loads(text('contracts/gatekeeper/authz-decision.schema.json'))
ROUTE_SCHEMA = json.loads(text('contracts/gateway/route-intent.schema.json'))


def valid(schema, doc):
    return not list(Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(doc))


class DecisionArtefact(unittest.TestCase):
    def test_openapi_reuses_the_schema_file(self):
        component = GATEKEEPER['components']['schemas']['DecisionResponse']
        self.assertEqual(component['$ref'], './authz-decision.schema.json')
        self.assertFalse({'properties', 'required', 'type'} & set(component), 'second inline definition')

    def test_example_valid_and_bound_to_policy_and_revocation(self):
        example = json.loads(text('contracts/gatekeeper/authz-decision.example.json'))
        self.assertTrue(valid(DECISION_SCHEMA, example))
        for field in ['request_id', 'policy_version', 'revocation_epoch']:
            with self.subTest(missing=field):
                broken = copy.deepcopy(example)
                broken.pop(field)
                self.assertFalse(valid(DECISION_SCHEMA, broken))

    def test_decision_request_carries_what_the_decision_is_bound_to(self):
        request = GATEKEEPER['components']['schemas']['DecisionRequest']
        self.assertLessEqual({'route_id', 'operation_id', 'provider_id', 'requested_account_id', 'environment',
                              'method', 'path', 'config_digest'}, set(request['required']))
        self.assertLessEqual({'service_id', 'tenant_id', 'delegated_subject'}, set(request['properties']))


class CredentialRedemption(unittest.TestCase):
    def test_only_the_deprecated_endpoint_returns_material_in_a_body(self):
        for path, item in GATEKEEPER['paths'].items():
            for method, operation in item.items():
                body = json.dumps(operation.get('responses', {}).get('200', {}).get('content', {}))
                if 'header_value' in body or 'token' in body.lower():
                    self.assertTrue(operation.get('deprecated'), f'{method} {path} returns credential material')

    def test_extauthz_check_releases_the_credential_as_a_header(self):
        check = GATEKEEPER['paths']['/v1/extauthz/check']['get']
        allow = check['responses']['200']
        self.assertTrue(allow['headers']['Authorization']['required'])
        self.assertNotIn('content', allow)
        self.assertEqual(check['security'], [{'WorkloadMTLS': []}])

    def test_no_unredeemable_handle(self):
        handle = GATEKEEPER['components']['schemas']['CredentialUseResponse']['properties']['secure_binding_handle']
        self.assertTrue(handle.get('deprecated'))

    POC_PORTS = {'gatekeeper': '127.0.0.1:27613', 'broker': '127.0.0.1:27618'}

    def poc_routes(self):
        """Every PoC route with ExtAuthZ: the base file plus the route only 1.7.0 accepts."""
        routes = (yaml.safe_load(text('poc/p1/agentgateway.poc.yaml'))['routes']
                  + yaml.safe_load(text('poc/p1/agentgateway.poc.key-expression.yaml')))
        routes = [r for r in routes if 'extAuthz' in r.get('policies', {})]
        self.assertEqual(len(routes), 4)
        return routes

    def test_poc_gateway_sends_exactly_the_documented_trusted_context(self):
        documented = {p['name'] for p in GATEKEEPER['paths']['/v1/extauthz/check']['get']['parameters']}
        for route in self.poc_routes():
            ext = route['policies']['extAuthz']
            http = ext['protocol']['http']
            sent = set(http['addRequestHeaders']) | set(ext['includeRequestHeaders'])
            with self.subTest(route=route['name']):
                self.assertEqual(sent, documented)
                self.assertEqual(ext['failureMode'], 'deny')
                # The credential leaves the PDP's answer in exactly one way per route.
                copied, read = http.get('includeResponseHeaders'), http.get('metadata')
                if route['name'].endswith('-expression'):
                    self.assertIsNone(copied)
                    self.assertEqual(read, {'credential': 'response.headers["authorization"]'})
                else:
                    self.assertEqual(copied, ['authorization'])
                    self.assertIsNone(read)

    def test_poc_gateway_reaches_gatekeeper_over_mutual_tls_only(self):
        """WorkloadMTLS in the contract: a certificate, a pinned CA and a pinned name, and no bearer key."""
        for route in self.poc_routes():
            ext = route['policies']['extAuthz']
            with self.subTest(route=route['name']):
                if ext['host'] == self.POC_PORTS['gatekeeper']:
                    tls = ext['policies']['backendTLS']
                    self.assertEqual(set(tls), {'cert', 'key', 'root', 'hostname'})
                    self.assertNotIn('backendAuth', ext['policies'])
                else:
                    self.assertEqual(ext['host'], self.POC_PORTS['broker'])

    def test_broker_decision_request_is_the_documented_one(self):
        """What the mock broker sends to /v1/egress/authorizations/decision must fit DecisionRequest."""
        request = GATEKEEPER['components']['schemas']['DecisionRequest']
        tree = ast.parse(text('poc/p1/mock_broker.py'))
        sent = next({k.value for k in node.keys} for node in ast.walk(tree) if isinstance(node, ast.Dict)
                    and any(isinstance(k, ast.Constant) and k.value == 'requested_account_id' for k in node.keys))
        self.assertLessEqual(set(request['required']), sent)
        self.assertLessEqual(sent, set(request['properties']))
        self.assertIn('token_environment', sent)


class PublicationEnvelope(unittest.TestCase):
    def setUp(self):
        self.envelope = FABRIC['components']['schemas']['RoutePublicationIntent']
        self.example = json.loads(text('contracts/fabric/route-publication-intent.example.json'))

    def check(self, doc):
        """Envelope against the OpenAPI component, the embedded intent against the RouteIntent schema."""
        shell = copy.deepcopy(self.envelope)
        shell['properties']['intent'] = {'type': 'object'}
        return valid(shell, doc) and valid(ROUTE_SCHEMA, doc.get('intent'))

    def test_post_body_is_the_envelope_and_the_route_stays_single_sourced(self):
        post = FABRIC['paths']['/v1/route-intents']['post']
        self.assertEqual(post['requestBody']['content']['application/json']['schema']['$ref'],
                         '#/components/schemas/RoutePublicationIntent')
        self.assertEqual(self.envelope['properties']['intent']['$ref'], '#/components/schemas/RouteIntent')
        self.assertEqual(FABRIC['components']['schemas']['RouteIntent'], {'$ref': '../gateway/route-intent.schema.json'})

    def test_example(self):
        self.assertTrue(self.check(self.example))
        self.assertEqual(self.example['intent'], json.loads(text('contracts/gateway/route-intent.example.json')))

    def test_envelope_fields_are_required_and_not_duplicated_in_the_route(self):
        for field in ['idempotency_key', 'release_ref', 'target_id', 'intent']:
            with self.subTest(missing=field):
                broken = copy.deepcopy(self.example)
                broken.pop(field)
                self.assertFalse(self.check(broken))
        for field in ['idempotency_key', 'release_ref', 'target_id']:
            self.assertNotIn(field, ROUTE_SCHEMA['properties'])
        for field in ['approval_ref', 'expected_generation']:
            self.assertNotIn(field, self.envelope['properties'])
            self.assertIn(field, ROUTE_SCHEMA['required'])
        bare_route = self.example['intent']
        self.assertFalse(self.check(bare_route))


class ReleaseStates(unittest.TestCase):
    CANONICAL = ['DRAFT', 'VALIDATED', 'APPROVED', 'STAGED', 'APPLYING', 'OBSERVING', 'ACTIVE', 'REJECTED', 'CANCELED',
                 'FAILED', 'PARTIAL', 'UNKNOWN', 'SUPERSEDED', 'WITHDRAW_REQUESTED', 'REVOKING', 'REVOKED']
    CONSOLE_LABELS = ['REVIEW', 'ROLLOUT', 'RECONCILED', 'REVERTED']  # labels, never states

    def test_one_enum_used_by_every_response(self):
        self.assertEqual(FABRIC['components']['schemas']['ReleaseState']['enum'], self.CANONICAL)
        ref = {'$ref': '#/components/schemas/ReleaseState'}
        accepted = FABRIC['paths']['/v1/route-intents']['post']['responses']['202']
        status = FABRIC['paths']['/v1/route-intents/{intent_id}/status']['get']['responses']['200']
        for response in [accepted, status]:
            state = response['content']['application/json']['schema']['properties']['state']
            self.assertEqual({k: v for k, v in state.items() if k == '$ref'}, ref)
        self.assertNotIn('RECEIVED', text('contracts/fabric/route-publication-intent.openapi.yaml'))

    def test_g03_state_machine_uses_only_canonical_states(self):
        g03 = text('docs/G03_Routing_and_Configuration.md')
        diagram = g03.split('## 3. 配置发布状态机')[1].split('```')[1]
        words = set(re.findall(r'[A-Z][A-Z_]{3,}', diagram))
        self.assertEqual(words - set(self.CANONICAL), {'RECONCILE', 'ROLLBACK'})  # the two events
        self.assertEqual(set(self.CANONICAL) - words, set())

    def test_console_labels_are_mapped_wherever_they_are_used(self):
        for path in ['docs/G03_Routing_and_Configuration.md', 'portal/spec/Gateway_Operations_UX_Spec_V1.0.md']:
            for line in text(path).splitlines():
                if any(re.search(rf'\b{label}\b', line) for label in self.CONSOLE_LABELS):
                    with self.subTest(file=path, line=line[:40]):
                        self.assertIn('ReleaseState', line, 'console label used without pointing at the canonical states')


class PocMockSpeaksTheContract(unittest.TestCase):
    def test_denial_body_fields(self):
        """The mock's denial body must carry the fields ExtAuthzDenial requires."""
        required = set(GATEKEEPER['components']['schemas']['ExtAuthzDenial']['required'])
        tree = ast.parse(text('poc/p1/mock_gatekeeper.py'))
        keys = {k.value for node in ast.walk(tree) if isinstance(node, ast.Dict)
                for k in node.keys if isinstance(k, ast.Constant) and isinstance(k.value, str)}
        self.assertLessEqual(required, keys)


if __name__ == '__main__':
    unittest.main()
