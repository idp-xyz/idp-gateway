"""Regression tests for bypasses found when reviewing the offline preflight and schemas.

Each test was written against the baseline as delivered and failed there.
OFFLINE reference tests, not proxy/network/security validation.
"""
import copy, json, sys, unittest
from pathlib import Path
from jsonschema import Draft202012Validator

R = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(R / 'scripts'))
from preflight_intents import errors_for_schema, evaluate
import diagnostic_reference

ROUTE_SCHEMA = 'contracts/gateway/route-intent.schema.json'
load = lambda path: json.loads((R / path).read_text(encoding='utf-8'))


def reasons(report):
    return {i.get('reason') or i.get('code') for i in report['issues']}


class EgressUpstreamAllowlist(unittest.TestCase):
    def setUp(self):
        self.egress = load('contracts/gateway/route-intent.example.json')

    def variant(self, **changes):
        intent = copy.deepcopy(self.egress)
        intent.update(changes)
        return intent

    def test_delivered_example_still_passes(self):
        self.assertEqual(evaluate([self.egress])['issues'], [])

    def test_public_looking_hosts_nobody_registered(self):
        for host in ['attacker-controlled.com', 'kubernetes.default.svc', '169.254.169.254.nip.io',
                     'mockcarrier.example.evil.com', 'evil-mockcarrier.example', 'localtest.me']:
            with self.subTest(host=host):
                report = evaluate([self.variant(upstream_hostname=host, upstream_sni=host)])
                self.assertEqual(report['status'], 'REJECT')
                self.assertIn('UPSTREAM_NOT_REGISTERED_FOR_PROVIDER', reasons(report))

    def test_registered_host_on_another_port(self):
        self.assertIn('UPSTREAM_NOT_REGISTERED_FOR_PROVIDER', reasons(evaluate([self.variant(upstream_port=8443)])))

    def test_provider_or_environment_without_registration(self):
        self.assertIn('PROVIDER_NOT_REGISTERED', reasons(evaluate([self.variant(provider_id='othercarrier')])))
        self.assertIn('PROVIDER_NOT_REGISTERED',
                      reasons(evaluate([self.variant(environment='PROD', gateway_pool='egress-prod')])))

    def test_operation_method_or_path_outside_the_registration(self):
        for label, changes in {
            'unregistered operation': {'operation_id': 'labels.create'},
            'unregistered method': {'allowed_methods': ['GET', 'DELETE']},
            'path outside the registered prefix': {'logical_path': '/providers/mockcarrier/v1/admin'},
            'path only shares a string prefix': {'logical_path': '/providers/mockcarrier/v1/tracking-admin'},
            'path above the registered prefix': {'logical_path': '/providers/mockcarrier'},
        }.items():
            with self.subTest(case=label):
                self.assertIn('OPERATION_NOT_REGISTERED', reasons(evaluate([self.variant(**changes)])))

    def test_credential_binding_other_than_the_registered_one(self):
        report = evaluate([self.variant(credential_binding_ref='gatekeeper:some-other-binding')])
        self.assertIn('CREDENTIAL_BINDING_NOT_REGISTERED', reasons(report))

    def test_no_registry_means_no_egress(self):
        for registry in [{}, {'registered_operations': []}]:
            with self.subTest(registry=registry):
                report = evaluate([self.egress], registry=registry)
                self.assertEqual(report['status'], 'REJECT')
                self.assertIn('PROVIDER_NOT_REGISTERED', reasons(report))

    def test_report_names_the_registry_it_used(self):
        self.assertRegex(evaluate([self.egress])['provider_registry_sha256'], '^[a-f0-9]{64}$')


class PoolConsistency(unittest.TestCase):
    def setUp(self):
        self.by_class = {'EGRESS': load('contracts/gateway/route-intent.example.json'),
                         'INGRESS': load('contracts/gateway/route-intent.ingress.example.json'),
                         'AI': load('contracts/gateway/route-intent.ai.example.json')}

    def test_delivered_examples_still_pass(self):
        self.assertEqual(evaluate(list(self.by_class.values()))['issues'], [])

    def test_intent_placed_in_a_pool_of_another_class_or_environment(self):
        for traffic_class, pool in [('EGRESS', 'ingress-prod'), ('EGRESS', 'egress-prod'), ('EGRESS', 'ingress-test'),
                                    ('EGRESS', 'ai-test'), ('INGRESS', 'egress-test'), ('INGRESS', 'ingress-prod'),
                                    ('AI', 'egress-test'), ('AI', 'ai-prod'), ('EGRESS', 'shared'),
                                    ('EGRESS', 'egress-testing'), ('EGRESS', 'not-egress-test')]:
            with self.subTest(traffic_class=traffic_class, pool=pool):
                intent = copy.deepcopy(self.by_class[traffic_class])
                intent['gateway_pool'] = pool
                self.assertIn('POOL_CLASS_ENVIRONMENT_MISMATCH', reasons(evaluate([intent])))

    def test_pool_may_carry_a_suffix(self):
        intent = copy.deepcopy(self.by_class['INGRESS'])
        intent['gateway_pool'] = 'ingress-test-eu1'
        self.assertEqual(evaluate([intent])['issues'], [])

    def test_egress_only_fields_on_other_classes(self):
        extras = {'upstream_hostname': 'attacker-controlled.com', 'upstream_port': 443, 'upstream_tls': 'VERIFY_REQUIRED',
                  'upstream_sni': 'attacker-controlled.com', 'redirect_policy': 'ALLOW_SAME_APPROVED_HOST',
                  'operation_id': 'tracking.get'}
        for traffic_class in ['INGRESS', 'AI']:
            for field, value in extras.items():
                with self.subTest(traffic_class=traffic_class, field=field):
                    intent = copy.deepcopy(self.by_class[traffic_class])
                    intent[field] = value
                    self.assertNotEqual(errors_for_schema(ROUTE_SCHEMA, intent), [])
                    self.assertEqual(evaluate([intent])['status'], 'REJECT')


class PrefixOverlap(unittest.TestCase):
    def setUp(self):
        self.parent = load('contracts/gateway/route-intent.ingress.example.json')

    def child(self, **changes):
        intent = copy.deepcopy(self.parent)
        intent.update(intent_id='gwi-public-002', logical_path='/v1/shipments/labels')
        intent.update(changes)
        return intent

    def overlap(self, *intents):
        return 'PREFIX_ROUTE_OVERLAP' in reasons(evaluate(list(intents)))

    def test_nested_prefix_on_a_shared_method(self):
        self.assertTrue(self.overlap(self.parent, self.child()))
        self.assertTrue(self.overlap(self.child(), self.parent))

    def test_overlap_remains_without_distinct_explicit_priorities(self):
        self.assertTrue(self.overlap({**self.parent, 'route_priority': 10}, self.child()))
        self.assertTrue(self.overlap({**self.parent, 'route_priority': 10}, self.child(route_priority=10)))

    def test_distinct_explicit_priorities_resolve_it(self):
        self.assertFalse(self.overlap({**self.parent, 'route_priority': 10}, self.child(route_priority=20)))

    def test_not_an_overlap(self):
        self.assertFalse(self.overlap(self.parent, self.child(allowed_methods=['POST'])))
        self.assertFalse(self.overlap(self.parent, self.child(logical_path='/v1/shipments-archive')))
        self.assertFalse(self.overlap(self.parent, self.child(public_hostname='other.cargopai.example')))
        self.assertFalse(self.overlap(self.parent, self.child(environment='PROD', gateway_pool='ingress-prod')))


class DiagnosticEventSchema(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.schema = load('contracts/gateway/diagnostic-event.schema.json')
        cls.validator = Draft202012Validator(cls.schema)
        cls.ok200 = load('contracts/gateway/diagnostic-event.paired-200.example.json')
        cls.ok504 = load('contracts/gateway/diagnostic-event.example.json')

    def invalid(self, event):
        return bool(list(self.validator.iter_errors(event)))

    def test_delivered_examples_still_valid(self):
        self.assertFalse(self.invalid(self.ok200))
        self.assertFalse(self.invalid(self.ok504))

    def test_header_names_outside_the_allowlist(self):
        for name in ['X-Amz-Security-Token', 'Api-Key', 'apikey', 'X-Upstream-Secret', 'Token', 'X-Session-Id',
                     'X-Goog-Api-Key', 'Ocp-Apim-Subscription-Key', 'X-Csrf-Token', 'Signature', 'X-Client-Id',
                     'Content-Type ', 'content-type\n']:
            with self.subTest(name=name):
                event = copy.deepcopy(self.ok200)
                event['stages'][0]['sanitized_headers'][name] = 'x'
                self.assertTrue(self.invalid(event))

    def test_allowlisted_names_are_recorded_lowercase(self):
        for name in sorted(diagnostic_reference.ALLOWED_HEADERS):
            with self.subTest(name=name):
                event = copy.deepcopy(self.ok200)
                event['stages'][0]['sanitized_headers'] = {name: 'value-1'}
                self.assertFalse(self.invalid(event))
                event['stages'][0]['sanitized_headers'] = {name.upper(): 'value-1'}
                self.assertTrue(self.invalid(event))
        kept = diagnostic_reference.sanitize_headers({'Content-Type': 'application/json', 'X-Correlation-ID': 't-1'})
        self.assertEqual(kept, {'content-type': 'application/json', 'x-correlation-id': 't-1'})

    def test_schema_and_reference_share_one_allowlist(self):
        names = self.schema['$defs']['sanitized_header_name']['enum']
        self.assertEqual(sorted(names), sorted(diagnostic_reference.ALLOWED_HEADERS))

    def test_credential_shaped_values_under_an_allowed_name(self):
        jwt_like = 'eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ4In0.c2lnbmF0dXJl'
        for value in ['Bearer abcdef123456', 'bearer abcdef123456', 'Basic dXNlcjpwYXNz', jwt_like, 'x' * 300,
                      'ok\r\nAuthorization: Bearer abc']:
            with self.subTest(value=value[:24]):
                event = copy.deepcopy(self.ok200)
                event['stages'][0]['sanitized_headers'] = {'X-Request-Id': value}
                self.assertTrue(self.invalid(event))

    def test_unobserved_stage_carrying_observations(self):
        for status in ['NOT_SENT', 'NOT_OBSERVED']:
            for field, value in [('http_status', 200), ('body_sha256', 'a' * 64), ('body_sample_sanitized', '{}'),
                                 ('sanitized_headers', {'Content-Type': 'application/json'}), ('grpc_status', 0),
                                 ('provider_request_id_sanitized', 'REQ-1')]:
                with self.subTest(status=status, field=field):
                    event = copy.deepcopy(self.ok504)
                    event['stages'][2].update({'status': status, field: value})
                    self.assertTrue(self.invalid(event))


if __name__ == '__main__':
    unittest.main()
