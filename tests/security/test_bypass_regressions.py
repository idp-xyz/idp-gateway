"""Regression tests for bypasses found when reviewing the offline reference helpers.

Each test was written against the helper as delivered and failed there; the helper was
then changed from "reject what looks bad" to "accept only what is known good".
OFFLINE reference tests, not Gateway/Gatekeeper integration tests.

The path-bypass regressions that used to be here were about the egress policy rules. Those
rules are Go now, and so are their tests: internal/egressauthz/domain/policy_test.go.
"""
import copy, json, sys, unittest
from datetime import datetime
from pathlib import Path

R = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(R / 'scripts'))
import diagnostic_reference
from diagnostic_reference import authorize_capture

GRANT = json.loads((R / 'contracts/gateway/policies/diagnostic-capture.example.json').read_text(encoding='utf-8'))
NOW = datetime.fromisoformat('2026-11-10T08:05:00+00:00')


def approve(grant):
    return authorize_capture(grant, trusted_route='gwi-example-001', trusted_tenant='tenant-blue',
                             trusted_environment='TEST', now=NOW)


class CaptureGrantBypass(unittest.TestCase):
    def test_delivered_example_still_approved(self):
        self.assertEqual(approve(GRANT), (True, 'APPROVED_BOUND_SCOPE'))

    def test_approver_must_be_present(self):
        for label, mutate in {
            'approved_by missing': lambda g: g.pop('approved_by'),
            'approved_by empty': lambda g: g.update(approved_by=''),
            'approved_by blank': lambda g: g.update(approved_by='   '),
            'approved_by null': lambda g: g.update(approved_by=None),
            'approved_by not a string': lambda g: g.update(approved_by=['security-reviewer-b']),
            'requested_by missing': lambda g: g.pop('requested_by'),
            'requested_by empty': lambda g: g.update(requested_by=''),
            'both missing': lambda g: (g.pop('approved_by'), g.pop('requested_by')),
        }.items():
            with self.subTest(case=label):
                grant = copy.deepcopy(GRANT)
                mutate(grant)
                self.assertEqual(approve(grant), (False, 'APPROVAL_IDENTITY_MISSING'))

    def test_same_person_under_another_spelling(self):
        for approver in ['Engineer-A', 'ENGINEER-A', ' engineer-a ', 'engineer-a\t']:
            with self.subTest(approved_by=approver):
                grant = copy.deepcopy(GRANT)
                grant['approved_by'] = approver
                self.assertEqual(approve(grant), (False, 'SEGREGATION_OF_DUTIES'))

    def test_limit_must_be_an_integer_in_range(self):
        for value in ['16384', None, True, 1.5, -1, 65537, [1], {}]:
            with self.subTest(max_bytes_per_message=value):
                grant = copy.deepcopy(GRANT)
                grant['max_bytes_per_message'] = value
                self.assertEqual(approve(grant), (False, 'UNSAFE_LIMIT'))
        grant = copy.deepcopy(GRANT)
        grant.pop('max_bytes_per_message')
        self.assertEqual(approve(grant), (False, 'UNSAFE_LIMIT'))


class DiagnosticEventSemantics(unittest.TestCase):
    """What the JSON Schema cannot express about a diagnostic event."""

    def setUp(self):
        load = lambda name: json.loads((R / 'contracts/gateway' / name).read_text(encoding='utf-8'))
        self.ok200, self.ok504 = load('diagnostic-event.paired-200.example.json'), load('diagnostic-event.example.json')
        self.check = getattr(diagnostic_reference, 'event_semantic_errors', None)
        self.assertIsNotNone(self.check, 'diagnostic_reference.event_semantic_errors is not implemented')

    def test_delivered_examples_are_consistent(self):
        self.assertEqual(self.check(self.ok200), [])
        self.assertEqual(self.check(self.ok504), [])

    def test_stage_reported_twice(self):
        event = copy.deepcopy(self.ok504)
        event['stages'][1] = copy.deepcopy(event['stages'][0])
        self.assertIn('DUPLICATE_STAGE', self.check(event))

    def test_unobserved_stage_carrying_observations(self):
        for status in ['NOT_SENT', 'NOT_OBSERVED']:
            for field, value in [('http_status', 200), ('body_sha256', 'a' * 64), ('body_sample_sanitized', '{}'),
                                 ('sanitized_headers', {'Content-Type': 'application/json'}), ('grpc_status', 0)]:
                with self.subTest(status=status, field=field):
                    event = copy.deepcopy(self.ok504)
                    event['stages'][2].update({'status': status, field: value})
                    self.assertIn('UNOBSERVED_STAGE_HAS_OBSERVATIONS', self.check(event))

    def test_not_sent_outcome_with_an_upstream_exchange(self):
        event = copy.deepcopy(self.ok200)
        event['business_outcome'] = 'NOT_SENT'
        self.assertIn('NOT_SENT_OUTCOME_WITH_UPSTREAM_EXCHANGE', self.check(event))

    def test_success_outcome_without_an_upstream_response(self):
        event = copy.deepcopy(self.ok504)
        event['business_outcome'] = 'SUCCESS'
        self.assertIn('SUCCESS_OUTCOME_WITHOUT_UPSTREAM_RESPONSE', self.check(event))


if __name__ == '__main__':
    unittest.main()
