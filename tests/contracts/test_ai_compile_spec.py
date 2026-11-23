"""The AI compile spec is an input document.

The example is a legal AI spec, and its intent fields form a legal AI
RouteIntent. This test checks that contract. It does not run the compiler.
"""
import json
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

R = Path(__file__).resolve().parents[2]
SCHEMA = json.loads((R / "contracts/gateway/ai-compile-spec.schema.json").read_text(encoding="utf-8"))
EXAMPLE = json.loads((R / "contracts/gateway/ai-compile-spec.example.json").read_text(encoding="utf-8"))
INTENT = json.loads((R / "contracts/gateway/route-intent.schema.json").read_text(encoding="utf-8"))
FORBIDDEN = {
    "provider_id", "operation_id", "credential_binding_ref", "credential_scheme",
    "api_key", "accounts_by_tenant", "upstream_hostname",
}


class AICompileSpec(unittest.TestCase):
    def test_example_matches_the_schema(self):
        errors = list(Draft202012Validator(SCHEMA, format_checker=FormatChecker()).iter_errors(EXAMPLE))
        self.assertEqual(errors, [])

    def test_example_carries_no_key_or_egress_credential(self):
        self.assertFalse(FORBIDDEN & set(EXAMPLE))
        self.assertFalse(FORBIDDEN & set(EXAMPLE["pool"]))
        self.assertFalse(FORBIDDEN & set(EXAMPLE["provider"]))
        self.assertNotIn("api_key", EXAMPLE["provider"])
        self.assertTrue(EXAMPLE["provider"]["api_key_file"].startswith("tls/"))

    def test_intent_is_an_ai_route_intent(self):
        pool = EXAMPLE["pool"]
        intent_fields = EXAMPLE["intent"]
        intent = {
            "intent_id": intent_fields["intent_id"],
            "gateway_pool": pool["name"],
            "traffic_class": "AI",
            "environment": pool["environment"],
            "logical_path": pool["path_prefix"],
            "ai_protocol": intent_fields["ai_protocol"],
            "ai_target_ref": intent_fields["ai_target_ref"],
            "authz_profile": intent_fields["authz_profile"],
            "approval_ref": intent_fields["approval_ref"],
            "expected_generation": intent_fields["expected_generation"],
            "policy_bundle_ref": intent_fields["policy_bundle_ref"],
        }
        validator = Draft202012Validator(INTENT, format_checker=FormatChecker())
        self.assertEqual(list(validator.iter_errors(intent)), [])
