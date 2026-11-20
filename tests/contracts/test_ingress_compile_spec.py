"""The ingress compile spec is an input document.

The example is a legal ingress spec, and each route plus the pool and backend
is a legal INGRESS RouteIntent. This test checks that contract. It does not
run the compiler.
"""
import json
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

R = Path(__file__).resolve().parents[2]
SCHEMA = json.loads((R / "contracts/gateway/ingress-compile-spec.schema.json").read_text(encoding="utf-8"))
EXAMPLE = json.loads((R / "contracts/gateway/ingress-compile-spec.example.json").read_text(encoding="utf-8"))
INTENT = json.loads((R / "contracts/gateway/route-intent.schema.json").read_text(encoding="utf-8"))
FORBIDDEN = {
    "provider_id", "operation_id", "credential_binding_ref", "credential_scheme",
    "provider_account_strategy", "upstream_hostname", "accounts_by_tenant",
}


class IngressCompileSpec(unittest.TestCase):
    def test_example_matches_the_schema(self):
        errors = list(Draft202012Validator(SCHEMA, format_checker=FormatChecker()).iter_errors(EXAMPLE))
        self.assertEqual(errors, [])

    def test_example_carries_no_egress_credential_fields(self):
        self.assertFalse(FORBIDDEN & set(EXAMPLE))
        self.assertFalse(FORBIDDEN & set(EXAMPLE["pool"]))
        self.assertFalse(FORBIDDEN & set(EXAMPLE["backend"]))
        for route in EXAMPLE["routes"]:
            self.assertFalse(FORBIDDEN & set(route))

    def test_each_route_is_an_ingress_intent(self):
        pool = EXAMPLE["pool"]
        backend = EXAMPLE["backend"]
        validator = Draft202012Validator(INTENT, format_checker=FormatChecker())
        for route in EXAMPLE["routes"]:
            intent = {
                "intent_id": route["intent_id"],
                "gateway_pool": pool["name"],
                "traffic_class": "INGRESS",
                "environment": pool["environment"],
                "logical_path": route["logical_path"],
                "allowed_methods": route["allowed_methods"],
                "public_hostname": pool["public_hostname"],
                "backend_service_ref": backend["backend_service_ref"],
                "api_asset_ref": route["api_asset_ref"],
                "authz_profile": route["authz_profile"],
                "approval_ref": route["approval_ref"],
                "expected_generation": route["expected_generation"],
                "transport": route["transport"],
                "policy_bundle_ref": route["policy_bundle_ref"],
            }
            self.assertEqual(list(validator.iter_errors(intent)), [])
