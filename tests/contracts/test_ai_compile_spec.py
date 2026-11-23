"""The AI compile spec is an input document.

Each example is a legal AI spec, and its intent fields form a legal AI
RouteIntent. A document that mixes branches fails the schema. This test
checks that contract. It does not run the compiler.
"""
import json
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

R = Path(__file__).resolve().parents[2]
SCHEMA = json.loads((R / "contracts/gateway/ai-compile-spec.schema.json").read_text(encoding="utf-8"))
EXAMPLES = {
    "LLM": json.loads((R / "contracts/gateway/ai-compile-spec.example.json").read_text(encoding="utf-8")),
    "MCP": json.loads((R / "contracts/gateway/ai-compile-spec.mcp.example.json").read_text(encoding="utf-8")),
    "A2A": json.loads((R / "contracts/gateway/ai-compile-spec.a2a.example.json").read_text(encoding="utf-8")),
}
INTENT = json.loads((R / "contracts/gateway/route-intent.schema.json").read_text(encoding="utf-8"))
FORBIDDEN = {
    "provider_id", "operation_id", "credential_binding_ref", "credential_scheme",
    "api_key", "accounts_by_tenant", "upstream_hostname",
}
VALIDATOR = Draft202012Validator(SCHEMA, format_checker=FormatChecker())


def intent_of(example):
    pool = example["pool"]
    fields = example["intent"]
    return {
        "intent_id": fields["intent_id"],
        "gateway_pool": pool["name"],
        "traffic_class": "AI",
        "environment": pool["environment"],
        "logical_path": pool["path_prefix"],
        "ai_protocol": fields["ai_protocol"],
        "ai_target_ref": fields["ai_target_ref"],
        "authz_profile": fields["authz_profile"],
        "approval_ref": fields["approval_ref"],
        "expected_generation": fields["expected_generation"],
        "policy_bundle_ref": fields["policy_bundle_ref"],
    }


class AICompileSpec(unittest.TestCase):
    def test_each_example_matches_the_schema(self):
        for protocol, example in EXAMPLES.items():
            errors = list(VALIDATOR.iter_errors(example))
            self.assertEqual(errors, [], protocol)

    def test_each_example_is_an_ai_route_intent(self):
        validator = Draft202012Validator(INTENT, format_checker=FormatChecker())
        for protocol, example in EXAMPLES.items():
            self.assertEqual(example["intent"]["ai_protocol"], protocol)
            self.assertEqual(list(validator.iter_errors(intent_of(example))), [], protocol)

    def test_llm_example_carries_no_key_or_egress_credential(self):
        example = EXAMPLES["LLM"]
        self.assertFalse(FORBIDDEN & set(example))
        self.assertFalse(FORBIDDEN & set(example["pool"]))
        self.assertFalse(FORBIDDEN & set(example["provider"]))
        self.assertNotIn("api_key", example["provider"])
        self.assertTrue(example["provider"]["api_key_file"].startswith("tls/"))

    def test_mcp_and_a2a_examples_carry_no_credential(self):
        for protocol in ("MCP", "A2A"):
            example = EXAMPLES[protocol]
            self.assertFalse(FORBIDDEN & set(example))
            self.assertNotIn("provider", example)
            self.assertNotIn("models", example)
            self.assertNotIn("api_key", json.dumps(example))

    def test_mixing_branches_fails_the_schema(self):
        llm = json.loads(json.dumps(EXAMPLES["LLM"]))
        llm["mcp"] = json.loads(json.dumps(EXAMPLES["MCP"]["mcp"]))
        self.assertNotEqual(list(VALIDATOR.iter_errors(llm)), [])

        mcp = json.loads(json.dumps(EXAMPLES["MCP"]))
        mcp["provider"] = json.loads(json.dumps(EXAMPLES["LLM"]["provider"]))
        self.assertNotEqual(list(VALIDATOR.iter_errors(mcp)), [])

        mcp["a2a"] = json.loads(json.dumps(EXAMPLES["A2A"]["a2a"]))
        self.assertNotEqual(list(VALIDATOR.iter_errors(mcp)), [])

        a2a = json.loads(json.dumps(EXAMPLES["A2A"]))
        a2a["models"] = json.loads(json.dumps(EXAMPLES["LLM"]["models"]))
        self.assertNotEqual(list(VALIDATOR.iter_errors(a2a)), [])

        a2a_with_mcp = json.loads(json.dumps(EXAMPLES["A2A"]))
        a2a_with_mcp["mcp"] = json.loads(json.dumps(EXAMPLES["MCP"]["mcp"]))
        self.assertNotEqual(list(VALIDATOR.iter_errors(a2a_with_mcp)), [])
