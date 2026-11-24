"""The fabric publication HTTP surface stays aligned with its OpenAPI document."""

import re
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
DOC = yaml.safe_load((ROOT / "contracts/fabric/route-publication-intent.openapi.yaml").read_text(encoding="utf-8"))
HANDLER = (ROOT / "internal/fabricpub/adapters/httpapi/handler.go").read_text(encoding="utf-8")
STATES = (ROOT / "internal/fabricpub/domain/state.go").read_text(encoding="utf-8")

CANONICAL = [
    "DRAFT", "VALIDATED", "APPROVED", "STAGED", "APPLYING", "OBSERVING", "ACTIVE",
    "REJECTED", "CANCELED", "FAILED", "PARTIAL", "UNKNOWN", "SUPERSEDED",
    "WITHDRAW_REQUESTED", "REVOKING", "REVOKED",
]
NOT_STATES = ["RECEIVED", "REVIEW", "ROLLOUT", "RECONCILED", "REVERTED", "OVERTAKEN"]


def fields(source, struct):
    body = re.search(rf"^type {struct} struct \{{$\n(.*?)^\}}$", source, re.S | re.M)
    if body is None:
        raise AssertionError(f"struct {struct} not found")
    found = re.findall(r'^\s+\w+\s+\S+\s+`json:"([a-z_]+)(,omitempty)?"`', body.group(1), re.M)
    return {name: bool(omit) for name, omit in found}


class FabricOpenAPI(unittest.TestCase):
    def test_only_the_two_paths(self):
        self.assertEqual(set(DOC["paths"]), {"/v1/route-intents", "/v1/route-intents/{intent_id}/status"})
        self.assertIn('"/v1/route-intents"', HANDLER)
        self.assertIn('"/v1/route-intents/{intent_id}/status"', HANDLER)

    def test_response_fields_match_the_document(self):
        accepted = DOC["paths"]["/v1/route-intents"]["post"]["responses"]["202"]["content"]["application/json"]["schema"]
        status = DOC["paths"]["/v1/route-intents/{intent_id}/status"]["get"]["responses"]["200"]["content"]["application/json"]["schema"]
        sent202 = fields(HANDLER, "acceptedBody")
        sent200 = fields(HANDLER, "statusBody")
        self.assertEqual(set(sent202), set(accepted["properties"]))
        self.assertEqual(set(sent202), set(accepted["required"]))
        self.assertFalse(any(sent202.values()))
        self.assertEqual(set(sent200), set(status["properties"]))
        self.assertTrue(set(status["required"]) <= set(sent200))
        self.assertFalse(any(sent200.values()), "status fields are always present")

    def test_release_state_matches_the_sixteen_words(self):
        words = re.findall(r'ReleaseState = "([A-Z_]+)"', STATES)
        self.assertEqual(words, CANONICAL)
        self.assertEqual(DOC["components"]["schemas"]["ReleaseState"]["enum"], CANONICAL)
        for banned in NOT_STATES:
            self.assertNotIn(banned, words)


if __name__ == "__main__":
    unittest.main()
