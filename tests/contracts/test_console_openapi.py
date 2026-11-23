"""The console OpenAPI stays a closed loopback contract."""

import unittest
from pathlib import Path

import yaml

DOC = yaml.safe_load(
    (Path(__file__).resolve().parents[2] / "contracts/console/openapi.yaml").read_text(encoding="utf-8")
)


class ConsoleOpenAPI(unittest.TestCase):
    def test_only_the_three_paths(self):
        self.assertEqual(
            set(DOC["paths"]),
            {"/v1/audit", "/v1/revocations", "/v1/operation-bans"},
        )

    def test_request_bodies_reject_unknown_fields(self):
        schemas = DOC["components"]["schemas"]
        for name in ("RevocationChange", "OperationBanChange", "Outcome"):
            self.assertIs(schemas[name]["additionalProperties"], False)
        row = schemas["Outcome"]["properties"]["revoked_accounts"]["items"]
        self.assertIs(row["additionalProperties"], False)

    def test_publish_and_rollback_are_absent(self):
        for path in DOC["paths"]:
            self.assertNotIn("rollback", path)
            self.assertNotIn("publish", path)
            self.assertNotIn("/v1/routes", path)


if __name__ == "__main__":
    unittest.main()
