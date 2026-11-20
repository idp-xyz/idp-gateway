"""compile-spec.json describes the hand-written carrier files.

This test does not run Go. The byte-for-structure proof that compiling the spec
reproduces agentgateway.yaml and policy.example.json lives in
internal/routecompile (go test), because the contract job does not install Go.
"""
import json
import re
import unittest
from pathlib import Path

import yaml

R = Path(__file__).resolve().parents[2]
ENV = re.compile(r"\$\{|\$[A-Z_]")
SENSITIVE = ("api_key", "password", "client_secret", "secret_value", "access_token", "refresh_token", "private_key", "bearer_token")


class RouteCompilerSpecs(unittest.TestCase):
    def test_wanbexpress_spec_matches_the_hand_written_files(self):
        self.check("wanbexpress")

    def test_sfintl_spec_matches_the_hand_written_files(self):
        self.check("sfintl")

    def check(self, name):
        base = R / "deploy" / "providers" / name
        raw = (base / "compile-spec.json").read_text(encoding="utf-8")
        self.assertIsNone(ENV.search(raw), "compile spec contains an environment reference")
        lowered = raw.lower()
        for key in SENSITIVE:
            self.assertNotIn(f'"{key}"', lowered)
        spec = json.loads(raw)
        cfg = yaml.safe_load((base / "agentgateway.yaml").read_text(encoding="utf-8"))
        policy = json.loads((base / "policy.example.json").read_text(encoding="utf-8"))
        self.assertEqual(set(spec), {"pool", "provider", "access", "routes"})
        routes = [route for route in cfg["routes"] if route["name"] != "read-back"]
        self.assertEqual(len(spec["routes"]), 4)
        self.assertEqual(len(routes), 4)
        self.assertEqual([route["route_id"] for route in spec["routes"]], [route["name"] for route in routes])
        self.assertEqual([row["route_id"] for row in policy["registered_operations"]], [route["route_id"] for route in spec["routes"]])
        self.assertEqual(cfg["config"]["storage"], {"mode": "readOnly"})
        self.assertNotIn("session", cfg["config"])
        self.assertEqual(spec["pool"]["bind_address"], cfg["gateways"][spec["pool"]["name"]]["bindAddress"])
        self.assertEqual(spec["pool"]["listen_port"], cfg["gateways"][spec["pool"]["name"]]["port"])
        self.assertEqual(spec["provider"]["policy_version"], policy["version"])
        self.assertEqual(spec["provider"]["enforce_tls_upstream"], policy["enforce_tls_upstream"])
        self.assertEqual(spec["access"]["policy_notes"], policy["notes"])
        self.assertEqual(spec["provider"]["route_timeout"], "9s")
        self.assertEqual(spec["provider"]["credential_scheme"][-1], " ")
        if name == "sfintl":
            self.assertIn("sfintl-labels-print", [route["route_id"] for route in spec["routes"]])
            self.assertEqual(spec["provider"]["internal_backend_host"], "provider-signer")
            self.assertEqual(spec["provider"]["backend_tls"]["hostname"], "provider-signer.idp.test")
            self.assertNotIn("plain_http_sandbox_host", spec["provider"])
            self.assertNotIn("set_request_headers", spec["provider"])
        else:
            self.assertEqual(spec["provider"]["plain_http_sandbox_host"], "api-sbx.wanbexpress.com")
            self.assertEqual(spec["provider"]["set_request_headers"], {"accept": "application/json"})
            self.assertNotIn("backend_tls", spec["provider"])
        for route, gateway, row in zip(spec["routes"], routes, policy["registered_operations"]):
            self.assertEqual(route["method"], gateway["matches"][0]["method"])
            self.assertEqual(route["method"], row["method"])
            self.assertEqual(route["logical_path"], row["path_prefix"])
            self.assertEqual(gateway["matches"][0]["path"], {"pathPrefix": route["logical_path"]})
            self.assertEqual(route["rewrite_path_prefix"], gateway["policies"]["urlRewrite"]["path"]["prefix"])
            self.assertEqual(route["operation_id"], row["operation_id"])
            self.assertEqual(f"{spec['provider']['upstream_host']}:{spec['provider']['upstream_port']}", gateway["backends"][0]["host"])
            allow = gateway["backends"][0]["policies"]["authorization"]["rules"][0]["allow"]
            self.assertIn(spec["provider"]["credential_scheme"], allow)
            self.assertNotIn("retry", gateway["policies"])
            mode = "one_segment" if ".matches(" in gateway["policies"]["authorization"]["rules"][0]["allow"] else "exact"
            self.assertEqual(route["path_match_mode"], mode)


if __name__ == "__main__":
    unittest.main()
