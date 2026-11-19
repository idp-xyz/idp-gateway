"""deploy/providers/wanbexpress: the configuration and the register example say the same thing.

OFFLINE; nothing here starts a gateway. The suite in tests/integration/wanbexpress runs the configuration.
"""
import json, re, unittest
from pathlib import Path
import yaml

R = Path(__file__).resolve().parents[2]
text = lambda path: (R / path).read_text(encoding='utf-8')
CONFIG = yaml.safe_load(text('deploy/providers/wanbexpress/agentgateway.yaml'))
POLICY = json.loads(text('deploy/providers/wanbexpress/policy.example.json'))
ROUTES = [r for r in CONFIG['routes'] if r['name'] != 'read-back']
constant = lambda expression: re.fullmatch(r"'\"([^\"]*)\"'", f"'{expression}'")[1]


class WanbExpressConfiguration(unittest.TestCase):
    def test_every_route_is_registered_and_every_registration_has_a_route(self):
        rows = {row['route_id']: row for row in POLICY['registered_operations']}
        self.assertEqual(len(rows), len(POLICY['registered_operations']), 'a route id registered twice')
        self.assertEqual({r['name'] for r in ROUTES}, set(rows))
        for route in ROUTES:
            sent = route['policies']['extAuthz']['protocol']['http']['addRequestHeaders']
            row = rows[route['name']]
            with self.subTest(route=route['name']):
                self.assertEqual(constant(sent['x-idp-route-id']), row['route_id'])
                self.assertEqual(constant(sent['x-idp-provider-id']), row['provider_id'])
                self.assertEqual(constant(sent['x-idp-operation-id']), row['operation_id'])
                self.assertEqual(constant(sent['x-idp-environment']), row['environment'])
                self.assertEqual(len(route['matches']), 1)
                self.assertEqual(route['matches'][0]['method'], row['method'])
                self.assertEqual(route['matches'][0]['path'], {'pathPrefix': row['path_prefix']})

    def test_no_two_routes_take_the_same_method_and_prefix(self):
        seen = [(r['matches'][0]['method'], r['matches'][0]['path']['pathPrefix']) for r in ROUTES]
        self.assertEqual(len(seen), len(set(seen)))

    def test_backend_rule_names_the_carrier_scheme_that_gateway_authz_releases(self):
        scheme = re.search(r'^const developerScheme = "([^" ]+)"$', text('internal/egressauthz/adapters/filestore/developer_tokens.go'), re.M)
        self.assertEqual(scheme[1], 'Hc-OweDeveloper')
        for route in ROUTES:
            with self.subTest(route=route['name']):
                self.assertEqual(route['backends'][0]['policies']['authorization']['rules'],
                                 [{'allow': 'request.headers["authorization"].startsWith("Hc-OweDeveloper ")'}])

    def test_every_route_writes_accept_and_filters_headers_as_the_reviewed_configuration_does(self):
        reviewed = text('tests/acceptance/blackbox/agentgateway.poc.yaml')
        expression = re.search(r"replace: '(request\.headers\.filterKeys[^']*)'", reviewed)[1]
        for route in ROUTES:
            policies = route['backends'][0]['policies']
            with self.subTest(route=route['name']):
                self.assertEqual(policies['requestHeaderModifier']['set'], {'accept': 'application/json'})
                self.assertEqual(policies['transformations'], {'request': {'replace': expression}})
                self.assertIn('accept', expression, 'the allow list keeps Accept so that the value written after it replaces the caller\'s')
                self.assertEqual(route['policies']['responseHeaderModifier']['remove'], ['location', 'set-cookie', 'x-idp-decision-id'])

    def test_the_only_upstream_is_the_sandbox_on_port_80_and_the_host_is_its_name(self):
        for route in ROUTES:
            with self.subTest(route=route['name']):
                self.assertEqual([b['host'] for b in route['backends']], ['api-sbx.wanbexpress.com:80'])
                self.assertEqual(route['policies']['urlRewrite']['authority'], {'full': 'api-sbx.wanbexpress.com'})

    def test_no_secret_and_no_environment_variable_in_the_configuration(self):
        raw = text('deploy/providers/wanbexpress/agentgateway.yaml')
        self.assertNotRegex(raw, r'\$\{|\$[A-Z_]+')
        self.assertNotIn('session', CONFIG.get('config', {}), 'the session key comes from SESSION_KEY')
        self.assertEqual(CONFIG['config']['storage'], {'mode': 'readOnly'})
        self.assertEqual(CONFIG['gateways']['egress-test']['bindAddress'], '127.0.0.1')


if __name__ == '__main__':
    unittest.main()
