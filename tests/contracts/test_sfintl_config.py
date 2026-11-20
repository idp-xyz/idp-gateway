"""deploy/providers/sfintl: the configuration, the register example and the Go code they depend on say the same thing.

OFFLINE; nothing here starts a gateway or the signer. There is no suite that runs the configuration yet (tests/integration/sfintl).
"""
import json, re, unittest
from pathlib import Path
import yaml

R = Path(__file__).resolve().parents[2]
text = lambda path: (R / path).read_text(encoding='utf-8')
CONFIG = yaml.safe_load(text('deploy/providers/sfintl/agentgateway.yaml'))
MODEL = yaml.safe_load(text('deploy/providers/wanbexpress/agentgateway.yaml'))
POLICY = json.loads(text('deploy/providers/sfintl/policy.example.json'))
ROUTES = [r for r in CONFIG['routes'] if r['name'] != 'read-back']
constant = lambda expression: re.fullmatch(r"'\"([^\"]*)\"'", f"'{expression}'")[1]
seconds = lambda value: int(re.fullmatch(r'(\d+)s', value)[1])
keys = lambda node: [k for key, value in node.items() for k in (key, *keys(value))] if isinstance(node, dict) else \
    [k for value in node for k in keys(value)] if isinstance(node, list) else []
# The signer's table: (method, path) -> (id, msgType). A regular expression over the Go source; nothing is compiled.
TABLE = {(m, p): (i, t) for i, m, p, t in re.findall(
    r'\{ID: "([^"]+)", Method: "([^"]+)", Path: "([^"]+)", MsgType: "([^"]+)"\}', text('internal/providersigner/domain/operations.go'))}
BACKEND_TLS = {'cert': 'tls/gateway.crt', 'key': 'tls/gateway.key', 'root': 'tls/ca.crt', 'hostname': 'provider-signer.idp.test'}


class SfIntlConfiguration(unittest.TestCase):
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
                self.assertEqual((row['provider_id'], row['environment']), ('sfintl', 'TEST'))
                self.assertEqual(len(route['matches']), 1)
                self.assertEqual(route['matches'][0]['method'], row['method'])
                self.assertEqual(route['matches'][0]['path'], {'pathPrefix': row['path_prefix']})
                self.assertEqual(f"{row['upstream_hostname']}:{row['port']}", route['backends'][0]['host'])

    def test_no_two_routes_take_the_same_method_and_prefix_and_no_prefix_starts_another(self):
        seen = [(r['matches'][0]['method'], r['matches'][0]['path']['pathPrefix']) for r in ROUTES]
        self.assertEqual(len(seen), len(set(seen)))
        for method, prefix in seen:
            for other_method, other in seen:
                if (method, prefix) != (other_method, other):
                    self.assertFalse(other.startswith(prefix), f'{prefix} is a string prefix of {other}')

    def test_each_route_allows_its_own_path_only_is_post_has_no_retry_and_a_timeout_between_the_signers_and_fronts(self):
        match = re.search(r'"carrier-timeout",\s*(\d+)\*time\.Second', text('cmd/provider-signer/main.go'))
        self.assertIsNotNone(match, 'the default --carrier-timeout is not in cmd/provider-signer/main.go in the form 8*time.Second')
        signer = int(match[1])
        front = re.search(r'proxy_read_timeout (\d+)s;', text('deploy/compose/front.nginx.conf'))
        self.assertIsNotNone(front, 'front\'s proxy_read_timeout is not in seconds')
        for route in ROUTES:
            prefix = route['matches'][0]['path']['pathPrefix']
            with self.subTest(route=route['name']):
                self.assertEqual(route['matches'][0]['method'], 'POST')
                self.assertEqual(route['policies']['authorization']['rules'], [{'allow': f'request.path == "{prefix}"'}])
                self.assertEqual(route['policies']['timeout'], {'requestTimeout': '9s'})
                self.assertLess(seconds(route['policies']['timeout']['requestTimeout']), int(front[1]), 'front would answer first')
                self.assertGreater(seconds(route['policies']['timeout']['requestTimeout']), signer, 'the route would give up before the signer\'s own 504')
                self.assertNotIn('retry', keys(route), 'a create that times out has an unknown result; nothing here repeats a request')

    def test_each_rewritten_path_is_a_row_of_the_signers_table_and_the_table_has_no_row_without_a_route(self):
        self.assertEqual(len(TABLE), 3, 'the signer\'s table was not read, or it changed: this configuration has three routes')
        for route in ROUTES:
            rewritten = route['policies']['urlRewrite']['path']['prefix']
            sent = route['policies']['extAuthz']['protocol']['http']['addRequestHeaders']
            with self.subTest(route=route['name']):
                self.assertIn(('POST', rewritten), TABLE)
                self.assertEqual(constant(sent['x-idp-operation-id']), TABLE['POST', rewritten][0])
                self.assertEqual(route['matches'][0]['path']['pathPrefix'], '/providers' + rewritten)
        self.assertEqual({('POST', r['policies']['urlRewrite']['path']['prefix']) for r in ROUTES}, set(TABLE))
        self.assertEqual(len(ROUTES), len(TABLE))

    def test_backend_rule_names_the_scheme_that_gateway_authz_releases_and_the_signer_parses(self):
        released = re.search(r'^\s*Scheme = "([^"]+)"$', text('internal/egressauthz/adapters/sfopenapi/client.go'), re.M)
        parsed = re.search(r'^const CredentialScheme = "([^"]+)"$', text('internal/providersigner/domain/credential.go'), re.M)
        self.assertEqual((released[1], parsed[1]), ('Sf-OpenApi', 'Sf-OpenApi '))
        self.assertEqual(parsed[1], released[1] + ' ')
        for route in ROUTES:
            with self.subTest(route=route['name']):
                self.assertEqual(route['backends'][0]['policies']['authorization']['rules'],
                                 [{'allow': 'request.headers["authorization"].startsWith("Sf-OpenApi ")'}])

    def test_headers_are_filtered_as_the_reviewed_configuration_does_and_nothing_is_written(self):
        reviewed = text('tests/acceptance/blackbox/agentgateway.poc.yaml')
        expression = re.search(r"replace: '(request\.headers\.filterKeys[^']*)'", reviewed)[1]
        removed = MODEL['routes'][0]['backends'][0]['policies']['requestHeaderModifier']['remove']
        self.assertIn('x-provider-account', removed)
        for route in ROUTES:
            policies = route['backends'][0]['policies']
            with self.subTest(route=route['name']):
                self.assertEqual(policies['transformations'], {'request': {'replace': expression}})
                self.assertEqual(policies['requestHeaderModifier'], {'remove': removed}, 'the model\'s list and no set: no Accept, no Content-Type')
                self.assertEqual(route['policies']['responseHeaderModifier']['remove'], ['location', 'set-cookie', 'x-idp-decision-id'])

    def test_the_only_upstream_is_the_signer_over_mutual_tls_and_the_host_is_its_name(self):
        for route in ROUTES:
            with self.subTest(route=route['name']):
                self.assertEqual([b['host'] for b in route['backends']], ['provider-signer:9444'])
                self.assertEqual(route['backends'][0]['policies']['backendTLS'], BACKEND_TLS)
                self.assertEqual(route['policies']['urlRewrite']['authority'], {'full': 'provider-signer.idp.test'})

    def test_the_access_log_reads_the_two_numbers_the_way_the_model_does(self):
        added, model = CONFIG['frontendPolicies']['accessLog']['add'], MODEL['frontendPolicies']['accessLog']['add']
        self.assertEqual(set(added), set(model))
        for name in ('authz_decision_id', 'tenant_ref'):
            self.assertEqual(added[name], model[name])
        number = lambda path: f'{path}.matches("^[A-Za-z0-9._-]{{1,64}}$") ? {path} : "(malformed)"'
        self.assertEqual(added['provider_reference_id'], number('json(request.body).customerOrderNo'))
        self.assertEqual(added['provider_request_id'], number('json(response.body).apiResultData.data.sfWaybillNo'))

    def test_what_must_be_the_same_as_in_the_wanbexpress_file_is(self):
        for key in ('config', 'gateways'):
            self.assertEqual(CONFIG[key], MODEL[key], key)
        self.assertEqual(CONFIG['frontendPolicies']['networkAuthorization'], MODEL['frontendPolicies']['networkAuthorization'])
        read_back = lambda config: [r for r in config['routes'] if r['name'] == 'read-back']
        self.assertEqual(len(read_back(CONFIG)), 1)
        self.assertEqual(read_back(CONFIG), read_back(MODEL))

    def test_no_secret_and_no_environment_variable_in_the_configuration(self):
        raw = text('deploy/providers/sfintl/agentgateway.yaml')
        self.assertNotRegex(raw, r'\$\{|\$[A-Z_]+')
        self.assertNotIn('session', CONFIG.get('config', {}), 'the session key comes from SESSION_KEY')
        self.assertEqual(CONFIG['config']['storage'], {'mode': 'readOnly'})
        self.assertEqual(CONFIG['gateways']['egress-test']['bindAddress'], '127.0.0.1')


class PoolValues(unittest.TestCase):
    """The file describes the single-host pool (deploy/compose)."""
    RAW = text('deploy/providers/sfintl/agentgateway.yaml')

    def test_ports_and_paths_are_the_pools(self):
        self.assertEqual(CONFIG['gateways']['egress-test']['port'], 8081, 'front hands the callers\' requests to 127.0.0.1:8081')
        self.assertEqual(CONFIG['gateways']['read-back']['port'], 8443)
        self.assertEqual({CONFIG['config'][k] for k in ('adminAddr', 'statsAddr', 'readinessAddr')},
                         {'127.0.0.1:15000', '127.0.0.1:15020', '127.0.0.1:15021'})
        self.assertEqual(CONFIG['gateways']['egress-test']['jwtAuth']['jwks'], {'file': 'tls/jwks.json'})
        self.assertNotIn('.run/', self.RAW)
        for route in ROUTES:
            ext = route['policies']['extAuthz']
            with self.subTest(route=route['name']):
                self.assertEqual(ext['host'], 'gateway-authz:9443', 'found by name: the pool\'s egress rules pin it')
                self.assertEqual(ext['policies']['backendTLS'], {'cert': 'tls/gateway.crt', 'key': 'tls/gateway.key', 'root': 'tls/ca.crt', 'hostname': 'gatekeeper.idp.test'})
                self.assertEqual(ext['failureMode'], {'denyWithStatus': 503})
                self.assertEqual(ext['includeRequestHeaders'], ['x-provider-account'])
                self.assertEqual(ext['policies']['http'], {'requestTimeout': '1s'})
                self.assertEqual(ext['protocol']['http']['includeResponseHeaders'], ['authorization'])


if __name__ == '__main__':
    unittest.main()
