"""deploy/providers/wanbexpress: the configuration and the register example say the same thing.

OFFLINE; nothing here starts a gateway. The suite in tests/integration/wanbexpress runs the configuration.
"""
import ast, json, re, unittest
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


class PoolValues(unittest.TestCase):
    """The file describes the single-host pool (deploy/compose); the suites put the rig's values back with exact replacements."""
    RAW = text('deploy/providers/wanbexpress/agentgateway.yaml')

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

    def test_route_timeouts_are_shorter_than_what_front_waits(self):
        front = text('deploy/compose/front.nginx.conf')
        self.assertIn('proxy_read_timeout 10s;', front)
        for route in ROUTES:
            with self.subTest(route=route['name']):
                self.assertLess(int(route['policies']['timeout']['requestTimeout'].rstrip('s')), 10)

    def test_the_replacements_of_the_rig_suite_still_fit(self):
        tree = ast.parse(text('tests/integration/wanbexpress/run.py'))
        values = next(n.value for n in tree.body if isinstance(n, ast.Assign) and getattr(n.targets[0], 'id', None) == 'RIG_VALUES')
        self.assertGreaterEqual(len(values.elts), 10)
        for element in values.elts:
            old, times = ast.literal_eval(element.elts[0]), ast.literal_eval(element.elts[2])
            with self.subTest(replaced=old.strip()):
                self.assertEqual(self.RAW.count(old), times)


class GatewayAuthzOverlay(unittest.TestCase):
    """deploy/compose/gateway-authz.yml: a service of its own, hardened like place and confirm, every variable required."""
    OVERLAY = yaml.safe_load(text('deploy/compose/gateway-authz.yml'))
    SERVICE = OVERLAY['services']['gateway-authz']

    def test_only_one_service_is_added_and_it_is_not_in_the_namespace_of_netns(self):
        self.assertEqual(set(self.OVERLAY), {'services'})
        self.assertEqual(set(self.OVERLAY['services']), {'gateway-authz'})
        self.assertNotIn('network_mode', self.SERVICE)
        self.assertNotIn('depends_on', self.SERVICE)

    def test_hardened(self):
        self.assertEqual((self.SERVICE['read_only'], self.SERVICE['cap_drop'], self.SERVICE['security_opt'], self.SERVICE['restart']),
                         (True, ['ALL'], ['no-new-privileges:true'], 'no'))
        self.assertEqual(self.SERVICE['user'], '${GATEWAY_AUTHZ_USER:?see gateway-authz.env.example}')
        self.assertIn('@sha256:', self.SERVICE['image'])
        self.assertTrue(all(v.endswith(':ro') for v in self.SERVICE['volumes']))

    def test_the_pdp_is_not_loopback_so_all_four_gatekeeper_tls_arguments_are_given(self):
        given = {a.split('=', 1)[0] for a in self.SERVICE['command']}
        self.assertTrue({'--gatekeeper-tls-cert', '--gatekeeper-tls-key', '--gatekeeper-tls-ca', '--gatekeeper-name', '--gatekeeper-url'} <= given)

    def test_every_variable_is_required_and_listed_in_the_example(self):
        raw = text('deploy/compose/gateway-authz.yml')
        found = re.findall(r'\$\{([A-Z0-9_]+)(:?[-?]?)([^}]*)\}', raw)
        self.assertEqual(len(found), raw.count('${'))
        self.assertEqual({kind for name, kind, rest in found if name != 'FRONT_IMAGE'}, {':?'})
        listed = re.findall(r'^([A-Z][A-Z0-9_]*)=$', text('deploy/compose/gateway-authz.env.example'), re.M)
        self.assertEqual(sorted(set(listed)), sorted({n for n, _, _ in found if n != 'FRONT_IMAGE'}))
        self.assertEqual(len(listed), len(set(listed)))

    def test_it_is_a_plain_overlay_of_compose_yml(self):
        base = yaml.safe_load(text('deploy/compose/compose.yml'))
        self.assertNotIn('gateway-authz', base['services'])
        self.assertEqual(self.SERVICE['image'], base['x-gateway-control']['image'])

class EvidenceFiles(unittest.TestCase):
    """tests/integration/wanbexpress/evidence/: what `run.py --evidence` and `pool.py --evidence` leave. With no file there, every test passes."""
    FILES = sorted((R / 'tests/integration/wanbexpress/evidence').glob('*.json'))
    NAMES = {'rig-sandbox.json', 'rig-standin.json', 'pool-sandbox.json', 'pool-standin.json'}
    FIELDS = ('kind', 'upstream_kind', 'operator_and_approver', 'agentgateway', 'gatekeeper_commit', 'repository', 'registry_sha256',
              'gateway_configuration_sha256', 'environment', 'started_at_utc', 'finished_at_utc', 'clock', 'dataset', 'upstream',
              'gateway_proxy_variables', 'cases', 'summary')
    SHAPES = (re.compile(r'Hc-OweDeveloper [^;\s"\']+;'), re.compile(r'Bearer [A-Za-z0-9._~+/=-]{16,}'))

    def test_each_file_is_one_of_the_four_and_has_every_field(self):
        for path in self.FILES:
            with self.subTest(file=path.name):
                self.assertIn(path.name, self.NAMES)
                document = json.loads(path.read_text(encoding='utf-8'))
                self.assertEqual([f for f in self.FIELDS if f not in document], [])
                self.assertTrue({'version', 'image'} <= set(document['agentgateway']))
                self.assertIn('@sha256:', document['agentgateway']['image'])
                self.assertTrue({'commit', 'uncommitted_files'} <= set(document['repository']))
                self.assertTrue({'reference_prefix', 'parcels_created_and_deleted', 'parcels_left_undeleted'} <= set(document['dataset']))
                self.assertRegex(document['registry_sha256'], r'^[0-9a-f]{64}$')
                self.assertRegex(document['gateway_configuration_sha256'], r'^[0-9a-f]{64}$')
                self.assertTrue(document['cases'])
                for case in document['cases']:
                    self.assertIn(case['result'], ('pass', 'fail', 'skipped'))
                    for check in case['checks']:
                        self.assertIn(check['result'], ('pass', 'fail', 'skipped'))
                        self.assertEqual('reason' in check, check['result'] == 'skipped')
                self.assertIn('Not recorded', document['operator_and_approver'])

    def test_no_token_authorization_value_or_secret_shape(self):
        for path in self.FILES:
            with self.subTest(file=path.name):
                body = path.read_text(encoding='utf-8')
                for shape in self.SHAPES:
                    self.assertIsNone(shape.search(body), shape.pattern)


if __name__ == '__main__':
    unittest.main()
