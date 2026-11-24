"""deploy/compose/coordinators.yml: sf-token-coordinator, authz-state, and the arguments added to gateway-authz.

OFFLINE. Compose replaces a command list, so the overlay repeats provider-signer.yml's gateway-authz command and adds its
own arguments; the test locks that the added ones are exactly these, and nothing of the repeated list is dropped. The two
coordinators are locked down as gateway-authz is, and gateway-authz waits for both before it starts.
"""
import re, unittest
from pathlib import Path
import yaml

R = Path(__file__).resolve().parents[2]
text = lambda path: (R / path).read_text(encoding='utf-8')
VARIABLE = r'\$\{([A-Z0-9_]+)(:?[-?]?)([^}]*)\}'


class CoordinatorsOverlay(unittest.TestCase):
    OVERLAY = yaml.safe_load(text('deploy/compose/coordinators.yml'))
    BASE_AUTHZ = yaml.safe_load(text('deploy/compose/gateway-authz.yml'))['services']['gateway-authz']
    SIGNER_AUTHZ = yaml.safe_load(text('deploy/compose/provider-signer.yml'))['services']['gateway-authz']
    COORDINATORS = {'sf-token-coordinator': ('9445', '--lease-file=/coordinator/state/leases.json'),
                    'authz-state': ('9446', '--state-file=/coordinator/state/state.json')}
    ADDED = ['--revocations=/authz/mirror/revocations.json',
             '--revoker-identity=${GATEWAY_AUTHZ_REVOKER_IDENTITY:?see coordinators.env.example}',
             '--rate-limits=/authz/rate-limits.json',
             '--sf-openapi-lease-url=https://sf-token-coordinator:9445',
             '--sf-openapi-lease-cert=/authz/pdp-client.crt',
             '--sf-openapi-lease-key=/authz/pdp-client.key',
             '--sf-openapi-lease-ca=/authz/coordinators-ca.crt',
             '--sf-openapi-lease-name=${SF_TOKEN_COORDINATOR_NAME:?see coordinators.env.example}',
             '--authz-state-url=https://authz-state:9446',
             '--authz-state-cert=/authz/pdp-client.crt',
             '--authz-state-key=/authz/pdp-client.key',
             '--authz-state-ca=/authz/coordinators-ca.crt',
             '--authz-state-name=${AUTHZ_STATE_NAME:?see coordinators.env.example}']

    def test_the_services(self):
        self.assertEqual(set(self.OVERLAY), {'services'})
        self.assertEqual(set(self.OVERLAY['services']), {'sf-token-coordinator', 'authz-state', 'gateway-authz'})

    def test_each_coordinator_is_hardened_like_gateway_authz(self):
        authz = self.BASE_AUTHZ
        for name in self.COORDINATORS:
            with self.subTest(name):
                service = self.OVERLAY['services'][name]
                self.assertEqual((service['read_only'], service['cap_drop'], service['security_opt'], service['restart']),
                                 (authz['read_only'], authz['cap_drop'], authz['security_opt'], authz['restart']))
                self.assertEqual((service['read_only'], service['cap_drop'], service['security_opt'], service['restart']),
                                 (True, ['ALL'], ['no-new-privileges:true'], 'no'))
                self.assertEqual(service['image'], authz['image'])
                self.assertIn('@sha256:', service['image'])
                self.assertEqual(service['entrypoint'], [f'/usr/local/bin/{name}'])
                variable = name.upper().replace('-', '_')
                self.assertEqual(service['user'], f'${{{variable}_USER:?see coordinators.env.example}}')
                self.assertEqual(service['stop_grace_period'], authz['stop_grace_period'])
                self.assertNotIn('ports', service)
                self.assertNotIn('network_mode', service)
                self.assertNotIn('networks', service)

    def test_each_coordinator_writes_only_its_state_directory(self):
        for name, (port, state) in self.COORDINATORS.items():
            with self.subTest(name):
                service = self.OVERLAY['services'][name]
                written = [v for v in service['volumes'] if not v.endswith(':ro')]
                variable = name.upper().replace('-', '_')
                self.assertEqual(written, [f'${{{variable}_STATE_DIR:?see coordinators.env.example}}:/coordinator/state'])
                self.assertIn(state, service['command'])
                self.assertIn(f'--listen=0.0.0.0:{port}', service['command'])
                self.assertIn('--authz-identity=${COORDINATORS_AUTHZ_IDENTITY:?see coordinators.env.example}', service['command'])
                self.assertIn('--client-ca=/coordinator/client-ca.crt', service['command'])

    def test_the_health_check_opens_the_coordinators_own_port(self):
        for name, (port, _) in self.COORDINATORS.items():
            with self.subTest(name):
                check = self.OVERLAY['services'][name]['healthcheck']
                self.assertEqual(check['test'], ['CMD', 'nc', '-z', '-w', '1', '127.0.0.1', port])
                self.assertIn('start_interval', check)

    def test_gateway_authz_waits_for_both_coordinators(self):
        over = self.OVERLAY['services']['gateway-authz']
        self.assertEqual(over['depends_on'], {name: {'condition': 'service_healthy'} for name in self.COORDINATORS})

    def test_gateway_authz_command_is_the_signer_overlays_list_plus_these_arguments(self):
        """The overlay repeats the whole command because compose replaces the list. Nothing else is added or dropped."""
        over = self.OVERLAY['services']['gateway-authz']
        self.assertEqual(set(over), {'entrypoint', 'command', 'volumes', 'tmpfs', 'depends_on'})
        self.assertEqual(over['command'], self.SIGNER_AUTHZ['command'] + self.ADDED)
        self.assertEqual(over['command'][:len(self.BASE_AUTHZ['command'])], self.BASE_AUTHZ['command'])
        for flag in ('--revocations', '--revoker-identity', '--rate-limits', '--sf-openapi-lease-url', '--authz-state-url'):
            self.assertNotIn(flag, ' '.join(self.SIGNER_AUTHZ['command']))
            self.assertEqual(sum(1 for arg in over['command'] if arg.startswith(flag + '=')), 1)

    def test_the_urls_name_the_services_on_their_listen_ports(self):
        command = self.OVERLAY['services']['gateway-authz']['command']
        self.assertIn(f"--sf-openapi-lease-url=https://sf-token-coordinator:{self.COORDINATORS['sf-token-coordinator'][0]}", command)
        self.assertIn(f"--authz-state-url=https://authz-state:{self.COORDINATORS['authz-state'][0]}", command)

    def test_the_revocation_file_is_in_a_tmpfs_of_its_own_with_its_mode_written_out(self):
        over = self.OVERLAY['services']['gateway-authz']
        self.assertEqual(over['tmpfs'], ['/authz/mirror:mode=1777'])
        self.assertNotIn('/authz/mirror', ' '.join(over['volumes']))
        self.assertTrue(all(v.endswith(':ro') for v in over['volumes']))

    def test_the_entrypoint_writes_an_empty_table_only_when_missing_then_execs_gateway_authz(self):
        entrypoint = self.OVERLAY['services']['gateway-authz']['entrypoint']
        self.assertEqual(entrypoint[:2], ['/bin/sh', '-ec'])
        self.assertEqual(entrypoint[3:], ['gateway-authz'])
        script = entrypoint[2]
        self.assertIn('umask 077', script)
        self.assertIn('[ -e /authz/mirror/revocations.json ] ||', script)
        self.assertTrue(script.rstrip().endswith('exec /usr/local/bin/gateway-authz "$$@"'))
        empty = re.search(r"'(\{.*\})'", script).group(1)
        self.assertEqual(yaml.safe_load(empty), {'epoch': 0, 'revoked_accounts': {}})

    def test_every_variable_is_required_except_the_image_and_the_repeated_plain_http_host(self):
        raw = text('deploy/compose/coordinators.yml')
        found = re.findall(VARIABLE, raw)
        self.assertEqual(len(found), raw.count('${'))
        self.assertEqual({name for name, kind, _ in found if kind != ':?'}, {'FRONT_IMAGE', 'GATEWAY_AUTHZ_SF_PLAIN_HTTP_HOST'})
        # The repeated command still names the other overlays' variables; they stay documented in those files' examples.
        already = {name for path in ('deploy/compose/gateway-authz.yml', 'deploy/compose/provider-signer.yml')
                   for name, _, _ in re.findall(VARIABLE, text(path))}
        listed = re.findall(r'^([A-Z][A-Z0-9_]*)=', text('deploy/compose/coordinators.env.example'), re.M)
        introduced = {name for name, _, _ in found if name != 'FRONT_IMAGE' and name not in already}
        self.assertEqual(sorted(set(listed)), sorted(introduced))
        self.assertEqual(len(listed), len(set(listed)))
