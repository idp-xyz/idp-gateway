"""deploy/compose/provider-signer.yml: the signer's namespace, its egress step, and the arguments added to gateway-authz.

OFFLINE. Compose replaces a command list, so the overlay repeats gateway-authz.yml's command and adds its own
arguments; the test locks that the added ones are exactly those two, and nothing in gateway-authz.yml is dropped.
"""
import re, unittest
from pathlib import Path
import yaml

R = Path(__file__).resolve().parents[2]
text = lambda path: (R / path).read_text(encoding='utf-8')


class ProviderSignerOverlay(unittest.TestCase):
    OVERLAY = yaml.safe_load(text('deploy/compose/provider-signer.yml'))
    BASE_AUTHZ = yaml.safe_load(text('deploy/compose/gateway-authz.yml'))['services']['gateway-authz']
    COMPOSE = yaml.safe_load(text('deploy/compose/compose.yml'))
    ADDED = ['--sf-openapi-apps=/authz/credentials/sfintl.apps.json',
             '--sf-openapi-plain-http-host=${GATEWAY_AUTHZ_SF_PLAIN_HTTP_HOST-}']

    def test_the_services_and_whose_namespace_they_use(self):
        self.assertEqual(set(self.OVERLAY), {'services'})
        self.assertEqual(set(self.OVERLAY['services']), {'provider-signer', 'signer-egress', 'signer', 'gateway-authz'})
        holder, egress, signer = (self.OVERLAY['services'][name] for name in ('provider-signer', 'signer-egress', 'signer'))
        self.assertNotIn('network_mode', holder)
        self.assertEqual(egress['network_mode'], 'service:provider-signer')
        self.assertEqual(signer['network_mode'], 'service:provider-signer')
        self.assertNotEqual(egress['network_mode'], 'service:netns')
        self.assertEqual(signer['depends_on']['signer-egress']['condition'], 'service_completed_successfully')
        self.assertEqual(egress['command'], ['once'])
        self.assertNotIn('watch', [service.get('command') for service in self.OVERLAY['services'].values()])

    def test_the_signer_is_hardened_like_gateway_authz(self):
        signer = self.OVERLAY['services']['signer']
        authz = self.BASE_AUTHZ
        self.assertEqual((signer['read_only'], signer['cap_drop'], signer['security_opt'], signer['restart']),
                         (authz['read_only'], authz['cap_drop'], authz['security_opt'], authz['restart']))
        self.assertEqual((signer['read_only'], signer['cap_drop'], signer['security_opt'], signer['restart']),
                         (True, ['ALL'], ['no-new-privileges:true'], 'no'))
        self.assertEqual(signer['user'], '${SIGNER_USER:?see provider-signer.env.example}')
        self.assertNotIn('0:0', signer['user'])
        self.assertIn('@sha256:', signer['image'])
        self.assertEqual(signer['image'], authz['image'])
        self.assertTrue(all(v.endswith(':ro') for v in signer['volumes']))
        self.assertEqual(signer['entrypoint'], ['/usr/local/bin/provider-signer'])

    def test_the_namespace_holder_is_hardened_and_is_not_the_process(self):
        holder = self.OVERLAY['services']['provider-signer']
        self.assertEqual((holder['read_only'], holder['cap_drop'], holder['security_opt'], holder['restart']),
                         (True, ['ALL'], ['no-new-privileges:true'], 'no'))
        self.assertEqual(holder['user'], '65534:65534')
        self.assertEqual(holder['entrypoint'], ['sleep', 'infinity'])
        self.assertNotIn('9444', str(holder.get('command', '')))

    def test_signer_egress_uses_the_gateways_script_and_image(self):
        egress = self.OVERLAY['services']['signer-egress']
        shared = self.COMPOSE['x-pin-egress']
        self.assertEqual(egress['image'], shared['image'])
        self.assertEqual(egress['entrypoint'], shared['entrypoint'])
        self.assertEqual(egress['user'], shared['user'])
        self.assertEqual(egress['cap_add'], shared['cap_add'])
        self.assertIn('./pin-egress.sh:/opt/pin-egress.sh:ro', egress['volumes'])
        self.assertIn('./pin-egress.sh:/opt/pin-egress.sh:ro', shared['volumes'])
        self.assertEqual(egress['environment']['LOOP_ALLOW'], '')
        self.assertIn('/tmp', egress['tmpfs'])
        self.assertEqual((egress['read_only'], egress['cap_drop'], egress['restart']), (True, ['ALL'], 'no'))

    def test_gateway_authz_command_is_the_base_list_plus_the_two_arguments(self):
        """The overlay repeats the whole command because compose replaces the list. Nothing else is added or dropped."""
        over = self.OVERLAY['services']['gateway-authz']
        self.assertEqual(set(over), {'command'})
        self.assertEqual(over['command'], self.BASE_AUTHZ['command'] + self.ADDED)
        self.assertEqual(over['command'].count('--sf-openapi-apps=/authz/credentials/sfintl.apps.json'), 1)
        self.assertNotIn('--sf-openapi-apps', self.BASE_AUTHZ['command'])

    def test_every_variable_is_required_except_the_two_plain_http_hosts(self):
        raw = text('deploy/compose/provider-signer.yml')
        found = re.findall(r'\$\{([A-Z0-9_]+)(:?[-?]?)([^}]*)\}', raw)
        self.assertEqual(len(found), raw.count('${'))
        optional = {'FRONT_IMAGE', 'EGRESS_IMAGE', 'SIGNER_PLAIN_HTTP_HOST', 'GATEWAY_AUTHZ_SF_PLAIN_HTTP_HOST'}
        self.assertEqual({name for name, kind, _ in found if kind != ':?'}, optional)
        self.assertEqual({kind for name, kind, _ in found if name in ('SIGNER_PLAIN_HTTP_HOST', 'GATEWAY_AUTHZ_SF_PLAIN_HTTP_HOST')}, {'-'})
        # The repeated command still names gateway-authz.yml's variables; they stay documented in that file's example.
        already = {name for name, _, _ in re.findall(r'\$\{([A-Z0-9_]+)(:?[-?]?)([^}]*)\}', text('deploy/compose/gateway-authz.yml'))}
        listed = re.findall(r'^([A-Z][A-Z0-9_]*)=', text('deploy/compose/provider-signer.env.example'), re.M)
        introduced = {name for name, _, _ in found if name not in ('FRONT_IMAGE', 'EGRESS_IMAGE') and name not in already}
        self.assertEqual(sorted(set(listed)), sorted(introduced))
        self.assertEqual(len(listed), len(set(listed)))
