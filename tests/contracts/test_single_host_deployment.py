"""The single-host deployment (deploy/compose) must keep saying what was tested.

The compose suite (tests/integration/compose/run.py) runs deploy/compose/compose.yml itself, but it needs
docker and is run by hand. These tests keep what can be read off the files from drifting between two runs
of that suite: the images, the start order that gates the front proxy, what is published on the host, the
front proxy configuration, and the variables an operator fills in.
OFFLINE contract tests; nothing here starts a container.
"""
import json, re, unittest
from pathlib import Path
import yaml

R = Path(__file__).resolve().parents[2]
text = lambda path: (R / path).read_text(encoding='utf-8')
COMPOSE_TEXT = text('deploy/compose/compose.yml')
SERVICES = yaml.safe_load(COMPOSE_TEXT)['services']
LOCK = json.loads(text('deploy/agentgateway/agentgateway.lock.json'))
CONTROL = text('cmd/gateway-control/main.go')
# ${NAME:?message} must be given; ${NAME:-default} may be left out.
REFERENCE = re.compile(r'\$\{([A-Z][A-Z0-9_]*)(:\?|:-)?([^}]*)\}')
STARTED, COMPLETED = {'condition': 'service_started'}, {'condition': 'service_completed_successfully'}
STEPS = ('place', 'confirm')   # run to completion, then exit


def front_image() -> str:
    """The front proxy image the black-box cases were run with, as the suites write it."""
    found = re.search(r"FRONT_IMAGE = \('(public\.ecr\.aws/nginx/nginx-unprivileged:[\w.-]+)'\s*\n?\s*'(@sha256:[0-9a-f]{64})'",
                      text('tests/acceptance/blackbox/run.py'))
    return ''.join(found.groups())


def flags(command: list) -> list:
    return [argument[2:].split('=', 1)[0] for argument in command if argument.startswith('--')]


class Images(unittest.TestCase):
    def test_the_gateway_runs_the_pinned_image_by_digest(self):
        pinned = f"{LOCK['image']['repository']}@{LOCK['image']['index']}"
        self.assertEqual(SERVICES['agentgateway']['image'], '${GATEWAY_IMAGE:-' + pinned + '}')

    def test_everything_else_runs_the_front_proxy_image_of_the_black_box_cases(self):
        """place and confirm only borrow that image as a carrier for the publisher binary; netns only sleeps in it."""
        for name in ('netns', 'place', 'confirm', 'front'):
            with self.subTest(service=name):
                self.assertEqual(SERVICES[name]['image'], '${FRONT_IMAGE:-' + front_image() + '}')


class StartOrder(unittest.TestCase):
    """compose starts a service once what it depends on is in the stated condition. This order is the boot gate."""

    def test_the_pool_is_these_five_services(self):
        self.assertEqual(list(SERVICES), ['netns', 'place', 'agentgateway', 'confirm', 'front'])

    def test_the_gateway_starts_after_the_confirmed_snapshot_is_in_place(self):
        self.assertEqual(SERVICES['agentgateway']['depends_on'], {'netns': STARTED, 'place': COMPLETED})

    def test_the_front_proxy_starts_after_the_read_back_was_confirmed(self):
        self.assertEqual(SERVICES['confirm']['depends_on'], {'agentgateway': STARTED})
        self.assertEqual(SERVICES['front']['depends_on'], {'agentgateway': STARTED, 'confirm': COMPLETED})

    def test_nothing_else_is_ordered(self):
        for name in ('netns', 'place'):
            with self.subTest(service=name):
                self.assertNotIn('depends_on', SERVICES[name])

    def test_docker_restarts_none_of_them_by_itself(self):
        """A restart policy would start the gateway or the front proxy without going through place and confirm."""
        for name, service in SERVICES.items():
            with self.subTest(service=name):
                self.assertEqual(service['restart'], 'no')

    def test_the_two_steps_run_the_publisher(self):
        self.assertEqual(SERVICES['place']['command'], ['place', '--config-dir=/pool/config'])
        self.assertEqual(SERVICES['confirm']['command'][0], 'reconcile')
        self.assertEqual(flags(SERVICES['confirm']['command']),
                         ['config-dir', 'read-back', 'read-back-name', 'tls-cert', 'tls-key', 'tls-ca', 'timeout'])
        for name in STEPS:
            with self.subTest(service=name):
                self.assertEqual(SERVICES[name]['entrypoint'], ['/usr/local/bin/gateway-control'])
                self.assertIn('${GATEWAY_CONTROL:?see .env.example}:/usr/local/bin/gateway-control:ro', SERVICES[name]['volumes'])
                self.assertIn('${POOL_DIR:?see .env.example}/config:/pool/config', SERVICES[name]['volumes'])
                self.assertEqual(SERVICES[name]['user'], '${CONTROL_USER:?see .env.example}')

    def test_the_publisher_knows_the_commands_and_flags_the_steps_use(self):
        for name in STEPS:
            command = SERVICES[name]['command']
            with self.subTest(service=name):
                self.assertRegex(CONTROL, r'command\w+\s*=\s*"' + command[0] + '"')
                for flag in flags(command):
                    self.assertIn(f'"{flag}"', CONTROL)

    def test_confirm_reads_the_gateway_where_the_holder_is(self):
        """The gateway sits in the network namespace of netns, so that is the name confirm dials."""
        self.assertIn('--read-back=netns:8443', SERVICES['confirm']['command'])
        self.assertNotIn('network_mode', SERVICES['confirm'])


class Exposure(unittest.TestCase):
    def test_the_gateway_and_the_front_proxy_share_the_namespace_of_the_holder(self):
        for name in ('agentgateway', 'front'):
            with self.subTest(service=name):
                self.assertEqual(SERVICES[name]['network_mode'], 'service:netns')

    def test_only_the_holder_publishes_ports_and_the_read_back_stays_on_loopback(self):
        self.assertEqual([name for name, service in SERVICES.items() if 'ports' in service], ['netns'])
        self.assertEqual(SERVICES['netns']['ports'],
                         ['${CALLERS_LISTEN:?see .env.example}:8080', '127.0.0.1:${READBACK_PORT:?see .env.example}:8443'])

    def test_place_has_no_network_and_gets_no_certificate(self):
        self.assertEqual(SERVICES['place']['network_mode'], 'none')
        self.assertEqual(len(SERVICES['place']['volumes']), 2)

    def test_the_gateway_gets_its_directories_read_only_and_not_the_publisher_certificate(self):
        self.assertEqual(SERVICES['agentgateway']['volumes'],
                         ['${POOL_DIR:?see .env.example}/config:/work/config:ro', '${POOL_DIR:?see .env.example}/tls:/work/tls:ro'])
        self.assertEqual(SERVICES['agentgateway']['command'], ['-f', 'config/config.yaml'])
        self.assertEqual(SERVICES['agentgateway']['working_dir'], '/work')

    def test_every_container_is_locked_down(self):
        for name, service in SERVICES.items():
            with self.subTest(service=name):
                self.assertIs(service['read_only'], True)
                self.assertEqual(service['cap_drop'], ['ALL'])
                self.assertEqual(service['security_opt'], ['no-new-privileges:true'])
                self.assertNotIn('privileged', service)
                self.assertNotIn('cap_add', service)


class Variables(unittest.TestCase):
    """An operator fills in .env from .env.example; the two files must name the same variables."""
    REFERENCES = REFERENCE.findall(COMPOSE_TEXT)
    EXAMPLE = text('deploy/compose/.env.example').splitlines()

    def test_every_reference_says_whether_it_is_required(self):
        self.assertTrue(self.REFERENCES)
        self.assertNotIn('', {kind for _, kind, _ in self.REFERENCES}, 'a bare ${NAME} is silently empty when it is not set')
        self.assertEqual(len(self.REFERENCES), COMPOSE_TEXT.count('${'), 'a reference this test does not understand')

    def test_a_variable_is_required_everywhere_or_optional_everywhere_with_one_default(self):
        seen = {}
        for name, kind, rest in self.REFERENCES:
            seen.setdefault(name, set()).add((kind, rest))
        self.assertEqual({name: len(uses) for name, uses in seen.items() if len(uses) != 1}, {})

    def test_the_example_lists_the_required_variables_empty(self):
        required = {name for name, kind, _ in self.REFERENCES if kind == ':?'}
        listed = [line.split('=', 1) for line in self.EXAMPLE if re.match(r'[A-Z][A-Z0-9_]*=', line)]
        self.assertEqual(sorted(name for name, _ in listed), sorted(required))
        self.assertEqual([value for _, value in listed if value], [], 'the example must not carry values of one host')

    def test_the_example_shows_the_optional_variables_with_their_defaults(self):
        optional = {name: default for name, kind, default in self.REFERENCES if kind == ':-'}
        shown = dict(line[2:].split('=', 1) for line in self.EXAMPLE if re.match(r'# [A-Z][A-Z0-9_]*=', line))
        self.assertEqual(shown, optional)

    def test_the_filled_in_file_is_not_committed(self):
        self.assertIn('deploy/compose/.env', text('.gitignore').splitlines())


class FrontProxy(unittest.TestCase):
    """The pool carries the front proxy configuration the black-box cases were run with."""

    @staticmethod
    def directives(path: str) -> list:
        lines = (' '.join(line.split('#', 1)[0].split()) for line in text(path).splitlines())
        return [line for line in lines if line]

    def test_the_configuration_differs_from_the_black_box_one_only_in_the_two_addresses(self):
        blackbox = self.directives('tests/acceptance/blackbox/front.nginx.conf')
        deployed = self.directives('deploy/compose/front.nginx.conf')
        self.assertEqual(len(blackbox), len(deployed))
        self.assertEqual([pair for pair in zip(blackbox, deployed) if pair[0] != pair[1]],
                         [('listen 127.0.0.1:27620;', 'listen 8080;'),
                          ('proxy_pass http://127.0.0.1:27611;', 'proxy_pass http://127.0.0.1:8081;')])

    def test_the_front_service_runs_that_file_on_the_published_port(self):
        front = SERVICES['front']
        self.assertEqual(front['entrypoint'], ['nginx', '-c', '/etc/front/nginx.conf', '-g', 'daemon off;'])
        self.assertEqual(front['volumes'], ['./front.nginx.conf:/etc/front/nginx.conf:ro'])
        self.assertTrue(SERVICES['netns']['ports'][0].endswith(':8080'))
        self.assertNotIn('stop_signal', front, 'the image stops nginx with SIGQUIT, which lets requests in flight finish')


class BootUnit(unittest.TestCase):
    UNIT = [line.strip() for line in text('deploy/compose/idp-gateway-pool.service').splitlines()]

    def test_the_unit_runs_the_commands_the_suite_runs(self):
        self.assertIn('ExecStart=/usr/bin/docker compose up -d', self.UNIT)
        self.assertIn('ExecStop=/usr/bin/docker compose stop', self.UNIT)

    def test_a_failed_start_shows_as_a_failed_unit(self):
        """up -d exits non-zero when place or confirm does; a oneshot unit then fails instead of looking started."""
        self.assertIn('Type=oneshot', self.UNIT)
        self.assertIn('RemainAfterExit=yes', self.UNIT)
        self.assertFalse([line for line in self.UNIT if line.startswith(('Restart=', 'ExecStartPre=-', 'ExecStart=-'))])

    def test_the_unit_waits_for_docker(self):
        self.assertIn('Requires=docker.service', self.UNIT)
        after = next(line for line in self.UNIT if line.startswith('After='))
        self.assertIn('docker.service', after.split('=', 1)[1].split())


class ComposeSuite(unittest.TestCase):
    """The suite must keep running the deployment file itself, not a copy of it."""
    RUNNER = text('tests/integration/compose/run.py')

    def test_the_suite_runs_the_deployment_file(self):
        self.assertIn("DEPLOY = ROOT / 'deploy/compose'", self.RUNNER)
        self.assertIn("'-f', str(DEPLOY / 'compose.yml'), '-f', str(HERE / 'echo.yml')", self.RUNNER)

    def test_the_overlay_only_adds_the_backend(self):
        overlay = yaml.safe_load(text('tests/integration/compose/echo.yml'))
        self.assertEqual(list(overlay), ['services'])
        self.assertEqual(list(overlay['services']), ['echo'])


if __name__ == '__main__':
    unittest.main()
