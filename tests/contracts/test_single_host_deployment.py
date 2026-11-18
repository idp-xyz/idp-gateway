"""The single-host deployment (deploy/compose) must keep saying what was tested.

The compose suite (tests/integration/compose/run.py) runs deploy/compose/compose.yml itself, but it needs
docker and is run by hand. These tests keep what can be read off the files from drifting between two runs
of that suite: the images, the start order that gates the front proxy, what is published on the host, the
front proxy configuration, the variables an operator fills in, and the two systemd units (the pool and its
keeper, which tests/integration/compose/units.py runs under a user-level systemd).
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
POOL_ADAPTER = text('internal/gatewayconfig/adapters/container/pool.go')
# ${NAME:?message} must be given; ${NAME:-default} may be left out.
REFERENCE = re.compile(r'\$\{([A-Z][A-Z0-9_]*)(:\?|:-)?([^}]*)\}')
STARTED, COMPLETED = {'condition': 'service_started'}, {'condition': 'service_completed_successfully'}
STEPS = ('place', 'confirm')   # run to completion, then exit
# What gateway-control keep accepts in the env file: comments, blank lines and NAME=value with a value that
# systemd and docker compose read alike (container.CheckEnvFiles).
PLAIN = re.compile(r"""[A-Za-z_][A-Za-z0-9_]*=[^\s"'$#\\`]*""")
# Filled in by the operator like the rest of .env, but read by the keeper unit only: where the keeper gives out its
# metrics. docker compose has no use for it.
KEEPER_ONLY = {'KEEPER_METRICS_LISTEN'}
RULES_FILE = 'deploy/compose/idp-gateway-pool.rules.yml'
EXPOSITION_FILE = 'internal/gatewayconfig/adapters/telemetry/testdata/exposition.txt'


def directives(path: str) -> list:
    """The settings of a unit file, in order: comments dropped, a line ending in a backslash joined with the next."""
    found, pending = [], ''
    for line in text(path).splitlines():
        if not pending and (not line.strip() or line.lstrip().startswith(('#', ';'))):
            continue
        pending += line.strip()
        if pending.endswith('\\'):
            pending = pending[:-1] + ' '
            continue
        found.append(' '.join(pending.split()))
        pending = ''
    return found


def setting(unit: list, name: str) -> str:
    """The value of a setting that a unit gives exactly once."""
    values = [line.split('=', 1)[1] for line in unit if line.startswith(name + '=')]
    assert len(values) == 1, f'{name}= appears {len(values)} times'
    return values[0]


def go_constant(source: str, name: str) -> str:
    return re.search(r'\b' + name + r'\s*=\s*"([^"]*)"', source).group(1)


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

    def test_the_egress_rules_are_installed_from_the_image_the_suites_ran_them_with(self):
        """Only its iptables is used. By digest, like the other two, and the same one in both suites."""
        used = re.search(r'^IPTABLES = "(docker@sha256:[0-9a-f]{64})"$', text('tests/integration/egressnet/run.py'), re.M)
        self.assertIsNotNone(used)
        for name in ('egress', 'egress-watch'):
            with self.subTest(service=name):
                self.assertEqual(SERVICES[name]['image'], '${EGRESS_IMAGE:-' + used[1] + '}')


class StartOrder(unittest.TestCase):
    """compose starts a service once what it depends on is in the stated condition. This order is the boot gate."""

    def test_the_pool_is_these_services(self):
        self.assertEqual(list(SERVICES), ['netns', 'place', 'egress', 'agentgateway', 'confirm', 'front', 'egress-watch'])

    def test_the_gateway_starts_after_the_confirmed_snapshot_is_in_place_and_the_egress_rules_are_in(self):
        """A gateway that starts before the rules are in its network namespace can connect anywhere."""
        self.assertEqual(SERVICES['agentgateway']['depends_on'], {'netns': STARTED, 'place': COMPLETED, 'egress': COMPLETED})

    def test_the_egress_rules_are_installed_from_the_placed_snapshot_on_every_start(self):
        """egress runs to completion like place: `up -d` runs it again, so a namespace that replaced the old one
        gets its rules before the gateway is started in it."""
        egress = SERVICES['egress']
        self.assertEqual(egress['command'], ['once'])
        self.assertEqual(egress['depends_on'], {'netns': STARTED, 'place': COMPLETED})
        self.assertNotIn('pid', egress)

    def test_the_egress_watcher_cannot_outlive_the_namespace_it_was_started_in(self):
        """It shares the holder's PID namespace: when the holder dies it dies, and the next `up -d` starts it in the
        new network namespace. Left running in the old one it would add nothing where the gateway is."""
        watcher = SERVICES['egress-watch']
        self.assertEqual(watcher['command'], ['watch'])
        self.assertEqual(watcher['pid'], 'service:netns')
        self.assertEqual(watcher['depends_on'], {'egress': COMPLETED})
        self.assertNotIn('egress-watch', {name for service in SERVICES.values() for name in service.get('depends_on', {})},
                         'nothing waits for the watcher')

    def test_both_egress_services_run_the_script_in_the_namespace_of_the_holder(self):
        for name in ('egress', 'egress-watch'):
            service = SERVICES[name]
            with self.subTest(service=name):
                self.assertEqual(service['network_mode'], 'service:netns')
                self.assertEqual(service['entrypoint'], ['/bin/sh', '/opt/pin-egress.sh'])
                self.assertEqual(service['user'], '0:0')
                self.assertEqual(service['volumes'], ['./pin-egress.sh:/opt/pin-egress.sh:ro',
                                                      '${POOL_DIR:?see .env.example}/config:/work/config:ro'])
                self.assertEqual(service['tmpfs'], ['/tmp'])
                self.assertEqual(service['environment'], {'CONFIG': '/work/config/config.yaml', 'LOOP_ALLOW': '127.0.0.1:8081'})
        # The one loopback destination allowed besides what the snapshot names is where the front proxy sends requests.
        self.assertIn('proxy_pass http://127.0.0.1:8081;', text('deploy/compose/front.nginx.conf'))
        script = text('deploy/compose/pin-egress.sh')
        for mode in ('once', 'watch', 'forget'):
            self.assertRegex(script, r'(?m)^    ' + mode + r'\)$')
        # Replaced in one transaction, and the jump is added only after the chain is filled.
        self.assertIn('iptables-restore --noflush < "$rules"', script)
        self.assertNotIn('iptables -F', script)
        self.assertLess(script.index('iptables-restore --noflush < "$rules"'), script.index('iptables -I OUTPUT 1 -j "$CHAIN"'))

    def test_what_the_egress_script_remembers_sits_in_a_chain_that_nothing_jumps_to(self):
        """A backend the configuration stops naming is not allowed but stays remembered, so that a name is still resolved
        once. The memory is a chain of its own, written in the same transaction as the one in force. Only the latter may
        be jumped to; and what is in the memory would allow nothing even if a jump to it were ever added by mistake."""
        script = text('deploy/compose/pin-egress.sh')
        self.assertIn('KEPT=${CHAIN}_KEPT', script)
        self.assertEqual(set(re.findall(r'-j\s+"?\$\{?(\w+)', script)), {'CHAIN'})
        remembered = re.findall(r'echo "-A \$KEPT .*"', script)
        self.assertTrue(remembered)
        for line in remembered:
            self.assertTrue(line.endswith('-j RETURN"'), line)
        commit = script.index('echo COMMIT')
        self.assertLess(script.index('echo ":$KEPT - [0:0]"'), commit)
        self.assertLess(script.index('echo "-A $KEPT '), commit)

    def test_a_pass_of_the_egress_script_is_never_run_where_errexit_is_ignored(self):
        """In POSIX sh `set -e` is ignored inside whatever runs as the condition of `if` or `while`, on the left of `||`
        or `&&`, or after `!`, a subshell or a function included. A pass called that way goes on after its first failing
        command: a failed read of the configuration would be followed by rules built from an empty list. So each of the
        three appears only as a command on a line of its own, and the subshell that survives a failed pass in watch mode
        sets `set -e` itself. (EG-08 in tests/integration/egressnet shows the behaviour; this keeps the text from drifting.)"""
        script = text('deploy/compose/pin-egress.sh')
        for name in ('apply', 'write_rules', 'one_pass'):
            with self.subTest(function=name):
                calls = [line.strip() for line in script.splitlines()
                         if not line.strip().startswith(('#', name + '()')) and re.search(r'\b' + name + r'\b', line)]
                self.assertTrue(calls)
                for call in calls:
                    self.assertEqual(call, name)
        self.assertRegex(script, r'(?m)^    \(\n        set -e\n(?:        .*\n)*?        apply\n    \) 2> "\$WORK/said"\n    status=\$\?\n')

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
                if name in ('egress', 'egress-watch'):
                    # Installing the rules takes this one capability, and no other.
                    self.assertEqual(service['cap_add'], ['NET_ADMIN'])
                else:
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
        # ...and the one the keeper unit alone reads. Nothing else may be listed: the suites refuse a variable
        # the example does not have.
        self.assertFalse(KEEPER_ONLY & {name for name, _, _ in self.REFERENCES}, 'docker compose does not read these')
        self.assertEqual(sorted(name for name, _ in listed), sorted(required | KEEPER_ONLY))
        self.assertEqual([value for _, value in listed if value], [], 'the example must not carry values of one host')

    def test_the_example_shows_the_optional_variables_with_their_defaults(self):
        optional = {name: default for name, kind, default in self.REFERENCES if kind == ':-'}
        shown = dict(line[2:].split('=', 1) for line in self.EXAMPLE if re.match(r'# [A-Z][A-Z0-9_]*=', line))
        self.assertEqual(shown, optional)

    def test_the_filled_in_file_is_not_committed(self):
        self.assertIn('deploy/compose/.env', text('.gitignore').splitlines())

    def test_the_example_is_written_the_way_the_keeper_accepts(self):
        """systemd reads .env for the keeper unit; the keeper refuses lines the two readers read differently."""
        for line in self.EXAMPLE:
            with self.subTest(line=line):
                self.assertTrue(not line.strip() or line.startswith('#') or PLAIN.fullmatch(line))
        for line in (line[2:] for line in self.EXAMPLE if re.match(r'# [A-Z][A-Z0-9_]*=', line)):
            with self.subTest(default=line):
                self.assertTrue(PLAIN.fullmatch(line), 'an optional variable, once uncommented, must be accepted too')

    def test_the_accepted_form_is_the_one_the_keeper_checks(self):
        self.assertIn('strings.ContainsRune("\\"\'$#\\\\`", r)', POOL_ADAPTER)
        self.assertIn('unicode.IsSpace(r) || unicode.IsControl(r)', POOL_ADAPTER)
        self.assertIn('envName     = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)', POOL_ADAPTER)
        for line, accepted in (('POOL_DIR=/srv/pool', True), ('EMPTY=', True), ('POOL_DIR=/srv/pool # here', False),
                               ('POOL_DIR="/srv/pool"', False), ("POOL_DIR='/srv/pool'", False), ('POOL_DIR=$HOME/pool', False),
                               ('POOL_DIR=C:\\pool', False), ('POOL_DIR=`pwd`', False), ('export POOL_DIR=/srv/pool', False)):
            with self.subTest(line=line):
                self.assertEqual(bool(PLAIN.fullmatch(line)), accepted)


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


class KeeperUnit(unittest.TestCase):
    """The unit that runs gateway-control keep next to the pool unit."""
    UNIT = directives('deploy/compose/idp-gateway-pool-keep.service')
    POOL = directives('deploy/compose/idp-gateway-pool.service')
    COMMAND = setting(UNIT, 'ExecStart').split()
    REQUIRED = {name for name, kind, _ in REFERENCE.findall(COMPOSE_TEXT) if kind == ':?'}

    def test_the_two_files_have_these_sections(self):
        self.assertEqual([line for line in self.UNIT if line.startswith('[')], ['[Unit]', '[Service]', '[Install]'])
        self.assertEqual([line for line in self.POOL if line.startswith('[')], ['[Unit]', '[Service]', '[Install]'])

    def test_it_follows_the_pool_unit(self):
        """Started with it and after its start command, stopped before it, restarted with it."""
        self.assertEqual(setting(self.UNIT, 'After').split(), ['docker.service', 'idp-gateway-pool.service'])
        self.assertEqual(setting(self.UNIT, 'PartOf'), 'idp-gateway-pool.service')
        self.assertEqual(setting(self.UNIT, 'WantedBy'), 'idp-gateway-pool.service')
        self.assertEqual(setting(self.UNIT, 'Requires'), 'docker.service')

    def test_it_does_not_depend_on_the_start_of_the_pool_succeeding(self):
        """A pool that failed to start at boot is exactly what the keeper is there to retry."""
        for line in self.UNIT:
            name, _, value = line.partition('=')
            if name in ('Requires', 'Requisite', 'BindsTo', 'Upholds', 'ConditionPathExists', 'AssertPathExists'):
                self.assertNotIn('idp-gateway-pool.service', value, line)

    def test_the_pool_unit_does_not_mention_the_keeper(self):
        """The pool unit is the one the compose suite's start and stop commands stand for; it stays as it was."""
        self.assertFalse([line for line in self.POOL if 'keep' in line])
        self.assertEqual(setting(self.POOL, 'WantedBy'), 'multi-user.target')

    def test_it_is_restarted_unless_what_it_was_given_is_wrong(self):
        self.assertEqual(setting(self.UNIT, 'Type'), 'simple')
        self.assertEqual(setting(self.UNIT, 'Restart'), 'always')
        self.assertEqual(setting(self.UNIT, 'RestartPreventExitStatus'), '2')
        self.assertRegex(CONTROL, r'exitUsage\s*=\s*2\b')
        self.assertIn('if errors.Is(err, container.ErrEnvFile) {', CONTROL)

    def test_stopping_lets_the_compose_command_in_hand_finish(self):
        """Only the keeper is signalled; the docker compose command it is running gets the time gateway-control allows it."""
        self.assertEqual(setting(self.UNIT, 'KillMode'), 'mixed')
        minutes = int(re.search(r'"compose-timeout", (\d+)\*time\.Minute', CONTROL).group(1))
        self.assertGreater(int(setting(self.UNIT, 'TimeoutStopSec')), minutes * 60)
        # The same limit as the pool unit gives its own start command.
        self.assertEqual(int(setting(self.POOL, 'TimeoutStartSec')), minutes * 60)

    def test_it_runs_in_the_directory_of_the_pool_and_reads_its_env_file(self):
        directory = setting(self.POOL, 'WorkingDirectory')
        self.assertEqual(setting(self.UNIT, 'WorkingDirectory'), directory)
        self.assertEqual(setting(self.UNIT, 'EnvironmentFile'), directory + '/.env')

    def test_docker_compose_finds_the_project_the_way_the_pool_unit_does(self):
        """No compose flags: docker compose reads compose.yml and .env of the working directory; only the project is named."""
        self.assertFalse([word for word in self.COMMAND if word.startswith('--compose')])
        self.assertEqual(go_constant(POOL_ADAPTER, 'DefaultProject'), yaml.safe_load(COMPOSE_TEXT)['name'])
        self.assertIn('"compose-project", container.DefaultProject,', CONTROL)

    def test_the_command_is_keep_with_the_settings_of_the_pool(self):
        self.assertEqual(self.COMMAND, [
            '/usr/bin/env', '${GATEWAY_CONTROL}', 'keep', '--config-dir', '${POOL_DIR}/config',
            '--read-back', '127.0.0.1:${READBACK_PORT}', '--read-back-name', '${READBACK_NAME}',
            '--tls-cert', '${PUBLISHER_CERT}', '--tls-key', '${PUBLISHER_KEY}', '--tls-ca', '${READBACK_CA}',
            '--metrics-listen', '${KEEPER_METRICS_LISTEN}'])
        self.assertRegex(CONTROL, r'commandKeep\s*=\s*"keep"')
        for flag in flags(self.COMMAND):
            with self.subTest(flag=flag):
                self.assertIn(f'"{flag}"', CONTROL)

    def test_every_variable_of_the_command_is_one_the_operator_must_fill_in(self):
        used = re.findall(r'\$\{([^}]*)\}', ' '.join(self.COMMAND))
        self.assertEqual(len(used), ' '.join(self.COMMAND).count('$'), 'systemd expands ${NAME} inside a word, $NAME only as a word')
        self.assertLessEqual(set(used), self.REQUIRED | KEEPER_ONLY)
        self.assertLessEqual(KEEPER_ONLY, set(used))

    def test_the_command_points_at_what_the_compose_file_gives_the_pool(self):
        """The same binary as place and confirm, the directory they write, and the port the read-back is published on."""
        self.assertIn('${GATEWAY_CONTROL:?see .env.example}:/usr/local/bin/gateway-control:ro', SERVICES['place']['volumes'])
        self.assertIn('${POOL_DIR:?see .env.example}/config:/pool/config', SERVICES['place']['volumes'])
        self.assertIn('127.0.0.1:${READBACK_PORT:?see .env.example}:8443', SERVICES['netns']['ports'])
        self.assertIn('--read-back-name=${READBACK_NAME:?see .env.example}', SERVICES['confirm']['command'])
        for variable, mounted in (('PUBLISHER_CERT', 'tls.crt'), ('PUBLISHER_KEY', 'tls.key'), ('READBACK_CA', 'ca.crt')):
            self.assertIn('${' + variable + ':?see .env.example}:/publisher/' + mounted + ':ro', SERVICES['confirm']['volumes'])

    def test_it_does_not_run_as_root(self):
        """It must be the owner of the configuration directory (CONTROL_USER); a unit without User= runs as root."""
        self.assertNotIn(setting(self.UNIT, 'User'), ('', 'root', '0'))
        self.assertNotIn(setting(self.UNIT, 'Group'), ('', 'root', '0'))

    def test_the_keeper_knows_the_long_running_services_by_their_names(self):
        names = [go_constant(POOL_ADAPTER, name) for name in ('HolderService', 'GatewayService', 'FrontService')]
        self.assertEqual(names, ['netns', 'agentgateway', 'front'])
        # What it stops before starting over: the two that sit in the network namespace of the holder and outlive it.
        # The two egress services sit there too and the keeper does not know them: one has exited by then, and the
        # other dies with the holder (it shares the holder's PID namespace).
        sharing = {name for name, service in SERVICES.items() if service.get('network_mode') == f'service:{names[0]}'}
        self.assertEqual(sharing, set(names[1:]) | {'egress', 'egress-watch'})
        self.assertEqual(SERVICES['egress-watch']['pid'], f'service:{names[0]}')
        self.assertIn('p.compose(ctx, "stop", FrontService, GatewayService)', POOL_ADAPTER)
        self.assertIn('p.compose(ctx, "up", "-d")', POOL_ADAPTER)
        for name in names:
            with self.subTest(reported=name):
                self.assertIn(f'`json:"{name}"`', CONTROL)

    def test_the_units_script_runs_these_two_files(self):
        script = text('tests/integration/compose/units.py')
        self.assertIn("DEPLOY = ROOT / 'deploy/compose'", script)
        self.assertIn("POOL, KEEP = 'idp-gateway-pool.service', 'idp-gateway-pool-keep.service'", script)
        self.assertIn("for line in (DEPLOY / name).read_text(encoding='utf-8').splitlines():", script)
        self.assertIn(f"RESTART_SECONDS = {setting(self.UNIT, 'RestartSec')} ", script)


class Alerting(unittest.TestCase):
    """The alert rules are written against the numbers the keeper gives out. The Go test of the telemetry adapter
    pins those numbers to a file; here the rules are held to that file, and the unit to the flag that opens them."""
    RULES = yaml.safe_load(text(RULES_FILE))
    ALERTS = [rule for group in RULES['groups'] for rule in group['rules']]
    EXPOSITION = text(EXPOSITION_FILE)
    TYPES = dict(re.findall(r'^# TYPE (\S+) (\S+)$', EXPOSITION, re.M))
    SERIES = {line.rsplit(' ', 1)[0] for line in EXPOSITION.splitlines() if line and not line.startswith('#')}
    README = text('deploy/compose/README.md')
    JOB = 'idp-gateway-keeper'

    def test_the_file_is_one_group_of_alerts(self):
        self.assertEqual(list(self.RULES), ['groups'])
        self.assertEqual([group['name'] for group in self.RULES['groups']], ['idp-gateway-pool'])
        names = [rule.get('alert') for rule in self.ALERTS]
        self.assertTrue(all(names), 'recording rules are not expected here')
        self.assertEqual(len(names), len(set(names)))
        self.assertEqual(len(names), 8)

    def test_every_alert_says_how_bad_it_is_and_what_it_means(self):
        for rule in self.ALERTS:
            with self.subTest(alert=rule['alert']):
                self.assertLessEqual(set(rule), {'alert', 'expr', 'for', 'labels', 'annotations'})
                self.assertEqual(list(rule['labels']), ['severity'])
                self.assertIn(rule['labels']['severity'], ('critical', 'warning'))
                self.assertEqual(sorted(rule['annotations']), ['description', 'summary'])
                self.assertTrue(all(len(words.strip()) > 10 for words in rule['annotations'].values()))
                if 'for' in rule:
                    self.assertRegex(rule['for'], r'^[1-9]\d*m$')

    def test_the_go_test_pins_the_numbers_to_the_file_read_here(self):
        self.assertIn('golden := filepath.Join("testdata", "exposition.txt")',
                      text('internal/gatewayconfig/adapters/telemetry/telemetry_test.go'))
        self.assertTrue(self.TYPES and self.SERIES)
        self.assertLessEqual(set(self.TYPES.values()), {'gauge', 'counter'})

    def test_the_rules_only_read_series_the_keeper_gives_out(self):
        used = set()
        for rule in self.ALERTS:
            with self.subTest(alert=rule['alert']):
                names = set(re.findall(r'\bidp_gateway_[a-z_]+', rule['expr']))
                self.assertLessEqual(names, set(self.TYPES))
                self.assertTrue(names or 'up{' in rule['expr'], 'every rule reads the keeper, or whether it can be read')
                used |= names
                # A label matcher must be able to match: each value it names is one the keeper gives out.
                for name, label, operator, value in re.findall(r'(idp_gateway_[a-z_]+)\{(\w+)(=~|=)"([^"]*)"\}', rule['expr']):
                    for one in (value.split('|') if operator == '=~' else [value]):
                        self.assertIn(f'{name}{{{label}="{one}"}}', self.SERIES)
                self.assertEqual(rule['expr'].count('{'), len(re.findall(r'(idp_gateway_[a-z_]+|\bup)\{\w+(=~|=)"[^"]*"\}', rule['expr'])),
                                 'a selector this test does not understand')
        # What an alert is expected to hang on, by name.
        self.assertGreaterEqual(used, {
            'idp_gateway_keeper_last_look_timestamp_seconds', 'idp_gateway_keeper_last_look_failed', 'idp_gateway_keeper_start_time_seconds',
            'idp_gateway_pool_condition', 'idp_gateway_pool_reconcile_outcome', 'idp_gateway_pool_starts_total',
            'idp_gateway_pool_snapshots_put_back_total'})

    def test_counters_are_read_as_what_they_grew_by(self):
        counters = {name for name, kind in self.TYPES.items() if kind == 'counter'}
        self.assertEqual({name for name in self.TYPES if name.endswith('_total')}, counters)
        for rule in self.ALERTS:
            for name in counters & set(re.findall(r'\bidp_gateway_[a-z_]+', rule['expr'])):
                with self.subTest(alert=rule['alert'], counter=name):
                    self.assertIn(f'increase({name}[', rule['expr'])
                    # ...and the growth Prometheus cannot see: the keeper acted before it was first read.
                    self.assertIn(f'{name} > 0 and time() - idp_gateway_keeper_start_time_seconds <', rule['expr'])

    def test_the_states_that_need_a_person_each_have_an_alert(self):
        by_name = {rule['alert']: rule for rule in self.ALERTS}
        self.assertEqual(by_name['GatewayPoolNotWhole']['expr'], 'idp_gateway_pool_condition{condition="whole"} == 0')
        # Every outcome of a reconcile that is not "the pool is as recorded" is either alerted on as a state...
        states = {'UNKNOWN', 'UNCONFIRMED', 'RESTART_PENDING'}
        named = set()
        for rule in self.ALERTS:
            for _, value in re.findall(r'idp_gateway_pool_reconcile_outcome\{outcome(=~|=)"([^"]*)"\}', rule['expr']):
                named |= set(value.split('|'))
        outcomes = {series.split('"')[1] for series in self.SERIES if series.startswith('idp_gateway_pool_reconcile_outcome{')}
        self.assertEqual(named, states)
        # ...or, for RESTORED, as something that happened (the count of snapshots put back).
        self.assertEqual(outcomes - states, {'IN_SYNC', 'RESTORED'})
        self.assertIn('idp_gateway_pool_snapshots_put_back_total', by_name['GatewayPoolSnapshotPutBack']['expr'])

    def test_a_keeper_that_cannot_be_read_is_the_first_alert(self):
        """Every other rule reads the keeper's own numbers; when it is gone they have nothing to read and stay silent."""
        first = self.ALERTS[0]
        self.assertEqual(first['alert'], 'GatewayKeeperDown')
        self.assertEqual(first['expr'], f'up{{job="{self.JOB}"}} == 0 or absent(up{{job="{self.JOB}"}})')
        self.assertEqual(first['labels']['severity'], 'critical')
        # The job name is part of the contract: the README gives the scrape configuration that carries it.
        self.assertIn(f'job_name: {self.JOB}', self.README)
        self.assertIn('idp-gateway-pool.rules.yml', self.README)
        self.assertIn('KEEPER_METRICS_LISTEN', self.README)

    def test_the_keeper_unit_opens_the_metrics_where_the_env_file_says(self):
        command = KeeperUnit.COMMAND
        self.assertEqual(command[command.index('--metrics-listen') + 1], '${KEEPER_METRICS_LISTEN}')
        self.assertIn('flags.StringVar(&o.metricsListen, "metrics-listen", "",', CONTROL)
        self.assertIn('KEEPER_METRICS_LISTEN=', text('deploy/compose/.env.example').splitlines())
        self.assertNotIn('KEEPER_METRICS_LISTEN', COMPOSE_TEXT)

    def test_a_missing_address_stops_the_keeper_instead_of_switching_alerting_off(self):
        """systemd puts an empty word where ${NAME} is not set. The keeper must not read that as "no metrics"."""
        self.assertIn('flags.Visit(func(f *flag.Flag) { given = given || f.Name == "metrics-listen" })', CONTROL)
        self.assertIn('if host, port, err := net.SplitHostPort(o.metricsListen); err != nil || host == "" || port == "" {', CONTROL)
        self.assertEqual(setting(KeeperUnit.UNIT, 'RestartPreventExitStatus'), '2')

    def test_the_rules_are_exercised_as_they_are_shipped(self):
        tests = yaml.safe_load(text('tests/integration/compose/rules.test.yml'))
        self.assertEqual(tests['rule_files'], ['../../../' + RULES_FILE])
        exercised = json.dumps(tests)
        for rule in self.ALERTS:
            with self.subTest(alert=rule['alert']):
                self.assertIn(f'alertname=\\"{rule["alert"]}\\"', exercised)
        runner = text('tests/integration/compose/run.py')
        self.assertIn("RULES = DEPLOY / 'idp-gateway-pool.rules.yml'", runner)
        self.assertIn("RULE_TESTS = HERE / 'rules.test.yml'", runner)
        self.assertIn(f"JOB = '{self.JOB}'", runner)


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

    def test_the_keeper_of_the_suite_starts_the_pool_from_the_same_files(self):
        """The keeper the suite runs is given the project, the env file and the two files of the suite's own docker compose calls."""
        self.assertIn("['docker', 'compose', '-p', PROJECT, '--env-file', str(POOL_ENV),", self.RUNNER)
        self.assertIn("env_file: Path = POOL_ENV", self.RUNNER)
        self.assertIn("'--compose-project', PROJECT, '--compose-env-file', str(env_file),", self.RUNNER)
        self.assertIn("'--compose-file', str(DEPLOY / 'compose.yml'), '--compose-file', str(HERE / 'echo.yml'), *extra]", self.RUNNER)
        for flag in ('compose-project', 'compose-env-file', 'compose-file'):
            with self.subTest(flag=flag):
                self.assertIn(f'"{flag}"', CONTROL)

    def test_the_suite_runs_the_commands_the_two_units_carry(self):
        """SH-19 takes ExecStart= and ExecStop= out of the two unit files and runs them, outside systemd, in a directory
        that holds compose.yml and .env: nothing names the project or the files for docker compose."""
        self.assertIn("pool_unit, keep_unit = unit_commands('idp-gateway-pool.service'), unit_commands('idp-gateway-pool-keep.service')",
                      self.RUNNER)
        self.assertIn("for line in (DEPLOY / name).read_text(encoding='utf-8').replace('\\\\\\n', ' ').splitlines():", self.RUNNER)
        self.assertIn("if assigned and key in ('ExecStart', 'ExecStop'):", self.RUNNER)
        self.assertIn("return subprocess.run(words, cwd=HOSTED, env=plain, capture_output=True, text=True, timeout=300)", self.RUNNER)
        self.assertIn("up = run_in_place(pool_unit.get('ExecStart') or ['false'])", self.RUNNER)
        self.assertIn("halted = run_in_place(pool_unit.get('ExecStop') or ['false'])", self.RUNNER)
        self.assertIn("argv = filled_in(keep_unit.get('ExecStart') or ['false'], settings)", self.RUNNER)
        self.assertIn("keeper = Keeper(command=argv, cwd=HOSTED, environment={**plain, **settings})", self.RUNNER)
        # The directory holds the deployment's own files, and the pool it starts carries the project name they give.
        self.assertIn("for name in ('compose.yml', 'front.nginx.conf', 'pin-egress.sh'):\n        shutil.copy2(DEPLOY / name, HOSTED / name)", self.RUNNER)
        self.assertIn("DEPLOYED_PROJECT = yaml.safe_load((DEPLOY / 'compose.yml').read_text(encoding='utf-8'))['name']", self.RUNNER)
        # Cut the way the suite cuts it, the keeper's command is the one KeeperUnit checks.
        joined = text('deploy/compose/idp-gateway-pool-keep.service').replace('\\\n', ' ')
        cut = [line.partition('=')[2].split() for line in joined.splitlines() if line.partition('=')[0] == 'ExecStart']
        self.assertEqual(cut, [KeeperUnit.COMMAND])


if __name__ == '__main__':
    unittest.main()
