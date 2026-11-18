"""The contracts must agree with each other and with what gateway-authz and the black-box suite actually speak.

These tests pin the four contradictions found in review so they cannot come back:
two definitions of the decision artefact, a publication API without the envelope G03 §4
describes, several release-state vocabularies, and a credential handle nobody can redeem.
OFFLINE contract tests; nothing here calls a Gatekeeper or a gateway.
"""
import ast, copy, json, re, unittest
from pathlib import Path
import yaml
from jsonschema import Draft202012Validator, FormatChecker

R = Path(__file__).resolve().parents[2]
text = lambda path: (R / path).read_text(encoding='utf-8')
GATEKEEPER = yaml.safe_load(text('contracts/gatekeeper/openapi.yaml'))
FABRIC = yaml.safe_load(text('contracts/fabric/route-publication-intent.openapi.yaml'))
DECISION_SCHEMA = json.loads(text('contracts/gatekeeper/authz-decision.schema.json'))
ROUTE_SCHEMA = json.loads(text('contracts/gateway/route-intent.schema.json'))


def valid(schema, doc):
    return not list(Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(doc))


class DecisionArtefact(unittest.TestCase):
    def test_openapi_reuses_the_schema_file(self):
        component = GATEKEEPER['components']['schemas']['DecisionResponse']
        self.assertEqual(component['$ref'], './authz-decision.schema.json')
        self.assertFalse({'properties', 'required', 'type'} & set(component), 'second inline definition')

    def test_example_valid_and_bound_to_policy_and_revocation(self):
        example = json.loads(text('contracts/gatekeeper/authz-decision.example.json'))
        self.assertTrue(valid(DECISION_SCHEMA, example))
        for field in ['request_id', 'policy_version', 'revocation_epoch']:
            with self.subTest(missing=field):
                broken = copy.deepcopy(example)
                broken.pop(field)
                self.assertFalse(valid(DECISION_SCHEMA, broken))

    def test_decision_request_carries_what_the_decision_is_bound_to(self):
        request = GATEKEEPER['components']['schemas']['DecisionRequest']
        self.assertLessEqual({'route_id', 'operation_id', 'provider_id', 'requested_account_id', 'environment',
                              'method', 'path', 'config_digest'}, set(request['required']))
        self.assertLessEqual({'service_id', 'tenant_id', 'delegated_subject'}, set(request['properties']))


class CredentialRedemption(unittest.TestCase):
    def test_only_the_deprecated_endpoint_returns_material_in_a_body(self):
        for path, item in GATEKEEPER['paths'].items():
            for method, operation in item.items():
                body = json.dumps(operation.get('responses', {}).get('200', {}).get('content', {}))
                if 'header_value' in body or 'token' in body.lower():
                    self.assertTrue(operation.get('deprecated'), f'{method} {path} returns credential material')

    def test_extauthz_check_releases_the_credential_as_a_header(self):
        check = GATEKEEPER['paths']['/v1/extauthz/check']['get']
        allow = check['responses']['200']
        self.assertTrue(allow['headers']['Authorization']['required'])
        self.assertNotIn('content', allow)
        self.assertEqual(check['security'], [{'WorkloadMTLS': []}])

    def test_no_unredeemable_handle(self):
        handle = GATEKEEPER['components']['schemas']['CredentialUseResponse']['properties']['secure_binding_handle']
        self.assertTrue(handle.get('deprecated'))

    POC_PORTS = {'gatekeeper': '127.0.0.1:27613', 'broker': '127.0.0.1:27618'}

    def poc_routes(self):
        """Every black-box route with ExtAuthZ."""
        routes = yaml.safe_load(text('tests/acceptance/blackbox/agentgateway.poc.yaml'))['routes']
        routes = [r for r in routes if 'extAuthz' in r.get('policies', {})]
        self.assertEqual(len(routes), 5)
        return routes

    def test_poc_gateway_sends_exactly_the_documented_trusted_context(self):
        documented = {p['name'] for p in GATEKEEPER['paths']['/v1/extauthz/check']['get']['parameters']}
        for route in self.poc_routes():
            ext = route['policies']['extAuthz']
            http = ext['protocol']['http']
            sent = set(http['addRequestHeaders']) | set(ext['includeRequestHeaders'])
            with self.subTest(route=route['name']):
                self.assertEqual(sent, documented)
                self.assertEqual(ext['failureMode'], {'denyWithStatus': 503})
                # The credential leaves the PDP's answer in exactly one way per route.
                copied, read = http.get('includeResponseHeaders'), http.get('metadata')
                if route['name'].endswith('-expression'):
                    self.assertIsNone(copied)
                    self.assertEqual(read, {'credential': 'response.headers["authorization"]'})
                else:
                    self.assertEqual(copied, ['authorization'])
                    self.assertIsNone(read)

    def test_poc_gateway_reaches_gatekeeper_over_mutual_tls_only(self):
        """WorkloadMTLS in the contract: a certificate, a pinned CA and a pinned name, and no bearer key."""
        for route in self.poc_routes():
            ext = route['policies']['extAuthz']
            with self.subTest(route=route['name']):
                if ext['host'] == self.POC_PORTS['gatekeeper']:
                    tls = ext['policies']['backendTLS']
                    self.assertEqual(set(tls), {'cert', 'key', 'root', 'hostname'})
                    self.assertNotIn('backendAuth', ext['policies'])
                else:
                    self.assertEqual(ext['host'], self.POC_PORTS['broker'])

    def test_backend_rule_names_the_scheme_of_the_credential_the_route_is_given(self):
        """A route whose credential comes from the PDP lets a request through to its backend only when the credential
        starts with the first word of what gateway-authz releases for it: "Bearer" from the Bearer file, the developer
        scheme from the developer-token file (ADR-0011). With the wrong word the gateway refuses every request."""
        scheme = re.search(r'^const developerScheme = "([^" ]+)"$', text('internal/egressauthz/adapters/filestore/developer_tokens.go'), re.M)
        self.assertIsNotNone(scheme)
        developer = [r['name'] for r in self.poc_routes() if r['name'].endswith('-developer-token')]
        self.assertEqual(len(developer), 1)
        for route in self.poc_routes():
            rules = route['backends'][0]['policies']['authorization']['rules']
            word = scheme[1] if route['name'] in developer else 'Bearer'
            with self.subTest(route=route['name']):
                if route['name'].endswith('-expression'):
                    self.assertEqual(rules, [{'allow': f'has(extauthz.credential) && extauthz.credential.startsWith("{word} ")'}])
                else:
                    self.assertEqual(rules, [{'allow': f'request.headers["authorization"].startsWith("{word} ")'}])

    def test_poc_provider_backends_share_one_header_allow_list(self):
        """G03 §5: every provider backend rebuilds headers from the same allow list.

        The expression is compared as text: a typo on one route would otherwise only show up
        when that route is exercised. Removals stay as a second line for headers the allow list
        must not keep if the expression ever fails to evaluate.
        """
        routes = yaml.safe_load(text('tests/acceptance/blackbox/agentgateway.poc.yaml'))['routes']
        provider = [r for r in routes if r['name'] != 'read-back']
        self.assertEqual(len(provider), 6)
        expected = 'request.headers.filterKeys(k, k in ["accept", "authorization", "content-type", "idempotency-key", "traceparent", "x-client-trace"])'
        # The list the black-box cases hold the provider's headers against is the list in the expression.
        runner = re.search(r'^HEADER_ALLOW = \(([^)]*)\)$', text('tests/acceptance/blackbox/run.py'), re.M)
        self.assertIsNotNone(runner)
        allowed = re.findall(r'"([^"]+)"', runner[1])
        self.assertEqual(expected, 'request.headers.filterKeys(k, k in [' + ', '.join(f'"{name}"' for name in allowed) + '])')
        self.assertEqual(allowed, [name.lower() for name in allowed], 'the gateway compares lower-case names')
        self.assertIn('authorization', allowed, 'the credential is placed before the list is applied')
        for route in provider:
            policies = route['backends'][0]['policies']
            with self.subTest(route=route['name']):
                self.assertEqual(policies['transformations'], {'request': {'replace': expected}})
                removed = policies['requestHeaderModifier']['remove']
                self.assertIn('x-provider-account', removed)
                self.assertIn('cookie', removed)
                # What is removed by name must never be registered as well.
                self.assertEqual(set(removed) & set(allowed), set())

    def test_gatekeeper_suite_can_still_derive_its_gateway_configuration(self):
        """tests/integration/gatekeeper starts the gateway from the black-box configuration with a few pieces of
        text replaced, and refuses to run when one of them does not occur as often as it expects. That suite needs
        a local Gatekeeper and is run by hand, so a change here that breaks it would otherwise go unnoticed."""
        tree = ast.parse(text('tests/integration/gatekeeper/run.py'))
        differences = next(node.value for node in tree.body if isinstance(node, ast.Assign)
                           and getattr(node.targets[0], 'id', None) == 'GATEWAY_DIFFERENCES')
        config = text('tests/acceptance/blackbox/agentgateway.poc.yaml')
        self.assertGreaterEqual(len(differences.elts), 3)
        for element in differences.elts:
            old, times = ast.literal_eval(element.elts[0]), ast.literal_eval(element.elts[2])
            with self.subTest(replaced=old.strip()):
                self.assertEqual(config.count(old), times)

    def test_broker_decision_request_is_the_documented_one(self):
        """What the mock broker sends to /v1/egress/authorizations/decision must fit DecisionRequest."""
        request = GATEKEEPER['components']['schemas']['DecisionRequest']
        tree = ast.parse(text('tests/acceptance/blackbox/mock_broker.py'))
        sent = next({k.value for k in node.keys} for node in ast.walk(tree) if isinstance(node, ast.Dict)
                    and any(isinstance(k, ast.Constant) and k.value == 'requested_account_id' for k in node.keys))
        self.assertLessEqual(set(request['required']), sent)
        self.assertLessEqual(sent, set(request['properties']))
        self.assertIn('token_environment', sent)


class PublicationEnvelope(unittest.TestCase):
    def setUp(self):
        self.envelope = FABRIC['components']['schemas']['RoutePublicationIntent']
        self.example = json.loads(text('contracts/fabric/route-publication-intent.example.json'))

    def check(self, doc):
        """Envelope against the OpenAPI component, the embedded intent against the RouteIntent schema."""
        shell = copy.deepcopy(self.envelope)
        shell['properties']['intent'] = {'type': 'object'}
        return valid(shell, doc) and valid(ROUTE_SCHEMA, doc.get('intent'))

    def test_post_body_is_the_envelope_and_the_route_stays_single_sourced(self):
        post = FABRIC['paths']['/v1/route-intents']['post']
        self.assertEqual(post['requestBody']['content']['application/json']['schema']['$ref'],
                         '#/components/schemas/RoutePublicationIntent')
        self.assertEqual(self.envelope['properties']['intent']['$ref'], '#/components/schemas/RouteIntent')
        self.assertEqual(FABRIC['components']['schemas']['RouteIntent'], {'$ref': '../gateway/route-intent.schema.json'})

    def test_example(self):
        self.assertTrue(self.check(self.example))
        self.assertEqual(self.example['intent'], json.loads(text('contracts/gateway/route-intent.example.json')))

    def test_envelope_fields_are_required_and_not_duplicated_in_the_route(self):
        for field in ['idempotency_key', 'release_ref', 'target_id', 'intent']:
            with self.subTest(missing=field):
                broken = copy.deepcopy(self.example)
                broken.pop(field)
                self.assertFalse(self.check(broken))
        for field in ['idempotency_key', 'release_ref', 'target_id']:
            self.assertNotIn(field, ROUTE_SCHEMA['properties'])
        for field in ['approval_ref', 'expected_generation']:
            self.assertNotIn(field, self.envelope['properties'])
            self.assertIn(field, ROUTE_SCHEMA['required'])
        bare_route = self.example['intent']
        self.assertFalse(self.check(bare_route))


class ReleaseStates(unittest.TestCase):
    CANONICAL = ['DRAFT', 'VALIDATED', 'APPROVED', 'STAGED', 'APPLYING', 'OBSERVING', 'ACTIVE', 'REJECTED', 'CANCELED',
                 'FAILED', 'PARTIAL', 'UNKNOWN', 'SUPERSEDED', 'WITHDRAW_REQUESTED', 'REVOKING', 'REVOKED']
    CONSOLE_LABELS = ['REVIEW', 'ROLLOUT', 'RECONCILED', 'REVERTED']  # labels, never states

    def test_one_enum_used_by_every_response(self):
        self.assertEqual(FABRIC['components']['schemas']['ReleaseState']['enum'], self.CANONICAL)
        ref = {'$ref': '#/components/schemas/ReleaseState'}
        accepted = FABRIC['paths']['/v1/route-intents']['post']['responses']['202']
        status = FABRIC['paths']['/v1/route-intents/{intent_id}/status']['get']['responses']['200']
        for response in [accepted, status]:
            state = response['content']['application/json']['schema']['properties']['state']
            self.assertEqual({k: v for k, v in state.items() if k == '$ref'}, ref)
        self.assertNotIn('RECEIVED', text('contracts/fabric/route-publication-intent.openapi.yaml'))

    def test_g03_state_machine_uses_only_canonical_states(self):
        g03 = text('docs/G03_Routing_and_Configuration.md')
        diagram = g03.split('## 3. 配置发布状态机')[1].split('```')[1]
        words = set(re.findall(r'[A-Z][A-Z_]{3,}', diagram))
        self.assertEqual(words - set(self.CANONICAL), {'RECONCILE', 'ROLLBACK'})  # the two events
        self.assertEqual(set(self.CANONICAL) - words, set())

    def test_console_labels_are_mapped_wherever_they_are_used(self):
        for path in ['docs/G03_Routing_and_Configuration.md']:
            for line in text(path).splitlines():
                if any(re.search(rf'\b{label}\b', line) for label in self.CONSOLE_LABELS):
                    with self.subTest(file=path, line=line[:40]):
                        self.assertIn('ReleaseState', line, 'console label used without pointing at the canonical states')


class ServiceSpeaksTheContract(unittest.TestCase):
    """What gateway-authz puts on the wire, read from its source, against the contract.

    The Go tests cover behaviour. These only compare names: the JSON fields of the structs the
    handler encodes and decodes, and the header names it reads.
    """
    HANDLER = text('internal/egressauthz/adapters/httpapi/handler.go')

    def fields(self, struct):
        """-> {json field: (is a pointer, has omitempty)} of a Go struct in the handler."""
        body = re.search(rf'^type {struct} struct \{{\n(.*?)^\}}', self.HANDLER, re.S | re.M)
        self.assertIsNotNone(body, f'struct {struct} not found in the handler')
        found = {name: (kind.startswith('*'), bool(omit))
                 for kind, name, omit in re.findall(r'^\s+\w+\s+(\S+)\s+`json:"([a-z_]+)(,omitempty)?"`', body[1], re.M)}
        self.assertTrue(found, f'no JSON fields read from struct {struct}')
        return found

    def test_denial_body_fields(self):
        denial = GATEKEEPER['components']['schemas']['ExtAuthzDenial']
        sent = self.fields('denialBody')
        self.assertEqual(set(sent), set(denial['required']))
        self.assertFalse(any(omit for _, omit in sent.values()), 'a required field may be left out')

    def test_trusted_context_headers(self):
        """The service reads exactly the headers the contract documents, and the gateway routes send."""
        documented = {p['name'] for p in GATEKEEPER['paths']['/v1/extauthz/check']['get']['parameters']}
        read = {value.lower() for value in re.findall(r'^\s+header\w+\s+= "([^"]+)"', self.HANDLER, re.M)}
        self.assertEqual(read, documented)

    def test_decision_request_fields(self):
        """Unknown fields are refused by the decoder, so the struct is the whole of what is accepted."""
        request = GATEKEEPER['components']['schemas']['DecisionRequest']
        accepted = self.fields('decisionRequest')
        self.assertIn('DisallowUnknownFields', self.HANDLER)
        self.assertIs(request['additionalProperties'], False)
        self.assertEqual(set(accepted), set(request['properties']))
        self.assertEqual({name for name, (pointer, _) in accepted.items() if pointer}, set(request['required']))

    def test_decision_response_fields(self):
        sent = self.fields('decisionResponse')
        self.assertLessEqual(set(sent), set(DECISION_SCHEMA['properties']))
        self.assertEqual({name for name, (_, omit) in sent.items() if not omit}, set(DECISION_SCHEMA['required']))
        self.assertIn('credential_handle', sent)

    def test_revocation_interface_fields(self):
        """The interface that changes gateway-authz's revocations (ADR-0012): what the handler decodes and encodes."""
        schemas = GATEKEEPER['components']['schemas']
        request, change = schemas['RevocationRequest'], schemas['RevocationChange']
        accepted = self.fields('revocationRequest')
        self.assertIn('DisallowUnknownFields', self.HANDLER)
        self.assertIs(request['additionalProperties'], False)
        self.assertEqual(set(accepted), set(request['properties']))
        self.assertEqual({name for name, (pointer, _) in accepted.items() if pointer}, set(request['required']))
        for field, constant in {'account_id': 'maxAccountIDBytes', 'reason': 'maxReasonBytes'}.items():
            limit = re.search(rf'^\s+{constant}\s+= (\d+)$', self.HANDLER, re.M)
            self.assertIsNotNone(limit, constant)
            self.assertEqual(request['properties'][field]['maxLength'], int(limit[1]))

        sent = self.fields('revocationChange')
        self.assertEqual(set(sent), set(change['properties']))
        self.assertEqual({name for name, (_, omit) in sent.items() if not omit}, set(change['required']))
        errors = set(re.findall(r'^\s+error\w+\s+= "([a-z_]+)"$', self.HANDLER, re.M))
        self.assertEqual(errors, set(change['properties']['error']['enum']))

        self.assertEqual(set(self.fields('revocationState')), set(schemas['RevocationState']['required']))
        self.assertEqual(set(self.fields('revokedAccount')), set(schemas['RevokedAccount']['required']))

        path = GATEKEEPER['paths']['/v1/egress/revocations']
        self.assertEqual(set(path), {'get', 'post'})
        for method, operation in path.items():
            with self.subTest(method=method):
                self.assertEqual(operation['security'], [{'WorkloadMTLS': []}])
                self.assertIn('401', operation['responses'])
        path_constant = re.search(r'^\s+PathRevocations\s+= "([^"]+)"$', self.HANDLER, re.M)
        self.assertIsNotNone(path_constant)
        self.assertEqual(path_constant[1], '/v1/egress/revocations')

    def test_canonical_path_rule_is_the_same_everywhere(self):
        """One expression: in the service, in the offline preflight and (checked by the Go tests) on the gateway routes."""
        service = re.search(r'CanonicalPathPattern = `([^`]+)`', text('internal/egressauthz/domain/path.go'))
        preflight = re.search(r"CANONICAL_PATH=re\.compile\(r'([^']+)'\)", text('scripts/preflight_intents.py'))
        self.assertIsNotNone(service)
        self.assertIsNotNone(preflight)
        self.assertEqual('^' + preflight[1] + '$', service[1])


class AgentgatewayPin(unittest.TestCase):
    """One agentgateway build is pinned, and the project manifest names the same release."""
    LOCK = json.loads(text('deploy/agentgateway/agentgateway.lock.json'))

    def test_lock_names_one_release_completely(self):
        self.assertRegex(self.LOCK['version'], r'^\d+\.\d+\.\d+$', 'a release, not a pre-release')
        self.assertRegex(self.LOCK['git_revision'], r'^[0-9a-f]{40}$')
        self.assertTrue(self.LOCK['release'].endswith('/releases/tag/v' + self.LOCK['version']))

    def test_lock_names_the_image_by_digest(self):
        image = self.LOCK['image']
        self.assertTrue(image['repository'])
        self.assertEqual(image['tag'], 'v' + self.LOCK['version'])
        self.assertTrue(image['binary'].startswith('/'))
        self.assertIn('linux/amd64', image['manifests'])
        for name, digest in {'index': image['index'], **image['manifests']}.items():
            with self.subTest(digest_of=name):
                self.assertRegex(digest, r'^sha256:[0-9a-f]{64}$')
        self.assertEqual(len({image['index'], *image['manifests'].values()}), 1 + len(image['manifests']), 'two entries share a digest')

    def test_lock_names_one_binary_under_test(self):
        """The runners start a binary whose SHA-256 is listed here. One entry: there is one build under test."""
        self.assertEqual(len(self.LOCK['sha256']), 1)
        for artefact, digest in self.LOCK['sha256'].items():
            self.assertIn(self.LOCK['image']['binary'], artefact)
            self.assertRegex(digest, r'^[0-9a-f]{64}$')

    def test_the_suites_put_the_same_front_proxy_before_the_gateway(self):
        """The Kubernetes suite's pods and the compose suite's pool carry the front proxy the black-box cases were run with."""
        reference = r"'(public\.ecr\.aws/nginx/nginx-unprivileged:[\w.-]+)'\s*\n?\s*'(@sha256:[0-9a-f]{64})'"
        blackbox = re.search(r'FRONT_IMAGE = \(' + reference, text('tests/acceptance/blackbox/run.py'))
        self.assertIsNotNone(blackbox)
        for suite in ('kubernetes', 'compose'):
            with self.subTest(suite=suite):
                found = re.search(r'FRONT_IMAGE = \(' + reference, text(f'tests/integration/{suite}/run.py'))
                self.assertIsNotNone(found)
                self.assertEqual(blackbox.groups(), found.groups())

    def test_manifest_names_the_pinned_release(self):
        manifest = json.loads(text('docs/governance/project-manifest.json'))
        component = next(c for c in manifest['technology']['components'] if c['id'] == 'AGENTGATEWAY')
        self.assertEqual(component['version'], self.LOCK['version'])
        self.assertEqual(component['source'], self.LOCK['release'])


if __name__ == '__main__':
    unittest.main()
