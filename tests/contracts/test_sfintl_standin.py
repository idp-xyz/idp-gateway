"""tests/integration/sfintl/mock_sfintl.py: the stand-in of SF International's open platform does what its header says.

OFFLINE; each test starts a stand-in in this process on an ephemeral loopback port. No sleep is longer than about a second.
The crypto is checked against internal/providersigner/domain/testdata/vectors.json, which the Go code is checked against as well.
"""
import base64, hashlib, http.client, importlib.util, io, json, secrets, struct, time, threading, unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from urllib.parse import urlencode
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

R = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location('mock_sfintl', R / 'tests/integration/sfintl/mock_sfintl.py')
m = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(m)
VECTORS = json.loads((R / 'internal/providersigner/domain/testdata/vectors.json').read_text(encoding='utf-8'))
KEY, APP = m.parse_key(VECTORS['encoding_aes_key']), VECTORS['app_key']
A = {'app_key': APP, 'app_secret': 'secret-of-a', 'encoding_aes_key': VECTORS['encoding_aes_key'], 'api_username': 'user-a'}
B = {'app_key': 'idpgw-test-app-b', 'app_secret': 'secret-of-b', 'api_username': 'user-b',
     'encoding_aes_key': base64.b64encode(bytes(range(64, 96))).decode().rstrip('=')}
KEY_B = m.parse_key(B['encoding_aes_key'])
SECRET = 'admin-secret'
CREATE, CANCEL, QUERY = m.CREATE, m.CANCEL, m.QUERY
BAD_PARAMS = '请求参数错误'
FAILED_CANCEL = {'code': '500', 'msg': '请求服务发生异常', 'success': False}


def seal(key, frame):
    """Encrypt a frame exactly as given (no padding added), so that a test can break the padding or the length."""
    sealer = Cipher(algorithms.AES(key), modes.CBC(key[:16])).encryptor()
    return base64.b64encode(sealer.update(frame) + sealer.finalize()).decode()


def frame(body, app_key=APP, pad=None, length=None):
    plain = b'R' * 16 + struct.pack('>I', len(body) if length is None else length) + body + app_key.encode()
    pad = pad if pad is not None else bytes([32 - len(plain) % 32]) * (32 - len(plain) % 32)
    return plain + pad


def order(number, app=A):
    return {'apiUsername': app['api_username'], 'customerOrderNo': number, 'senderInfo': {'name': 'S'}, 'receiverInfo': {'name': 'R'},
            'parcelInfoList': [{'name': 'P'}]}


def query_body(*pairs):
    return {'service': 'WaybillService', 'waybillList': [{'orderNo': o, 'sfWaybillNo': w} for o, w in pairs]}


class Crypto(unittest.TestCase):
    def test_every_vector_both_ways(self):
        self.assertGreaterEqual(len(VECTORS['cases']), 4)
        for case in VECTORS['cases']:
            body = base64.b64decode(case['body_base64'])
            with self.subTest(case=case['name']):
                self.assertEqual(m.decrypt(KEY, APP, case['ciphertext']), body)
                self.assertEqual(m.encrypt(KEY, APP, body, case['random16'].encode()), case['ciphertext'])
                self.assertEqual(m.sign(VECTORS['token'], case['timestamp'], case['nonce'], case['ciphertext']), case['signature'])

    def test_encrypt_without_random16_makes_sixteen_alphanumeric_bytes_and_a_whole_number_of_blocks(self):
        body = b'{"a":1}'
        first, second = m.encrypt(KEY, APP, body), m.encrypt(KEY, APP, body)
        self.assertNotEqual(first, second)
        for text in (first, second):
            self.assertEqual(len(base64.b64decode(text)) % 32, 0)
            self.assertEqual(m.decrypt(KEY, APP, text), body)
        opener = Cipher(algorithms.AES(KEY), modes.CBC(KEY[:16])).decryptor()
        self.assertRegex(opener.update(base64.b64decode(first))[:16].decode('ascii'), r'^[A-Za-z0-9]{16}$')
        with self.assertRaises(ValueError):
            m.encrypt(KEY, APP, body, b'short')

    def test_parse_key(self):
        self.assertEqual(m.parse_key(VECTORS['encoding_aes_key']), base64.b64decode(VECTORS['encoding_aes_key'] + '='))
        for bad in (VECTORS['encoding_aes_key'][:-1], VECTORS['encoding_aes_key'] + '=', VECTORS['encoding_aes_key'] + '\n',
                    '-' + VECTORS['encoding_aes_key'][1:], '', None):
            with self.subTest(bad=bad), self.assertRaises(m.CryptoError):
                m.parse_key(bad)

    def test_decrypt_refuses_every_defect(self):
        body = b'{"a":1}'                  # with the appKey of the vectors the frame is 50 bytes and wants 14 bytes of padding
        good = m.encrypt(KEY, APP, body, b'ABCDEFGHIJKLMNOP')
        raw = base64.b64decode(good)
        b64 = lambda data: base64.b64encode(data).decode()
        self.assertEqual(m.decrypt(KEY, APP, seal(KEY, frame(body))), body, 'the frame helper below builds what it should')
        defects = {
            'wrong key': (KEY_B, APP, good),
            'key of 16 bytes': (KEY[:16], APP, good),
            'wrong appKey': (KEY, APP[:-1], good),
            'a longer appKey': (KEY, APP + 'x', good),
            'trailer is another appKey': (KEY, APP, seal(KEY, frame(body, app_key='someone-else-key-00001'))),
            'pad byte 0': (KEY, APP, seal(KEY, frame(body, pad=b'\x00' * 14))),
            'pad byte 33': (KEY, APP, seal(KEY, frame(body, pad=b'\x21' * 14))),
            'pad bytes unequal': (KEY, APP, seal(KEY, frame(body, pad=b'\x0e' * 12 + b'\x07\x0e'))),
            'no pad at all (the last byte is the appKey)': (KEY, APP, seal(KEY, frame(b'x' * 21, pad=b''))),
            'length field longer than the body': (KEY, APP, seal(KEY, frame(body, length=9000))),
            'length field shorter than the body': (KEY, APP, seal(KEY, frame(body, length=3))),
            'frame shorter than its header': (KEY, APP, seal(KEY, b'R' * 18 + b'\x0e' * 14)),
            'padded to 16, not to 32': (KEY, APP, seal(KEY, frame(b'', pad=b'\x05' * 5))),
            'truncated by a block of 32 bytes': (KEY, APP, b64(raw[:-32])),
            'the front cut off': (KEY, APP, b64(raw[32:])),
            'truncated by 16 bytes': (KEY, APP, b64(raw[:-16])),
            'truncated base64': (KEY, APP, good[:-4]),
            'one byte flipped in the last block': (KEY, APP, b64(raw[:-1] + bytes([raw[-1] ^ 1]))),
            'empty': (KEY, APP, ''),
            'not base64': (KEY, APP, 'not base64!'),
            'a newline inside': (KEY, APP, good[:8] + '\n' + good[8:]),
        }
        for name, args in defects.items():
            with self.subTest(defect=name), self.assertRaises(m.CryptoError):
                m.decrypt(*args)


class Answer:
    def __init__(self, status, headers, raw, app=None, sent=b''):
        self.status, self.headers, self.raw, self.app, self.sent = status, headers, raw, app, sent

    def header(self, name):
        return [v for k, v in self.headers if k.lower() == name.lower()]

    @property
    def envelope(self):
        return json.loads(self.raw)

    @property
    def plain(self):
        return m.decrypt(m.parse_key(self.app['encoding_aes_key']), self.app['app_key'], self.envelope['apiResultData'])

    @property
    def data(self):
        return json.loads(self.plain)


class Rig:
    """A stand-in on an ephemeral loopback port, and a minimal caller that speaks the carrier's protocol to it."""

    def __init__(self, **extra):
        self.server = m.make_server('127.0.0.1', 0, {'admin_secret': SECRET, 'apps': [A, B], **extra})
        self.port, self.tokens = self.server.server_address[1], {}
        threading.Thread(target=self.server.serve_forever, kwargs={'poll_interval': 0.02}, daemon=True).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()

    def call(self, method, target, body=b'', headers=()):
        connection = http.client.HTTPConnection('127.0.0.1', self.port, timeout=5)
        try:
            connection.putrequest(method, target, skip_accept_encoding=True)
            for pair in headers:
                connection.putheader(*pair)
            if not any(name.lower() == 'content-length' for name, _ in headers):
                connection.putheader('Content-Length', str(len(body)))
            connection.endheaders(body)
            response = connection.getresponse()
            return response.status, response.getheaders(), response.read()
        finally:
            connection.close()

    def issue(self, app, **query):
        query = {'appKey': app['app_key'], 'appSecret': app['app_secret'], **query}
        answer = Answer(*self.call('GET', m.TOKEN_PATH + '?' + urlencode(query)), app)
        if answer.envelope['apiResultCode'] == 0:
            self.tokens[app['app_key']] = answer.envelope['apiResultData']['accessToken']
        return answer

    def dispatch(self, app, msg_type, payload, token=None, *, headers=None, extra=(), timestamp=None, nonce=None, signature=None,
                 ciphertext=None):
        """headers replaces (or, with None, drops) a header; extra adds headers; the other keywords replace what would be computed."""
        body = payload if isinstance(payload, bytes) else json.dumps(payload, ensure_ascii=False, separators=(',', ':')).encode()
        if token is None:
            if app['app_key'] not in self.tokens:
                self.issue(app)
            token = self.tokens[app['app_key']]
        if ciphertext is None:
            ciphertext = m.encrypt(m.parse_key(app['encoding_aes_key']), app['app_key'], body)
        timestamp, nonce = timestamp or str(int(time.time() * 1000)), nonce or secrets.token_hex(16)
        values = {'appKey': app['app_key'], 'token': token, 'timestamp': timestamp, 'nonce': nonce,
                  'signature': signature or m.sign(token, timestamp, nonce, ciphertext), 'msgType': msg_type, 'lang': 'en',
                  'Content-Type': 'application/json', **(headers or {})}
        pairs = [(k, v) for k, v in values.items() if v is not None] + list(extra)
        return Answer(*self.call('POST', m.DISPATCH_PATH, ciphertext.encode(), pairs), app, body)

    def admin(self, method, path, secret=SECRET):
        return self.call(method, path, headers=[('X-Poc-Admin', secret)] if secret else [])

    def hits(self):
        return json.loads(self.admin('GET', '/admin/hits')[2])['hits']

    def orders(self):
        return json.loads(self.admin('GET', '/admin/orders')[2])['orders']


class StandIn(unittest.TestCase):
    def setUp(self):
        self.rig = Rig()
        self.addCleanup(self.rig.close)

    def create(self, number, app=A):
        return self.rig.dispatch(app, CREATE, order(number, app))

    def cancel(self, number, waybill, app=A):
        return self.rig.dispatch(app, CANCEL, {'cancelReason': 'test', 'customerOrderNo': number, 'sfWaybillNo': waybill})

    def query(self, number, waybill, app=A):
        return self.rig.dispatch(app, QUERY, query_body((number, waybill)))

    # ---- the token endpoint

    def test_token_is_issued_as_documented_and_a_second_one_voids_the_first(self):
        first = self.rig.issue(A)
        self.assertEqual((first.status, list(first.envelope)), (200, ['apiResultCode', 'apiErrorMsg', 'apiResultData', 'apiTimestamp']))
        self.assertEqual((first.envelope['apiResultCode'], first.envelope['apiErrorMsg']), (0, None))
        data = first.envelope['apiResultData']
        self.assertEqual((sorted(data), data['expireIn']), (['accessToken', 'expireIn'], 7200))
        self.assertRegex(data['accessToken'], r'^auth_[0-9a-f]{40}$')
        self.assertLess(abs(first.envelope['apiTimestamp'] - time.time() * 1000), 5000)
        old = data['accessToken']
        self.assertEqual(self.create('T-1').envelope['apiResultCode'], 0)
        second = self.rig.issue(A)
        self.assertNotEqual(second.envelope['apiResultData']['accessToken'], old)
        refused = self.rig.dispatch(A, CREATE, order('T-2'), token=old).envelope
        self.assertEqual((refused['apiResultCode'], refused['apiErrorMsg']), (500, 'Access denied, token invalid'))
        self.assertEqual(self.create('T-2').envelope['apiResultCode'], 0)
        self.assertEqual(self.create('T-3', B).envelope['apiResultCode'], 0)         # another app's token is not touched
        self.rig.issue(B)
        self.assertEqual(self.create('T-4').envelope['apiResultCode'], 0)

    def test_token_endpoint_refusals(self):
        self.rig.issue(A)
        for name, query in (('wrong secret', {'appSecret': 'nope'}), ('unknown app', {'appKey': 'nobody'}), ('empty secret', {'appSecret': ''})):
            with self.subTest(name):
                envelope = self.rig.issue(A, **query).envelope
                self.assertEqual((envelope['apiResultCode'], envelope['apiErrorMsg'], envelope['apiResultData']), (1002, '用户不存在', None))
                self.assertEqual(sorted(envelope), ['apiErrorMsg', 'apiResultCode', 'apiResultData', 'apiTimestamp'])
        self.assertEqual(self.create('R-1').envelope['apiResultCode'], 0, 'a refused token request leaves the current token alone')
        for target in ('', '?appKey=' + A['app_key'], '?appSecret=x', '?appKey=a&appKey=b&appSecret=x', '?appKey=a&appSecret=x&appSecret=y'):
            with self.subTest(target=target):
                status, _, raw = self.rig.call('GET', m.TOKEN_PATH + target)
                self.assertEqual((status, json.loads(raw)['apiResultCode'], json.loads(raw)['apiErrorMsg']), (200, 502, BAD_PARAMS))
        self.assertEqual(self.rig.call('POST', m.TOKEN_PATH)[0], 404)

    # ---- the nine checks of a dispatch

    def test_each_check_refuses_with_its_code(self):
        r, now = self.rig, int(time.time() * 1000)
        create, body = (CREATE, order('X-1')), json.dumps(order('X-1')).encode()
        bad = lambda text: dict(ciphertext=text)
        cases = [
            ('content_type', 500, 'system error', create, dict(headers={'Content-Type': 'text/plain'})),
            ('content_type', 500, 'system error', create, dict(headers={'Content-Type': None})),
            ('headers', 502, BAD_PARAMS, create, dict(headers={'nonce': None})),
            ('headers', 502, BAD_PARAMS, create, dict(headers={'appKey': None})),
            ('headers', 502, BAD_PARAMS, create, dict(headers={'msgType': ''})),
            ('headers', 502, BAD_PARAMS, create, dict(headers={'lang': 'fr'})),
            ('headers', 502, BAD_PARAMS, create, dict(extra=[('lang', 'en')])),
            ('token', 500, 'Access denied, token invalid', create, dict(token='auth_nope')),
            ('token', 500, 'Access denied, token invalid', create, dict(headers={'appKey': 'nobody'})),
            ('timestamp', 502, BAD_PARAMS, create, dict(timestamp='yesterday')),
            ('timestamp', 502, BAD_PARAMS, create, dict(timestamp=str(now - 11 * 60 * 1000))),
            ('timestamp', 502, BAD_PARAMS, create, dict(timestamp=str(now + 11 * 60 * 1000))),
            ('timestamp', 502, BAD_PARAMS, create, dict(timestamp=str(now // 1000))),                      # seconds, not milliseconds
            ('signature', 500, '签名验证错误', create, dict(signature='0' * 64)),
            ('decrypt', 505, '请求报文格式不对', create, bad('AAAA')),
            ('decrypt', 505, '请求报文格式不对', create, bad(m.encrypt(KEY_B, APP, body))),
            ('decrypt', 505, '请求报文格式不对', create, bad(m.encrypt(KEY, 'someone-else', body))),
            ('msg_type', 702, '缺少映射配置', ('IECS_PRINT_WAYBILL', order('X-1')), {}),
            ('plaintext', 505, '请求报文格式不对', (CREATE, b'[1]'), {}),
            ('plaintext', 505, '请求报文格式不对', (CREATE, b'not json'), {}),
            ('plaintext', 505, '请求报文格式不对', (CREATE, b'{"a":1}{"b":2}'), {}),
            ('plaintext', 505, '请求报文格式不对', (CREATE, b'{"a":NaN}'), {}),
            ('plaintext', 505, '请求报文格式不对', (CREATE, b''), {}),
        ]
        for at, code, message, args, kwargs in cases:
            with self.subTest(at=at, kwargs=sorted(kwargs)):
                answer = r.dispatch(A, *args, **kwargs)
                self.assertEqual(answer.status, 200)
                self.assertEqual(answer.header('Content-Type'), ['application/json'])
                self.assertEqual({k: v for k, v in answer.envelope.items() if k != 'apiTimestamp'},
                                 {'apiResultCode': code, 'apiErrorMsg': message, 'apiResultData': None})
                self.assertEqual(sorted(answer.envelope), ['apiErrorMsg', 'apiResultCode', 'apiResultData', 'apiTimestamp'])
                self.assertLess(abs(answer.envelope['apiTimestamp'] - time.time() * 1000), 5000)
                self.assertEqual({k: r.hits()[-1][k] for k in ('refused', 'refused_at', 'business_success')}, {'refused': code, 'refused_at': at, 'business_success': None})
        self.assertEqual(r.orders(), [], 'nothing was performed')

    def test_the_first_failing_check_answers(self):
        r = self.rig
        ladder = [('content_type', {'Content-Type': 'text/plain'}, {}), ('headers', {'lang': 'fr'}, {}), ('token', {}, dict(token='auth_nope')),
                  ('timestamp', {}, dict(timestamp='x')), ('signature', {}, dict(signature='0' * 64)), ('decrypt', {}, dict(ciphertext='AAAA'))]
        for i, (at, _, _) in enumerate(ladder):          # a request that fails this check and every later one is refused at this one
            headers, kwargs = {}, {}
            for _, more_headers, more in ladder[i:]:
                headers.update(more_headers)
                kwargs.update(more)
            with self.subTest(expected=at):
                r.dispatch(A, CREATE, order('F-1'), headers=headers, **kwargs)
                self.assertEqual(r.hits()[-1]['refused_at'], at)
        self.assertEqual(r.dispatch(A, 'IECS_NOPE', b'[1]').envelope['apiResultCode'], 702, 'the msgType is checked before the plaintext')

    def test_a_nonce_is_used_up_per_app_only_by_a_request_whose_signature_is_right(self):
        r = self.rig
        self.assertEqual(r.dispatch(A, CREATE, order('N-1'), nonce='fixed', signature='0' * 64).envelope['apiResultCode'], 500)
        self.assertEqual(r.dispatch(A, CREATE, order('N-1'), nonce='fixed').envelope['apiResultCode'], 0, 'the refused one did not use it up')
        again = r.dispatch(A, CREATE, order('N-2'), nonce='fixed', ciphertext='AAAA')
        self.assertEqual((again.envelope['apiResultCode'], again.envelope['apiErrorMsg'], r.hits()[-1]['refused_at']), (502, BAD_PARAMS, 'nonce'))
        self.assertEqual(r.dispatch(B, CREATE, order('N-1', B), nonce='fixed').envelope['apiResultCode'], 0, 'nonces are per app')
        self.assertEqual(r.orders()[-1]['customer_order_no'], 'N-1')

    def test_what_is_accepted_at_the_edges(self):
        r, now = self.rig, int(time.time() * 1000)
        for name, kwargs in (('9 minutes ago', dict(timestamp=str(now - 9 * 60 * 1000))), ('9 minutes ahead', dict(timestamp=str(now + 9 * 60 * 1000))),
                             ('content type with a parameter', dict(headers={'Content-Type': 'application/json; charset=utf-8'})),
                             ('lang zh-CN', dict(headers={'lang': 'zh-CN'})), ('lang zh-HK', dict(headers={'lang': 'zh-HK'}))):
            with self.subTest(name):
                self.assertEqual(r.dispatch(A, QUERY, query_body(('Q', 'W')), **kwargs).envelope['apiResultCode'], 0)

    # ---- the business, as measured

    def test_order_life_cycle_as_measured(self):
        created = self.create('ORD-1')
        waybill = created.data['data']['sfWaybillNo']
        self.assertRegex(waybill, r'^SF6043[0-9]{9}$')
        self.assertEqual(created.plain, ('{"data":{"agentCode":"IB-US","customerOrderNo":"ORD-1","directionCode":"27-IB-US-US",'
                                         '"sfWaybillNo":"%s"},"success":true}' % waybill).encode())
        again = '{"code":"123052","data":{"agentCode":"IB-US","agentWaybillNo":"","customerOrderNo":"ORD-1","directionCode":"27-IB-US-US",' \
                '"sfWaybillNo":"%s"},"success":true}' % waybill
        self.assertEqual(self.create('ORD-1').plain, again.encode())
        other_body = order('ORD-1')
        other_body['parcelInfoList'] = [{'name': 'something else'}]
        self.assertEqual(self.rig.dispatch(A, CREATE, other_body).plain, again.encode(), 'a different body: our assumption, the same answer')
        pending = ('{"code":"1","service":"WaybillService","success":true,"successData":[],"wrongData":[{"description":"代理单号未生成，请稍后再试",'
                   '"orderNo":"ORD-1","sfWaybillNo":"%s","status":"4002"}]}' % waybill).encode()
        self.assertEqual(self.query('ORD-1', waybill).plain, pending)
        self.assertEqual(self.cancel('ORD-1', waybill).plain, b'{"code":"200","msg":"success","success":true}')
        self.assertEqual(self.query('ORD-1', waybill).plain,
                         ('{"code":"1","service":"WaybillService","success":true,"successData":[],"wrongData":[{"description":"顺丰单号或者订单号错误，'
                          '未找到对应的代理单号","orderNo":"ORD-1","sfWaybillNo":"%s","status":"4001"}]}' % waybill).encode())
        fresh = self.create('ORD-1').data
        self.assertNotIn('code', fresh)
        self.assertTrue(fresh['success'])
        self.assertRegex(fresh['data']['sfWaybillNo'], r'^SF6043[0-9]{9}$')
        self.assertNotEqual(fresh['data']['sfWaybillNo'], waybill)
        self.assertEqual(self.rig.orders(), [{'customer_order_no': 'ORD-1', 'sf_waybill_no': waybill, 'state': 'cancelled'},
                                            {'customer_order_no': 'ORD-1', 'sf_waybill_no': fresh['data']['sfWaybillNo'], 'state': 'active'}])

    def test_the_success_envelope_has_exactly_three_members(self):
        answer = self.create('E-1')
        self.assertEqual((answer.status, sorted(answer.envelope)), (200, ['apiResultCode', 'apiResultData', 'apiTimestamp']))
        self.assertEqual((answer.envelope['apiResultCode'], answer.header('Content-Type')), (0, ['application/json']))
        self.assertIsInstance(answer.envelope['apiResultData'], str)
        self.assertLess(abs(answer.envelope['apiTimestamp'] - time.time() * 1000), 5000)

    def test_create_checks_user_and_shape(self):
        wrong_user = dict(order('U-1'), apiUsername='someone')
        self.assertEqual(self.rig.dispatch(A, CREATE, wrong_user).data, {'code': '500', 'msg': '没有此用户|current user not supported', 'success': False})
        self.assertEqual(self.rig.dispatch(A, CREATE, order('U-1', B)).data['msg'], '没有此用户|current user not supported')
        broken = [dict(order('U-1'), customerOrderNo=''), dict(order('U-1'), customerOrderNo=7), dict(order('U-1'), customerOrderNo='x' * 65),
                  dict(order('U-1'), senderInfo=[]), dict(order('U-1'), receiverInfo='r'), dict(order('U-1'), parcelInfoList=[]),
                  dict(order('U-1'), parcelInfoList={})]
        for name in ('customerOrderNo', 'senderInfo', 'receiverInfo', 'parcelInfoList'):
            broken.append({k: v for k, v in order('U-1').items() if k != name})
        for body in broken:
            with self.subTest(body=body):
                self.assertEqual(self.rig.dispatch(A, CREATE, body).data, {'code': '500', 'msg': BAD_PARAMS, 'success': False})
        self.assertEqual(self.rig.orders(), [])
        self.assertTrue(self.create('x' * 64).data['success'])

    def test_a_cancel_that_is_not_for_an_active_order_gets_the_failure_and_changes_nothing(self):
        waybill = self.create('C-1').data['data']['sfWaybillNo']
        good = {'cancelReason': 'r', 'customerOrderNo': 'C-1', 'sfWaybillNo': waybill}
        for name, body in (('unknown order', dict(good, customerOrderNo='C-9')), ('waybill of another order', dict(good, sfWaybillNo='SF6043000000000')),
                           ('no reason', {k: v for k, v in good.items() if k != 'cancelReason'}), ('number is not a string', dict(good, customerOrderNo=1)),
                           ('list as number', dict(good, customerOrderNo=['C-1'])), ('reason is not a string', dict(good, cancelReason=None))):
            with self.subTest(name):
                self.assertEqual(self.rig.dispatch(A, CANCEL, body).data, FAILED_CANCEL)
        self.assertEqual(self.rig.orders()[0]['state'], 'active')
        self.assertTrue(self.cancel('C-1', waybill).data['success'])
        self.assertEqual(self.cancel('C-1', waybill).data, FAILED_CANCEL, 'already cancelled')

    def test_query_shape_and_several_entries(self):
        waybill = self.create('Q-1').data['data']['sfWaybillNo']
        data = self.rig.dispatch(A, QUERY, query_body(('Q-1', waybill), ('Q-1', 'SF6043000000000'), ('Q-2', waybill))).data
        self.assertEqual([(w['orderNo'], w['sfWaybillNo'], w['status']) for w in data['wrongData']],
                         [('Q-1', waybill, '4002'), ('Q-1', 'SF6043000000000', '4001'), ('Q-2', waybill, '4001')])
        self.assertEqual((data['code'], data['successData'], data['success']), ('1', [], True))
        failure = {'code': '500', 'msg': BAD_PARAMS, 'success': False}
        for body in (dict(query_body(('Q-1', waybill)), service='Other'), {'waybillList': [{'orderNo': 'a', 'sfWaybillNo': 'b'}]}, {'service': 'WaybillService'},
                     query_body(), {'service': 'WaybillService', 'waybillList': [{'orderNo': 'a'}]},
                     {'service': 'WaybillService', 'waybillList': [{'orderNo': 1, 'sfWaybillNo': 'b'}]}, {'service': 'WaybillService', 'waybillList': ['a']}):
            with self.subTest(body=body):
                self.assertEqual(self.rig.dispatch(A, QUERY, body).data, failure)

    def test_orders_belong_to_the_app_that_made_them(self):
        waybill = self.create('S-1').data['data']['sfWaybillNo']
        self.assertEqual(self.cancel('S-1', waybill, B).data, FAILED_CANCEL)
        self.assertEqual(self.query('S-1', waybill, B).data['wrongData'][0]['status'], '4001')
        self.assertEqual(self.query('S-1', waybill).data['wrongData'][0]['status'], '4002')
        theirs = self.create('S-1', B).data
        self.assertNotIn('code', theirs, 'the same number at another app is a new order')
        self.assertNotEqual(theirs['data']['sfWaybillNo'], waybill)
        self.assertEqual(self.cancel('S-1', waybill, A).data['code'], '200')
        self.assertEqual(self.query('S-1', theirs['data']['sfWaybillNo'], B).data['wrongData'][0]['status'], '4002')
        self.assertEqual([o['state'] for o in self.rig.orders()], ['cancelled', 'active'])

    # ---- faults

    def fault(self, query):
        self.assertEqual(self.rig.admin('POST', '/admin/fault?' + query)[0], 200)

    def test_slow_holds_back_the_next_create_only(self):
        self.fault('kind=slow&seconds=0.3')
        started = time.monotonic()
        self.assertEqual(self.query('L-1', 'W').envelope['apiResultCode'], 0)
        self.assertEqual(self.rig.dispatch(A, CREATE, order('L-1'), signature='0' * 64).envelope['apiResultCode'], 500)
        self.assertLess(time.monotonic() - started, 0.25, 'a query and a refused create do not use the fault up')
        started = time.monotonic()
        held = self.create('L-1')
        self.assertGreaterEqual(time.monotonic() - started, 0.28)
        self.assertTrue(held.data['success'])
        self.assertEqual(self.rig.orders()[0]['customer_order_no'], 'L-1')
        self.assertEqual(self.rig.hits()[-1]['fault'], {'kind': 'slow', 'seconds': 0.3})
        started = time.monotonic()
        self.create('L-2')
        self.assertLess(time.monotonic() - started, 0.25)
        self.assertIsNone(self.rig.hits()[-1]['fault'])

    def test_cut_performs_the_create_and_cuts_the_answer(self):
        self.fault('kind=cut')
        with self.assertRaises((http.client.IncompleteRead, ConnectionError)):
            self.create('K-1')
        self.assertEqual([o['customer_order_no'] for o in self.rig.orders()], ['K-1'])
        self.assertEqual(self.rig.hits()[-1]['fault'], {'kind': 'cut'})
        self.assertEqual(self.create('K-1').data['code'], '123052', 'the order exists; the answer is whole this time')

    def test_cancel_not_yet_answers_the_failure_and_cancels_nothing_once(self):
        waybill = self.create('N-1').data['data']['sfWaybillNo']
        self.fault('kind=cancel-not-yet')
        self.assertEqual(self.query('N-1', waybill).data['wrongData'][0]['status'], '4002')      # a query leaves it pending
        self.assertEqual(self.cancel('N-1', waybill).data, FAILED_CANCEL)
        self.assertEqual(self.rig.hits()[-1]['fault'], {'kind': 'cancel-not-yet'})
        self.assertEqual(self.rig.orders()[0]['state'], 'active')
        self.assertEqual(self.cancel('N-1', waybill).data['code'], '200')

    def test_status_and_garbage_answer_the_next_dispatch_of_any_kind_and_perform_nothing(self):
        self.fault('kind=status&code=503')
        status, headers, raw = self.rig.call('POST', m.DISPATCH_PATH, b'', [('Content-Type', 'text/plain')])    # not even a proper request
        self.assertEqual((status, raw), (503, b'carrier fault 503'))
        self.assertEqual(self.rig.hits()[-1]['fault'], {'kind': 'status', 'code': 503})
        self.fault('kind=status&code=500')
        self.assertEqual(self.create('G-1').status, 500)
        self.fault('kind=garbage')
        answer = self.create('G-1')
        self.assertEqual((answer.status, answer.header('Content-Type')), (200, ['text/html']))
        with self.assertRaises(ValueError):
            json.loads(answer.raw)
        self.assertEqual(self.rig.orders(), [], 'nothing was performed')
        self.assertEqual(self.rig.hits()[-1]['fault'], {'kind': 'garbage'})
        self.assertEqual(self.create('G-1').data['success'], True)

    def test_undecryptable_performs_the_request_and_answers_with_another_key(self):
        self.fault('kind=undecryptable')
        answer = self.query('U-1', 'W')
        self.assertEqual((answer.status, answer.envelope['apiResultCode']), (200, 0))
        with self.assertRaises(m.CryptoError):
            answer.plain
        self.assertEqual(self.rig.hits()[-1]['fault'], {'kind': 'undecryptable'})
        self.fault('kind=undecryptable')
        self.create('U-1')
        self.assertEqual(len(self.rig.orders()), 1)
        self.assertEqual(self.query('U-1', 'W').data['code'], '1')

    def test_reset_clears_a_pending_fault_and_a_bad_fault_changes_nothing(self):
        self.fault('kind=cut')
        self.assertEqual(self.rig.admin('POST', '/admin/reset')[0], 200)
        self.assertTrue(self.create('Z-1').data['success'])
        self.fault('kind=status&code=503')
        for query in ('kind=nope', 'kind=slow', 'kind=slow&seconds=0', 'kind=slow&seconds=61', 'kind=slow&seconds=x', 'kind=slow&seconds=nan',
                      'kind=status', 'kind=status&code=200', 'kind=status&code=600', 'kind=status&code=x', ''):
            with self.subTest(query=query):
                status, _, raw = self.rig.admin('POST', '/admin/fault?' + query)
                self.assertEqual(status, 400)
                self.assertIn('error', json.loads(raw))
        self.assertEqual(self.create('Z-2').status, 503, 'the pending fault was not replaced')

    # ---- tokens

    def test_void_makes_every_token_invalid(self):
        self.rig.issue(A), self.rig.issue(B)
        self.assertEqual(self.rig.admin('POST', '/admin/tokens/void')[0], 200)
        for app in (A, B):
            envelope = self.rig.dispatch(app, QUERY, query_body(('a', 'b'))).envelope
            self.assertEqual((envelope['apiResultCode'], envelope['apiErrorMsg']), (500, 'Access denied, token invalid'))
        self.rig.issue(A)
        self.assertEqual(self.query('V-1', 'W').envelope['apiResultCode'], 0)

    def test_lifetime_and_expiry(self):
        self.rig.issue(B)
        self.assertEqual(self.rig.admin('POST', '/admin/token-lifetime?seconds=1')[0], 200)
        short = self.rig.issue(A).envelope['apiResultData']
        self.assertEqual(short['expireIn'], 1)
        self.assertEqual(self.query('L-1', 'W').envelope['apiResultCode'], 0)
        time.sleep(1.1)
        envelope = self.query('L-1', 'W').envelope
        self.assertEqual((envelope['apiResultCode'], envelope['apiErrorMsg']), (500, 'Access denied, token invalid'))
        self.assertEqual(self.query('L-1', 'W', B).envelope['apiResultCode'], 0, 'a token issued before keeps the lifetime it had')
        for seconds in ('0', '-1', '1.5', 'x', ''):
            with self.subTest(seconds=seconds):
                self.assertEqual(self.rig.admin('POST', '/admin/token-lifetime?seconds=' + seconds)[0], 400)
        self.assertEqual(self.rig.issue(A).envelope['apiResultData']['expireIn'], 1, 'a bad request changed nothing')

    def test_lifetime_from_the_state_file(self):
        other = Rig(token_lifetime_seconds=3600)
        self.addCleanup(other.close)
        self.assertEqual(other.issue(A).envelope['apiResultData']['expireIn'], 3600)

    # ---- admin, records, headers

    def test_admin_without_the_secret_is_like_any_unknown_path(self):
        self.create('M-1')
        for method, path in (('GET', '/admin/hits'), ('GET', '/admin/orders'), ('POST', '/admin/reset'), ('POST', '/admin/fault?kind=garbage'),
                             ('POST', '/admin/tokens/void'), ('POST', '/admin/token-lifetime?seconds=1'), ('POST', '/admin/nothing'), ('GET', '/nothing')):
            for secret in (None, 'wrong'):
                with self.subTest(path=path, secret=secret):
                    status, _, raw = self.rig.admin(method, path, secret)
                    self.assertEqual((status, raw), (404, b'not found'))
        self.assertEqual(self.rig.admin('GET', '/admin/nothing')[:1], (404,))
        self.assertTrue(self.create('M-2').data['success'], 'no fault, no void: the calls above did nothing')
        hits = self.rig.hits()
        self.assertEqual([h['kind'] for h in hits[:2]], ['token', 'dispatch'])
        self.assertEqual([h['kind'] for h in hits[2:-1]], ['other'] * 16, 'the unauthenticated calls are recorded like any other request')
        self.assertEqual(self.rig.call('GET', '/admin/hits', headers=[('X-Poc-Admin', SECRET)])[0], 200)

    def test_a_dispatch_record(self):
        r = self.rig
        r.issue(A)
        created = self.create('REC-1')
        waybill = created.data['data']['sfWaybillNo']
        self.query('REC-1', waybill)
        self.cancel('REC-1', waybill)
        self.rig.dispatch(A, CREATE, order('REC-2'), ciphertext='AAAA')
        token, create, query, cancel, refused = r.hits()
        common = {'seq', 'at', 'method', 'raw_target', 'headers', 'body_len', 'body_sha256', 'kind'}
        self.assertEqual(set(token), common)
        self.assertEqual((token['kind'], token['method'], token['body_len']), ('token', 'GET', 0))
        self.assertEqual(token['raw_target'], f"{m.TOKEN_PATH}?appKey={A['app_key']}&appSecret={A['app_secret']}")
        self.assertEqual(set(create), common | {'msg_type', 'refused', 'refused_at', 'plaintext_len', 'plaintext_sha256', 'customer_order_no',
                                                'business_success', 'fault'})
        self.assertEqual([h['seq'] for h in r.hits()], [1, 2, 3, 4, 5])
        self.assertLess(abs(create['at'] - time.time()), 5)
        self.assertEqual((create['method'], create['raw_target'], create['kind'], create['msg_type']), ('POST', m.DISPATCH_PATH, 'dispatch', CREATE))
        self.assertEqual([k for k, _ in create['headers']], ['Host', 'appKey', 'token', 'timestamp', 'nonce', 'signature', 'msgType', 'lang',
                                                              'Content-Type', 'Content-Length'])
        self.assertEqual(dict(create['headers'])['appKey'], A['app_key'])
        self.assertEqual(dict(create['headers'])['token'], r.tokens[A['app_key']])
        self.assertEqual(create['body_len'], int(dict(create['headers'])['Content-Length']))
        self.assertEqual((create['refused'], create['refused_at'], create['business_success'], create['fault']), (None, None, True, None))
        self.assertEqual((create['plaintext_len'], create['plaintext_sha256']), (len(created.sent), hashlib.sha256(created.sent).hexdigest()))
        self.assertEqual((create['customer_order_no'], query['customer_order_no'], cancel['customer_order_no']), ('REC-1', 'REC-1', 'REC-1'))
        self.assertEqual((query['msg_type'], cancel['msg_type'], query['business_success'], cancel['business_success']), (QUERY, CANCEL, True, True))
        self.assertEqual({k: refused[k] for k in ('refused', 'refused_at', 'plaintext_len', 'plaintext_sha256', 'customer_order_no', 'business_success')},
                         {'refused': 505, 'refused_at': 'decrypt', 'plaintext_len': None, 'plaintext_sha256': None, 'customer_order_no': None,
                          'business_success': None})
        self.assertEqual(refused['body_sha256'], hashlib.sha256(b'AAAA').hexdigest())
        failed = self.rig.dispatch(A, CREATE, dict(order('REC-3'), apiUsername='x'))
        self.assertIs(r.hits()[-1]['business_success'], False)
        self.assertEqual(r.hits()[-1]['customer_order_no'], 'REC-3')
        self.assertFalse(failed.data['success'])

    def test_reset_clears_the_hits_and_nothing_else(self):
        waybill = self.create('Y-1').data['data']['sfWaybillNo']
        self.assertEqual(self.rig.admin('POST', '/admin/reset')[0], 200)
        self.assertEqual(self.rig.hits(), [])
        self.assertEqual(self.create('Y-1').data['code'], '123052', 'orders and the token are still there')
        self.assertEqual(self.rig.hits()[0]['seq'], 1)
        self.assertEqual(self.rig.orders()[0]['sf_waybill_no'], waybill)
        self.assertEqual(self.rig.dispatch(A, CREATE, order('Y-1'), nonce='used').envelope['apiResultCode'], 0)
        self.rig.admin('POST', '/admin/reset')
        self.assertEqual(self.rig.dispatch(A, CREATE, order('Y-1'), nonce='used').envelope['apiResultCode'], 502, 'nonces are still there')

    def test_every_answer_carries_the_cookie_and_the_provider_header(self):
        r = self.rig
        answers = [r.issue(A), self.create('H-1'), r.dispatch(A, CREATE, order('H-2'), signature='0' * 64), Answer(*r.call('GET', '/nowhere')),
                   Answer(*r.admin('GET', '/admin/hits')), Answer(*r.admin('GET', '/admin/hits', None)), Answer(*r.call('POST', m.TOKEN_PATH)),
                   Answer(*r.call('POST', m.DISPATCH_PATH, b'x', [('Content-Length', 'abc')]))]
        for query in ('kind=status&code=503', 'kind=garbage', 'kind=undecryptable', 'kind=cut'):
            self.fault(query)
            try:
                answers.append(self.create('H-3'))
            except (http.client.IncompleteRead, ConnectionError):
                pass
        self.assertEqual([a.status for a in answers[-3:]], [503, 200, 200])
        for answer in answers:
            with self.subTest(status=answer.status, raw=answer.raw[:20]):
                self.assertEqual((answer.header('Set-Cookie'), answer.header('X-Mock-Provider')), (['carrier_session=mock; Path=/'], ['sfintl']))

    def test_a_request_with_a_framing_the_stand_in_does_not_read_gets_400_and_is_recorded(self):
        status, headers, raw = self.rig.call('POST', m.DISPATCH_PATH, b'', [('Content-Length', 'abc')])
        self.assertEqual((status, raw), (400, b'unsupported request framing'))
        hit = self.rig.hits()[-1]
        self.assertEqual((hit['kind'], hit['body_len'], hit['refused']), ('dispatch', 0, None))

    def test_the_stand_in_writes_nothing_to_stdout_or_stderr(self):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            self.create('P-1')
            self.rig.dispatch(A, CREATE, order('P-2'), ciphertext='AAAA')
            self.rig.call('GET', '/nowhere')
            self.rig.call('POST', m.DISPATCH_PATH, b'x', [('Content-Length', 'abc')])
            self.rig.call('HEAD', m.DISPATCH_PATH)
            self.fault('kind=cut')
            with self.assertRaises((http.client.IncompleteRead, ConnectionError)):
                self.create('P-3')
        self.assertEqual((out.getvalue(), err.getvalue()), ('', ''))

    # ---- several instances, bad state

    def test_two_instances_in_one_process_do_not_share_state(self):
        other = Rig()
        self.addCleanup(other.close)
        mine = self.create('I-1').data['data']['sfWaybillNo']
        self.assertEqual((other.orders(), other.hits()), ([], []))
        refused = other.dispatch(A, CREATE, order('I-1'), token=self.rig.tokens[A['app_key']]).envelope
        self.assertEqual(refused['apiResultCode'], 500, 'a token of one instance means nothing to the other')
        self.assertEqual(other.dispatch(A, CREATE, order('I-1'), token=other.issue(A).envelope['apiResultData']['accessToken']).data['data']['sfWaybillNo'], mine,
                         'each instance counts its own waybill numbers')
        self.fault('kind=garbage')
        self.assertTrue(other.dispatch(A, CREATE, order('I-2')).data['success'], 'a fault is for the instance it was set at')

    def test_bad_state_is_refused_at_start(self):
        good = {'admin_secret': SECRET, 'apps': [A, B]}
        without = {k: v for k, v in A.items() if k != 'api_username'}
        for name, cfg in (('short key', dict(good, apps=[dict(A, encoding_aes_key='short')])), ('same app twice', dict(good, apps=[A, A])),
                          ('no admin secret', dict(good, admin_secret='')), ('lifetime 0', dict(good, token_lifetime_seconds=0)),
                          ('lifetime is a string', dict(good, token_lifetime_seconds='7200')), ('no api_username', dict(good, apps=[without]))):
            with self.subTest(name), self.assertRaises(ValueError):
                m.make_server('127.0.0.1', 0, cfg)


if __name__ == '__main__':
    unittest.main()
