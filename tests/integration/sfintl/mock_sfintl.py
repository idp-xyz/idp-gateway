#!/usr/bin/env python3
"""A stand-in for the open platform of SF International (IECS export e-commerce), only as far as the facts below go. Loopback, synthetic data.

The four sections are kept apart on purpose: what the documentation says, what was measured at the real sandbox, where the stand-in is
stricter than anything measured, and what is only our assumption. Where nothing is said, the stand-in does the simplest thing.

From the documentation:
  - GET /openapi/api/token?appKey=..&appSecret=.. -> HTTP 200 {"apiResultCode":0,"apiErrorMsg":null,
    "apiResultData":{"expireIn":7200,"accessToken":"auth_..."},"apiTimestamp":<Unix ms>}. In production a token lives 2 hours and
    asking for a new one makes the previous one invalid; in the test environment the token is fixed. The stand-in follows PRODUCTION
    here, on purpose: a new token voids the app's previous one at once (the sandbox does not), so that the suite can show what a
    voided token looks like.
  - POST /openapi/api/dispatch, headers appKey, token, timestamp (Unix ms, decimal), nonce, signature, msgType, lang (en | zh-CN |
    zh-HK), Content-Type: application/json; the body is the ciphertext text only.
  - Key: base64-decode(encodingAesKey + "=") is 32 bytes (encodingAesKey is 43 characters). AES-256-CBC, IV = the first 16 bytes of the
    key. Plaintext frame = 16 random alphanumeric bytes | 4-byte big-endian length of the body | body | appKey, padded PKCS#7-style
    to a multiple of 32 bytes (pad value 1..32). Ciphertext is standard base64. internal/providersigner/domain/testdata/vectors.json
    (made with openssl and hashlib, invented values) holds independent vectors; encrypt, decrypt and sign reproduce them.
  - Signature = lowercase hex SHA-256 of token, timestamp, nonce and ciphertext, sorted byte-wise and concatenated.
  - Answer envelope: apiResultCode (0 is success), apiErrorMsg, apiResultData (with code 0: a ciphertext made the same way, with the
    same key and appKey), apiTimestamp. Codes used here from the documentation's table: 0 success; 500 (system error; "Access denied,
    token invalid"); 502 bad request parameters; 505 request message format wrong; 702 missing mapping configuration;
    1002 user does not exist. The FAQ gives these texts: a wrong Content-Type is answered "system error"; a wrong signature "签名验证错误";
    a create whose apiUsername is not the customer's user name "没有此用户|current user not supported".

Measured at the real sandbox on 2026-11-20 (the documentation does not say; the stand-in follows the measurements):
  - every answer below was HTTP 200, Content-Type application/json; the envelope of a successful dispatch has exactly three members,
    apiResultCode (0), apiResultData, apiTimestamp (no apiErrorMsg);
  - IECS_CREATE_ORDER, new customerOrderNo: {"data":{"agentCode":"IB-US","customerOrderNo":..,"directionCode":"27-IB-US-US",
    "sfWaybillNo":"SF6043..."},"success":true}, no code member;
  - the same create again while the order exists (identical body): {"code":"123052","data":{.. "agentWaybillNo":"" ..},"success":true}
    with the same waybill number; nothing new is made;
  - IECS_QUERY_AGENTNO for an order that exists: {"code":"1","service":"WaybillService","success":true,"successData":[],"wrongData":
    [{"description":"代理单号未生成，请稍后再试",..,"status":"4002"}]}; after the cancel the same shape with "status":"4001" and the
    description "顺丰单号或者订单号错误，未找到对应的代理单号";
  - IECS_CANCEL_ORDER: sent within a few seconds of the create it answered {"code":"500","msg":"请求服务发生异常","success":false} (twice, 1.2 s
    and about 3.6 s after the create) and the order still existed; sent again later {"code":"200","msg":"success","success":true}. The
    stand-in does NOT imitate this timing by itself: a cancel succeeds at once, and the failure is the fault `cancel-not-yet`;
  - after a successful cancel the same customerOrderNo can be used again and makes a new order with a new waybill number;
  - IECS_PRINT_ORDER while the order is active: {"code":"200","data":{"customerOrderNo":<the order's number>,"sfWaybillNo":<waybill>,
    "url":"http://ibu-lomp-core-er-shenzhen-xili1-oss.sit.sf-express.com:8080/v1.2/AUTH_IBU-LOMP-CORE-ER/sfosspublic001/kts-label%2F<hex>.pdf"},
    "success":true}. The request body was {"apiUsername":...,"printWaybillNoDtoList":[{"sfWaybillNo":...}]}. Fetching that url returned
    HTTP 206 application/pdf, beginning with %PDF-, and needed no Authorization header. This stand-in does not serve the PDF and does not
    use that host: the url it returns is http://mock-oss.sfintl.invalid/labels/<waybill>.pdf. The same call after a successful cancel was
    still HTTP 200, apiResultCode 0, code "200", success true, the same sfWaybillNo and the same url, with customerOrderNo suffixed "_cancel".

Stricter than anything measured (our choice, as in the stand-in of the first carrier):
  - a nonce an app used before is refused (502); the sandbox was not tried with a repeated nonce;
  - the timestamp has to be within 10 minutes of the stand-in's clock (the documentation gives no window);
  - the token lifetime is enforced (a token past it is refused as invalid);
  - decrypt takes only a ciphertext of a whole number of 32-byte blocks (the frame is padded to 32); the Go signer's own decrypt takes
    any multiple of 16. The 16 leading bytes are not checked to be alphanumeric.

Our assumptions (not measured, not in the documentation; nothing here is evidence about the real carrier):
  - the member set of every refusal: apiResultCode, apiErrorMsg, apiResultData null, apiTimestamp; every refusal is HTTP 200;
  - which code goes with which refusal. The FAQ gives only the text of the signature refusal (we use 500) and of the Content-Type
    refusal (we use 500, the row for system errors); a missing or empty header, an unknown lang, a bad timestamp and a repeated nonce
    are 502; an undecryptable body or a plaintext that is not one JSON object is 505; an unknown msgType is 702; an unknown appKey or a
    wrong appSecret at the token endpoint is 1002; a token endpoint call without both parameters exactly once is 502;
  - the order of the nine checks (see dispatch) and that Content-Type may carry parameters (application/json; charset=utf-8);
  - only the dispatch answers were measured: that the token endpoint answers HTTP 200 with Content-Type application/json, refusals included,
    is ours, and so are the refusals' headers; a request that is neither a token GET nor a dispatch POST is HTTP 404 with a text body;
  - orders belong to the app that made them and are unique per app, not across apps; another app does not see them;
  - a create with the same order number and a different body gets the 123052 answer as well; the body of a create is checked only for
    apiUsername, customerOrderNo (a string, 1..64 characters), senderInfo and receiverInfo (objects) and a non-empty parcelInfoList;
    a bad body is answered {"code":"500","msg":"请求参数错误","success":false}; a wrong apiUsername {"code":"500","msg":"没有此用户|current user
    not supported","success":false} (the text is from the FAQ, the code 500 is assumed);
  - a cancel of an order that does not exist, is already cancelled, or whose numbers are not its own, or a body of another shape,
    gets the measured failure of a too early cancel; a query body has to be {"service":"WaybillService","waybillList":[non-empty list of
    objects with string orderNo and sfWaybillNo]}, else {"code":"500","msg":"请求参数错误","success":false};
  - waybill numbers are SF6043 and a 9-digit serial counted from 100001 in this process; tokens are auth_ and 40 hex digits;
  - IECS_PRINT_ORDER. A wrong apiUsername gets the create's user failure (code "500", "没有此用户|current user not supported").
    printWaybillNoDtoList must be a non-empty list of objects, each with a non-empty string sfWaybillNo, else code "500" and
    "请求参数错误". A waybill this app did not create, including another app's, is the same "请求参数错误" (not measured; orders belong
    to the app that made them, and a cancelled order stays findable by its waybill). One entry returns the measured single-object data,
    with the synthetic url above. More than one entry was not measured: if onePdf is not false (the documentation's default is true) the
    answer is that same shape for the first waybill only; if onePdf is false, data also has printWaybillNoDtoList, one object per waybill,
    and the other data fields are the first waybill's. An unknown waybill anywhere in the list fails the whole call. version, printPicking
    and fileFormat are ignored. The dispatch record's customer_order_no stays null: the print body has sfWaybillNo and no customerOrderNo.
Faults, for the cases that need the carrier to misbehave (default: none; each is for the next matching dispatch only, then it is gone,
a refused dispatch does not use up a fault that needs a performed one; /admin/reset clears a pending one):
  POST /admin/fault?kind=slow&seconds=N     the next create is performed and its answer is held back N seconds (0 < N <= 60);
  POST /admin/fault?kind=cut                the next create is performed and the answer is cut off half way through its body (connection closed);
  POST /admin/fault?kind=cancel-not-yet     the next cancel answers the measured code "500" failure and cancels nothing;
  POST /admin/fault?kind=status&code=N      the next dispatch of any kind answers HTTP status N (400..599) with a short text; nothing is performed;
  POST /admin/fault?kind=garbage            the next dispatch answers HTTP 200 with a body that is not JSON; nothing is performed;
  POST /admin/fault?kind=undecryptable      the next dispatch is performed, but apiResultData is a ciphertext made with a different key.
Admin (header X-Poc-Admin equal to the secret in the state file; without it these paths are like any unknown path: HTTP 404, and they
are recorded like any other request):
  GET /admin/hits -> {"hits": [...]}; POST /admin/reset clears the hits and a pending fault (not orders, tokens or nonces);
  GET /admin/orders -> {"orders": [{customer_order_no, sf_waybill_no, state: active | cancelled}]}, every order made in this process,
  no app and no body; POST /admin/tokens/void makes every app's current token invalid (what another system asking for a token for the
  same app does in production); POST /admin/token-lifetime?seconds=N lets tokens issued from now on live N seconds (N a whole number >= 1).
  A wrong parameter to a fault or to token-lifetime is HTTP 400 {"error": ..} and changes nothing.
Every request that is not an admin call is recorded as the stand-in received it: seq, at (epoch seconds), method, raw_target, headers
(every header in order, [[name, value], ..]), body_len, body_sha256 and kind (token | dispatch | other). A dispatch also has msg_type,
refused (null, or the apiResultCode it was refused with), refused_at (the failed check: content_type, headers, token, timestamp,
signature, nonce, decrypt, msg_type, plaintext), plaintext_len and plaintext_sha256 (when the body decrypted), customer_order_no (the
plaintext's customerOrderNo, else the first waybillList[].orderNo; a print body has neither, so the field stays null), business_success
and fault (the fault applied, or null).
THE RECORDS HOLD CREDENTIALS: the target of a token request holds the app secret, the headers of a dispatch hold appKey and token. The
state file holds the secrets and AES keys of the apps. The stand-in writes nothing to stderr or stdout; the suite reads the records at
/admin/hits and keeps them out of its own output.
Every answer, a refusal as well, carries `Set-Cookie: carrier_session=mock; Path=/` and `X-Mock-Provider: sfintl`: what a carrier must not be
able to do to the caller (the suite checks that none of it reaches the caller).

State file (JSON): {"admin_secret": "..", "token_lifetime_seconds": 7200, "apps": [{"app_key": "..", "app_secret": "..",
"encoding_aes_key": "<43 characters>", "api_username": ".."}, ..]}; token_lifetime_seconds is optional.
make_server(host, port, cfg) gives an independent instance (all state is in server.carrier), so a test can run several in one process.
"""
from __future__ import annotations
import argparse, base64, hashlib, json, re, secrets, socket, string, struct, threading, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qsl, urlsplit

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

TOKEN_PATH, DISPATCH_PATH = '/openapi/api/token', '/openapi/api/dispatch'
CREATE, CANCEL, QUERY, PRINT = 'IECS_CREATE_ORDER', 'IECS_CANCEL_ORDER', 'IECS_QUERY_AGENTNO', 'IECS_PRINT_ORDER'
MSG_TYPES = (CREATE, CANCEL, QUERY, PRINT)
LANGS = ('en', 'zh-CN', 'zh-HK')
REQUIRED = ('appKey', 'token', 'timestamp', 'nonce', 'signature', 'msgType', 'lang')
WINDOW_MS = 10 * 60 * 1000
BLOCK, FRAME_HEADER = 32, 20             # the frame is padded to 32 bytes; 16 random bytes and a 4-byte length come before the body
ALPHABET = string.ascii_letters + string.digits
JSON = 'application/json'


# ---- the carrier's cryptography: plain functions, for the suites and the unit test ------------------------------------------------

class CryptoError(ValueError):
    """decrypt found a defect. The text says which kind and never holds any of the data."""


def parse_key(encoded: str) -> bytes:
    if not isinstance(encoded, str) or not re.fullmatch(r'[A-Za-z0-9+/]{43}', encoded):
        raise CryptoError('encodingAesKey is not 43 base64 characters')
    return base64.b64decode(encoded + '=')


def _cipher(key: bytes) -> Cipher:
    if not isinstance(key, bytes) or len(key) != 32:      # algorithms.AES would take 16 or 24 bytes as well
        raise CryptoError('the key is not 32 bytes')
    return Cipher(algorithms.AES(key), modes.CBC(key[:16]))


def encrypt(key: bytes, app_key: str, body: bytes, random16: bytes | None = None) -> str:
    if random16 is None:
        random16 = ''.join(secrets.choice(ALPHABET) for _ in range(16)).encode()
    if len(random16) != 16:
        raise ValueError('random16 is not 16 bytes')
    frame = random16 + struct.pack('>I', len(body)) + body + app_key.encode('utf-8')
    pad = BLOCK - len(frame) % BLOCK
    sealer = _cipher(key).encryptor()
    return base64.b64encode(sealer.update(frame + bytes([pad]) * pad) + sealer.finalize()).decode('ascii')


def decrypt(key: bytes, app_key: str, ciphertext: str) -> bytes:
    """The body in the ciphertext. Raises CryptoError on any defect: not base64, not whole 32-byte blocks, a pad byte that is not
    1..32 or a pad of unequal bytes, a frame shorter than its header, a length field that does not fit, a trailer that is not appKey."""
    try:
        data = base64.b64decode(ciphertext, validate=True)
    except ValueError:
        raise CryptoError('ciphertext is not valid base64') from None
    if not data or len(data) % BLOCK:
        raise CryptoError('ciphertext is not a non-empty whole number of 32-byte blocks')
    opener = _cipher(key).decryptor()
    frame = opener.update(data) + opener.finalize()
    pad = frame[-1]
    if not 1 <= pad <= BLOCK or frame[-pad:] != bytes([pad]) * pad:
        raise CryptoError('padding is invalid')
    frame = frame[:-pad]
    if len(frame) < FRAME_HEADER:
        raise CryptoError('frame is shorter than its header')
    length = struct.unpack('>I', frame[16:FRAME_HEADER])[0]
    if length > len(frame) - FRAME_HEADER:
        raise CryptoError('declared body length does not fit the frame')
    end = FRAME_HEADER + length
    if frame[end:] != app_key.encode('utf-8'):
        raise CryptoError('the trailer is not the appKey')
    return frame[FRAME_HEADER:end]


def sign(token: str, timestamp: str, nonce: str, ciphertext: str) -> str:
    parts = sorted(s.encode('utf-8', 'surrogateescape') for s in (token, timestamp, nonce, ciphertext))
    return hashlib.sha256(b''.join(parts)).hexdigest()


# ---- the carrier ---------------------------------------------------------------------------------------------------------------------

def _json(value) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(',', ':')).encode('utf-8')


def _refusal(code: int, message: str, now_ms: int) -> dict:
    return {'apiResultCode': code, 'apiErrorMsg': message, 'apiResultData': None, 'apiTimestamp': now_ms}


def _failure(code: str, message: str) -> dict:
    return {'code': code, 'msg': message, 'success': False}


def _plain_object(raw: bytes):
    """The one JSON object in raw, or None. Strict: UTF-8 only, no NaN or Infinity, nothing after the object."""
    def refuse(constant):
        raise ValueError(constant)
    try:
        value = json.loads(raw.decode('utf-8'), parse_constant=refuse)
    except ValueError:
        return None
    return value if isinstance(value, dict) else None


def _order_no(plain: dict):
    number = plain.get('customerOrderNo')
    if not isinstance(number, str):
        items = plain.get('waybillList')
        number = items[0].get('orderNo') if isinstance(items, list) and items and isinstance(items[0], dict) else None
    return number if isinstance(number, str) else None


class Reply:
    """What the handler sends: the status, the body, and the faults that act on the sending."""
    def __init__(self, status: int, body: bytes, content_type: str = JSON, hold: float = 0.0, cut: bool = False, close: bool = False):
        self.status, self.body, self.content_type, self.hold, self.cut, self.close = status, body, content_type, hold, cut, close


NOT_FOUND = Reply(404, b'not found', 'text/plain')


class App:
    def __init__(self, entry: dict):
        for name in ('app_key', 'app_secret', 'encoding_aes_key', 'api_username'):
            if not isinstance(entry.get(name), str) or not entry[name]:
                raise ValueError(f'an app needs a non-empty string {name}')
        self.app_key, self.app_secret, self.api_username = entry['app_key'], entry['app_secret'], entry['api_username']
        self.key = parse_key(entry['encoding_aes_key'])
        self.token, self.token_expires = None, 0.0     # the current token; the expiry is on the monotonic clock
        self.nonces: set[str] = set()
        self.active: dict[str, dict] = {}              # customerOrderNo -> order, only the orders that are not cancelled
        self.orders_by_waybill: dict[str, dict] = {}   # sfWaybillNo -> the same order dict, while it is active and after it is cancelled


def _lifetime(value) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ValueError('a token lifetime is a whole number of seconds, 1 or more')
    return value


class Carrier:
    """All the state of one stand-in. Every method that changes it is called with `lock` held, except admin() which takes it itself."""

    def __init__(self, cfg: dict):
        self.admin_secret = cfg['admin_secret']
        if not isinstance(self.admin_secret, str) or not self.admin_secret:
            raise ValueError('admin_secret is a non-empty string')
        self.lifetime = _lifetime(cfg.get('token_lifetime_seconds', 7200))
        self.apps: dict[str, App] = {}
        for entry in cfg['apps']:
            app = App(entry)
            if app.app_key in self.apps:
                raise ValueError('an app_key is listed twice')
            self.apps[app.app_key] = app
        self.lock = threading.Lock()
        self.hits: list[dict] = []
        self.orders: list[dict] = []     # every order ever made in this process: {customer_order_no, sf_waybill_no, state}
        self.fault: dict | None = None   # the fault for the next matching dispatch
        self.serial = 100000

    @staticmethod
    def now_ms() -> int:
        return int(time.time() * 1000)

    def record(self, method: str, target: str, headers, body: bytes, kind: str) -> dict:
        hit = {'seq': len(self.hits) + 1, 'at': round(time.time(), 3), 'method': method, 'raw_target': target,
               'headers': [[k, v] for k, v in headers.items()], 'body_len': len(body),
               'body_sha256': hashlib.sha256(body).hexdigest(), 'kind': kind}
        if kind == 'dispatch':
            hit.update(msg_type=headers.get('msgType'), refused=None, refused_at=None, plaintext_len=None, plaintext_sha256=None,
                       customer_order_no=None, business_success=None, fault=None)
        self.hits.append(hit)
        return hit

    def take_fault(self, kinds) -> dict | None:
        if self.fault is not None and self.fault['kind'] in kinds:
            fault, self.fault = self.fault, None
            return fault
        return None

    # -- GET /openapi/api/token

    def token(self, hit: dict, query: str) -> Reply:
        pairs = parse_qsl(query, keep_blank_values=True)
        names = [name for name, _ in pairs]
        if names.count('appKey') != 1 or names.count('appSecret') != 1:
            return Reply(200, _json(_refusal(502, '请求参数错误', self.now_ms())))
        given = dict(pairs)
        app = self.apps.get(given['appKey'])
        if app is None or not secrets.compare_digest(app.app_secret.encode('utf-8'), given['appSecret'].encode('utf-8')):
            return Reply(200, _json(_refusal(1002, '用户不存在', self.now_ms())))
        app.token, app.token_expires = 'auth_' + secrets.token_hex(20), time.monotonic() + self.lifetime   # the previous token is void
        return Reply(200, _json({'apiResultCode': 0, 'apiErrorMsg': None,
                                 'apiResultData': {'expireIn': self.lifetime, 'accessToken': app.token}, 'apiTimestamp': self.now_ms()}))

    # -- POST /openapi/api/dispatch

    def dispatch(self, hit: dict, headers, body: bytes) -> Reply:
        """The nine checks, in this order, each a refusal (HTTP 200, apiResultCode N): 1 content_type, 2 headers, 3 token, 4 timestamp,
        5 signature, 6 nonce, 7 decrypt, 8 msg_type, 9 plaintext. Then the business answer. A status or garbage fault comes before all."""
        fault = self.take_fault(('status', 'garbage'))
        if fault:
            hit['fault'] = fault
            if fault['kind'] == 'garbage':
                return Reply(200, b'<html><body>gateway busy</body></html>', 'text/html')
            return Reply(fault['code'], f'carrier fault {fault["code"]}'.encode(), 'text/plain')

        def refuse(at: str, code: int, message: str) -> Reply:
            hit['refused'], hit['refused_at'] = code, at
            return Reply(200, _json(_refusal(code, message, self.now_ms())))

        types = headers.get_all('Content-Type') or []
        if len(types) != 1 or types[0].split(';')[0].strip().lower() != JSON:
            return refuse('content_type', 500, 'system error')
        got = {}
        for name in REQUIRED:
            values = headers.get_all(name) or []
            if len(values) != 1 or not values[0].strip():
                return refuse('headers', 502, '请求参数错误')
            got[name] = values[0]
        if got['lang'] not in LANGS:
            return refuse('headers', 502, '请求参数错误')
        app = self.apps.get(got['appKey'])
        if app is None or app.token is None or got['token'] != app.token or time.monotonic() >= app.token_expires:
            return refuse('token', 500, 'Access denied, token invalid')
        if not re.fullmatch(r'[0-9]{1,16}', got['timestamp']) or abs(int(got['timestamp']) - self.now_ms()) > WINDOW_MS:
            return refuse('timestamp', 502, '请求参数错误')
        ciphertext = body.decode('utf-8', 'surrogateescape')
        if sign(got['token'], got['timestamp'], got['nonce'], ciphertext) != got['signature']:
            return refuse('signature', 500, '签名验证错误')
        if got['nonce'] in app.nonces:
            return refuse('nonce', 502, '请求参数错误')
        app.nonces.add(got['nonce'])
        try:
            raw = decrypt(app.key, app.app_key, ciphertext)
        except CryptoError:
            return refuse('decrypt', 505, '请求报文格式不对')
        hit['plaintext_len'], hit['plaintext_sha256'] = len(raw), hashlib.sha256(raw).hexdigest()
        plain = _plain_object(raw)
        if plain is not None:
            hit['customer_order_no'] = _order_no(plain)
        msg_type = got['msgType']
        if msg_type not in MSG_TYPES:
            return refuse('msg_type', 702, '缺少映射配置')
        if plain is None:
            return refuse('plaintext', 505, '请求报文格式不对')

        kinds = ('undecryptable',) + {CREATE: ('slow', 'cut'), CANCEL: ('cancel-not-yet',)}.get(msg_type, ())
        fault = self.take_fault(kinds)
        hit['fault'] = fault
        if fault and fault['kind'] == 'cancel-not-yet':
            answer = _failure('500', '请求服务发生异常')
        else:
            answer = {CREATE: self._create, CANCEL: self._cancel, QUERY: self._query, PRINT: self._print}[msg_type](app, plain)
        hit['business_success'] = answer['success']
        key = bytes(b ^ 0xFF for b in app.key) if fault and fault['kind'] == 'undecryptable' else app.key
        envelope = {'apiResultCode': 0, 'apiResultData': encrypt(key, app.app_key, _json(answer)), 'apiTimestamp': self.now_ms()}
        return Reply(200, _json(envelope), hold=fault['seconds'] if fault and fault['kind'] == 'slow' else 0.0,
                     cut=bool(fault and fault['kind'] == 'cut'))

    def _create(self, app: App, plain: dict) -> dict:
        if plain.get('apiUsername') != app.api_username:
            return _failure('500', '没有此用户|current user not supported')
        number, parcels = plain.get('customerOrderNo'), plain.get('parcelInfoList')
        if (not isinstance(number, str) or not 1 <= len(number) <= 64 or not isinstance(plain.get('senderInfo'), dict)
                or not isinstance(plain.get('receiverInfo'), dict) or not isinstance(parcels, list) or not parcels):
            return _failure('500', '请求参数错误')
        order = app.active.get(number)
        if order is not None:        # measured: the same create again makes nothing new, the answer carries the existing waybill number
            return {'code': '123052', 'data': {'agentCode': 'IB-US', 'agentWaybillNo': '', 'customerOrderNo': number,
                                               'directionCode': '27-IB-US-US', 'sfWaybillNo': order['sf_waybill_no']}, 'success': True}
        self.serial += 1
        order = {'customer_order_no': number, 'sf_waybill_no': f'SF6043{self.serial:09d}', 'state': 'active'}
        self.orders.append(order)
        app.active[number] = order
        app.orders_by_waybill[order['sf_waybill_no']] = order
        return {'data': {'agentCode': 'IB-US', 'customerOrderNo': number, 'directionCode': '27-IB-US-US',
                         'sfWaybillNo': order['sf_waybill_no']}, 'success': True}

    def _cancel(self, app: App, plain: dict) -> dict:
        if all(isinstance(plain.get(name), str) for name in ('sfWaybillNo', 'customerOrderNo', 'cancelReason')):
            order = app.active.get(plain['customerOrderNo'])
            if order is not None and order['sf_waybill_no'] == plain['sfWaybillNo']:
                order['state'] = 'cancelled'
                del app.active[order['customer_order_no']]
                return {'code': '200', 'msg': 'success', 'success': True}
        return _failure('500', '请求服务发生异常')

    def _query(self, app: App, plain: dict) -> dict:
        items = plain.get('waybillList')
        if (plain.get('service') != 'WaybillService' or not isinstance(items, list) or not items
                or not all(isinstance(i, dict) and isinstance(i.get('orderNo'), str) and isinstance(i.get('sfWaybillNo'), str) for i in items)):
            return _failure('500', '请求参数错误')
        wrong = []
        for item in items:
            order = app.active.get(item['orderNo'])
            known = order is not None and order['sf_waybill_no'] == item['sfWaybillNo']
            wrong.append({'description': '代理单号未生成，请稍后再试' if known else '顺丰单号或者订单号错误，未找到对应的代理单号',
                          'orderNo': item['orderNo'], 'sfWaybillNo': item['sfWaybillNo'], 'status': '4002' if known else '4001'})
        return {'code': '1', 'service': 'WaybillService', 'success': True, 'successData': [], 'wrongData': wrong}

    def _print(self, app: App, plain: dict) -> dict:
        if plain.get('apiUsername') != app.api_username:
            return _failure('500', '没有此用户|current user not supported')
        items = plain.get('printWaybillNoDtoList')
        if (not isinstance(items, list) or not items or not all(
                isinstance(item, dict) and isinstance(item.get('sfWaybillNo'), str) and item['sfWaybillNo'] for item in items)):
            return _failure('500', '请求参数错误')
        rendered = []
        for item in items:
            bill = item['sfWaybillNo']
            order = app.orders_by_waybill.get(bill)
            if order is None:        # not measured: an unknown waybill, including one that belongs to another app
                return _failure('500', '请求参数错误')
            customer = order['customer_order_no'] + ('_cancel' if order['state'] == 'cancelled' else '')
            rendered.append({'customerOrderNo': customer, 'sfWaybillNo': bill,
                             'url': f'http://mock-oss.sfintl.invalid/labels/{bill}.pdf'})
        # One entry is the shape measured on 2026-11-20. More than one is the assumption in the header.
        if len(rendered) == 1 or plain.get('onePdf', True) is not False:
            return {'code': '200', 'data': rendered[0], 'success': True}
        data = dict(rendered[0])
        data['printWaybillNoDtoList'] = rendered
        return {'code': '200', 'data': data, 'success': True}

    # -- /admin/...

    def admin(self, method: str, path: str, query: str) -> Reply:
        given = dict(parse_qsl(query))
        with self.lock:
            if (method, path) == ('GET', '/admin/hits'):
                return Reply(200, _json({'hits': self.hits}))
            if (method, path) == ('GET', '/admin/orders'):
                return Reply(200, _json({'orders': self.orders}))
            if (method, path) == ('POST', '/admin/reset'):
                self.hits.clear()
                self.fault = None
            elif (method, path) == ('POST', '/admin/tokens/void'):
                for app in self.apps.values():
                    app.token = None
            elif (method, path) == ('POST', '/admin/token-lifetime'):
                try:
                    self.lifetime = _lifetime(int(given.get('seconds', '')))
                except ValueError as error:
                    return Reply(400, _json({'error': str(error)}))
            elif (method, path) == ('POST', '/admin/fault'):
                try:
                    self.fault = self._parse_fault(given)
                except ValueError as error:
                    return Reply(400, _json({'error': str(error)}))
            else:
                return Reply(404, b'{}')
            return Reply(200, _json({'ok': True}))

    @staticmethod
    def _parse_fault(given: dict) -> dict:
        kind = given.get('kind')
        if kind == 'slow':
            seconds = float(given.get('seconds', ''))
            if not 0 < seconds <= 60:
                raise ValueError('seconds is a number above 0 and up to 60')
            return {'kind': kind, 'seconds': seconds}
        if kind == 'status':
            code = int(given.get('code', ''))
            if not 400 <= code <= 599:
                raise ValueError('code is a status from 400 to 599')
            return {'kind': kind, 'code': code}
        if kind in ('cut', 'cancel-not-yet', 'garbage', 'undecryptable'):
            return {'kind': kind}
        raise ValueError('kind is slow, cut, cancel-not-yet, status, garbage or undecryptable')


class Handler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    server_version = 'mock-sfintl'
    wbufsize = 1 << 16        # the headers and the body leave in one segment; unbuffered, Nagle and a delayed ACK add 40 ms to every answer

    def log_message(self, *a):
        pass

    def _send(self, reply: Reply):
        if reply.hold:
            time.sleep(reply.hold)      # outside the lock: a held-back answer must not stop the other requests
        try:
            self.send_response(reply.status)
            self.send_header('Content-Type', reply.content_type)
            self.send_header('Content-Length', str(len(reply.body)))
            self.send_header('X-Mock-Provider', 'sfintl')
            # What a carrier must not be able to do to the caller (tests the gateway's response header removal).
            self.send_header('Set-Cookie', 'carrier_session=mock; Path=/')
            if reply.close:
                self.send_header('Connection', 'close')
            self.end_headers()
            if self.command == 'HEAD':
                return
            if reply.cut:
                self.wfile.write(reply.body[:len(reply.body) // 2])
                self.wfile.flush()
                self.close_connection = True
                self.connection.shutdown(socket.SHUT_RDWR)
            else:
                self.wfile.write(reply.body)
        except OSError:       # the caller gave up on a held-back answer: nothing to say
            self.close_connection = True

    def _body(self) -> bytes | None:
        """The request body; None for a framing the stand-in does not read (chunked, or a Content-Length that is not a number)."""
        if self.headers.get('Transfer-Encoding') is not None:
            return None
        length = (self.headers.get('Content-Length') or '0').strip()
        if not re.fullmatch(r'[0-9]{1,9}', length):
            return None
        return self.rfile.read(int(length)) if int(length) else b''

    def _handle(self):
        carrier, body = self.server.carrier, self._body()
        parts = urlsplit(self.path)
        if parts.path.startswith('/admin/') and self.headers.get('X-Poc-Admin') == carrier.admin_secret:
            return self._send(carrier.admin(self.command, parts.path, parts.query))
        kind = {('GET', TOKEN_PATH): 'token', ('POST', DISPATCH_PATH): 'dispatch'}.get((self.command, parts.path), 'other')
        with carrier.lock:
            hit = carrier.record(self.command, self.path, self.headers, body or b'', kind)
            if body is None:
                reply = Reply(400, b'unsupported request framing', 'text/plain', close=True)
            elif kind == 'token':
                reply = carrier.token(hit, parts.query)
            elif kind == 'dispatch':
                reply = carrier.dispatch(hit, self.headers, body)
            else:
                reply = NOT_FOUND
        self._send(reply)

    do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = do_HEAD = do_OPTIONS = _handle


class Server(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address, carrier: Carrier):
        super().__init__(address, Handler)
        self.carrier = carrier

    def handle_error(self, request, client_address):
        pass        # the default prints a traceback to stderr; this stand-in writes nothing


def make_server(host: str, port: int, cfg: dict) -> Server:
    """A stand-in on host:port (port 0: an ephemeral one, see server_address) with its own state. The caller runs serve_forever()."""
    return Server((host, port), Carrier(cfg))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--port', type=int, required=True)
    parser.add_argument('--host', default='127.0.0.1', help='the pool runs it in a container: 0.0.0.0')
    parser.add_argument('--state', required=True, help='JSON: {"admin_secret": .., "token_lifetime_seconds": 7200, "apps": [{"app_key", "app_secret", '
                                                       '"encoding_aes_key", "api_username"}]}')
    args = parser.parse_args()
    with open(args.state, encoding='utf-8') as state:
        cfg = json.load(state)
    make_server(args.host, args.port, cfg).serve_forever()


if __name__ == '__main__':
    main()
