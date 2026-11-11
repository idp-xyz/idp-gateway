"""Per-run workload PKI for the P1 PoC, and the TLS plumbing the mocks and the runner share.

A CA and a handful of leaf certificates are generated for each run and thrown away with
.run/. Identities are SPIFFE-style URIs in the certificate's subjectAltName. This is a
stand-in for a workload identity system: there is no SPIFFE Workload API, no rotation and
no certificate revocation here.
"""
from __future__ import annotations
import datetime, http.client, os, socket, ssl
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

GATEKEEPER_NAME = 'gatekeeper.idp.test'   # the name the PDP's certificate is verified for
READBACK_NAME = 'egress-gateway.idp.test'  # the name the gateway's read-back listener is verified for
ID = {
    'gatekeeper': 'spiffe://idp.test/gatekeeper',
    'gateway': 'spiffe://idp.test/egress/agentgateway',        # may ask for a decision and a credential
    'broker': 'spiffe://idp.test/egress/credential-broker',    # may ask for a decision only
    'operator': 'spiffe://idp.test/poc/operator',              # the runner: PoC controls of the mock
    'business-app': 'spiffe://idp.test/apps/parcel-service',   # a real workload, but not a gateway
    'publisher': 'spiffe://idp.test/gateway-control/publisher',  # publishes the configuration and reads it back
}
# file name -> (issuing CA, identity, the DNS name a server certificate is for; None: a client certificate)
LEAVES = {
    'gatekeeper': ('ca', 'gatekeeper', GATEKEEPER_NAME),
    'gateway': ('ca', 'gateway', None),
    'gateway-readback': ('ca', 'gateway', READBACK_NAME),   # what the gateway serves its read-back listener with
    'broker': ('ca', 'broker', None),
    'operator': ('ca', 'operator', None),
    'business-app': ('ca', 'business-app', None),
    'publisher': ('ca', 'publisher', None),
    # Same names, signed by a CA nobody was told to trust.
    'rogue-gateway': ('rogue-ca', 'gateway', None),
    'rogue-gatekeeper': ('rogue-ca', 'gatekeeper', GATEKEEPER_NAME),
    'rogue-publisher': ('rogue-ca', 'publisher', None),
}


def _key_pem(key) -> bytes:
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())


def _write(path: Path, data: bytes):
    path.write_bytes(data)
    os.chmod(path, 0o600)


def issue(tls_dir: Path, hours: int = 6):
    """Create ca / rogue-ca and every leaf in LEAVES as <name>.crt and <name>.key."""
    tls_dir.mkdir(parents=True, exist_ok=True)
    now = datetime.datetime.now(datetime.timezone.utc)
    valid = lambda b: b.not_valid_before(now - datetime.timedelta(minutes=5)).not_valid_after(now + datetime.timedelta(hours=hours))
    cas = {}
    for name, cn in (('ca', 'IDP PoC workload CA'), ('rogue-ca', 'A CA outside the trust domain')):
        key = ec.generate_private_key(ec.SECP256R1())
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
        cert = (valid(x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key())
                      .serial_number(x509.random_serial_number()))
                .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
                .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True, content_commitment=False,
                                             key_encipherment=False, data_encipherment=False, key_agreement=False,
                                             encipher_only=False, decipher_only=False), critical=True)
                .sign(key, hashes.SHA256()))
        cas[name] = (key, cert)
        _write(tls_dir / f'{name}.crt', cert.public_bytes(serialization.Encoding.PEM))   # CA keys are not kept
    for name, (ca, identity, served_name) in LEAVES.items():
        ca_key, ca_cert = cas[ca]
        key = ec.generate_private_key(ec.SECP256R1())
        sans = [x509.UniformResourceIdentifier(ID[identity])] + ([x509.DNSName(served_name)] if served_name else [])
        usage = ExtendedKeyUsageOID.SERVER_AUTH if served_name else ExtendedKeyUsageOID.CLIENT_AUTH
        cert = (valid(x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)]))
                      .issuer_name(ca_cert.subject).public_key(key.public_key()).serial_number(x509.random_serial_number()))
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                .add_extension(x509.SubjectAlternativeName(sans), critical=False)
                .add_extension(x509.ExtendedKeyUsage([usage]), critical=False)
                .sign(ca_key, hashes.SHA256()))
        _write(tls_dir / f'{name}.crt', cert.public_bytes(serialization.Encoding.PEM))
        _write(tls_dir / f'{name}.key', _key_pem(key))


def server_context(tls_dir: Path, name: str = 'gatekeeper', client_ca: str | None = 'ca') -> ssl.SSLContext:
    """TLS server that requires a client certificate from client_ca (None: asks for none)."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(tls_dir / f'{name}.crt', tls_dir / f'{name}.key')
    if client_ca:
        ctx.load_verify_locations(tls_dir / f'{client_ca}.crt')
        ctx.verify_mode = ssl.CERT_REQUIRED
    return ctx


def client_context(tls_dir: Path, name: str | None, ca: str = 'ca') -> ssl.SSLContext:
    """TLS client that verifies the server against ca and presents <name>'s certificate (None: presents none)."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_verify_locations(tls_dir / f'{ca}.crt')
    if name:
        ctx.load_cert_chain(tls_dir / f'{name}.crt', tls_dir / f'{name}.key')
    return ctx


def peer_identity(tls_socket) -> str:
    """The URI subjectAltName of the verified peer certificate, or '' when there is exactly none."""
    cert = tls_socket.getpeercert() or {}
    uris = [value for kind, value in cert.get('subjectAltName', ()) if kind == 'URI']
    return uris[0] if len(uris) == 1 else ''


class GatekeeperConnection(http.client.HTTPSConnection):
    """Connects to the loopback port, verifies the certificate for name (GATEKEEPER_NAME unless given)."""

    def __init__(self, port: int, context: ssl.SSLContext, timeout: float, name: str = GATEKEEPER_NAME):
        super().__init__(name, port, timeout=timeout, context=context)
        self._tls, self._name = context, name

    def connect(self):
        sock = socket.create_connection(('127.0.0.1', self.port), self.timeout)
        try:
            self.sock = self._tls.wrap_socket(sock, server_hostname=self._name)
        except BaseException:
            sock.close()
            raise
