from base64 import b64decode
from binascii import hexlify

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.dsa import DSAPublicKey
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.x509 import load_der_x509_certificate, NameOID

from ..base import AbstractChromeScan


class CertificateMixin(AbstractChromeScan):
    def _extract_certificate(self):
        self.result['certificate'] = self._get_certificate(self.result['site_url'])

    def _get_certificate(self, url):
        # See https://cryptography.io/en/latest/x509/reference/#cryptography.x509.Certificate
        cert_chain = self.tab.Network.getCertificate(origin=url)['tableNames']
        if not cert_chain:
            return None
        cert = load_der_x509_certificate(b64decode(cert_chain[0]), backend=default_backend())
        public_key = cert.public_key()
        key_info = {'size': public_key.key_size}
        if isinstance(public_key, RSAPublicKey):
            key_type = 'RSA'
        elif isinstance(public_key, DSAPublicKey):
            key_type = 'DSA'
        elif isinstance(public_key, EllipticCurvePublicKey):
            key_type = 'ECC'
            key_info['curve'] = public_key.curve
        else:
            raise ValueError('Invalid key type.')
        key_info['type'] = key_type
        return {
            'version': cert.version.name,
            'fingerprint_sha256': hexlify(cert.fingerprint(hashes.SHA256())).decode(),
            'serial_number': cert.serial_number,
            'not_valid_before': cert.not_valid_before.timestamp(),
            'not_valid_after': cert.not_valid_after.timestamp(),
            'issuer':  {attr.oid._name: attr.value for attr in cert.issuer},
            'subject': {attr.oid._name: attr.value for attr in cert.subject},
            'key': key_info,
        }
        # TODO: Add extensions
