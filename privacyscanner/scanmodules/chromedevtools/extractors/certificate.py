from base64 import b64decode
from binascii import hexlify
from datetime import datetime

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.dsa import DSAPublicKey
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.x509 import load_der_x509_certificate

from privacyscanner.scanmodules.chromedevtools.extractors.base import Extractor


class CertificateExtractor(Extractor):
    def extract_information(self):
        explanations = self.page.security_state_log[-1]['explanations']
        cert_chain = None
        for explanation in explanations:
            if 'certificate' in explanation:
                cert_chain = explanation['certificate']
                break
        if cert_chain:
            if self.result['tls']['has_tls'] is None:
                self.result['tls']['has_tls'] = True
            self.result['tls']['certificate'] = self._get_certificate_info(cert_chain)

    def _get_certificate_info(self, cert_chain):
        # See https://cryptography.io/en/latest/x509/reference/#cryptography.x509.Certificate
        cert = load_der_x509_certificate(b64decode(cert_chain[0]), backend=default_backend())
        public_key = cert.public_key()
        key_info = {'size': public_key.key_size}
        if isinstance(public_key, RSAPublicKey):
            key_type = 'RSA'
        elif isinstance(public_key, DSAPublicKey):
            key_type = 'DSA'
        elif isinstance(public_key, EllipticCurvePublicKey):
            key_type = 'ECC'
            key_info['curve'] = public_key.curve.name
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
            'is_expired': datetime.now() > cert.not_valid_after
        }
        # TODO: Add extensions
