from binascii import hexlify
from datetime import datetime

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.dsa import DSAPublicKey
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.x509 import load_der_x509_certificate

from privacyscanner.utils.cipherinfo import lookup_ciphersuite


def get_certificate_info(cert_der):
    # See https://cryptography.io/en/latest/x509/reference/#cryptography.x509.Certificate
    cert = load_der_x509_certificate(cert_der, backend=default_backend())
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


def get_cipher_info(cipher_tuple):
    cipher_string, protocol, bits = cipher_tuple
    return _build_cipher_info(lookup_ciphersuite(cipher_string), protocol)


def _build_cipher_info(cipher_info, protocol):
    if 'symmetric' not in cipher_info:
        raise RuntimeError('OpenSSL 1.1 is required. Even Debian 9 has it.')
    cipher = cipher_info['symmetric'].replace('-', '_').upper()
    params = _parse_openssl_description(cipher_info['description'])
    key_exchange = None
    if 'Kx' in params:
        key_exchange = params['Kx']
    if 'Au':
        key_exchange += '_' + params['Au']
    # Unfortunately, OpenSSL does not provide any information about the group.
    key_exchange_group = None
    mac = None
    if 'mac' in params:
        # AHEAD ciphers do not have a MAC
        mac = params['mac'] if params['mac'] != 'AHEAD' else None
    return {
        'cipher': cipher,
        'key_exchange': key_exchange,
        'key_exchange_group': None,
        'mac': mac,
        'protocol': protocol.replace('TLSv', 'TLS '),
    }


def _parse_openssl_description(description):
    parts = description.split()
    result = {}
    for part in parts:
        if '=' in part:
            key, value = part.split('=', 1)
            result[key] = value
    result['name'] = parts[0]
    result['protocol'] = parts[1]
    return result
