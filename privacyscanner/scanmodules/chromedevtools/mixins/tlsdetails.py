from ..utils import camelcase_to_underscore
from ..base import AbstractChromeScan


class TLSDetailsMixin(AbstractChromeScan):
    def _extract_tls_details(self):
        response_lookup = {response['url']: response for response in self.response_log}
        response = response_lookup[self.result['final_url']]

        if 'securityDetails' not in response:
            self.result['tls'] = {
                'has_tls': False,
                'details': None
            }

        details = {}
        # See https://chromedevtools.github.io/devtools-protocol/tot/Network#type-SecurityDetails
        properties = [
            # Protocol name (e.g. "TLS 1.2" or "QUIC")
            'protocol',
            # Key Exchange used by the connection, or the empty string
            # if not applicable.
            'keyExchange',
            # (EC)DH group used by the connection, if applicable.
            'keyExchangeGroup',
            # Cipher name.
            'cipher',
            # TLS MAC. Note that AEAD ciphers do not have separate MACs.
            'mac',
            # TODO: The following might be also interesting
            # signedCertificateTimestampList
            # certificateTransparencyCompliance
        ]

        for key, value in response['securityDetails'].items():
            if key not in properties:
                continue
            details[camelcase_to_underscore(key)] = value

        self.result['tls'] = {
            'has_tls': True,
        }
        self.result['tls'].update(details)
