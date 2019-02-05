from privacyscanner.scanmodules.chromedevtools.extractors.base import Extractor
from privacyscanner.scanmodules.chromedevtools.utils import camelcase_to_underscore


class TLSDetailsExtractor(Extractor):
    def extract_information(self):
        redirects_secure = None
        redirects_insecure = None
        if self.result['site_url'].startswith('http://'):
            redirects_secure = self.result['final_url'].startswith('https://')
            if redirects_secure:
                redirects_insecure = False
        if self.result['site_url'].startswith('https://'):
            redirects_insecure = self.result['final_url'].startswith('http://')
            if redirects_insecure:
                redirects_secure = False

        self.result['https'] = {
            'has_tls': None,
            'redirects_secure': redirects_secure,
            'redirects_insecure': redirects_insecure
        }

        if redirects_insecure:
            response = self.page.response_log[0]
        else:
            response = self.page.final_response
        if response is None:
            self.logger.error('Could not get response for final_url')
            return

        if 'securityDetails' not in response:
            self.result['https']['has_tls'] = False
            return

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
        if 'mac' not in details:
            details['mac'] = None

        self.result['https']['has_tls'] = True
        self.result['https'].update(details)
