from base64 import b64decode

from privacyscanner.scanmodules.chromedevtools.extractors.base import Extractor
from privacyscanner.utils.tls import get_certificate_info


class CertificateExtractor(Extractor):
    def extract_information(self):
        explanations = self.page.security_state_log[-1]['explanations']
        cert_chain = None
        for explanation in explanations:
            if 'certificate' in explanation:
                cert_chain = explanation['certificate']
                break
        if cert_chain:
            if self.result['https']['has_tls'] is None:
                self.result['https']['has_tls'] = True
            cert_der = b64decode(cert_chain[0])
            self.result['https']['certificate'] = get_certificate_info(cert_der)
