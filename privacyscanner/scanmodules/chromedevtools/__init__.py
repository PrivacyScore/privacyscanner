from .mixins.cookies import CookieMixin
from .mixins.requests import RequestsMixin
from .mixins.certificate import CertificateMixin


name = 'chromedevtools'
dependencies = ['network']
required_keys = ['site_url']


class ChromeScan(RequestsMixin, CookieMixin, CertificateMixin):
    def _initialize_scripts(self):
        pass

    def _extract_information(self):
        self._extract_requests()
        self._extract_cookies()
        self._extract_certificate()

    def _receive_log(self, log_type, message, call_stack):
        pass


def scan_site(result, logger, options):
    chrome_scan = ChromeScan(result, logger, options)
    chrome_scan.scan()
