from .mixins.finalurl import FinalUrlMixin
from .mixins.googleanalytics import GoogleAnalyticsMixin
from .mixins.cookies import CookieMixin
from .mixins.requests import RequestsMixin
from .mixins.tlsdetails import TLSDetailsMixin
from .mixins.certificate import CertificateMixin
from .mixins.thirdparties import ThirdPartyMixin
from .mixins.insecurecontent import InsecureContentMixin
from .mixins.failedrequests import FailedRequestsMixin
from .mixins.responses import ResponsesMixin
from .mixins.securityheaders import SecurityHeadersMixin
from .mixins.trackerdetect import TrackerDetectMixin


name = 'chromedevtools'
dependencies = []
required_keys = ['site_url']


class ChromeScan(FinalUrlMixin, RequestsMixin, CookieMixin, TLSDetailsMixin,
                 CertificateMixin, GoogleAnalyticsMixin, ThirdPartyMixin,
                 InsecureContentMixin, FailedRequestsMixin, ResponsesMixin,
                 SecurityHeadersMixin, TrackerDetectMixin):
    def _initialize_scripts(self):
        pass

    def _extract_information(self):
        self._extract_final_url()
        self._extract_requests()
        self._extract_cookies()
        self._extract_tls_details()
        self._extract_certificate()
        self._extract_google_analytics()
        self._extract_third_parties()
        self._extract_security_state()
        self._extract_failed_requests()
        # TODO: Discuss if we really need the responses
        # self._extract_responses()
        self._extract_security_headers()
        self._extract_trackers()

    def _receive_log(self, log_type, message, call_stack):
        pass


def scan_site(result, logger, options):
    chrome_scan = ChromeScan(result, logger, options)
    chrome_scan.scan()
