from .extractors import FinalUrlExtractor, GoogleAnalyticsExtractor, \
    CookiesExtractor, RequestsExtractor, TLSDetailsExtractor, CertificateExtractor, \
    ThirdPartyExtractor, InsecureContentExtractor, FailedRequestsExtractor, \
    SecurityHeadersExtractor, TrackerDetectExtractor, CookieStatsExtractor, \
    JavaScriptLibsExtractor
from .chromescan import ChromeScan

name = 'chromedevtools'
dependencies = []
required_keys = ['site_url']


def scan_site(result, logger, options):
    extractor_classes = [FinalUrlExtractor, GoogleAnalyticsExtractor,
                         CookiesExtractor, RequestsExtractor, TLSDetailsExtractor,
                         CertificateExtractor, ThirdPartyExtractor,
                         InsecureContentExtractor, FailedRequestsExtractor,
                         SecurityHeadersExtractor, TrackerDetectExtractor,
                         CookieStatsExtractor, JavaScriptLibsExtractor]
    chrome_scan = ChromeScan(result, logger, options, extractor_classes)
    chrome_scan.scan()
