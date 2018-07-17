from .extractors import FinalUrlExtractor, GoogleAnalyticsExtractor, \
    CookiesExtractor, RequestsExtractor, TLSDetailsExtractor, CertificateExtractor, \
    ThirdPartyExtractor, InsecureContentExtractor, FailedRequestsExtractor, \
    SecurityHeadersExtractor, TrackerDetectExtractor, CookieStatsExtractor, \
    JavaScriptLibsExtractor, ScreenshotExtractor
from .chromescan import ChromeScan

name = 'chromedevtools'
dependencies = []
required_keys = ['site_url']


def scan_site(result, logger, options, worker_id):
    extractor_classes = [FinalUrlExtractor, GoogleAnalyticsExtractor,
                         CookiesExtractor, RequestsExtractor, TLSDetailsExtractor,
                         CertificateExtractor, ThirdPartyExtractor,
                         InsecureContentExtractor, FailedRequestsExtractor,
                         SecurityHeadersExtractor, TrackerDetectExtractor,
                         CookieStatsExtractor, JavaScriptLibsExtractor,
                         ScreenshotExtractor]
    chrome_scan = ChromeScan(extractor_classes)
    debugging_port = options.get('start_port', 9222) + worker_id
    chrome_scan.scan(result, logger, options, debugging_port)
