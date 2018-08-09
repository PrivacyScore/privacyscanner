from ...utils import file_is_outdated
from .extractors import FinalUrlExtractor, GoogleAnalyticsExtractor, \
    CookiesExtractor, RequestsExtractor, TLSDetailsExtractor, CertificateExtractor, \
    ThirdPartyExtractor, InsecureContentExtractor, FailedRequestsExtractor, \
    SecurityHeadersExtractor, TrackerDetectExtractor, CookieStatsExtractor, \
    JavaScriptLibsExtractor, ScreenshotExtractor, ImprintExtractor
from .chromescan import ChromeScan
from .utils import TLDEXTRACT_CACHE_FILE, tldextract

name = 'chromedevtools'
dependencies = []
required_keys = ['site_url']

EXTRACTOR_CLASSES = [FinalUrlExtractor, GoogleAnalyticsExtractor,
                     CookiesExtractor, RequestsExtractor, TLSDetailsExtractor,
                     CertificateExtractor, ThirdPartyExtractor,
                     InsecureContentExtractor, FailedRequestsExtractor,
                     SecurityHeadersExtractor, TrackerDetectExtractor,
                     CookieStatsExtractor, JavaScriptLibsExtractor,
                     ScreenshotExtractor, ImprintExtractor]


def scan_site(result, logger, options, meta):
    chrome_scan = ChromeScan(EXTRACTOR_CLASSES)
    debugging_port = options.get('start_port', 9222) + meta.worker_id
    chrome_scan.scan(result, logger, options, debugging_port)


def update_dependencies(options):
    max_age = 14 * 24 * 3600
    TLDEXTRACT_CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
    if file_is_outdated(TLDEXTRACT_CACHE_FILE, max_age):
        tldextract.update(now=True)
    for extractor_class in EXTRACTOR_CLASSES:
        if hasattr(extractor_class, 'update_dependencies'):
            extractor_class.update_dependencies(options)