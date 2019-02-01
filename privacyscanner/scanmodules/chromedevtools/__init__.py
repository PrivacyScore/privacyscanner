from pathlib import Path

from privacyscanner.scanmodules import ScanModule
from privacyscanner.scanmodules.chromedevtools.chromescan import ChromeScan
from privacyscanner.scanmodules.chromedevtools.extractors import FinalUrlExtractor, \
    GoogleAnalyticsExtractor, CookiesExtractor, RequestsExtractor,  RedirectChainExtractor, \
    TLSDetailsExtractor, CertificateExtractor, ThirdPartyExtractor, InsecureContentExtractor, \
    FailedRequestsExtractor, SecurityHeadersExtractor, TrackerDetectExtractor, \
    CookieStatsExtractor, JavaScriptLibsExtractor, ScreenshotExtractor, ImprintExtractor
from privacyscanner.scanmodules.chromedevtools.utils import TLDEXTRACT_CACHE_FILE, parse_domain
from privacyscanner.utils import file_is_outdated, set_default_options


EXTRACTOR_CLASSES = [FinalUrlExtractor, RedirectChainExtractor, GoogleAnalyticsExtractor,
                     CookiesExtractor, RequestsExtractor, TLSDetailsExtractor,
                     CertificateExtractor, ThirdPartyExtractor, InsecureContentExtractor,
                     FailedRequestsExtractor, SecurityHeadersExtractor, TrackerDetectExtractor,
                     CookieStatsExtractor, JavaScriptLibsExtractor, ScreenshotExtractor,
                     ImprintExtractor]


class ChromeDevtoolsScanModule(ScanModule):
    name = 'chromedevtools'
    dependencies = []
    required_keys = ['site_url']

    def __init__(self, options):
        set_default_options(options, {
            'disable_javascript': False
        })
        super().__init__(options)
        cache_file = self.options['storage_path'] / TLDEXTRACT_CACHE_FILE
        parse_domain.cache_file = str(cache_file)

    def scan_site(self, result, logger, meta):
        chrome_scan = ChromeScan(EXTRACTOR_CLASSES)
        debugging_port = self.options.get('start_port', 9222) + meta.worker_id
        chrome_scan.scan(result, logger, self.options, meta, debugging_port)

    def update_dependencies(self):
        max_age = 14 * 24 * 3600
        cache_file = Path(parse_domain.cache_file)
        cache_file.parent.mkdir(parents=True, exist_ok=True)
        if file_is_outdated(cache_file, max_age):
            parse_domain.update(fetch_now=True)
        for extractor_class in EXTRACTOR_CLASSES:
            if hasattr(extractor_class, 'update_dependencies'):
                extractor_class.update_dependencies(self.options)
