from pathlib import Path

from privacyscanner.filehandlers import NoOpFileHandler
from privacyscanner.result import Result
from privacyscanner.scanmodules import ScanModule
from privacyscanner.scanmodules.chromedevtools.chromescan import ChromeScan, find_chrome_executable
from privacyscanner.scanmodules.chromedevtools.extractors import FinalUrlExtractor, \
    GoogleAnalyticsExtractor, CookiesExtractor, RequestsExtractor, RedirectChainExtractor, \
    TLSDetailsExtractor, CertificateExtractor, ThirdPartyExtractor, InsecureContentExtractor, \
    FailedRequestsExtractor, SecurityHeadersExtractor, TrackerDetectExtractor, \
    CookieStatsExtractor, JavaScriptLibsExtractor, ScreenshotExtractor, ImprintExtractor, \
    HSTSPreloadExtractor, FingerprintingExtractor
from privacyscanner.scanmodules.chromedevtools.utils import TLDEXTRACT_CACHE_FILE, parse_domain
from privacyscanner.utils import file_is_outdated, set_default_options, calculate_jaccard_index


EXTRACTOR_CLASSES = [FinalUrlExtractor, RedirectChainExtractor, GoogleAnalyticsExtractor,
                     CookiesExtractor, RequestsExtractor, TLSDetailsExtractor,
                     CertificateExtractor, ThirdPartyExtractor, InsecureContentExtractor,
                     FailedRequestsExtractor, SecurityHeadersExtractor, TrackerDetectExtractor,
                     CookieStatsExtractor, JavaScriptLibsExtractor, ScreenshotExtractor,
                     ImprintExtractor, HSTSPreloadExtractor, FingerprintingExtractor]

EXTRACTOR_CLASSES_HTTPS_RUN = [FinalUrlExtractor, TLSDetailsExtractor, CertificateExtractor,
                               InsecureContentExtractor, SecurityHeadersExtractor,
                               HSTSPreloadExtractor]


class ChromeDevtoolsScanModule(ScanModule):
    name = 'chromedevtools'
    dependencies = []
    required_keys = ['site_url']

    def __init__(self, options):
        if 'chrome_executable' not in options:
            options['chrome_executable'] = find_chrome_executable()
        set_default_options(options, {
            'disable_javascript': False,
            'https_same_content_threshold': 0.9,
            'profile_directory': None,
        })
        super().__init__(options)
        cache_file = self.options['storage_path'] / TLDEXTRACT_CACHE_FILE
        parse_domain.cache_file = str(cache_file)

    def scan_site(self, result, meta):
        chrome_scan = ChromeScan(EXTRACTOR_CLASSES)
        debugging_port = self.options.get('start_port', 9222) + meta.worker_id
        content = chrome_scan.scan(result, self.logger, self.options, meta, debugging_port)
        if not result['reachable']:
            return
        result['https']['same_content'] = None
        result['https']['same_content_score'] = None
        if result['site_url'].startswith('http://') and not result['https']['redirects_secure']:
            # Lets do another scan with https but with limited extractors.
            # We use this to annotate the http result with TLS details and
            # insecure content details if there is not redirect to https
            site_url = 'https://' + result['site_url'][len('http://'):]
            extra_result = Result({'site_url': site_url}, NoOpFileHandler())
            chrome_scan = ChromeScan(EXTRACTOR_CLASSES_HTTPS_RUN)
            https_content = chrome_scan.scan(extra_result, self.logger, self.options, meta,
                                             debugging_port)
            if not extra_result['reachable']:
                return
            similarity = calculate_jaccard_index(content, https_content)
            same_content = similarity >= self.options['https_same_content_threshold']
            if same_content:
                result['insecure_content'] = extra_result['insecure_content']
                result['https'] = extra_result['https']
                result['https']['redirects_secure'] = False
            result['https']['same_content_score'] = similarity
            result['https']['same_content'] = same_content

    def update_dependencies(self):
        max_age = 14 * 24 * 3600
        cache_file = Path(parse_domain.cache_file)
        cache_file.parent.mkdir(parents=True, exist_ok=True)
        if file_is_outdated(cache_file, max_age):
            parse_domain.update(fetch_now=True)
        for extractor_class in EXTRACTOR_CLASSES:
            if hasattr(extractor_class, 'update_dependencies'):
                extractor_class.update_dependencies(self.options)
