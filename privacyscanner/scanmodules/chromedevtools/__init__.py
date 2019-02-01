import re
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

EXTRACTOR_CLASSES_HTTPS_RUN = [FinalUrlExtractor, TLSDetailsExtractor, CertificateExtractor,
                               InsecureContentExtractor]


class ChromeDevtoolsScanModule(ScanModule):
    name = 'chromedevtools'
    dependencies = []
    required_keys = ['site_url']

    def __init__(self, options):
        set_default_options(options, {
            'disable_javascript': False,
            'https_same_content_threshold': 0.9
        })
        super().__init__(options)
        cache_file = self.options['storage_path'] / TLDEXTRACT_CACHE_FILE
        parse_domain.cache_file = str(cache_file)

    def scan_site(self, result, logger, meta):
        chrome_scan = ChromeScan(EXTRACTOR_CLASSES)
        debugging_port = self.options.get('start_port', 9222) + meta.worker_id
        content = chrome_scan.scan(result, logger, self.options, meta, debugging_port)
        if not result['reachable']:
            return
        result['https']['same_content'] = None
        result['https']['same_content_score'] = None
        if result['site_url'].startswith('http://') and not result['https']['redirect']:
            # Lets do another scan with https but with limited extractors.
            # We use this to annotate the http result with TLS details and
            # insecure content details if there is not redirect to https
            site_url = 'https://' + result['site_url'][len('http://'):]
            extra_result = {'site_url': site_url}
            chrome_scan = ChromeScan(EXTRACTOR_CLASSES_HTTPS_RUN)
            https_content = chrome_scan.scan(extra_result, logger, self.options, meta,
                                             debugging_port)
            if not extra_result['reachable']:
                return
            similarity = _calculate_jaccard_index(content, https_content)
            same_content = similarity >= self.options['https_same_content_threshold']
            if same_content:
                result['insecure_content'] = extra_result['insecure_content']
                result['https'] = extra_result['https']
                result['https']['redirect'] = False
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


def _calculate_jaccard_index(a: bytes, b: bytes) -> float:
    """Calculate the jaccard similarity of a and b."""
    pattern = re.compile(rb'[ \n]')
    # remove tokens containing / to prevent wrong classifications for
    # absolute paths
    a = {token for token in pattern.split(a) if b'/' not in token}
    b = {token for token in pattern.split(b) if b'/' not in token}
    intersection = a.intersection(b)
    union = a.union(b)
    return len(intersection) / len(union)
