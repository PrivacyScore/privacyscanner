from pathlib import Path

from adblockeval import AdblockRules

from privacyscanner.scanmodules.chromedevtools.utils import parse_domain
from privacyscanner.scanmodules.chromedevtools.extractors.base import Extractor
from privacyscanner.utils import download_file


EASYLIST_DOWNLOAD_PREFIX = 'https://easylist.to/easylist/'
EASYLIST_FILES = ['easylist.txt', 'easyprivacy.txt', 'fanboy-annoyance.txt']
EASYLIST_PATH = Path('easylist')

_adblock_rules_cache = None


class TrackerDetectExtractor(Extractor):
    def extract_information(self):
        self._load_rules()
        trackers_fqdn = set()
        trackers_domain = set()
        num_tracker_requests = 0
        blacklist = set()
        num_evaluations = 0
        for request in self.page.request_log:
            request['is_tracker'] = False
            if not request['is_thirdparty'] or request['url'].startswith('data:'):
                continue
            is_tracker = request['parsed_url'].netloc in blacklist
            if not is_tracker:
                # Giving only the first 150 characters of an URL is
                # sufficient to get good matches, so this will speed
                # up checking quite a bit!
                match_result = self.rules.match(request['url'][:150],
                                                request['document_url'])
                is_tracker = match_result.is_match
                num_evaluations += 1
            if is_tracker:
                request['is_tracker'] = True
                extracted = parse_domain(request['url'])
                if extracted.fqdn:
                    trackers_fqdn.add(extracted.fqdn)
                trackers_domain.add(extracted.registered_domain)
                num_tracker_requests += 1
                blacklist.add(request['parsed_url'].netloc)

        num_tracker_cookies = 0
        for cookie in self.result['cookies']:
            is_tracker = False
            domain = cookie['domain']
            if domain in trackers_fqdn or domain in trackers_domain:
                is_tracker = True
            elif domain.startswith('.'):
                reg_domain = parse_domain(domain[1:]).registered_domain
                if reg_domain in trackers_domain:
                    is_tracker = True

            if is_tracker:
                num_tracker_cookies += 1
            cookie['is_tracker'] = is_tracker

        self.result['tracking'] = {
            'trackers': list(sorted(trackers_fqdn)),
            'num_tracker_requests': num_tracker_requests,
            'num_tracker_cookies': num_tracker_cookies
        }

    def _load_rules(self):
        global _adblock_rules_cache

        if _adblock_rules_cache is not None:
            self.rules = _adblock_rules_cache
            return

        easylist_path = self.options['storage_path'] / EASYLIST_PATH
        easylist_files = [easylist_path / filename for filename in EASYLIST_FILES]
        self.rules = AdblockRules(rule_files=easylist_files,
                                  cache_file=easylist_path / 'rules.cache',
                                  skip_parsing_errors=True)
        _adblock_rules_cache = self.rules

    @staticmethod
    def update_dependencies(options):
        easylist_path = options['storage_path'] / EASYLIST_PATH
        easylist_path.mkdir(parents=True, exist_ok=True)
        for filename in EASYLIST_FILES:
            download_url = EASYLIST_DOWNLOAD_PREFIX + filename
            target_file = (easylist_path / filename).open('wb')
            download_file(download_url, target_file)
