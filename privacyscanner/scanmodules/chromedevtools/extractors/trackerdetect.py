import pickle
import sys
from pathlib import Path

# This is a somewhat ugly hack. There are several implementations or re2
# but none of them except cffi_re2 can be installed without pain. However,
# adblockparser checks whether he can import re2 and not whether it can
# import cffi_re2. Therefore we put cffi_re2 into sys.modules as re2
# so adblockparser will import cffi_re2 when importing re2.

try:
    import cffi_re2
    sys.modules['re2'] = cffi_re2
except ModuleNotFoundError:
    pass
from adblockparser import AdblockRules

from privacyscanner.scanmodules.chromedevtools.utils import parse_domain
from privacyscanner.scanmodules.chromedevtools.extractors.base import Extractor
from privacyscanner.utils import download_file


EASYLIST_DOWNLOAD_PREFIX = 'https://easylist.to/easylist/'
EASYLIST_FILES = ['easylist.txt', 'easyprivacy.txt', 'fanboy-annoyance.txt']
EASYLIST_PATH = Path('~/.local/share/privacyscanner/easylist').expanduser()

_adblock_rules_cache = None


class TrackerDetectExtractor(Extractor):
    def extract_information(self):
        self._load_rules()
        trackers_fqdn = set()
        trackers_domain = set()
        num_tracker_requests = 0
        blacklist = set()
        for request in self.page.request_log:
            request['is_tracker'] = False
            if not request['is_thirdparty']:
                continue
            is_tracker = request['parsed_url'].netloc in blacklist
            if not is_tracker:
                # Giving only the first 150 characters of an URL is
                # sufficient to get good matches, so this will speed
                # up checking quite a bit!
                is_tracker = self.rules.should_block(request['url'][:150])
            if is_tracker:
                request['is_tracker'] = True
                extracted = parse_domain(request['url'])
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

        easylist_path = Path(self.options['easylist_path'])
        easylist_files = [easylist_path / filename for filename in EASYLIST_FILES]

        mtime = max(filename.stat().st_mtime for filename in easylist_files)
        if _adblock_rules_cache is not None and _adblock_rules_cache['mtime'] >= mtime:
            self.rules = _adblock_rules_cache['rules']
            return

        cache_file = self.options.get('adblockrules_cache')
        if cache_file:
            cache_file = Path(cache_file)
        if cache_file and cache_file.exists() and cache_file.stat().st_mtime >= mtime:
            with cache_file.open('rb') as f:
                rules = pickle.load(f)
        else:
            lines = []
            for easylist_file in easylist_files:
                for line in (easylist_path / easylist_file).open():
                    # Lines with @@ are exceptions which are not blocked
                    # even if other adblocking rules match. This is done
                    # to fix a few sites. We do not need those exceptions.
                    if line.startswith('@@'):
                        continue
                    lines.append(line)
            rules = AdblockRules(lines)
            if cache_file:
                with cache_file.open('wb') as f:
                    pickle.dump(rules, f, pickle.HIGHEST_PROTOCOL)

        _adblock_rules_cache = {
            'mtime': mtime,
            'rules': rules
        }
        self.rules = rules

    @staticmethod
    def update_dependencies(options):
        EASYLIST_PATH.mkdir(parents=True, exist_ok=True)
        for filename in EASYLIST_FILES:
            download_url = EASYLIST_DOWNLOAD_PREFIX + filename
            target_file = (EASYLIST_PATH / filename).open('wb')
            download_file(download_url, target_file)