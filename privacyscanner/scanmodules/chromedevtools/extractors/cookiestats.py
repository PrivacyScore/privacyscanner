from privacyscanner.scanmodules.chromedevtools.extractors.base import Extractor
from privacyscanner.scanmodules.chromedevtools.utils import parse_domain


class CookieStatsExtractor(Extractor):
    long_cookie_time = 24 * 60 * 60

    def extract_information(self):
        stats = {}
        for party in ('first', 'third'):
            for duration in ('short', 'long'):
                stats['{}_party_{}'.format(party, duration)] = 0
        cookietrackers = set()
        for cookie in self.result['cookies']:
            prefix = 'third' if cookie['is_thirdparty'] else 'first'
            suffix = 'long' if cookie['lifetime'] > self.long_cookie_time else 'short'
            stats['{}_party_{}'.format(prefix, suffix)] += 1
            if cookie['is_tracker']:
                tracker = parse_domain(cookie['domain'])
                cookietrackers.add(tracker.registered_domain)
        stats['trackers'] = list(sorted(cookietrackers))
        self.result['cookiestats'] = stats
