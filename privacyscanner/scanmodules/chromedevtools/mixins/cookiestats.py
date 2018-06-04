from collections import defaultdict

import tldextract

from ..base import AbstractChromeScan


class CookieStataMixin(AbstractChromeScan):
    long_cookie_time = 24 * 60 * 60

    def _extract_cookiestats(self):
        stats = defaultdict(lambda: 0)
        cookietrackers = set()
        for cookie in self.result['cookies']:
            prefix = 'third' if cookie['is_thirdparty'] else 'first'
            suffix = 'long' if cookie['lifetime'] > self.long_cookie_time else 'short'
            stats['{}_party_{}'.format(prefix, suffix)] += 1
            if cookie['is_tracker']:
                tracker = tldextract.extract(cookie['domain'])
                cookietrackers.add(tracker.registered_domain)

        self.result['cookiestats'] = dict(stats)
        self.result['cookiestats']['trackers'] = list(sorted(cookietrackers))
