from ..base import AbstractChromeScan


class CookieMixin(AbstractChromeScan):
    def _extract_cookies(self):
        self.result['cookies'] = self.tab.Network.getAllCookies()['cookies']
