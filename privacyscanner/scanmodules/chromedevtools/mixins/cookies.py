from ..base import AbstractChromeScan


class CookieMixin(AbstractChromeScan):
    def _extract_cookies(self):
        cookies = self.tab.Network.getAllCookies()['cookies']
        timestamp = int(self.scan_start.timestamp())
        for cookie in cookies:
            if cookie['session']:
                cookie['lifetime'] = -1
            else:
                cookie['lifetime'] = cookie['expires'] - timestamp
        self.result['cookies'] = cookies
