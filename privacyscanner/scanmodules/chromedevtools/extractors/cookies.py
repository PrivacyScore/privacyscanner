from privacyscanner.scanmodules.chromedevtools.extractors.base import Extractor


class CookiesExtractor(Extractor):
    def extract_information(self):
        cookies = self.page.tab.Network.getAllCookies()['cookies']
        timestamp = int(self.page.scan_start.timestamp())
        for cookie in cookies:
            if cookie['session'] or cookie['expires'] is None:
                cookie['lifetime'] = -1
            else:
                cookie['lifetime'] = cookie['expires'] - timestamp
        self.result['cookies'] = cookies
