from privacyscanner.scanmodules.chromedevtools.extractors.base import Extractor


class CookieSyncExtractor(Extractor):

    def extract_information(self):
        cookies_synced = []
        self.result['cookiesync'] = cookies_synced
