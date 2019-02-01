from privacyscanner.scanmodules.chromedevtools.extractors.base import Extractor


class FinalUrlExtractor(Extractor):
    def extract_information(self):
        self.result['final_url'] = self.page.final_response['url']
