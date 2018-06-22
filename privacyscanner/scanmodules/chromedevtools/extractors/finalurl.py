from .base import Extractor


class FinalUrlExtractor(Extractor):
    def extract_information(self):
        response_urls = {response['url'] for response in self.page.response_log}
        history = self.page.tab.Page.getNavigationHistory()
        index = history['currentIndex']
        final_url = self.result['site_url']
        # We look for actual response because JavaScript might tamper with
        # the navigation history (You know, those Angular hipster sites ...)
        while index >= 0:
            entry = history['entries'][index]
            if entry['url'] in response_urls:
                final_url = entry['url']
                break
            index -= 1
        self.result['final_url'] = final_url