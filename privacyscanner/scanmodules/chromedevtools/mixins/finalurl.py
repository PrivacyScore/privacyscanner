from ..base import AbstractChromeScan

class FinalUrlMixin(AbstractChromeScan):
    def _extract_final_url(self):
        response_urls = {response['url'] for response in self.response_log}
        history = self.tab.Page.getNavigationHistory()
        index = history['currentIndex']
        final_url = self.result['site_url']
        # We look for actual response because JavaScript might tamper with
        # the navigation history (You know, those Angular hipster sites ...)
        while index >= 0:
            entry = history['entries'][index]
            print('looking for', entry)
            if entry['url'] in response_urls:
                final_url = entry['url']
                break
            index -= 1
        self.result['final_url'] = final_url