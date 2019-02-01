from privacyscanner.scanmodules.chromedevtools.extractors.base import Extractor


class RedirectChainExtractor(Extractor):
    def extract_information(self):
        request_id = self.page.request_log[0]['requestId']
        response_chain = self.page.get_response_chain_by_id(request_id)
        self.result['redirect_chain'] = [response['url'] for response in response_chain]
