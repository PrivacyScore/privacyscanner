from privacyscanner.scanmodules.chromedevtools.extractors.base import Extractor


class RedirectChainExtractor(Extractor):
    def extract_information(self):
        response_chain = []
        for request in self.page.document_request_log:
            response_chain += self.page.get_response_chain_by_id(request['requestId'])
        self.result['redirect_chain'] = [response['url'] for response in response_chain]
