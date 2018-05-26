import tldextract

from ..base import AbstractChromeScan


class ThirdPartyMixin(AbstractChromeScan):
    def _extract_third_parties(self):
        third_parties = {
            'fqdns': set(),
            'http_requests': [],
            'https_requests': []
        }
        first_party_domains = set()
        for url in (self.result['site_url'], self.result['final_url']):
            extracted = tldextract.extract(url)
            first_party_domains.add(extracted.registered_domain)
        for request in self.request_log:
            extracted_url = tldextract.extract(request['url'])
            parsed_url = request['parsed_url']
            if extracted_url.registered_domain in first_party_domains:
                continue
            third_parties['fqdns'].add(extracted_url.fqdn)
            if parsed_url.scheme not in ('http', 'https'):
                continue
            third_parties[parsed_url.scheme + '_requests'].append(request['url'])
        third_parties['fqdns'] = list(third_parties['fqdns'])
        third_parties['fqdns'].sort()
        self.result['third_parties'] = third_parties