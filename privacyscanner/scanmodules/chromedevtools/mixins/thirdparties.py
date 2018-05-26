import tldextract

from ..base import AbstractChromeScan


class ThirdPartyMixin(AbstractChromeScan):
    def _extract_third_parties(self):
        third_parties = {
            'http': set(),
            'https': set()
        }
        extracted = tldextract.extract(self.result['site_url'])
        first_party_domains = {extracted.registered_domain}
        for request in self.request_log:
            extracted_url = tldextract.extract(request['url'])
            scheme = request['parsed_url'].scheme
            if scheme not in ('http', 'https'):
                continue
            if extracted_url.registered_domain not in first_party_domains:
                third_parties[scheme].add(extracted_url.fqdn)
        for scheme in ('http', 'https'):
            third_parties[scheme] = list(third_parties[scheme])
            third_parties[scheme].sort()
        self.result['third_parties'] = third_parties