from privacyscanner.scanmodules.chromedevtools.utils import parse_domain
from privacyscanner.scanmodules.chromedevtools.extractors.base import Extractor


class ThirdPartyExtractor(Extractor):
    def extract_information(self):
        third_parties = {
            'fqdns': set(),
            'num_http_requests': 0,
            'num_https_requests': 0
        }
        first_party_domains = set()
        for url in (self.result['site_url'], self.result['final_url']):
            extracted = parse_domain(url)
            first_party_domains.add(extracted.registered_domain)
        for request in self.page.request_log:
            request['is_thirdparty'] = False
            extracted_url = parse_domain(request['url'])
            parsed_url = request['parsed_url']
            if extracted_url.registered_domain in first_party_domains:
                continue
            if request['url'].startswith('data:'):
                continue
            request['is_thirdparty'] = True
            third_parties['fqdns'].add(extracted_url.fqdn)
            if parsed_url.scheme not in ('http', 'https'):
                continue
            third_parties['num_{}_requests'.format(parsed_url.scheme)] += 1
        third_parties['fqdns'] = list(third_parties['fqdns'])
        third_parties['fqdns'].sort()
        self.result['third_parties'] = third_parties

        for cookie in self.result['cookies']:
            domain = cookie['domain']
            if domain.startswith('.'):
                domain = domain[1:]
            domain = parse_domain(domain).registered_domain
            cookie['is_thirdparty'] = domain not in first_party_domains
