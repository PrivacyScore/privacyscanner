import dns.resolver
import tldextract

from .base import Extractor


class FailedRequestsExtractor(Extractor):
    def extract_information(self):
        requests_lookup = {request['requestId']: request for request in self.page.request_log}
        failed_requests = []
        for failed_request in self.page.failed_request_log:
            error_text = failed_request['errorText']
            if 'net::ERR_ABORTED' in error_text:
                # Requests that were aborted by the site (e.g. a XHR
                # request that was canceled) are not considered failed.
                continue
            extra = None
            request = requests_lookup[failed_request['requestId']]
            if 'net::ERR_NAME_NOT_RESOLVED' in error_text:
                error_type = 'dns-not-resolved'
                # We could not resolve the IP address of this host. One
                # reason might be, that the domain is not registered.
                # To check whether this is the case, we check for the
                # absence of a SOA record for the domain itself, i.e.,
                # not the netloc of the URL. Unregistered domains
                # should have no SOA entry, while registered should.
                domain = tldextract.extract(request['url']).registered_domain
                try:
                    dns.resolver.query(domain, 'SOA')
                    domain_registered = True
                except dns.resolver.NXDOMAIN:
                    domain_registered = False
                extra = {'domain_registered': domain_registered}
            elif 'net::ERR_UNKNOWN_URL_SCHEME' in error_text:
                error_type = 'unknown-url-scheme'
            else:
                error_type = 'unknown'
            error = {
                'url': request['url'],
                'error_type': error_type,
            }
            if extra is not None:
                error.update(extra)
            if error_type == 'unknown':
                error['error_text'] = error_text
            failed_requests.append(error)
        self.result['failed_requests'] = failed_requests
