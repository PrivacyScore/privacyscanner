import re

import dns.resolver

from privacyscanner.scanmodules.chromedevtools.extractors.base import Extractor
from privacyscanner.scanmodules.chromedevtools.utils import parse_domain


class FailedRequestsExtractor(Extractor):
    def extract_information(self):
        requests_lookup = {request['requestId']: request for request in self.page.request_log}
        failed_requests = []
        for failed_request in self.page.failed_request_log:
            error_text = failed_request['errorText']
            valid_errors = ('net::ERR_CACHE_MISS', 'net::ERR_ABORTED')
            if any(error in error_text for error in valid_errors):
                # Requests that were aborted by the site (e.g. a XHR
                # request that was canceled) and cache misses are
                # not considered failed.
                continue
            extra = None
            try:
                request = requests_lookup[failed_request['requestId']]
            except KeyError:
                # Some requests will never be sent because they for example
                # use an invalid URL scheme, so no request will be triggered.
                continue
            if 'net::ERR_NAME_NOT_RESOLVED' in error_text:
                error_type = 'dns-not-resolved'
                # We could not resolve the IP address of this host. One
                # reason might be, that the domain is not registered.
                # To check whether this is the case, we check for the
                # absence of a SOA record for the domain itself, i.e.,
                # not the netloc of the URL. Unregistered domains
                # should have no SOA entry, while registered should.
                domain = parse_domain(request['url']).registered_domain
                try:
                    dns.resolver.query(domain, 'SOA')
                    domain_registered = True
                # If we have a timeout, we better don't say anything about
                # this domain rather than giving a wrong impressing wether
                # the domain is registered or net
                except dns.resolver.Timeout:
                    domain_registered = None
                # Nameservers behave weird, if the domain is not registered.
                # Some send NXDOMAIN as expected, others prefer to give an
                # answer but do not include a SOA entry in the response.
                # Sometimes all nameservers do not like to answer if the
                # domain is not registered. It is a real mess.
                except (dns.resolver.NXDOMAIN, dns.resolver.NoNameservers,
                        dns.resolver.NoAnswer):
                    domain_registered = False
                extra = {'domain_registered': domain_registered}
            elif 'net::ERR_' in error_text:
                error_type = 'unknown'
                match = re.search('net::ERR_([^\s])+', error_text)
                if match:
                    error_type = match.group(1).replace('_', '-').lower()
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
