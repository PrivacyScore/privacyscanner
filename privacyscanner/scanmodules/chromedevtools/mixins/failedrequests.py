from ..base import AbstractChromeScan


class FailedRequestsMixin(AbstractChromeScan):
    def _extract_failed_requests(self):
        requests_lookup = {request['requestId']: request for request in self.request_log}
        failed_requests = []
        for failed_request in self.failed_request_log:
            request = requests_lookup[failed_request['requestId']]
            error_text = failed_request['errorText']
            if 'net::ERR_NAME_NOT_RESOLVED' in error_text:
                error_type = 'dns-not-resolved'
            elif 'net::ERR_UNKNOWN_URL_SCHEME' in error_text:
                error_type = 'unknown-url-scheme'
            elif 'net::ERR_ABORTED' in error_text:
                # Requests that were aborted by the site (e.g. a XHR
                # request that was canceled) are not considered failed.
                continue
            else:
                error_type = 'unknown'
            error = {
                'url': request['url'],
                'error_type': error_type,
            }
            if error_type == 'unknown':
                error['error_text'] = error_text
            failed_requests.append(error)
        self.result['failed_requests'] = failed_requests
