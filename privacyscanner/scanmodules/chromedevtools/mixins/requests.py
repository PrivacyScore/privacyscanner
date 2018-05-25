from ..base import AbstractChromeScan


class RequestsMixin(AbstractChromeScan):
    def _extract_requests(self):
        self.result['requested_urls'] = [req['url'] for req in self.request_log]
