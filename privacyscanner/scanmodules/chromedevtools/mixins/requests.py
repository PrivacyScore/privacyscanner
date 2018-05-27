from ..base import AbstractChromeScan


class RequestsMixin(AbstractChromeScan):
    def _extract_requests(self):
        requests = []

        for request in self.request_log:
            if request['url'].startswith('data:'):
                continue
            response = self.response_lookup.get(request['url'])
            requests.append({
                'url': request['url'],
                'is_thirdparty': request['is_thirdparty'],
                'is_tracker': request['is_tracker'],
                'sets_cookie': self._get_sets_cookie(response),
                'mime_type': response['mimeType'] if response else None,
                'status_code': response['status'] if response else None,
                'status_text': response['statusText'] if response else None
            })
        self.result['requests'] = requests

    @staticmethod
    def _get_sets_cookie(response):
        if response is None:
            return False
        return 'set-cookie' in response['headers_lower']
