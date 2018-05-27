from ..base import AbstractChromeScan


class RequestsMixin(AbstractChromeScan):
    def _extract_requests(self):
        self.result['requests'] = [{
            'url': request['url'],
            'is_thirdparty': request['is_thirdparty'],
            'is_tracker': request['is_tracker']
        } for request in self.request_log
          if not request['url'].startswith('data:')]
