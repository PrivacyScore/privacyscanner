from privacyscanner.scanmodules.chromedevtools.extractors.base import Extractor


class RequestsExtractor(Extractor):
    def extract_information(self):
        requests = []

        for request in self.page.request_log:
            if request['url'].startswith('data:'):
                continue
            response = self.page.get_final_response_by_id(request['requestId'],
                                                          fail_silently=True)
            request_dict = {
                'url': request['url'],
                'sets_cookie': self._get_sets_cookie(response),
                'mime_type': response['mimeType'] if response else None,
                'status_code': response['status'] if response else None,
                'status_text': response['statusText'] if response else None
            }
            # is_thirdparty is only availavle if the thirdparties mixin is enabled
            if 'is_thirdparty' in request:
                request_dict['is_thirdparty'] = request['is_thirdparty']
            # is_tracker is only available if the trackerdetect mixin is enabled
            if 'is_tracker' in request:
                request_dict['is_tracker'] = request['is_tracker']
            # Add headers if requested
            # To enable this option, set SCAN_MODULE_OPTIONS in your config file to
            # {'chromedevtools': {'RequestsExtractor.save_headers': True}}
            # (or change it in a similar way)
            if self.options.get('RequestsExtractor.save_headers', False):
                request_dict['request_headers'] = request["headers"]
                request_dict['response_headers'] = response["headers"]
            requests.append(request_dict)
        self.result['requests'] = requests

    @staticmethod
    def _get_sets_cookie(response):
        if response is None:
            return False
        return 'set-cookie' in response['headers_lower']
