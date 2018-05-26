from ..base import AbstractChromeScan


class ResponsesMixin(AbstractChromeScan):
    def _extract_responses(self):
        responses = []
        for response in self.response_log:
            responses.append({
                'url': response['url'],
                'status': response['status'],
                'status_text': response['statusText'],
                'headers': response['headers'],
                'mime_type': response['mimeType'],
                'num_bytes': response['encodedDataLength']
            })
        self.result['responses'] = responses