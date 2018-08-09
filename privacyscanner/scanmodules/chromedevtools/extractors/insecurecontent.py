from privacyscanner.scanmodules.chromedevtools.extractors.base import Extractor
from privacyscanner.scanmodules.chromedevtools.utils import camelcase_to_underscore


class InsecureContentExtractor(Extractor):
    def extract_information(self):
        entry = self.page.security_state_log[-1]
        insecure_content = {}
        # See https://chromedevtools.github.io/devtools-protocol/tot/Security#type-InsecureContentStatus
        properties = [
            # True if the page was loaded over HTTPS and ran mixed
            # (HTTP) content such as scripts.
            'ranMixedContent',
            # True if the page was loaded over HTTPS and displayed
            # mixed (HTTP) content such as images.
            'displayedMixedContent',
            # True if the page was loaded over HTTPS and contained a
            # form targeting an insecure url.
            'containedMixedForm',
            # True if the page was loaded over HTTPS without
            # certificate errors, and ran content such as scripts that
            # were loaded with certificate errors.
            'ranContentWithCertErrors',
            # True if the page was loaded over HTTPS without
            # certificate errors, and displayed content such as images
            # that were loaded with certificate errors.
            'displayedContentWithCertErrors'
        ]
        status = entry['insecureContentStatus']
        for key, value in status.items():
            if key not in properties:
                continue
            insecure_content[camelcase_to_underscore(key)] = value
        insecure_content['has_mixed_content'] = (status['ranMixedContent'] or
                                                 status['displayedMixedContent'])
        insecure_content['has_cert_errors'] = (status['ranContentWithCertErrors'] or
                                               status['displayedContentWithCertErrors'])
        self.result['insecure_content'] = insecure_content
