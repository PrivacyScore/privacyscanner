from privacyscanner.scanmodules.testsslsh.base import TestsslshScanModuleBase
from privacyscanner.scanmodules.testsslsh.scanner import Parameter


class TestsslshHttpsScanModule(TestsslshScanModuleBase):
    name = 'testssl_https'
    required_keys = ['final_url', 'https', 'testssl_https']
    target_type = 'https'
    target_parameters = []

    def _get_host(self, result):
        return result['final_url']
