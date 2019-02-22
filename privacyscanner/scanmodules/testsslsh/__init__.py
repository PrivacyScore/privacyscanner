from privacyscanner.scanmodules.testsslsh.base import TestsslshScanModuleBase
from privacyscanner.scanmodules.testsslsh.scanner import Parameter


class TestsslshHttpsScanModule(TestsslshScanModuleBase):
    name = 'testssl_https'
    required_keys = ['final_url', 'https', 'testssl_https']
    target_type = 'https'
    target_parameters = []

    def _get_host(self, result):
        host_url = result['final_url']
        # An HTTP site might have an HTTPS version too, but does not redirect
        # to it. In this case, we still want to scan the HTTPS version.
        if host_url.startswith('http://'):
            host_url = 'https://' + host_url[len('http://'):]
        return host_url

    def _can_run(self, result):
        return result['https']['has_tls']


class TestsslshMailScanModule(TestsslshScanModuleBase):
    name = 'testssl_mail'
    required_keys = ['mail', 'testssl_mail']
    target_type = 'mail'
    target_parameters = [Parameter.STARTTLS, 'smtp']

    def _get_host(self, result):
        return result['mail']['domain'] + ':25'

    def _can_run(self, result):
        return result['mail']['has_starttls']
