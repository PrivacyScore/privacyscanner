from urllib.parse import urlparse

from privacyscanner.scanmodules import ScanModule


class ExampleScanModule(ScanModule):
    name = 'example'
    dependencies = []
    required_keys = ['site_url']

    def scan_site(self, result, meta):
        """Scans a site and adds more information to the result.

        The parameter result behaves like a dictionary, you can set keys on it
        and call the usual methods on dicts. If you change a non-shallow key,
        you have to mark the underlying shallow key as dirty by calling
        result.mark_dirty(shallow_key).

        Furthermore result exposes a logger on the logger parameter where you can
        send log messages to the scanning master.

        For storing files, you can call result.add_file(identifier, filecontents)
        which will send filecontents to the master. If you provide a file-like
        object it will read from the file and send the file contents to the
        master. The identifier represents a file name and must be unique within
        a scan. To store files for debug purposes, call result.add_debug_file
        instead, which has the same API.

        To start with, you can access result['site_url'], which is populated by the
        master.

        The parameter options is a dictionary with the configuration of the scan
        module as specified in the configuration file at SCAN_MODULE_OPTIONS.
        """
        self.logger.info('we will check the site for https')
        parsed_site = urlparse(result['site_url'])
        result['is_https'] = parsed_site.scheme == 'https'
        # result.add_file('screenshot.png')
        if self.options.get('save_nops'):
            result.add_debug_file('nops.bin', b'\x90\x90\x90\x90')
