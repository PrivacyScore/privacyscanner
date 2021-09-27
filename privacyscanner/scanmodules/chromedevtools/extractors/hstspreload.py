import io
import json

from privacyscanner.scanmodules.chromedevtools.utils import parse_domain
from privacyscanner.scanmodules.chromedevtools.extractors.base import Extractor
from privacyscanner.utils import download_file, file_is_outdated


HSTS_PRELOAD_URL = 'https://github.com/chromium/chromium/raw/master/net/http/transport_security_state_static.json'

_hsts_lookup = None


class HSTSPreloadExtractor(Extractor):
    def extract_information(self):
        global _hsts_lookup

        hsts_preload = {
            'is_ready': False,
            'is_preloaded': False
        }
        self.result['https']['hsts_preload'] = hsts_preload
        self.result.mark_dirty('https')

        if _hsts_lookup is None:
            lookup_file = self.options['storage_path'] / 'hsts.json'
            with lookup_file.open() as f:
                _hsts_lookup = json.load(f)

        domain = parse_domain(self.result['final_url']).registered_domain
        is_preloaded = domain in _hsts_lookup

        # Iterate over all subdomains and check if any of it is preloaded.
        # We have to handle three cases:
        # 1) all subdomains are not in the preload list. Reject.
        # 2) a subdomain is in the preload list, and include_subdomains is set.
        #    Accept in this case.
        # 3) a subdomain is in the preload list, but include_subdomains
        #    is not set. Then we have to do two things. Firstly, continue
        #    searching: maybe another subdomain of the current subdomain
        #    is in the list and has include_subdomains. See case 2. Secondly,
        #    the full domain might be in the lookup. This has already been
        #    checked beforehand, so nothing to do.
        current_domain = ''
        for part in domain.split('.'):
            current_domain = part + '.' + current_domain
            if current_domain in _hsts_lookup:
                include_subdomains = _hsts_lookup[current_domain]
                if include_subdomains:
                    is_preloaded = True
                    break
            else:
                break

        hsts_header = self.result['security_headers']['Strict-Transport-Security']
        if hsts_header is None:
            return

        # There are some big players who got exceptions from the standard
        # requirements to be HSTS ready, therefore we treat them as HSTS ready
        # if they are already in the preload list. However, we require the HSTS
        # header to be set (see return statement above).
        hsts_preload['is_preloaded'] = is_preloaded
        if is_preloaded:
            hsts_preload['is_ready'] = True
            return

        # According to hstspreload.org, these are the criteria for being ready
        # to be included in the HSTS preload list:
        #
        # 1. Serve a valid certificate.
        # 2. Redirect from HTTP to HTTPS on the same host, if you are listening
        #    on port 80.
        # 3. Serve all subdomains over HTTPS.
        #    In particular, you must support HTTPS for the www subdomain if a
        #    DNS record for that subdomain exists.
        # 4. Serve an HSTS header on the base domain for HTTPS requests:
        #    4.1 The max-age must be at least 31536000 seconds (1 year).
        #    4.2 The includeSubDomains directive must be specified.
        #    4.3 The preload directive must be specified.
        #    4.4 If you are serving an additional redirect from your HTTPS site,
        #        that redirect must still have the HSTS header (rather than the
        #        page it redirects to).

        fail_reasons = []
        if not self.result['final_url'].startswith('https://'):
            fail_reasons.append('no-https-redirect')
        if not hsts_header['includeSubDomains']:
            fail_reasons.append('no-include-subdomains')
        if hsts_header['max-age'] is None:
            fail_reasons.append('no-max-age')
        elif hsts_header['max-age'] < 31536000:
            fail_reasons.append('max-age-too-short')
        if not hsts_header['preload']:
            fail_reasons.append('missing-preload')

        fail_reasons.sort()
        hsts_preload['is_ready'] = len(fail_reasons) == 0
        if fail_reasons:
            hsts_preload['fail_reasons'] = fail_reasons

    @classmethod
    def update_dependencies(cls, options):
        lookup_file = options['storage_path'] / 'hsts.json'
        if not file_is_outdated(lookup_file, 3600 * 24 * 7):
            return
        buf = io.BytesIO()
        download_url = options.get('hsts_preload_url', HSTS_PRELOAD_URL)
        download_file(download_url, buf)
        plain_json = ''.join(line for line in buf.getvalue().decode().splitlines()
                             if not line.lstrip().startswith('//'))
        hsts_data = json.loads(plain_json)
        lookup = {entry['name']: entry.get('include_subdomains')
                  for entry in hsts_data['entries']}
        with lookup_file.open('w') as f:
            json.dump(lookup, f)
