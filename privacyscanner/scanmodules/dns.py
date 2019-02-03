import tarfile
import tempfile
from pathlib import Path

from dns import resolver, reversename
from dns.exception import DNSException
from geoip2.database import Reader
from geoip2.errors import AddressNotFoundError

from privacyscanner.scanmodules import ScanModule
from privacyscanner.scanmodules.chromedevtools import parse_domain, TLDEXTRACT_CACHE_FILE
from privacyscanner.utils import set_default_options, copy_to, download_file, file_is_outdated


GEOIP_DATABASE_PATH = Path('GeoIP/GeoLite2-Country.mmdb')
GEOIP_DOWNLOAD_URL = 'https://geolite.maxmind.com/download/geoip/database/GeoLite2-Country.tar.gz'
GEOIP_MAX_AGE = 3 * 24 * 3600


class DNSScanModule(ScanModule):
    name = 'dns'
    dependencies = ['chromedevtools']
    required_keys = ['site_url', 'redirect_chain']

    def __init__(self, options):
        set_default_options(options, {
            'geoip_download_url': GEOIP_DOWNLOAD_URL,
            'geoip_max_age': GEOIP_MAX_AGE,
        })
        super().__init__(options)
        cache_file = self.options['storage_path'] / TLDEXTRACT_CACHE_FILE
        parse_domain.cache_file = str(cache_file)
        try:
            geoip_path = Path(options['geoip_database_path'])
        except KeyError:
            geoip_path = self.options['storage_path'] / GEOIP_DATABASE_PATH
        self.options['geoip_database_path'] = geoip_path
        self._geoip_reader = None

    def scan_site(self, result, logger, meta):
        dns = {}
        for url in result['redirect_chain']:
            p = parse_domain(url)
            if p.fqdn in dns:
                continue
            records = dns.setdefault(p.fqdn, {})
            records['A'] = self._get_dns_records(p.fqdn, 'A')
            records['AAAA'] = self._get_dns_records(p.fqdn, 'AAAA')
        result['dns'] = dns

    def update_dependencies(self):
        geoip_database_path = self.options['geoip_database_path']
        geoip_max_age = self.options['geoip_max_age']
        if not file_is_outdated(geoip_database_path, geoip_max_age):
            return
        geoip_database_path.parent.mkdir(parents=True, exist_ok=True)
        FILES = ['COPYRIGHT.txt', 'LICENSE.txt', 'GeoLite2-Country.mmdb']
        with tempfile.NamedTemporaryFile() as f:
            download_file(GEOIP_DOWNLOAD_URL, f)
            archive = tarfile.open(f.name)
            for member in archive.getmembers():
                base_name = Path(member.name).name
                if base_name in FILES and member.isfile():
                    with (geoip_database_path.parent / base_name).open('wb') as f:
                        copy_to(archive.extractfile(member), f)

    def _get_geoip_reader(self):
        if self._geoip_reader is None:
            self._geoip_reader = Reader(str(self.options['geoip_database_path']))
        return self._geoip_reader

    def _get_dns_records(self, qname, rdtype):
        reader = self._get_geoip_reader()
        try:
            answer = resolver.query(qname, rdtype)
        except resolver.NXDOMAIN:
            return []
        except DNSException:
            return None
        entries = []
        for a in answer:
            country = None
            continent = None
            try:
                geo_result = reader.country(a.address)
                country = geo_result.country.name
                continent = geo_result.continent.name
            except AddressNotFoundError:
                pass
            entries.append({
                'ip': a.address,
                'reverse': self._get_reverse_records(a.address),
                'country': country,
                'continent': continent
            })
        return entries

    def _get_reverse_records(self, address):
        qname = reversename.from_address(address)
        try:
            answer = resolver.query(qname, 'PTR')
        except resolver.NXDOMAIN:
            return []
        except DNSException:
            return None
        return [a.target.to_text()[:-1] for a in answer]
