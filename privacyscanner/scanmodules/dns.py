import sys
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
GEOIP_DOWNLOAD_URL = 'https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-Country&license_key={license_key}&suffix=tar.gz'
GEOIP_MAX_AGE = 3 * 24 * 3600


class DNSScanModule(ScanModule):
    name = 'dns'
    dependencies = ['chromedevtools']
    required_keys = ['site_url', 'redirect_chain']

    def __init__(self, options):
        set_default_options(options, {
            'geoip_download_url': GEOIP_DOWNLOAD_URL,
            'geoip_max_age': GEOIP_MAX_AGE,
            'geoip_license_key': None,
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

    def scan_site(self, result, meta):
        self._warn_geoip_availability()
        dns = {}

        # Fetch MX records
        p = parse_domain(result['site_url'])
        mail_domain = p.fqdn[len('www.'):] if p.fqdn.startswith('www.') else p.fqdn
        mx_records = self._get_mx_records(mail_domain)

        # Create a list for which we fetch A/AAAA records
        domain_list = {mail_domain}
        # If the site is not reachable, we do not have a redirect chain.
        # Nonetheless, we try to get as much information as possible without it.
        if 'redirect_chain' in result:
            domain_list.update(parse_domain(url).fqdn for url in result['redirect_chain'])
        if mx_records is not None:
            domain_list.update(record['host'] for record in mx_records)

        # Fetch A/AAAA records and reverse (PTR)
        for url in domain_list:
            p = parse_domain(url)
            records = dns.setdefault(p.fqdn, {})
            records['A'] = self._get_dns_records(p.fqdn, 'A')
            records['AAAA'] = self._get_dns_records(p.fqdn, 'AAAA')

        dns.setdefault(mail_domain, {})['MX'] = mx_records

        # If there is neither an A/AAAA record nor an MX record it makes no
        # sense to add a mail domain because there will be no mailserver.
        mail_dns = dns[mail_domain]
        if mail_dns['A'] or mail_dns['AAAA'] or mail_dns['MX']:
            result['mail'] = {'domain': mail_domain}
        result['dns'] = dns

    def update_dependencies(self):
        if self.options['geoip_license_key'] is None:
            self.logger.warning('License key for GeoIP database download not specified.')
            return
        geoip_database_path = self.options['geoip_database_path']
        geoip_max_age = self.options['geoip_max_age']
        if not file_is_outdated(geoip_database_path, geoip_max_age):
            return
        geoip_database_path.parent.mkdir(parents=True, exist_ok=True)
        FILES = ['COPYRIGHT.txt', 'LICENSE.txt', 'GeoLite2-Country.mmdb']
        with tempfile.NamedTemporaryFile() as f:
            download_url = GEOIP_DOWNLOAD_URL.format(
                    license_key=self.options['geoip_license_key'])
            download_file(download_url, f)
            archive = tarfile.open(f.name)
            for member in archive.getmembers():
                base_name = Path(member.name).name
                if base_name in FILES and member.isfile():
                    with (geoip_database_path.parent / base_name).open('wb') as f:
                        copy_to(archive.extractfile(member), f)

    def _get_geoip_reader(self):
        if self._geoip_reader is None:
            if not self.options['geoip_database_path'].exists():
                return None
            self._geoip_reader = Reader(str(self.options['geoip_database_path']))
        return self._geoip_reader

    def _get_dns_records(self, qname, rdtype):
        reader = self._get_geoip_reader()
        try:
            answer = resolver.query(qname, rdtype)
        except (resolver.NXDOMAIN, resolver.NoAnswer, resolver.NoNameservers):
            return []
        except DNSException as e:
            self.logger.exception('Could not get %(rdtype) records for %(qname)s: %(msg)s',
                                  {'qname': qname, 'rdtype': rdtype, 'msg': str(e)})
            return None
        entries = []
        for a in answer:
            country = None
            continent = None
            if reader:
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
        except (resolver.NXDOMAIN, resolver.NoAnswer, resolver.NoNameservers):
            return []
        except DNSException as e:
            self.logger.exception('Could not get PTR records for %s: %s', address, str(e))
            return None
        return [a.target.to_text()[:-1] for a in answer]

    def _get_mx_records(self, mail_domain):
        try:
            answer = resolver.query(mail_domain, 'MX')
        except (resolver.NXDOMAIN, resolver.NoAnswer, resolver.NoNameservers):
            return []
        except DNSException as e:
            self.logger.exception('Could not get MX records for %s: %s', mail_domain, str(e))
            return None
        mx_records = []
        for a in answer:
            host = a.exchange.to_text()
            # The dot at the end marks a FQDN; it is not part of the host.
            if host.endswith('.'):
                host = host[:-1]
            else:
                host = '{}.{}'.format(host, mail_domain)
            if not host:
                continue
            mx_records.append({
                'priority': a.preference,
                'host': host
            })
        # We include the name in the ordering to have a deterministic order
        mx_records.sort(key=lambda rec: (rec['priority'], rec['host']))
        return mx_records

    def _warn_geoip_availability(self):
        if not self.options['geoip_database_path'].exists():
            self.logger.warning('GeoIP database not available. Country lookup disabled.')
