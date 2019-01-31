"""
This test module does a number of network-based checks to determine web- and mailserver
addresses and the final URL after following any HTTP forwards.
"""
import os
import re
import tempfile
import warnings
from pathlib import Path
import tarfile
from typing import List, Iterable, Tuple
from urllib.parse import urlparse

import requests
import urllib3
from dns import resolver, reversename
from dns.exception import DNSException
from geoip2.database import Reader
from geoip2.errors import AddressNotFoundError

from privacyscanner.scanmodules import ScanModule
from privacyscanner.utils import download_file, copy_to, file_is_outdated


class NetworkScanModule(ScanModule):
    name = 'network'
    dependencies = []
    required_keys = ['site_url']

    def scan_site(self, result, logger, meta):
        scan_site(result, logger, self.options, meta)


# The minimum Jaccard coefficient required for the
# comparison of http and https version of a site
# so that we accept both sites to show the same
# content (if threshold not reached we will report
# that the scanned site is not available via https)
MINIMUM_SIMILARITY = 0.90

# PrivacyScanner's local copy of the GeoIP database
# which takes precedence over copies in other locations
GEOIP_DATABASE_PATH = Path('~/.local/share/privacyscanner/GeoIP/GeoLite2-Country.mmdb').expanduser()
GEOIP_DOWNLOAD_URL = 'https://geolite.maxmind.com/download/geoip/database/GeoLite2-Country.tar.gz'
GEOIP_MAX_AGE = 3 * 24 * 3600


def scan_site(result, logger, options, meta):
    # determine hostname
    hostname = urlparse(result['site_url']).hostname

    _insert_dns_records(result, logger, options, hostname)
    _insert_geoip(result, logger, options)

    result['reachable'] = True

    # Note: If you ask for a A record, but there is only a CNAME record,
    # the DNS resolver will also return the A record which is referenced
    # by the CNAME, i.e. result['a_records'] won't be empty if there is
    # only a CNAME referring to an A record (see RFC 1034).
    if not result['a_records']:
        result['dns_error'] = True
        result['reachable'] = False
        return

    # Determine final URL. The final URL is the URL that is retrieved
    # after some optional redirects when retrieving the site url.
    final_url = result['site_url']
    try:
        final_url, final_url_content = _retrieve_url(result['site_url'])
    except requests.exceptions.HTTPError as e:
        result['reachable'] = False
        result['http_error'] = str(e)
        final_url_content = e.response.content
    except requests.exceptions.RequestException as e:
        logger.exception('Failed to retrieve URL')
        result['reachable'] = False
        return
    finally:
        result['final_url'] = final_url


    final_url_is_https = final_url.startswith('https://')
    result['final_url_is_https'] = final_url_is_https

    # If our final URL is already HTTPS, we have nothing to do and just
    # set is as HTTPS-URL. Otherwise we fetch the site again with HTTPS
    # and compare it to the HTTP version later on using Jaccard index
    # similarity
    if final_url_is_https:
        result['final_https_url'] = result['final_url']
    else:
        https_url = 'https:/' + result['site_url'].split('/', maxsplit=1)[1]
        try:
            final_https_url, final_https_url_content = _retrieve_url(https_url)
            result['final_https_url'] = final_https_url
        except requests.exceptions.HTTPError as e:
            result['https_error'] = str(e)
            result['final_https_url'] = https_url
            final_https_url_content = e.response.content
        except requests.exceptions.RequestException:
            result['final_https_url'] = None
            return
        else:
            similarity = _jaccard_index(
                final_url_content,
                final_https_url_content)
            minimum_similarity = options.get('minimum_similarity', MINIMUM_SIMILARITY)
            result['same_content_via_https'] = similarity > minimum_similarity


def update_dependencies(options):
    if not file_is_outdated(GEOIP_DATABASE_PATH, GEOIP_MAX_AGE):
        return
    GEOIP_DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)
    FILES = ['COPYRIGHT.txt', 'LICENSE.txt', 'GeoLite2-Country.mmdb']
    with tempfile.NamedTemporaryFile() as f:
        download_file(GEOIP_DOWNLOAD_URL, f)
        archive = tarfile.open(f.name)
        for member in archive.getmembers():
            base_name = os.path.basename(member.name)
            if base_name in FILES and member.isfile():
                with (GEOIP_DATABASE_PATH.parent / base_name).open('wb') as f:
                    copy_to(archive.extractfile(member), f)


def _insert_dns_records(result, logger, options, hostname):
    # DNS
    # CNAME records
    result['cname_records'] = _cname_lookup(hostname)

    # A records
    result['a_records'] = _a_lookup(hostname)

    # MX records
    result['mx_records'] = _mx_lookup(hostname)
    if hostname.startswith('www.'):
        result['mx_records'] += _mx_lookup(hostname[4:])

    # A records for MX
    result['mx_a_records'] = [(pref, _a_lookup(mx)) for pref, mx in result['mx_records']]

    # Reverse A
    result['a_records_reverse'] = [_reverse_lookup(a) for a in result['a_records']]

    # Reverse A for MX
    result['mx_a_records_reverse'] = [
        (pref, [_reverse_lookup(a) for a in mx_a])
        for pref, mx_a in result['mx_a_records']]


def _insert_geoip(result, logger, options):
    # GeoIP
    reader = Reader(_get_geoip_database(options))

    result['a_locations'], result['a_locations_unknown'] = _get_countries(
        result['a_records'], reader)
    result['mx_locations'], result['mx_locations_unknown'] = _get_countries(
        (ip for mx_a_records in result['mx_a_records']
         for ip in mx_a_records[1]), reader)


def _retrieve_url(url):
    headers = {
        'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:53.0) Gecko/20100101 Firefox/53.0'
    }

    with warnings.catch_warnings():
        warnings.simplefilter('ignore', urllib3.exceptions.InsecureRequestWarning)
        r = requests.get(url, headers=headers, verify=False)
    r.raise_for_status()
    return r.url, r.content


def _a_lookup(name: str) -> List[str]:
    try:
        return [e.address for e in resolver.query(name, 'A')]
    except DNSException:
        return []


def _cname_lookup(name: str) -> List[str]:
    try:
        return [e.to_text()[:-1].lower() for e in resolver.query(name, 'CNAME')]
    except DNSException:
        return []


def _mx_lookup(name: str) -> Iterable[Tuple[str, str]]:
    try:
        return sorted(((e.preference, e.exchange.to_text()[:-1].lower())
                       for e in resolver.query(name, 'MX')), key=lambda v: v[0])
    except DNSException:
        return []


def _reverse_lookup(ip: str) -> List[str]:
    try:
        address = reversename.from_address(ip).to_text()
        return [rev.to_text()[:-1].lower()
                for rev in resolver.query(address, 'PTR')]
    except DNSException:
        return []


def _get_countries(addresses: Iterable[str], reader: Reader) -> Tuple[List[str], List[str]]:
    locations = set()
    unresolved_ips = set()
    for ip in addresses:
        try:
            geoip_result = reader.country(ip)
            this_result = geoip_result.country.name
            if not this_result:
                this_result = geoip_result.continent.name
            if not this_result:
                raise AddressNotFoundError
            locations.add(this_result)
        except AddressNotFoundError:
            unresolved_ips.add(ip)
            continue
    return list(locations), list(unresolved_ips)


def _jaccard_index(a: bytes, b: bytes) -> float:
    """Calculate the jaccard similarity of a and b."""
    pattern = re.compile(rb'[ \n]')
    # remove tokens containing / to prevent wrong classifications for
    # absolute paths
    a = {token for token in pattern.split(a) if b'/' not in token}
    b = {token for token in pattern.split(b) if b'/' not in token}
    intersection = a.intersection(b)
    union = a.union(b)
    return len(intersection) / len(union)


def _get_geoip_database(options):
    try:
        return options['country_database_path']
    except KeyError:
        possible_paths = [
            GEOIP_DATABASE_PATH,
            Path('~/.local/share/GeoIP/GeoLite2-Country.mmdb').expanduser(),
            Path('/var/lib/GeoIP/GeoLite2-Country.mmdb'),
            Path('/usr/local/var/GeoIP/GeoLite2-Country.mmdb'),
            Path('/usr/local/share/GeoIP/GeoLite2-Country.mmdb'),
            Path('/usr/share/GeoIP/GeoLite2-Country.mmdb'),
        ]
        for p in possible_paths:
            if p.exists():
                return str(p)
    raise RuntimeError('Could not find GeoIP database. '
                       'Please specify country_database_path option.')
