"""
This test module does a number of network-based checks to determine web- and mailserver
addresses and the final URL after following any HTTP forwards.
"""

import re
from typing import Dict, List, Union
from urllib.parse import urlparse

import requests
from dns import resolver, reversename
from dns.exception import DNSException
from geoip2.database import Reader
from geoip2.errors import AddressNotFoundError

name = 'network'
dependencies = []
required_keys = ['site_url']

# The minimum Jaccard coefficient required for the
# comparison of http and https version of a site
# so that we accept both sites to show the same
# content (if threshold not reached we will report
# that the scanned site is not available via https)
MINIMUM_SIMILARITY = 0.90


def scan_site(result, logger, options):
    """Test the specified URL with GeoIP."""

    # determine hostname
    hostname = urlparse(result['site_url']).hostname

    # DNS
    # CNAME records
    result['cname_records'] = _cname_lookup(hostname)

    # A records
    result['a_records'] = _a_lookup(hostname)

    # MX records
    result['mx_records'] = _mx_lookup(hostname)
    if hostname.startswith('www.'):
        result['mx_result'] += _mx_lookup(hostname[4:])

    # A records for MX
    result['mx_a_records'] = [(pref, _a_lookup(mx)) for pref, mx in result['mx_records']]

    # Reverse A
    result['a_records_reverse'] = [_reverse_lookup(a) for a in result['a_records']]

    # Reverse A for MX
    result['mx_a_records_reverse'] = [
        (pref,
         [_reverse_lookup(a) for a in mx_a])
         for pref, mx_a in result['mx_a_records']]

    result['reachable'] = True

    if not result['a_records']:
        result['dns_error'] = True
        result['reachable'] = False
    else:
        # determine final URL
        try:
            final_url, final_url_content, http_error = _retrieve_url(result['site_url'])
            if http_error:
                result['http_error'] = http_error
                result['final_url'] = result['site_url'] # so that we can check the HTTPS version below
            else:
                result['final_url'] = final_url

        except requests.exceptions.Timeout:
            # TODO: extend api to support registration of partial errors
            logger.exception('Failed to retrieve URL')
            result['final_url'] = result['site_url']
            result['reachable'] = False
            return

        # now let's check the HTTPS version again (unless we already have been redirected there)
        if not result['final_url'].startswith('https'):
            https_url = 'https:/' + result['site_url'].split('/', maxsplit=1)[1]
            try:

                final_https_url, final_https_url_content, https_error = _retrieve_url(https_url)

                if https_error:
                    result['https_error'] = https_error
                    result['final_https_url'] = https_url
                else:
                    result['final_https_url'] = final_https_url
            except requests.exceptions.Timeout:
                result['final_https_url'] = None
        else:
            result['final_https_url'] = result['final_url']

    # GeoIP
    reader = Reader(options.get('country_database_path'))

    result['a_locations'] = _get_countries(result['a_records'], reader)
    result['mx_locations'] = _get_countries(
        (ip for mx_a_records in result['mx_a_records']
         for ip in mx_a_records[1]), reader)

    # TODO: reverse mx-a matches mx

    result['final_url_is_https'] = (
        'final_url' in result and result['final_url'].startswith('https'))
    # handle non-https final url
    if (not result['final_url_is_https'] and
            'final_url_content' in result and
            'final_https_url_content' in result):
        similarity = _jaccard_index(
            result['final_url_content'],
            result['final_https_url_content'])
        minimum_similarity = options.get('minimum_similarity', MINIMUM_SIMILARITY)
        result['same_content_via_https'] = similarity > minimum_similarity

def _retrieve_url(url):
    headers = {
        'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:53.0) Gecko/20100101 Firefox/53.0'
    }

    r = requests.get(url, headers=headers, verify=False)

    return r.url, r.content, '{} {}'.format(r.status_code, r.reason)

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


def _mx_lookup(name: str) -> List[str]:
    try:
        return sorted([(e.preference, e.exchange.to_text()[:-1].lower())
                       for e in resolver.query(name, 'MX')], key=lambda v: v[0])
    except DNSException:
        return []


def _reverse_lookup(ip: str) -> List[str]:
    try:
        address = reversename.from_address(ip).to_text()
        return [rev.to_text()[:-1].lower()
                for rev in resolver.query(address, 'PTR')]
    except DNSException:
        return []


def _get_countries(addresses: List[str], reader: Reader) -> List[str]:
    res = set()
    for ip in addresses:
        try:
            geoip_result = reader.country(ip)
            this_result = geoip_result.country.name
            if not this_result:
                this_result = geoip_result.continent.name
            if not this_result:
                raise AddressNotFoundError
            res.add(this_result)
        except AddressNotFoundError:
            # TODO: Add entry specifying that at least one location has not been found
            continue
    return list(res)


def _jaccard_index(a: bytes, b: bytes) -> float:
    """Calculate the jaccard similarity of a and b."""
    pattern = re.compile(rb' |\n')
    # remove tokens containing / to prevent wrong classifications for
    # absolute paths
    a = set(token for token in pattern.split(a) if b'/' not in token)
    b = set(token for token in pattern.split(b) if b'/' not in token)
    intersection = a.intersection(b)
    union = a.union(b)
    return len(intersection) / len(union)
