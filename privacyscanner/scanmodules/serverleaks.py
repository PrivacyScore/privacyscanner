"""
Test for common server leaks.
"""
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse

import requests
from requests.exceptions import ConnectionError
from requests.models import Response
from tldextract import extract

from privacyscanner.scanmodules import ScanModule


class ServerleaksScanModule(ScanModule):
    name = 'serverleaks'
    dependencies = ['chromedevtools']
    required_keys = ['final_url', 'reachable']

    def scan_site(self, result, meta):
        scan_site(result, self.logger, self.options, meta)


def _match_db_dump(content):
    targets = ["SQLite", "CREATE TABLE", "INSERT INTO", "DROP TABLE"]
    matched = False
    for target in targets:
        matched |= target in content
    return matched


def _concat_sub(url, suffix):
    url_extract = extract(url)
    if url_extract.subdomain == "":
        return None
    site = url_extract.subdomain + "." + url_extract.domain
    return site + suffix


def _concat_full(url, suffix):
    url_extract = extract(url)
    site = url_extract.domain + "." + url_extract.suffix
    if url_extract.subdomain != "":
        site = url_extract.subdomain + "." + site
    return site + suffix


def _gen_db_domain_sql(url):
    return extract(url).domain + ".sql"


def _gen_db_sub_domain_sql(url):
    return _concat_sub(url, ".sql")


def _gen_db_full_domain_sql(url):
    return _concat_full(url, ".sql")


def _gen_db_domain_db(url):
    return extract(url).domain + ".db"


def _gen_db_sub_domain_db(url):
    return _concat_sub(url, ".db")


def _gen_db_full_domain_db(url):
    return _concat_full(url, ".db")


def _gen_db_domain_key(url):
    return extract(url).domain + ".key"


def _gen_db_sub_domain_key(url):
    return _concat_sub(url, ".key")


def _gen_db_full_domain_key(url):
    return _concat_full(url, ".key")


def _gen_db_domain_pem(url):
    return extract(url).domain + ".pem"


def _gen_db_sub_domain_pem(url):
    return _concat_sub(url, ".pem")


def _gen_db_full_domain_pem(url):
    return _concat_full(url, ".pem")


TRIALS = [
    ('server-status/', 'Apache Server Status'),
    ('server-info/', 'Apache Server Information'),
    ('test.php', 'phpinfo()'),
    ('phpinfo.php', 'phpinfo()'),
    ('.git/HEAD', 'ref:'),
    ('.svn/wc.db', 'SQLite'),
    ('core', 'ELF'),
    ('.DS_Store', 'Bud1'),

    # Check for Database dumps
    # sqldump - MySQL/MariaDB
    ('dump.db', _match_db_dump),
    ('dump.sql', _match_db_dump),
    ('sqldump.sql', _match_db_dump),
    ('sqldump.db', _match_db_dump),
    # SQLite
    ('db.sqlite', _match_db_dump),
    ('data.sqlite', _match_db_dump),
    ('sqlite.db', _match_db_dump),
    (_gen_db_domain_sql, _match_db_dump),
    (_gen_db_sub_domain_sql, _match_db_dump),
    (_gen_db_full_domain_sql, _match_db_dump),
    (_gen_db_domain_db, _match_db_dump),
    (_gen_db_sub_domain_db, _match_db_dump),
    (_gen_db_full_domain_db, _match_db_dump),

    # TODO PostgreSQL etc., additional common names

    # TLS Certs
    ('server.key', '-----BEGIN'),
    ('privatekey.key', '-----BEGIN'),
    ('private.key', '-----BEGIN'),
    ('myserver.key', '-----BEGIN'),
    ('key.pem', '-----BEGIN'),
    ('privkey.pem', '-----BEGIN'),
    (_gen_db_domain_key, '-----BEGIN'),
    (_gen_db_sub_domain_key, '-----BEGIN'),
    (_gen_db_full_domain_key, '-----BEGIN'),
    (_gen_db_domain_pem, '-----BEGIN'),
    (_gen_db_sub_domain_pem, '-----BEGIN'),
    (_gen_db_full_domain_pem, '-----BEGIN'),

    # Docker
    # https://infosec.rm-it.de/2018/08/19/scanning-the-alexa-top-1m-sites-for-dockerfiles/
    ('Dockerfile', 'FROM'),
    # https://twitter.com/svblxyz/status/1045013939904532482
    ('docker.env', '='),
    ('.env', '='),
    # Docker Compose
    ('docker-compose.yml', 'version:'),
]


def _get(url, timeout):
    try:
        response = requests.get(url, timeout=timeout)
        return response
    except ConnectionError:
        return None


def _response_to_json(resp: Response):
    """Generate a json byte string from a response
    received through requests."""
    # we store only the top of the file
    # because core dumps can become very large
    # also: we do not want to store more potentially sensitive data
    # than necessary to determine whether there is a leak or not

    return {
        'text': resp.content[0:50*1024].decode(errors='replace'),
        'status_code': resp.status_code,
        'headers': dict(resp.headers),
        'url': resp.url,
    }


def _check_leaks(url, max_workers):
    leaks = []
    trials = {}
    # determine hostname
    parsed_url = urlparse(url)

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        url_to_future = {}

        for trial, pattern in TRIALS:
            trial_t = trial
            # Check if trial is callable. If so, call it and save the result
            if callable(trial):
                trial_t = trial(url)
                if trial_t is None:
                    continue
            request_url = '{}://{}/{}'.format(
                parsed_url.scheme, parsed_url.netloc, trial_t)
            url_to_future[trial_t] = executor.submit(_get, request_url, 10)

        for trial in url_to_future:
            try:
                # response = requests.get(request_url, timeout=10)
                response = url_to_future[trial].result()
                if response is None:
                    continue

                match_url = '{}/{}'.format(parsed_url.netloc, trial)

                if match_url not in response.url:
                    # There has been a redirect.
                    continue

                trials[trial] = _response_to_json(response)
            except Exception:
                continue

    for trial, pattern in TRIALS:
        if callable(trial):
            trial = trial(url)
            if trial is None:
                continue
        if trial not in trials:
            # Test raw data too old or particular request failed.
            continue

        response = trials[trial]

        if response['status_code'] == 200:
            # The pattern can have three different types.
            # - If it is a simple string,
            #   we only check if it is contained in the response
            if isinstance(pattern, str):
                if pattern in response['text']:
                    leaks.append(trial)
            # - If it is callable,
            #   we call it with the response text and check the return value
            elif callable(pattern):
                if pattern(response['text']):
                    leaks.append(trial)

    return leaks


def scan_site(result, logger, options, meta):
    if not result['reachable']:
        return

    max_workers = options.get('max_workers', 8)

    # Note: This does not scan the original site_url before redirection.
    #       There might be cases where only the start page redirects, but
    #       other paths (which do not get redirected) contain sensitive files.
    result['leaks'] = _check_leaks(result['final_url'], max_workers)
