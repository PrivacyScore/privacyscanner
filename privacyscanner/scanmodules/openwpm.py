"""
Check the website for privacy issues like cookies, 3rd parties, etc, using OpenWPM.
"""

import json
import os
import re
import sqlite3
import sys
import timeit
import subprocess
import traceback

from io import BytesIO
from pathlib import Path

import tldextract
from PIL import Image
from adblockparser import AdblockRules

name = 'openwpm'
dependencies = [
    'network',
]
required_keys = ['site_url', 'dns_error', 'reachable', 'final_url']

OPENWPM_WRAPPER_EXECUTABLE = os.path.join(
    os.path.abspath(os.path.dirname(__file__)),
    'openwpm_wrapper.py')


def scan_site(result, logger, options):
    """Test a site using openwpm and related tests."""

    if 'dns_error' in result:
        result['openwpm_skipped_due_to_dns_error'] = True
        return

    if not result.get('reachable'):
        result['openwpm_skipped_due_to_not_reachable'] = True
        return

    virtualenv_path = options['virtualenv_path']
    subprocess.call([
        OPENWPM_WRAPPER_EXECUTABLE,
        result['site_url'],
        os.getcwd(),
    ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env={
        'VIRTUAL_ENV': virtualenv_path,
        'PATH': '{}:{}'.format(
            os.path.join(virtualenv_path, 'bin'), os.environ.get('PATH')),
        'PYTHONPATH': options['openwpm_path']
    })

    # collect raw output
    # log file
    with open('openwpm.log', 'rb') as f:
        result.add_debug_file('openwpm.log', f)

    # sqlite db
    crawl_sqlite_file = Path('crawl-data.sqlite3')
    with crawl_sqlite_file.open('rb') as f:
        result.add_debug_file('crawl-data.sqlite3', f)

    # screenshot
    screenshot_file = Path('screenshots/screenshot.png')
    if screenshot_file.is_file():
        with open('screenshots/screenshot.png', 'rb') as f:
            result.add_debug_file('screenshot_original.png', f)

    # html source
    if os.path.isfile('sources/source.html'):
        with open('sources/source.html', 'rb') as f:
            result.add_debug_file('source.html', f)

    # cropped and pixelized screenshot
    if screenshot_file.is_file():
        out = BytesIO()
        pixelize_screenshot(str(screenshot_file), out)
        result.add_file('screenshot.png', out)

    # TODO: Clean up collection
    # TODO: Find out what the author meant by "Clean up collection"
    result.update({
        'https': False,
        'success': False,
        'redirected_to_https': False,
        'responses': [],
        'profilecookies': [],
        'flashcookies': [],
        'headerchecks': {}
    })

    conn = sqlite3.connect(str(crawl_sqlite_file))
    outercur = conn.cursor()

    # requests
    for start_time, site_url in outercur.execute(
            "SELECT DISTINCT start_time, site_url " +
            "FROM crawl as c JOIN site_visits as s " +
            "ON c.crawl_id = s.crawl_id WHERE site_url LIKE ?;", (result['site_url'],)):
        # Get a new cursor to avoid confusing the old one
        cur = conn.cursor()

        result['initial_url'] = site_url

        # collect third parties (i.e. domains that differ in their second and third level domain
        third_parties = []
        third_party_requests = []
        extracted_visited_url = tldextract.extract(result['final_url'])
        maindomain_visited_url = "{}.{}".format(extracted_visited_url.domain, extracted_visited_url.suffix)

        # TODO: the following line results in urls starting with a dot
        # TODO: the following line is not even used actually
        hostname_visited_url = '.'.join(e for e in extracted_visited_url if e)

        openwpm_requests = []
        for requrl, method, referrer, headers in cur.execute(
                "SELECT url, method, referrer, headers " +
                "FROM site_visits as s JOIN http_requests as h ON s.visit_id = h.visit_id " +
                "WHERE s.site_url LIKE ? ORDER BY h.id;",
                (result['site_url'],)):
            openwpm_requests.append({
                'url': requrl,
                'method': method,
                'referrer': referrer,
                'headers': headers
            })

            # extract domain name from request and check whether it is a 3rd party host
            extracted = tldextract.extract(requrl)
            maindomain = "{}.{}".format(extracted.domain, extracted.suffix)
            hostname = '.'.join(e for e in extracted if e)
            if maindomain_visited_url != maindomain:
                third_parties.append(hostname)  # add full domain to list
                third_party_requests.append(requrl)  # add full domain to list
        result['requests'] = openwpm_requests

        result["requests_count"] = len(result["requests"])
        result["third_party_requests"] = third_party_requests
        result["third_party_requests_count"] = len(third_parties)

        third_parties = list(set(third_parties))
        result["third_parties"] = third_parties
        result["third_parties_count"] = len(third_parties)

        # Identify known trackers
        start_time = timeit.default_timer()
        _insert_detected_trackers(result, logger, options)
        elapsed = timeit.default_timer() - start_time
        result["tracker_requests_elapsed_seconds"] = elapsed

        # Google Analytics detection
        (present, anonymized, not_anonymized) = detect_google_analytics(third_party_requests)
        result["google_analytics_present"] = present
        result["google_analytics_anonymizeIP_set"] = anonymized
        result["google_analytics_anonymizeIP_not_set"] = not_anonymized

        # responses
        for respurl, method, referrer, headers, response_status, response_status_text, time_stamp in cur.execute(
                "SELECT url, method, referrer, headers, response_status, response_status_text, " +
                "time_stamp FROM site_visits as s JOIN http_responses as h " +
                "ON s.visit_id = h.visit_id WHERE s.site_url LIKE ? ORDER BY h.id;", (result['site_url'],)):
            result["responses"].append({
                'url': respurl,
                'method': method,
                'referrer': referrer,
                'headers': json.loads(headers) if headers else [],
                'response_status': response_status,
                'response_status_text': response_status_text,
                'time_stamp': time_stamp
            })

        # if there are no responses the site failed to load
        # (e.g. user entered URL with https://, but server doesn't support https)
        if result["responses"]:
            result["success"] = True

            # Check if the browser has been redirected to https.
            # The https-flag is also True if the URL was already specified with https://
            # and the browser succeeded in opening it (exception: page redirects
            # to http:// URL, see below)

            if site_url.startswith("https://"):
                result["https"] = True

            # OpenWPM times out after 60 seconds if it cannot reach a site (e.g. due to fail2ban on port 443)
            # Note that this is not "our" timeout that kills the scan worker, but OpenWPM terminates on its own..
            # As a result, the final_urls table will not have been created.
            # In this case redirected_to_https cannot be determined accurately here.
            # This issue must be handled in the evaluation by looking at 'success', which will be
            # false if final_urls table is missing.
            try:
                # retrieve final URL (after potential redirects) - will throw an exception if final_urls table
                # does not exist (i.e. OpenWPM timed out due to connectivity problems)
                cur.execute("SELECT final_url FROM final_urls WHERE original_url = ?;", [site_url])
                res = cur.fetchone()
                openwpm_final_url = ""
                if res:
                    openwpm_final_url = res[0]
                    result['openwpm_final_url'] = openwpm_final_url

                # if we are redirected to an insecure http:// site we have to set https-flag
                # to false even if the original URL used https://
                redirected_to_https = openwpm_final_url.startswith("https://")
                if redirected_to_https and result["success"]:
                    result["https"] = True
                else:
                    result["https"] = False

                # if we have been redirected from http:// to https:// this
                # is remembered separately
                if site_url.startswith("http://") and redirected_to_https:
                    result["redirected_to_https"] = True

            except Exception:
                result["exception"] = traceback.format_exc()
                result["redirected_to_https"] = False
                result["https"] = False
                result["success"] = False
                result["openwpm_final_url"] = site_url  # To ensure the next test does not crash and burn

            # HTTP Security Headers
            # Iterate through responses in order until we have arrived at the openwpm_final_url
            # (i.e. the URL of the website after all redirects), as this is the one whose headers we want.

            response = find_matching_response(result["openwpm_final_url"], result["responses"])
            # Javascript Hipster websites may have failed to find any matching request at this point.
            # Backup solution to find at least some matching request.
            if not response:
                for resp in result["responses"]:
                    if resp["response_status"] < 300 or resp["response_status"] > 399:
                        response = resp
                        break
            # Now we should finally have a response. Verify.
            assert response

            headers = response['headers']  # This is a list of lists: [ ['Server', 'nginx'], ['Date', '...'] ]
            headers_dict = {d[0]: d[1] for d in headers}  # This gets us { 'Server': 'nginx', 'Date': '...' }
            headers_lc = {k.lower(): v for k, v in
                          headers_dict.items()}  # lowercase keys, allows for case-insensitive lookup

            # Content-Security-Policy
            header_result = {'value': '', 'status': 'MISSING'}
            if 'content-security-policy' in headers_lc.keys():
                header_result['value'] = headers_lc['content-security-policy']
                header_result['status'] = "INFO"
            result['headerchecks']['content-security-policy'] = header_result

            # X-Frame-Options
            header_result = {'value': '', 'status': 'MISSING'}
            if 'x-frame-options' in headers_lc.keys():
                header_result['value'] = headers_lc['x-frame-options']
                header_result['status'] = "INFO"
            result['headerchecks']['x-frame-options'] = header_result

            # X-XSS-Protection
            header_result = {'value': '', 'status': 'MISSING'}
            if 'x-xss-protection' in headers_lc.keys():
                header_result['value'] = headers_lc['x-xss-protection']
                if header_result['value'] == '1; mode=block':
                    header_result['status'] = "OK"
                else:
                    header_result['status'] = "INFO"
            result['headerchecks']['x-xss-protection'] = header_result

            # X-Content-Type-Options
            header_result = {'value': '', 'status': 'MISSING'}
            if 'x-content-type-options' in headers_lc.keys():
                header_result['value'] = headers_lc['x-content-type-options']
                if header_result['value'] == 'nosniff':
                    header_result['status'] = "OK"
                else:
                    header_result['status'] = "WARN"
            result['headerchecks']['x-content-type-options'] = header_result

            # Referrer-Policy
            header_result = {'value': '', 'status': 'MISSING'}
            if 'referrer-policy' in headers_lc.keys():
                header_result = {'key': 'referrer-policy', 'value': headers_lc['referrer-policy']}
                if headers_lc['referrer-policy'] == 'no-referrer':
                    header_result['status'] = "OK"
                else:
                    header_result['status'] = "WARN"
            result['headerchecks']['referrer-policy'] = header_result

            # X-Powered-By
            header_result = {'value': '', 'status': 'MISSING'}
            if 'x-powered-by' in headers_lc.keys():
                header_result['value'] = headers_lc['x-powered-by']
                header_result['status'] = "INFO"
            result['headerchecks']['x-powered-by'] = header_result

            # Server
            header_result = {'value': '', 'status': 'MISSING'}
            if 'server' in headers_lc.keys():
                header_result['value'] = headers_lc['server']
                header_result['status'] = "INFO"
            result['headerchecks']['server'] = header_result

        # Cookies
        for baseDomain, name, value, host, path, expiry, accessed, creationTime, isSecure, isHttpOnly in cur.execute(
                "SELECT baseDomain, name, value, host, path, expiry, " +
                "accessed, creationTime, isSecure, isHttpOnly " +
                "FROM site_visits as s JOIN profile_cookies as c " +
                "ON s.visit_id = c.visit_id WHERE s.site_url LIKE ?;", (result['site_url'])):
            profilecookie = {
                'baseDomain': baseDomain,
                'name': name,
                'value': value,
                'host': host,
                'path': path,
                'expiry': expiry,
                'accessed': accessed,
                'creationTime': creationTime,
                'isSecure': isSecure,
                'isHttpOnly': isHttpOnly
            }
            result["profilecookies"].append(profilecookie)

        # Flash-Cookies
        for domain, filename, local_path, key, content in cur.execute(
                "SELECT domain, filename, local_path, key, content " +
                "FROM site_visits as s JOIN flash_cookies as c " +
                "ON s.visit_id = c.visit_id WHERE s.site_url LIKE ?;", (result['site_url'])):
            flashcookie = {
                'domain': domain,
                'filename': filename,
                'local_path': local_path,
                'key': key,
                'content': content
            }
            result["flashcookies"].append(flashcookie)

        result["flashcookies_count"] = len(result["flashcookies"])
        result["cookies_count"] = len(result["profilecookies"])
        result["cookie_stats"] = \
            detect_cookies(result['site_url'], result["profilecookies"],
                           result["flashcookies"], result["tracker_requests"])

        # Detect mixed content
        _insert_mixed_content_detection(result, logger, options, cur)

    # Close SQLite connection
    conn.close()

    return result


def find_matching_response(url, responses):
    """
    Find a response that matches the provided URL

    :param url: The URL to look for
    :param responses: A List of responses
    """
    for resp in responses:
        if resp["url"] == url:
            return resp
    return None


def pixelize_screenshot(screenshot, screenshot_pixelized, target_width=390, pixelsize=3):
    """
    Thumbnail a screenshot to `target_width` and pixelize it.
    
    :param screenshot: Screenshot to be thumbnailed in pixelized
    :param screenshot_pixelized: File to which the result should be written
    :param target_width: Width of the final thumbnail
    :param pixelsize: Size of the final pixels
    :return: None
    """
    if target_width % pixelsize != 0:
        raise ValueError("pixelsize must divide target_width")

    img = Image.open(screenshot)
    width, height = img.size
    if height > width:
        img = img.crop((0, 0, width, width))
        height = width
    undersampling_width = target_width // pixelsize
    ratio = width / height
    new_height = int(undersampling_width / ratio)
    img = img.resize((undersampling_width, new_height), Image.BICUBIC)
    img = img.resize((target_width, new_height * pixelsize), Image.NEAREST)
    img.save(screenshot_pixelized, format='png')


def _insert_detected_trackers(result, logger, options):
    """
    Detect 3rd party trackers and return a list of them.

    :param third_parties: List of third-party requests (not: hosts) to analyze
    :return: a list of unique hosts in the form domain.tld
    """
    if not result['third_party_requests']:
        return []

    blacklist = [re.compile('^[|]*http[s]*[:/]*$'),  # match http[s]:// in all variations
                 re.compile('^[|]*ws[:/]*$'),  # match ws:// in all variations
                 re.compile('^\.'),  # match rules like .com
                 re.compile('^/'),  # match rules like /stuff
                 re.compile('^#'),  # match rules beginning with #
                 re.compile('^:'),  # match rules beginning with :
                 re.compile('^\?'),  # match rules beginning with ?
                 ]

    def is_acceptable_rule(rule):
        if '@' in rule:
            return False
        for exp in blacklist:
            if exp.match(rule) is not None:
                return False
        return True

    lines = []
    rules = []
    trackers = []

    start_time = timeit.default_timer()

    # Generate paths to files
    easylist_base_path = Path(options['easylist_base_path'])
    easylist_files = ['easylist.txt', 'easyprivacy.txt', 'fanboy-annoyance.txt']

    for easylist_file in easylist_files:
        for line in (easylist_base_path / easylist_file).open('r', encoding='utf-8'):
            lines.append(line)

    # Clean up lines:
    for line in lines:
        try:
            rule = line.split('$')[0]
            if is_acceptable_rule(rule):
                rules.append(rule)
        except Exception:
            logger.exception('Unexpected error while applying easylist rules.')

    abr = AdblockRules(rules)

    elapsed = timeit.default_timer() - start_time
    logger.info('Took %i secs to parse easylist rules' % elapsed)

    i = 0

    for url in result['third_party_requests']:
        if abr.should_block(url):
            ext = tldextract.extract(url)
            trackers.append("{}.{}".format(ext.domain, ext.suffix))
        i = i + 1
        if i % 20 == 0:
            elapsed = timeit.default_timer() - start_time
            logger.info("Checked %i domains, %i secs elapsed..." % (i, elapsed))
    result['tracker_requests'] = list(set(trackers))


def detect_google_analytics(requests):
    """
    Detect if Google Analytics is being used, and if yes, if the privacy extensions are active.

    :param requests: All 3rd party requests (not: domains) of the website
    :return: A 3-tuple (present: boolean, anonymized: int, not_anonymized: int), where
        present indicates if Google Analytics is present, anonymized indicates the number of
        collect requests that have anonymizeIp set, and not_anonymized indicates the number of
        requests without anonymizeIp set.
    """
    present = False
    anonymized = 0
    not_anonymized = 0

    exp = re.compile('(google-analytics\.com/.*?collect)|' +  # Match JS tracking endpoint
                     '(google-analytics\.com/.*?utm\.gif)|' +  # Match tracking pixel
                     '(google\..+?/(pagead)|(ads)/ga-audiences)')  # Match audience remarketing endpoints

    for request in requests:
        if len(exp.findall(request)) > 0:
            present = True
            if "aip=1" in request:
                anonymized += 1
            else:
                not_anonymized += 1

    return present, anonymized, not_anonymized


def _insert_mixed_content_detection(result, logger, options, cursor):
    """
    Detect if we have mixed content on the site.

    Sets result['mixed_content'] to True iff https == True && at least one
    mixed content warning was thrown by firefox

    :param cursor: An SQLite curser to use
    :return: True
    """
    if not result['https']:
        result['mixed_content'] = False
        return
    has_mixed_content = False
    try:
        # Attempt to load all log entries from the database
        entries = cursor.execute("SELECT log_json FROM browser_logs WHERE original_url LIKE ?;",
                                 (result['site_url'],))
        # If we get here, the table existed, so mixed content detection should work
        exp = re.compile("mixed .* content \"(.*)\"")
        for entry in entries:
            match = exp.findall(entry[0])
            if match:
                has_mixed_content = True
        result['mixed_content'] = has_mixed_content
    except Exception:
        # Very likely, the database table does not exist, so we may be working on an old database format.
        # Log and ignore, do not make any statements about the existence of mixed content
        logger.exception('Unexpected error when detecting mixed content')


def detect_cookies(domain, cookies, flashcookies, trackers):
    """
    Detect cookies and return statistics about them.

    :param domain: The domain (not: URL) that is being scanned
    :param cookies: The regular cookies
    :param flashcookies: The flash cookies
    :param trackers: All trackers that have been identified on this website
    :return: A dictionary of values. See variable definitions below.
    """
    fp_short = 0  # Short-term first-party cookies
    fp_long = 0  # Long-Term first-party cookies
    fp_fc = 0  # First-party flash cookies
    tp_short = 0  # Short-term third party cookies
    tp_long = 0  # Long-term third-party cookies
    tp_fc = 0  # Third party flash cookies
    tp_track = 0  # Third party cookies from known trackers
    tp_track_uniq = 0  # Number of unique tracking domains that set cookies

    dom_ext = tldextract.extract(domain)
    seen_trackers = []

    for cookie in cookies:
        cd_ext = tldextract.extract(cookie["baseDomain"])
        if cd_ext.domain == dom_ext.domain and cd_ext.suffix == dom_ext.suffix:
            fp = True
        else:
            fp = False
            if cd_ext.domain + "." + cd_ext.suffix in trackers:
                if cd_ext.domain + "." + cd_ext.suffix not in seen_trackers:
                    seen_trackers.append(cd_ext.domain + "." + cd_ext.suffix)
                    tp_track_uniq += 1
                tp_track += 1

        if cookie["expiry"] - (
                cookie["accessed"] / 1000000) > 86400:  # Expiry is more than 24 hours away from last access
            if fp:
                fp_long += 1
            else:
                tp_long += 1
        else:
            if fp:
                fp_short += 1
            else:
                tp_short += 1

    for cookie in flashcookies:
        cd_ext = tldextract.extract(cookie["domain"])
        if cd_ext.domain == dom_ext.domain and cd_ext.suffix == dom_ext.suffix:
            fp_fc += 1
        else:
            tp_fc += 1
            if cd_ext.domain + "." + cd_ext.suffix in trackers:
                if cd_ext.domain + "." + cd_ext.suffix not in seen_trackers:
                    seen_trackers.append(cd_ext.domain + "." + cd_ext.suffix)
                    tp_track_uniq += 1
                tp_track += 1

    return {
        'first_party_short': fp_short,
        'first_party_long': fp_long,
        'first_party_flash': fp_fc,
        'third_party_short': tp_short,
        'third_party_long': tp_long,
        'third_party_flash': tp_fc,
        'third_party_track': tp_track,
        'third_party_track_uniq': tp_track_uniq,
        'third_party_track_domains': seen_trackers
    }
