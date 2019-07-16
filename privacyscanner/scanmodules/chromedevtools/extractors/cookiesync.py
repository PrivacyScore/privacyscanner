from privacyscanner.scanmodules.chromedevtools.extractors.base import Extractor
from datetime import datetime
from privacyscanner.utils import download_file
from pathlib import Path

CLIQZ_DOWNLOAD_PREFIX = 'https://raw.githubusercontent.com/cliqz-oss/whotracks.me/master/whotracksme/data/assets/'
CLIQZ_FILES = ['trackerdb.sql']
CLIQZ_PATH = Path('cliqz')


class CookieSyncExtractor(Extractor):

    def extract_information(self):
        trackerdb = self._load_tracker_db(True)
        cookies_synced = dict(cookie_sync_occurred=None, sync_occurrence_counter=0, sync_relation=[], sync_companies=[])
        tracker_requests = []
        tracker_cookies = []

        for request in self.page.request_log:
            if request['is_thirdparty']:
                tracker_requests.append(request)

        for cookie in self.result['cookies']:
            if cookie['is_tracker']:
                tracker_cookies.append(cookie)

        if len(tracker_cookies) == 0:
            cookies_synced['cookie_sync_occurred'] = False

        for cookie in tracker_cookies:
            for request in tracker_requests:
                if len(cookie['value']) > 6:
                    if cookie['value'] in request['url']:
                        cookie_domain = cookie['domain'].split('.')[len(cookie['domain'].split('.'))-2]
                        if cookie_domain not in request['url']:

                            try:
                                t_url = request['url'].split('/')[2]
                                d_name = t_url.split('.')
                                target_company_name = d_name[len(d_name)-2]
                            except IndexError:
                                target_company_name = request['url']
                            if target_company_name not in cookies_synced['sync_companies']:
                                cookies_synced['sync_companies'].append(target_company_name)

                            try:
                                origin_company_name = cookie['domain'].split('.')[len(cookie['domain'].split('.'))-2]
                            except IndexError:
                                origin_company_name = cookie['domain']
                            if origin_company_name not in cookies_synced['sync_companies']:
                                cookies_synced['sync_company_network'] = []
                                for company in trackerdb:
                                    if origin_company_name in company:
                                        cookies_synced['sync_company_network'].append(company)
                                cookies_synced['sync_companies'].append(origin_company_name)

                            strikeout_count = 0
                            if len(cookies_synced) > 0:
                                for element in cookies_synced['sync_relation']:
                                    strikeout_subcount = 0
                                    if target_company_name in element['cookie_sync_target']:
                                        strikeout_subcount += 1
                                    if origin_company_name in element['cookie_sync_target']:
                                        strikeout_subcount += 1
                                    if origin_company_name in element['cookie_sync_origin']:
                                        strikeout_subcount += 1
                                    if strikeout_subcount > 1:
                                        strikeout_count = 1

                            if len(cookie['value']) == 10:
                                possible_time_cookie = None
                                utcstamp = None
                                try:
                                    possible_time_cookie = datetime.utcfromtimestamp(int(cookie['value']))
                                    utcstamp = datetime.utcnow()
                                except ValueError:
                                    strikeout_count += 0
                                if possible_time_cookie is not None:
                                    if possible_time_cookie.date().year == utcstamp.date().year:
                                        if possible_time_cookie.date().month == utcstamp.date().month:
                                            strikeout_count += 1

                            if strikeout_count == 0:
                                cookies_synced['cookie_sync_occurred'] = True
                                cookies_synced['sync_relation'].append({'cookie_sync_origin': cookie['domain'],
                                                                        'cookie_sync_target': request['url'],
                                                                        'cookie_sync_value': cookie['value']})

        if cookies_synced['cookie_sync_occurred'] is None:
            cookies_synced['cookie_sync_occurred'] = False
            cookies_synced['sync_companies'] = None

        cookies_synced['sync_occurrence_counter'] = len(cookies_synced['sync_relation'])

        self.result['cookiesync'] = cookies_synced

    @staticmethod
    def update_dependencies(options):
        trackerdb_path = options['storage_path'] / CLIQZ_PATH
        trackerdb_path.mkdir(parents=True, exist_ok=True)
        for filename in CLIQZ_FILES:
            download_url = CLIQZ_DOWNLOAD_PREFIX + filename
            target_file = (trackerdb_path / filename).open('wb')
            download_file(download_url, target_file)

    def _load_tracker_db(self, load_switch):
        if load_switch:
            trackerdb = {}
            tracker_db_path = self.options['storage_path'] / CLIQZ_PATH / "trackerdb.sql"
            f = open(tracker_db_path, "r")
            sql_generator = f.readlines()
            for line in sql_generator:
                if 'INSERT INTO "tracker_domains"' in line:
                    sl = line.split("'")
                    trackerdb[sl[1]] = []
                    trackerdb[sl[1]].append(sl[3])

        if not load_switch:
            trackerdb = {}

        return trackerdb

    def query_tracker_db(self, domain):
        if domain in trackerdb:
            print("yes")
