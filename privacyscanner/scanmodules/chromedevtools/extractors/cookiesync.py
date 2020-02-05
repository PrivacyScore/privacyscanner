from privacyscanner.scanmodules.chromedevtools.extractors.base import Extractor
from datetime import datetime


class CookieSyncExtractor(Extractor):

    def extract_information(self):
        cookies_synced = dict(cookie_sync_occurred=None, number_sync_relations=0, number_sync_domains=0,
                              sync_relation=[], sync_domains=[])
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
                                target_domain = request['url'].split('/')[2]
                            except IndexError:
                                target_domain = request['url']
                            if target_domain not in cookies_synced['sync_domains']:
                                cookies_synced['sync_domains'].append(target_domain)

                            try:
                                origin_domain = cookie['domain']
                            except IndexError:
                                origin_domain = cookie['domain']
                            if origin_domain not in cookies_synced['sync_domains']:
                                cookies_synced['sync_domains'].append(origin_domain)

                            strikeout_count = 0
                            if len(cookies_synced) > 0:
                                for element in cookies_synced['sync_relation']:
                                    strikeout_subcount = 0
                                    if target_domain in element['target']:
                                        strikeout_subcount += 1
                                    if origin_domain in element['target']:
                                        strikeout_subcount += 1
                                    if origin_domain in element['origin']:
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
                                cookies_synced['sync_relation'].append({'origin': cookie['domain'],
                                                                        'target': request['url'],
                                                                        'value': cookie['value']})

        if cookies_synced['cookie_sync_occurred'] is None:
            cookies_synced['cookie_sync_occurred'] = False
            cookies_synced['sync_domains'] = None

        if cookies_synced['sync_domains'] and cookies_synced['sync_relation'] is not None:
            cookies_synced['number_sync_relations'] = len(cookies_synced['sync_relation'])
            cookies_synced['number_sync_domains'] = len(cookies_synced['sync_domains'])

        self.result['cookiesync'] = cookies_synced
