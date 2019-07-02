from privacyscanner.scanmodules.chromedevtools.extractors.base import Extractor


class CookieSyncExtractor(Extractor):

    def extract_information(self):
        cookies_synced = {}
        cookies_synced['cookie_sync_occured'] = None
        cookies_synced['sync_occurence_counter'] = 0
        # cookies_synced['cookie_sync_origin'] = None
        # cookies_synced['cookie_sync_target'] = None
        cookies_synced['sync_relation'] = []

        tracker_requests = []
        tracker_cookies = []
        user_ids = []

        for request in self.page.request_log:
            if request['is_thirdparty']:
                tracker_requests.append(request)

        for cookie in self.result['cookies']:
            if cookie['is_tracker']:
                tracker_cookies.append(cookie)

        if len(tracker_cookies) == 0:
            cookies_synced['cookie_sync_occured'] = False

        for cookie in tracker_cookies:
            for request in tracker_requests:
                if len(cookie['value']) > 10:
                    if cookie['value'] in request['url']:
                        cookie_domain = cookie['domain'].split('.')[len(cookie['domain'].split('.'))-2]
                        if cookie_domain not in request['url']:
                            try:
                                t_url = request['url'].split('/')[2]
                                d_name = t_url.split('.')
                                company = d_name[len(d_name)-2]
                            except IndexError:
                                company = request['url']
                            if len(cookies_synced) > 0:
                                strikeout_count = 0
                                for element in cookies_synced['sync_relation']:
                                    strikeout_subcount = 0
                                    if company in element['cookie_sync_target']:
                                        strikeout_subcount += 1
                                    if cookie['domain'] in element['cookie_sync_origin']:
                                        strikeout_subcount += 1
                                    if strikeout_subcount > 0:
                                        strikeout_count = 1
                            if strikeout_count == 0:
                                cookies_synced['cookie_sync_occured'] = True
                                cookies_synced['sync_relation'].append({'cookie_sync_origin': cookie['domain'],
                                                                        'cookie_sync_target': request['url'],
                                                                        'cookie_sync_value': cookie['value']})
        if cookies_synced['cookie_sync_occured'] is None:
            cookies_synced['cookie_sync_occured'] = False

        cookies_synced['sync_occurence_counter'] = len(cookies_synced['sync_relation'])

        self.result['cookiesync'] = cookies_synced
