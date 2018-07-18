import json
from urllib.parse import parse_qs

from .base import Extractor
from ..utils import javascript_stringify


TRACKER_JS = javascript_stringify("""
(function() {
    let info = {
        'has_ga_object': false,
        'has_gat_object': false,
        'trackers': []
    };
    if (typeof(ga) === 'undefined' && typeof(_gat) === 'undefined') {
        return info;
    }
    
    if (typeof(ga) !== 'undefined') {
        ga(function() {
            info['has_ga_object'] = true;
            ga.getAll().forEach(function(tracker) {
                let anonymize_ip = tracker.get('anonymizeIp');
                info['trackers'].push({
                    'name': tracker.get('name'),
                    'tracking_id': tracker.get('trackingId'),
                    'anonymize_ip': typeof(anonymize_ip) !== 'undefined' ? anonymize_ip : false
                });
            });
        });
    }
    if (typeof(_gat) !== 'undefined') {
        info['has_gat_object'] = true;
        _gat._getTrackers().forEach(function(tracker) {
            // There is only a global anonymize in the old _gat API
            let anonymize_ip = _gat.w; 
            info['trackers'].push({
                'name': tracker._getName(),
                'tracking_id': tracker._getAccount(),
                'anonymize_ip': typeof(anonymize_ip) !== 'undefined' ? anonymize_ip : false
            });
        });
    }
    
    return info;
})()
""").lstrip()


class GoogleAnalyticsExtractor(Extractor):
    def extract_information(self):
        ga = {
            'has_ga_object': False,
            'has_gat_object': False,
            'trackers': []
        }
        try:
            info = json.loads(self.page.tab.Runtime.evaluate(expression=TRACKER_JS)['result']['value'])
            ga.update(info)
        except KeyError:
            raise
            pass
        num_requests_aip = 0
        num_requests_no_aip = 0
        has_ga_requests = False
        for request in self.page.request_log:
            parsed_url = request['parsed_url']
            if self._is_google_request(parsed_url):
                qs = parse_qs(parsed_url.query)
                if 'aip' in qs and qs['aip'][-1] in ('1', 'true'):
                    num_requests_aip += 1
                else:
                    num_requests_no_aip += 1
                has_ga_requests = True
        ga['has_requests'] = has_ga_requests

        if has_ga_requests:
            if ga['trackers']:
                trackers_anonymize = [tracker['anonymize_ip'] for tracker in ga['trackers']] # noqa
                all_set_js = all(trackers_anonymize)
                any_set_js = any(trackers_anonymize)
            else:
                all_set_js = None
                any_set_js = None
            ga['anonymize'] = {
                'all_set_js': all_set_js,
                'any_set_js': any_set_js,
                'num_requests_aip': num_requests_aip,
                'num_requests_no_aip': num_requests_no_aip,
                'is_incorrect': ((any_set_js and not all_set_js) or
                                 (all_set_js and num_requests_no_aip > 0))
            }
        if not (ga['has_ga_object'] or ga['has_gat_object']):
            del ga['trackers']

        self.result['google_analytics'] = ga

    @staticmethod
    def _is_google_request(parsed_url):
        # Google uses stats.g.doubleclick.net for customers that have
        # enabled the Remarketing with Google Analytics feature,
        if parsed_url.netloc in ('www.google-analytics.com', 'stats.g.doubleclick.net'):
            return any(p in parsed_url.path for p in ('collect', 'utm.gif', 'gtm/js'))
