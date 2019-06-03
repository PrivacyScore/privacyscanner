from urllib.parse import parse_qs

from privacyscanner.scanmodules.chromedevtools.extractors.base import Extractor
from privacyscanner.scanmodules.chromedevtools.utils import JavaScriptError, javascript_evaluate


TRACKER_JS = """
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
                    'anonymize_ip': typeof(anonymize_ip) !== 'undefined' ? !!anonymize_ip : false
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
                'anonymize_ip': typeof(anonymize_ip) !== 'undefined' ? !!anonymize_ip : false
            });
        });
    }
    
    return info;
})()
""".lstrip()


class GoogleAnalyticsExtractor(Extractor):
    def extract_information(self):
        ga = {
            'has_ga_object': None,
            'has_gat_object': None,
            'trackers': []
        }

        if not self.options['disable_javascript']:
            ga['has_gat_object'] = False
            ga['has_gat_object'] = False
            try:
                info = javascript_evaluate(self.page.tab, TRACKER_JS)
                ga.update(info)
            except JavaScriptError:
                pass
        num_requests_aip = 0
        num_requests_no_aip = 0
        has_ga_requests = False
        for request in self.page.request_log:
            if self._is_google_request(request['parsed_url']):
                if self._is_anonymized(request):
                    num_requests_aip += 1
                else:
                    num_requests_no_aip += 1
                has_ga_requests = True
        ga['has_requests'] = has_ga_requests

        has_ga_js = ga['has_ga_object'] or ga['has_gat_object']
        ga['has_ga_js'] = has_ga_js

        if has_ga_requests or has_ga_js:
            all_set_js = None
            any_set_js = None
            if ga['trackers']:
                trackers_anonymize = [tracker.get('anonymize_ip') for tracker in ga['trackers']]
                if all(isinstance(aip, bool) for aip in trackers_anonymize):
                    all_set_js = all(trackers_anonymize)
                    any_set_js = any(trackers_anonymize)
            aip_ineffective = None
            if all_set_js is not None and any_set_js is not None:
                aip_ineffective = ((any_set_js and not all_set_js) or
                                   (all_set_js and num_requests_no_aip > 0))
            ga['anonymize'] = {
                'all_set_js': all_set_js,
                'any_set_js': any_set_js,
                'num_requests_aip': num_requests_aip,
                'num_requests_no_aip': num_requests_no_aip,
                'aip_ineffective': aip_ineffective
            }
        if not (ga['has_ga_object'] or ga['has_gat_object']):
            del ga['trackers']

        self.result['google_analytics'] = ga

    @staticmethod
    def _is_google_request(parsed_url):
        # Google uses stats.g.doubleclick.net for customers that have
        # enabled the Remarketing with Google Analytics feature.
        ga_domains = ('www.google-analytics.com', 'ssl.google-analytics.com',
                      'stats.g.doubleclick.net')
        if parsed_url.netloc in ga_domains:
            return any(p in parsed_url.path for p in ('collect', '__utm.gif'))

    @staticmethod
    def _is_anonymized(request):
        # There could be conflicting aip options, e.g., when a POST request
        # contains aip=0 in their post data, but aip=1 in the URL.
        # In this case, post data takes precedence.
        aip = None
        if request['method'] == 'POST' and request['post_data']:
            qs = parse_qs(request['post_data'])
            aip = qs.get('aip')
        if aip is None:
            qs = parse_qs(request['parsed_url'].query)
            aip = qs.get('aip')
        if aip and aip[-1] in ('1', 'true'):
            return True
        return False
