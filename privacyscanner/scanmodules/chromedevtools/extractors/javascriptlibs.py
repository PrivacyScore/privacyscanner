import json

from .base import Extractor


LIBRARY_JS = """
(function() {
    return JSON.stringify({
        'jQuery': typeof(jQuery) !== 'undefined' ? jQuery.fn.jquery : null,
        'React': typeof(React) !== 'undefined' ? React.version : null,
        'AngularJS': typeof(angular) !== 'undefined' ? angular.version.full : null
    });
})();
"""


class JavaScriptLibsExtractor(Extractor):
    def extract_information(self):
        versions = json.loads(self.page.tab.Runtime.evaluate(expression=LIBRARY_JS)['result']['value'])
        self.result['javascript_libraries'] = versions
