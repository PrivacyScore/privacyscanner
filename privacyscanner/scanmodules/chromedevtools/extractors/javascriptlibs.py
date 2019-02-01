from privacyscanner.scanmodules.chromedevtools.extractors.base import Extractor
from privacyscanner.scanmodules.chromedevtools.utils import javascript_evaluate, JavaScriptError


LIBRARY_JS = """
(function() {
    return {
        'jQuery': typeof(jQuery) !== 'undefined' ? jQuery.fn.jquery : null,
        'React': typeof(React) !== 'undefined' ? React.version : null,
        'AngularJS': typeof(angular) !== 'undefined' ? angular.version.full : null
    };
})()
"""


class JavaScriptLibsExtractor(Extractor):
    def extract_information(self):
        if self.options['disable_javascript']:
            return
        versions = {
            'jQuery': None,
            'React': None,
            'AngularJS': None
        }
        try:
            versions.update(javascript_evaluate(self.page.tab, LIBRARY_JS))
        except JavaScriptError:
            pass
        self.result['javascript_libraries'] = versions
