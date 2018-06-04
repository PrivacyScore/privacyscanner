import json

from ..base import AbstractChromeScan


LIBRARY_JS = """
(function() {
    return JSON.stringify({
        'jQuery': typeof(jQuery) !== 'undefined' ? jQuery.fn.jquery : null,
        'React': typeof(React) !== 'undefined' ? React.version : null
    });
})();
"""


class JavaScriptLibsMixin(AbstractChromeScan):
    def _extract_javascript_libs(self):
        versions = json.loads(self.tab.Runtime.evaluate(expression=LIBRARY_JS)['result']['value'])
        self.result['javascript_libraries'] = versions
