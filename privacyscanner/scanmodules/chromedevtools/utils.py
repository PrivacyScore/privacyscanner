import json
import re


class JavaScriptError(Exception):
    pass


def camelcase_to_underscore(text):
    return re.sub('[A-Z]', lambda m: '_' + m.group(0).lower(), text)


def javascript_evaluate(tab, js_expr):
    js_expr = _javascript_stringify(js_expr)
    result = tab.Runtime.evaluate(expression=js_expr)['result']
    if result.get('subtype') == 'error':
        error_type = result.get('className', 'UnknownError')
        error_description = result.get('description', 'No description')
        raise JavaScriptError('{}: {}'.format(error_type, error_description))
    elif result.get('type') == 'string':
        return json.loads(result.get('value', 'null'))
    else:
        raise RuntimeError('Unexpected response from Chrome: {}'.format(result))


def _javascript_stringify(js_expr):
    return """
    (function() {
        var __oldToJSON = Array.prototype.toJSON;
        delete Array.prototype.toJSON;
        var __returnValue = JSON.stringify(%s);
        if (typeof(__oldToJSON) !== undefined) {
            Array.prototype.toJSON = __oldToJSON;
        }
        return __returnValue;
    })();
    """ % js_expr.strip()
