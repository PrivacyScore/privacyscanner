import re


def camelcase_to_underscore(text):
    return re.sub('[A-Z]', lambda m: '_' + m.group(0).lower(), text)


def javascript_stringify(js_expr):
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