import re


def camelcase_to_underscore(text):
    return re.sub('[A-Z]', lambda m: '_' + m.group(0).lower(), text)