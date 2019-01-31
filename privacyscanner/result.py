class Result(object):
    def __init__(self, result_dict, file_handler):
        self._result_dict = result_dict
        self._file_handler = file_handler
        self._updated_keys = set()

    def add_debug_file(self, filename, contents=None):
        self._file_handler.add_file(
            filename, self._get_file_contents(filename, contents), debug=True)

    def add_file(self, filename, contents):
        self._file_handler.add_file(
            filename, self._get_file_contents(filename, contents), debug=False)

    def _get_file_contents(self, filename, contents=None):
        if contents is None:
            with open(filename, 'rb') as f:
                return f.read()
        if hasattr(contents, 'read'):
            contents = contents.read()
        return contents

    def __getitem__(self, key):
        return self._result_dict[key]

    def __setitem__(self, key, value):
        self.mark_dirty(key)
        self._result_dict[key] = value

    def __contains__(self, key):
        return key in self._result_dict

    def get(self, key, d=None):
        return self._result_dict.get(key, d)

    def keys(self):
        return self._result_dict.keys()

    def values(self):
        return self._result_dict.items()

    def items(self):
        return self._result_dict.items()

    def update(self, d, **kwargs):
        if isinstance(d, dict):
            for key in d:
                self.mark_dirty(key)
        else:
            for key, _value in d:
                self.mark_dirty(key)
        for key in kwargs:
            self.mark_dirty(key)
        return self._result_dict.update(d, **kwargs)

    def setdefault(self, key, d):
        self.mark_dirty(key)
        return self._result_dict.setdefault(key, d)

    def mark_dirty(self, key):
        self._updated_keys.add(key)

    def get_updates(self):
        return {key: self._result_dict[key] for key in self._updated_keys}

    def get_results(self):
        return self._result_dict
