import os
import errno
import fcntl
import time
from urllib.request import Request, urlopen


FAKE_UA = 'Mozilla/5.0 (X11; Linux x86_64; rv:61.0) Gecko/20100101 Firefox/61.0'


class NumericLock:
    def __init__(self, lock_dir):
        self.lock_dir = lock_dir
        self._lock_file = None

    def __enter__(self):
        i = 0
        while True:
            i += 1
            try:
                f = open(self.lock_dir / ('%d.lock' % i), 'wb')
                fcntl.lockf(f.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                self._lock_file = f
                return i
            except OSError as e:
                if e.errno in (errno.EACCES, errno.EAGAIN):
                    continue
                raise

    def __exit__(self, exc_type, exc_val, exc_tb):
        fcntl.lockf(self._lock_file.fileno(), fcntl.LOCK_UN)
        self._lock_file.close()
        os.unlink(self._lock_file.name)


def download_file(url, fileobj):
    request = Request(url)
    request.add_header('User-Agent', FAKE_UA)
    response = urlopen(request)
    copy_to(response, fileobj)
    fileobj.flush()


def copy_to(src, dest):
    while True:
        data = src.read(8192)
        if not data:
            break
        dest.write(data)


def file_is_outdated(path, max_age):
    try:
        return path.stat().st_mtime + max_age < time.time()
    except FileNotFoundError:
        return True


def set_default_options(target, defaults):
    for key, value in defaults.items():
        if key in target:
            new_target = target[key]
            if isinstance(new_target, dict):
                set_default_options(new_target, value)
        else:
            target[key] = value
