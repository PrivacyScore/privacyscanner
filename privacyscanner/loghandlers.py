import logging


class WorkerQueueHandler(logging.Handler):
    def __init__(self, pid, queue, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.pid = pid
        self.queue = queue
        fmt = '%(message)s (%(filename)s:%(lineno)d)'
        self.setFormatter(logging.Formatter(fmt))

    def emit(self, record):
        message = self.format(record)
        self.queue.put((self.pid, 'log', (record.created, record.levelno, message)))


class ScanFileHandler(logging.FileHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        fmt = '%(asctime)s: [%(levelname)s] %(message)s (%(filename)s:%(lineno)d)'
        self.setFormatter(logging.Formatter(fmt))


class ScanStreamHandler(logging.StreamHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        fmt = '%(name)s> %(asctime)s: [%(levelname)s] %(message)s (%(filename)s:%(lineno)d)'
        self.setFormatter(logging.Formatter(fmt))
