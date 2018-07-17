import logging


class WorkerWritePipeHandler(logging.Handler):
    def __init__(self, pid, write_pipe, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.pid = pid
        self.write_pipe = write_pipe
        fmt = '%(message)s (%(filename)s:%(lineno)d)'
        self.setFormatter(logging.Formatter(fmt))

    def emit(self, record):
        message = self.format(record)
        self.write_pipe.send((self.pid, 'log', (record.created, record.levelno, message)))


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
