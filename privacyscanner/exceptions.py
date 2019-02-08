from datetime import timedelta, datetime


class RetryScan(Exception):
    """Raise this exception in scan modules to run the scanning module again.

    Note: This will not retry a scan in case the maximum number of (re)tries
    (default: 3) is already reached.
    """
    pass


class RescheduleLater(Exception):
    def __init__(self, not_before, *args):
        super().__init__(*args)
        if isinstance(not_before, int):
            not_before = timedelta(seconds=not_before)
        if isinstance(not_before, timedelta):
            not_before = datetime.utcnow() + not_before
        self.not_before = not_before
