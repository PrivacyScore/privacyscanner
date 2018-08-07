class ScanMeta:
    def __init__(self, worker_id, num_try):
        self.worker_id = worker_id
        self.num_try = num_try

    @property
    def is_first_try(self):
        return self.num_try == 1
