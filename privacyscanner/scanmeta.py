class ScanMeta:
    def __init__(self, worker_id, num_tries):
        self.worker_id = worker_id
        self.num_tries = num_tries

    @property
    def is_first_try(self):
        return self.num_tries == 1
