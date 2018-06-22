class Extractor:
    def __init__(self, page, result, logger, options):
        self.page = page
        self.result = result
        self.logger = logger
        self.options = options

    def extract_information(self):
        raise NotImplementedError('You have to implement extract_information() in {}'.format(
            self.__class__.__name__))

    def receive_log(self, log_type, message, call_back):
        pass

    def register_javascript(self):
        pass