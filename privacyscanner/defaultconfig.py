QUEUE_DB_DSN = 'dbname=privacyscore user=privacyscore password=privacyscore host=localhost'
MAX_EXECUTION_TIMES = {None: 300}
SCAN_MODULE_OPTIONS = {}
SCAN_MODULES = ['privacyscanner.scanmodules.chromedevtools.ChromeDevtoolsScanModule',
                'privacyscanner.scanmodules.dns.DNSScanModule',
                'privacyscanner.scanmodules.mail.MailScanModule',
                'privacyscanner.scanmodules.serverleaks.ServerleaksScanModule',
                'privacyscanner.scanmodules.testsslsh.TestsslshHttpsScanModule',
                'privacyscanner.scanmodules.testsslsh.TestsslshMailScanModule',]
NUM_WORKERS = 2
MAX_EXECUTIONS = 100
RAVEN_DSN = None
MAX_TRIES = 3
STORAGE_PATH = '~/.local/share/privacyscanner'
