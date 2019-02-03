QUEUE_DB_DSN = 'dbname=privacyscore user=privacyscore password=privacyscore host=localhost'
MAX_EXECUTION_TIMES = {None: 300}
SCAN_MODULE_OPTIONS = {}
SCAN_MODULES = ['privacyscanner.scanmodules.network.NetworkScanModule',
                'privacyscanner.scanmodules.chromedevtools.ChromeDevtoolsScanModule',
                'privacyscanner.scanmodules.dns.DNSScanModule',
                'privacyscanner.scanmodules.serverleaks.ServerleaksScanModule']
NUM_WORKERS = 2
MAX_EXECUTIONS = 100
RAVEN_DSN = None
MAX_TRIES = 3
STORAGE_PATH = '~/.local/share/privacyscanner'
