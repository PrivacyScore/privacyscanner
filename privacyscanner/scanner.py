import argparse
import hashlib
import json
import logging
import os
import pprint
import string
import sys
import tempfile
import time
from collections import namedtuple
from copy import deepcopy
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

from toposort import toposort, toposort_flatten

from privacyscanner.filehandlers import DirectoryFileHandler
from privacyscanner.raven import has_raven, raven
from privacyscanner.result import Result
from privacyscanner.scanmeta import ScanMeta
from privacyscanner.scanmodules import load_modules
from privacyscanner import defaultconfig
from privacyscanner.loghandlers import ScanFileHandler, ScanStreamHandler
from privacyscanner.exceptions import RescheduleLater, RetryScan
from privacyscanner.utils import NumericLock


CONFIG_LOCATIONS = [
    Path('~/.config/privacyscanner/config.py').expanduser(),
    Path('/etc/privacyscanner/config.py')
]


class CommandError(Exception):
    pass


QueueEntry = namedtuple('QueueEntry', ['scan_module_name', 'num_try', 'not_before'])


def load_config(config_file):
    config = deepcopy(defaultconfig.__dict__)
    if config_file is None:
        for filename in CONFIG_LOCATIONS:
            if filename.is_file():
                config_file = filename
                break
    if config_file:
        config_file = Path(config_file)
        try:
            with config_file.open() as f:
                code = compile(f.read(), config_file.name, 'exec')
                exec(code, {}, config)
        except IOError as e:
            raise CommandError('Could not open config: {}'.format(e)) from e
        except Exception as e:
            raise CommandError('Could not parse config: {}: {}'.format(
                e.__class__.__name__, e)) from e

    config['STORAGE_PATH'] = Path(config['STORAGE_PATH']).expanduser()

    # Make sure that all scan modules know the path where dependencies
    # are stored. Use the default path if not configured.
    all_options = config['SCAN_MODULE_OPTIONS'].setdefault('__all__', {})
    all_options['storage_path'] = config['STORAGE_PATH']

    return config


def slugify(somestr):
    allowed_chars = string.ascii_lowercase + string.digits + '.-'
    return ''.join(x for x in somestr.lower() if x in allowed_chars)


def run_workers(args):
    from .worker import WorkerMaster

    config = load_config(args.config)
    _require_dependencies(config)

    raven_client = None
    if has_raven and config['RAVEN_DSN']:
        raven_client = raven.Client(config['RAVEN_DSN'])
    master = WorkerMaster(config['QUEUE_DB_DSN'], config['SCAN_MODULES'],
                          config['SCAN_MODULE_OPTIONS'], config['MAX_TRIES'],
                          config['NUM_WORKERS'], config['MAX_EXECUTIONS'],
                          config['MAX_EXECUTION_TIMES'], config['RAVEN_DSN'])
    try:
        master.start()
    except Exception:
        raven_client.captureException()


def scan_site(args):
    config = load_config(args.config)
    _require_dependencies(config)

    site_parsed = urlparse(args.site)
    if site_parsed.scheme not in ('http', 'https'):
        raise CommandError('Invalid site: {}'.format(args.site))

    results_dir = args.results
    if results_dir is None:
        results_dir = slugify(site_parsed.netloc) + '_'
        results_dir += hashlib.sha512(args.site.encode()).hexdigest()[:10]
    results_dir = Path(results_dir).resolve()
    try:
        results_dir.mkdir(exist_ok=True)
    except IOError as e:
        raise CommandError('Could not create results directory: {}'.format(e)) from e

    result_file = results_dir / 'results.json'
    result_json = {'site_url': args.site}
    if args.import_results:
        try:
            with open(args.import_results) as f:
                import_json = json.load(f)
        except IOError as e:
            raise CommandError('Could not open result JSON: {}'.format(e)) from e
        except ValueError as e:
            raise CommandError('Could not parse result JSON: {}'.format(e)) from e
        else:
            result_json.update(import_json)
    try:
        with result_file.open('w') as f:
            json.dump(result_json, f, indent=2)
            f.write('\n')
    except IOError as e:
        raise CommandError('Could not write result JSON: {}'.format(e)) from e

    scan_modules = load_modules(config['SCAN_MODULES'],
                                config['SCAN_MODULE_OPTIONS'])
    scan_module_names = args.scan_modules

    if scan_module_names is None:
        scan_module_names = scan_modules.keys()

    # Order scan_module_names by dependency topologically
    dependencies = {}
    for scan_module_name in scan_module_names:
        mod = scan_modules[scan_module_name]
        dependencies[mod.name] = set(mod.dependencies)
    scan_module_names = toposort_flatten(dependencies)

    if args.skip_dependencies:
        scan_module_names = [
            scan_module_name
            for scan_module_name in scan_module_names
            if scan_module_name in args.scan_modules
        ]

    has_error = False
    result = Result(result_json, DirectoryFileHandler(results_dir))
    stream_handler = ScanStreamHandler()
    logs_dir = results_dir / 'logs'
    logs_dir.mkdir(exist_ok=True)
    lock_dir = config['STORAGE_PATH'] / 'locks'
    lock_dir.mkdir(exist_ok=True)
    scan_queue = [QueueEntry(mod_name, 0, None) for mod_name in scan_module_names]
    scan_queue.reverse()
    while scan_queue:
        scan_module_name, num_try, not_before = scan_queue.pop()
        if not_before is not None:
            # noinspection PyTypeChecker
            while datetime.utcnow() < not_before:
                time.sleep(0.5)
        mod = scan_modules[scan_module_name]
        num_try += 1
        log_filename = (logs_dir / (mod.name + '.log'))
        file_handler = ScanFileHandler(str(log_filename))
        logger = logging.Logger(mod.name)
        logger.addHandler(stream_handler)
        logger.addHandler(file_handler)
        with tempfile.TemporaryDirectory() as temp_dir:
            old_cwd = os.getcwd()
            os.chdir(temp_dir)
            logger.info('Starting %s', mod.name)
            try:
                with NumericLock(lock_dir) as worker_id:
                    scan_meta = ScanMeta(worker_id=worker_id, num_tries=num_try)
                    mod.logger = logger
                    mod.scan_site(result, scan_meta)
            except RetryScan:
                if num_try <= config['MAX_TRIES']:
                    scan_queue.append(QueueEntry(scan_module_name, num_try, not_before))
                    logger.info('Scan module `%s` will be retried', mod.name)
                else:
                    has_error = True
            except RescheduleLater as e:
                scan_queue.append(QueueEntry(scan_module_name, num_try, e.not_before))
            except Exception:
                if num_try <= config['MAX_TRIES']:
                    scan_queue.append(QueueEntry(scan_module_name, num_try, not_before))
                has_error = True
                logger.exception('Scan module `%s` failed.', mod.name)
            finally:
                os.chdir(old_cwd)
                with result_file.open('w') as f:
                    json.dump(result.get_results(), f, indent=2, sort_keys=True)
                    f.write('\n')
            logger.info('Finished %s', mod.name)
    pprint.pprint(result.get_results())
    if has_error:
        sys.exit(1)


def update_dependencies(args):
    config = load_config(args.config)
    scan_modules = load_modules(config['SCAN_MODULES'],
                                config['SCAN_MODULE_OPTIONS'])
    updated = []
    stream_handler = ScanStreamHandler()
    for scan_module in scan_modules.values():
        logger = logging.Logger(scan_module.name)
        logger.addHandler(stream_handler)
        if hasattr(scan_module, 'update_dependencies'):
            logger.info('Updating dependencies')
            scan_module.update_dependencies()
            updated.append(scan_module.name)
    if updated:
        print('\nUpdated dependencies of: ' + ' '.join(updated))
    else:
        print('\nNothing to update.')


def print_master_config(args):
    config = load_config(args.config)
    scan_modules = load_modules(config['SCAN_MODULES'],
                                config['SCAN_MODULE_OPTIONS'])
    dependencies = {}
    for scan_module in scan_modules.values():
        dependencies[scan_module.name] = set(scan_module.dependencies)
    modules_topology = {}
    for index, module_list in enumerate(toposort(dependencies)):
        for module_name in module_list:
            modules_topology[module_name] = index
    output = '# Scan modules with topological dependency order index.\n'
    output += '# Run the following to obtain this configuration value:\n'
    output += '# privacyscanner print_master_config --config yourconfig.py\n'
    output += 'SCAN_MODULES = {}'.format(pprint.pformat(modules_topology, indent=4))
    print(output)


def _require_dependencies(config):
    if not config['STORAGE_PATH'].exists():
        print('Please run `privacyscanner update_dependencies` before the first scan.')
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(description='Scan sites for privacy.')
    subparsers = parser.add_subparsers(dest='command')

    parser_run_workers = subparsers.add_parser('run_workers')
    parser_run_workers.add_argument('-c', '--config', help='Configuration_file')
    parser_run_workers.set_defaults(func=run_workers)

    parser_scan = subparsers.add_parser('scan')
    parser_scan.add_argument('site', help='Site to scan')
    parser_scan.add_argument('-c', '--config', help='Configuration_file')
    parser_scan.add_argument('-r', '--results', help='Directory to store results')
    parser_scan.add_argument('--import-results', dest='import_results',
                             help='Import JSON results from a file before scanning')
    parser_scan.add_argument('-m', '--scan-modules', dest='scan_modules',
                             type=lambda scans: [x.strip() for x in scans.split(',')],
                             help='Comma separated list of scan modules')
    parser_scan.add_argument('--skip-dependencies', action='store_true',
                             help='Do not run dependencies that are not explicitly '
                                  'specified using --scans')
    parser_scan.add_argument('--print', dest='print_result', action='store_true')
    parser_scan.set_defaults(func=scan_site)

    parser_print_master_config = subparsers.add_parser('print_master_config')
    parser_print_master_config.add_argument('-c', '--config', help='Configuration_file')
    parser_print_master_config.set_defaults(func=print_master_config)

    parser_run_workers = subparsers.add_parser('update_dependencies')
    parser_run_workers.add_argument('--config', help='Configuration_file')
    parser_run_workers.set_defaults(func=update_dependencies)

    args = parser.parse_args()
    if args.command is None:
        parser.error('No arguments')
    if args.command == 'scan' and args.skip_dependencies and not args.scan_modules:
        parser.error('--skip-dependencies can only be set when using --scan-modules')
    try:
        args.func(args)
    except CommandError as e:
        print(str(e), file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
