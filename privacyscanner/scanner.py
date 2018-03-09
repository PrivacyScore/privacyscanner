import argparse
import json
import hashlib
import logging
import pprint
import string
import sys
from copy import deepcopy
from urllib.parse import urlparse
from pathlib import Path

from toposort import toposort, toposort_flatten

from privacyscanner.filehandlers import DirectoryFileHandler
from privacyscanner.result import Result
from privacyscanner.scanmodules import load_modules
from privacyscanner import defaultconfig
from privacyscanner.loghandlers import ScanFileHandler, ScanStreamHandler

CONFIG_LOCATIONS = [
    Path('~/.config/privacyscanner/config.py').expanduser(),
    Path('/etc/privacyscanner/config.py')
]


class CommandError(Exception):
    pass


def load_config(config_file):
    config = deepcopy(defaultconfig.__dict__)
    if config_file is None:
        for filename in CONFIG_LOCATIONS:
            if filename.is_file():
                config_file = filename
                break
        else:
            return config
    try:
        with open(config_file, 'r') as f:
            code = compile(f.read(), config_file, 'exec')
            exec(code, {}, config)
            return config
    except IOError as e:
        raise CommandError('Could not open config: {}'.format(e)) from e
    except Exception as e:
        raise CommandError('Could not parse config: {}: {}'.format(e.__class__.__name__, e)) from e


def slugify(somestr):
    allowed_chars = string.ascii_lowercase + '.-'
    return ''.join(x for x in somestr.lower() if x in allowed_chars)


def run_workers(args):
    from .worker import WorkerMaster

    config = load_config(args.config)
    master = WorkerMaster(config['QUEUE_DB_DSN'], config['SCAN_MODULES'],
                          config['SCAN_MODULE_OPTIONS'], config['NUM_WORKERS'],
                          config['MAX_EXECUTIONS'], config['MAX_EXECUTION_TIMES'])
    master.start()


def scan_site(args):
    config = load_config(args.config)
    
    site_parsed = urlparse(args.site)
    if site_parsed.scheme not in ('http', 'https'):
        raise CommandError('Invalid site: {}'.format(args.site))
    
    results_dir = args.results
    if results_dir is None:
        results_dir = slugify(site_parsed.netloc) + '_'
        results_dir += hashlib.sha512(args.site.encode()).hexdigest()[:10]
    results_dir = Path(results_dir)
    try:
        results_dir.mkdir(exist_ok=True)
    except IOError as e:
        raise CommandError('Could not create results directory: {}'.format(e)) from e

    result_file = results_dir / 'results.json'
    result_json = {'site': args.site}
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
        with open(result_file, 'w') as f:
            json.dump(result_json, f, indent=2)
            f.write('\n')
    except IOError as e:
        raise CommandError('Could not write result JSON: {}'.format(e)) from e

    scan_modules = load_modules(config['SCAN_MODULES'])
    scan_module_names = args.scan_modules

    if scan_module_names is None:
        scan_module_names = scan_modules.keys()

    # Order scan_module_names by dependency topologically
    dependencies = {}
    for scan_module_name in scan_module_names:
        mod = scan_modules[scan_module_name]
        dependencies[mod.name] = set(mod.dependencies)
    scan_module_names = toposort_flatten(dependencies)

    result = Result(result_json, DirectoryFileHandler(results_dir))
    stream_handler = ScanStreamHandler()
    for scan_module_name in scan_module_names:
        mod = scan_modules[scan_module_name]
        file_handler = ScanFileHandler(results_dir / (mod.name + '.log'))
        logger = logging.Logger(mod.name)
        logger.addHandler(stream_handler)
        logger.addHandler(file_handler)
        options = config['SCAN_MODULE_OPTIONS'].get(mod.name, {})
        try:
            mod.scan_site(result, logger, options)
        except Exception:
            logger.exception('Scan module `{}` failed.'.format(mod.name))
            sys.exit(1)
    pprint.pprint(result.get_results())


def print_master_config(args):
    config = load_config(args.config)
    scan_modules = load_modules(config['SCAN_MODULES'])
    dependencies = {}
    for scan_module in scan_modules.values():
        dependencies[scan_module.name] = set(scan_module.dependencies)
    modules_topology = {}
    for index, module_list in enumerate(toposort(dependencies)):
        for module_name in module_list:
            modules_topology[module_name] = index
    output = '# Scan modules with topological dependency order index.\n'
    output += '# Run the following to obtain this configuration value:\n'
    output += '# privacyscanner print_scan_modules --config yourconfig.py\n'
    output += 'SCAN_MODULES = {}'.format(pprint.pformat(modules_topology, indent=4))
    print(output)


def main():
    parser = argparse.ArgumentParser(description='Scan sites for privacy.')
    subparsers = parser.add_subparsers()

    parser_run_workers = subparsers.add_parser('run_workers')
    parser_run_workers.add_argument('--config', help='Configuration_file')
    parser_run_workers.set_defaults(func=run_workers)
    
    parser_scan = subparsers.add_parser('scan')
    parser_scan.add_argument('site', help='Site to scan')
    parser_scan.add_argument('--config', help='Configuration_file')
    parser_scan.add_argument('--results', help='Directory to store results')
    parser_scan.add_argument('--import-results', dest='import_results',
            help='Import JSON results from a file before scanning')
    parser_scan.add_argument('--scans', dest='scan_modules',
                             type=lambda scans: [x.strip() for x in scans.split(',')],
                             help='Comma separated list of scan modules')
    parser_scan.add_argument('--print', dest='print_result', action='store_true')
    parser_scan.set_defaults(func=scan_site)

    parser_print_master_config = subparsers.add_parser('print_master_config')
    parser_print_master_config.add_argument('--config', help='Configuration_file')
    parser_print_master_config.set_defaults(func=print_master_config)

    args = parser.parse_args()
    try:
        args.func(args)
    except CommandError as e:
        print(str(e), file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
