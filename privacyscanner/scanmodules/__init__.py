import importlib
import logging
from typing import Any, Dict, List


class ModuleLoadError(Exception):
    pass


class ScanModule:
    name = None  # type: str
    dependencies = None  # type: List[str]
    required_keys = None  # type: List[str]
    logger = None  # type: logging.Logger
    options = None  # type: Dict[str, Any]

    def __init__(self, options):
        self.options = options
        self.logger = logging.Logger(self.name)

    def scan_site(self, result, meta):
        raise NotImplemented

    def update_dependencies(self):
        pass


def load_modules(module_list, module_options):
    scan_modules = {}
    for module_class in module_list:
        module_name, class_name = module_class.rsplit('.', 1)
        try:
            mod = importlib.import_module(module_name)
            class_obj = getattr(mod, class_name)
        except (ImportError, AttributeError) as e:
            raise ModuleLoadError('Could not load module {}.'.format(module_class)) from e
        for attr_name in ('name', 'scan_site', 'dependencies', 'required_keys'):
            if not hasattr(class_obj, attr_name):
                raise ModuleLoadError('Module {} has no attribute `{}`.'.format(
                    module_class, attr_name
                ))
        # Copy options which are for all scan modules to each individual
        # scan module if they are not set, i.e., you can override them
        # for an individual scan module.
        options = module_options.get(class_obj.name, {})
        for key, value in module_options['__all__'].items():
            if key not in options:
                options[key] = value

        scan_modules[class_obj.name] = class_obj(options)
    return scan_modules
