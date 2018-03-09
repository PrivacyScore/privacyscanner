import importlib


class ModuleLoadError(Exception):
    pass


def load_modules(module_list):
    scan_modules = {}
    for module_name in module_list:
        try:
            mod = importlib.import_module(module_name)
        except ImportError as e:
            raise ModuleLoadError('Could not load module {}.'.format(module_name)) from e
        for attr_name in ('name', 'scan_site', 'dependencies', 'required_keys'):
            if not hasattr(mod, attr_name):
                raise ModuleLoadError('Module {} has no attribute `{}`.'.format(
                    module_name, attr_name
                ))
        scan_modules[mod.name] = mod
    return scan_modules
