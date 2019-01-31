import importlib


class ModuleLoadError(Exception):
    pass


class ScanModule:
    def __init__(self, options):
        self.options = options

    def scan_site(self, result, logger, meta):
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
        options = module_options.get(class_obj.name, {})
        scan_modules[class_obj.name] = class_obj(options.get(class_obj.name, {}))
    return scan_modules
