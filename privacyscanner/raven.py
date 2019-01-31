# Python 3.5 compatibility
try:
    ModuleNotFoundError
except NameError:
    ModuleNotFoundError = ImportError

try:
    import raven
    has_raven = True
except ModuleNotFoundError:
    raven = None
    has_raven = False
