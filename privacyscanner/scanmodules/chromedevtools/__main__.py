import logging
import sys
import pprint

from . import scan_site


if __name__ == '__main__':
    logger = logging.getLogger()
    result = {'site_url': sys.argv[1]}
    scan_site(result, logger, {})
    pprint.pprint(result)
