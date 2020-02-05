from privacyscanner.scanmodules.chromedevtools.extractors.base import Extractor
from privacyscanner.utils import download_file
from pathlib import Path

CLIQZ_DOWNLOAD_PREFIX = 'https://raw.githubusercontent.com/cliqz-oss/whotracks.me/master/whotracksme/data/assets/'
CLIQZ_FILES = ['trackerdb.sql']
CLIQZ_PATH = Path('cliqz')


class WhotracksmeExtractor(Extractor):

    def extract_information(self):
        trackerdb = self._load_tracker_db(True)
        domaindb = trackerdb[0]
        companydb = trackerdb[1]
        third_party_domains = self.result['third_parties']['fqdns']

        if len(third_party_domains) > 0:
            organizations = dict(domains={}, details={})

            if third_party_domains is not None and len(third_party_domains) > 0:
                for element in third_party_domains:
                    scn = self._find_company_network(domaindb, element)
                    if scn is not None:
                        organizations['domains'][element] = scn
                        organizations['details'][scn] = companydb[scn]

            self.result['organizations'] = organizations
        else:
            self.result['organizations'] = None

    @staticmethod
    def update_dependencies(options):
        trackerdb_path = options['storage_path'] / CLIQZ_PATH
        trackerdb_path.mkdir(parents=True, exist_ok=True)
        for filename in CLIQZ_FILES:
            download_url = CLIQZ_DOWNLOAD_PREFIX + filename
            target_file = (trackerdb_path / filename).open('wb')
            download_file(download_url, target_file)

    def _load_tracker_db(self, load_switch):
        domaindb = {}
        companydb = {}
        if load_switch:
            domaindb = {}
            companydb = {}
            tracker_db_path = self.options['storage_path'] / CLIQZ_PATH / "trackerdb.sql"
            f = open(tracker_db_path, "r")
            sql_generator = f.readlines()
            for line in sql_generator:
                if 'INSERT INTO "tracker_domains"' in line:
                    sl = line.split("'")
                    if not sl[1] in domaindb:
                        domaindb[sl[1]] = []
                    domaindb[sl[1]].append(sl[3])
                if 'INSERT INTO "trackers"' in line:
                    sl = line.split("'")
                    if not sl[1] in companydb:
                        companydb[sl[1]] = {}
                        companydb[sl[1]]['name'] = sl[3]
                        if ',NULL' in sl[4]:
                            companydb[sl[1]]['main-domain'] = None
                        else:
                            companydb[sl[1]]['main-domain'] = sl[5]

        return domaindb, companydb

    def _find_company_network(self, domaindb, domain):
        returnable = None

        # Everytime the domain is given with ".domain.tld", remove the leading .
        if domain[0] == '.':
            domain = domain[1:]

        # If a subdomain is given, but not in tracker list, search without subdomain
        dsplit = domain.split('.')

        if len(dsplit) > 2:
            no_sub_domain = dsplit[len(dsplit) - 2] + '.' + dsplit[len(dsplit) - 1]
        else:
            no_sub_domain = None

        for key in domaindb.keys():
            for i in range(len(domaindb[key])):
                if domain in domaindb[key][i]:
                    returnable = key
                elif no_sub_domain is not None and no_sub_domain in domaindb[key][i]:
                    returnable = key
        return returnable
