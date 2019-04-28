import pychrome

from privacyscanner.scanmodules.chromedevtools.extractors.base import Extractor
from privacyscanner.scanmodules.chromedevtools.utils import scripts_disabled

ELEMENT_NODE = 3


class SriExtractor(Extractor):

    def extract_information(self):
        # Disable scripts to avoid DOM changes while searching for generator tags, see imprint.py / pull request
        with scripts_disabled(self.page.tab, self.options):
            self.extract_sri()

    def extract_sri(self):
        integrity_elements = []
        requests = self.page.request_log

        sri_dict = {}
        final_sri_list = []
        failed_urls = []

        sri_dict['sri-required-for'] = None
        sri_dict['all-sri-active-valid'] = False

        # Check already read CSP Values in _self

        if 'require-sri-for' in self.result._result_dict['security_headers']['Content-Security-Policy']:
            sri_dict['sri-required-for'] = self.result._result_dict['security_headers']['Content-Security-Policy'][
                'sri-required-for'][0]

        for request in requests:
            searchterm = request['url'].rsplit('/', 1)[1]
            if searchterm != "":
                search = self.page.tab.DOM.performSearch(query=searchterm)
                if search['resultCount'] == 0:
                    continue
                results = self.page.tab.DOM.getSearchResults(
                    searchId=search['searchId'], fromIndex=0, toIndex=search['resultCount'])
                for node_id in results['nodeIds']:
                    while node_id is not None:
                        try:
                            node = self.page.tab.DOM.describeNode(nodeId=node_id)['node']
                        except pychrome.CallMethodException:
                            # For some reason, nodes seem to disappear in-between,
                            # so just ignore these cases.
                            break

                        if node['nodeType'] == 1 and 'href' in node['attributes']:
                            if "stylesheet" in node['attributes']:
                                self.add_element_to_linklist(final_sri_list, None, node['attributes'])
                                break
                        if node['nodeType'] == 1 and 'href' in node['attributes']:
                            if "script" in node['attributes']:
                                print('SCRIPT FOUND')
                                self.add_element_to_linklist(final_sri_list, None, node['attributes'])
                                break
                        node_id = node.get('parentId')

        logging_log = self.page.logging_log

        # Check if href is in entry list, if yes set attributes accordingly.
        for element in logging_log:
            if element['entry']['source'] == 'security' and element['entry']['level'] == 'error':
                if 'Failed to find a valid digest' in element['entry']['text']:
                    failed_urls.append(element['entry']['text'].split('\'')[3])
        for element in final_sri_list:
            for final_url in failed_urls:
                if '/' + element['href'].replace('/', '', 1) in final_url:
                    element['integrity_valid'] = False
                elif element['integrity_active']:
                    element['integrity_valid'] = True
                else:
                    element['integrity_valid'] = None

        sri_dict['link-list'] = final_sri_list

        # not active to not put useless results in json
        self.result['sri-fail'] = sri_dict

    def add_element_to_linklist(self, final_sri_list, node_value, node_attributes):
        global new_entry
        new_entry = dict(href=None, type=None, integrity_active=False, integrity_hash=None, integrity_valid=None)
        if node_value is not None:
            value_parts = node_value.split()
            for element in value_parts:
                if 'href=' in element:
                    new_entry['href'] = element.split('"')[1]
                if 'integrity' in element:
                    new_entry['integrity_active'] = True
                    new_entry['integrity_hash'] = element.split('"')[1]

        if node_attributes is not None:
            new_entry['href'] = node_attributes[node_attributes.index('href') + 1]
            new_entry['type'] = node_attributes[node_attributes.index('rel') + 1]
            if 'integrity' in node_attributes:
                new_entry['integrity_active'] = True
                new_entry['integrity_hash'] = node_attributes[node_attributes.index('integrity') + 1]

        if new_entry not in final_sri_list:
            final_sri_list.append(new_entry)
