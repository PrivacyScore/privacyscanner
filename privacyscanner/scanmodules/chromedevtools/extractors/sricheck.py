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
        sri_dict = {}
        final_sri_list = []
        failed_urls = []

        sri_dict['require_sri_for'] = None
        sri_dict['all_sri_active_and_valid'] = None
        sri_dict['at_least_one_sri_active'] = None
        sri_dict['all_sri_active'] = None

        # Check already read CSP Values in _self
        # Currently Chrome is configured to IGNORE require_sri_for. Only if the flag
        # #enable-experimental-web-platform-features is enabled, it correctly throws an error if a script / style
        # has no integrity-hash.

        security_headers = self.result['security_headers']
        if security_headers['Content-Security-Policy'] is not None:
            if 'require-sri-for' in security_headers['Content-Security-Policy']:
                sri_dict['require_sri_for'] = security_headers['Content-Security-Policy']['require-sri-for'][0]
        # This results in privacyscanner reading the CSP header for SRI but chromedevtools is currently not enforcing it

        node_id = self.page.tab.DOM.getDocument()['root']['nodeId']
        links = self.page.tab.DOM.querySelectorAll(nodeId=node_id, selector='link')['nodeIds']

        for node_id in links:
            while node_id is not None:
                try:
                    node = self.page.tab.DOM.describeNode(nodeId=node_id)['node']
                except pychrome.CallMethodException:
                    # For some reason, nodes seem to disappear in-between,
                    # so just ignore these cases.
                    break

                if node['nodeType'] == 1 and 'href' in node['attributes']:
                    if "stylesheet" in node['attributes']:
                        self._add_element_to_linklist(final_sri_list, None, node['attributes'])
                        break
                    if "script" in node['attributes']:
                        self._add_element_to_linklist(final_sri_list, None, node['attributes'])
                        break
                node_id = node.get('parentId')

        # Check if href is in entry list, if yes set attributes accordingly.
        logging_log = self.page.logging_log
        for element in logging_log:
            if element['entry']['source'] == 'security' and element['entry']['level'] == 'error':
                if 'Failed to find a valid digest' in element['entry']['text']:
                    failed_urls.append(element['entry']['text'].split('\'')[3])

        for element in final_sri_list:
            if len(failed_urls) == 0:
                if element['integrity_active']:
                    element['integrity_valid'] = True
            for final_url in failed_urls:
                # if '/' + element['href'].replace('/', '', 1) in final_url:
                if '/' + element['href'] in final_url:
                    element['integrity_valid'] = False
                elif element['integrity_active']:
                    element['integrity_valid'] = True
                else:
                    element['integrity_valid'] = None

        # Check if all links have SRI enabled and have a valid hash

        active_counter, valid_counter = 0, 0

        for element in final_sri_list:
            if element['integrity_active'] and not None:
                active_counter += 1
            if element['integrity_valid'] and not None:
                valid_counter += 1

        # Case 1: All CSS/JS have SRI active

        if len(final_sri_list) > 0 and len(final_sri_list) == active_counter:
            sri_dict['all_sri_active'] = True
        else:
            sri_dict['all_sri_active'] = False

        # Case 2: At least one of CSS/JS has SRI active (but can be invalid)
        # This is to not punish websites for using SRI and having a bad hash due to changed code.

        if active_counter > 0:
            sri_dict['at_least_one_sri_active'] = True
        else:
            sri_dict['at_least_one_sri_active'] = False

        # Case 3: All of the used CSS and JS have SRI enabled and all hashes match.

        if active_counter == valid_counter == len(final_sri_list) and len(final_sri_list) > 0:
            sri_dict['all_sri_active_and_valid'] = True
        else:
            sri_dict['all_sri_active_and_valid'] = False

        sri_dict['link-list'] = final_sri_list

        self.result['sri-info'] = sri_dict

    def _add_element_to_linklist(self, final_sri_list, node_value, node_attributes):
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
            if new_entry['type'] == 'preload':
                new_entry['type'] = node_attributes[node_attributes.index('preload') + 2]
            if 'integrity' in node_attributes:
                new_entry['integrity_active'] = True
                new_entry['integrity_hash'] = node_attributes[node_attributes.index('integrity') + 1]

        if new_entry not in final_sri_list:
            final_sri_list.append(new_entry)
