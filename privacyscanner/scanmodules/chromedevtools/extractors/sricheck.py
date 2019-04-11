import pychrome

from privacyscanner.scanmodules.chromedevtools.extractors.base import Extractor

ELEMENT_NODE = 3


class SriExtractor(Extractor):
    def extract_information(self):
        integrity_elements = []
        requests = self.page.request_log

        final_sri_list = []

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
                        if node['nodeType'] == ELEMENT_NODE and node['nodeName'].lower() == '#text':
                            if "stylesheet" in node['nodeValue']:
                                integrity_elements.append(node['nodeValue'])
                                print(node['nodeValue'])
                                break
                        node_id = node.get('parentId')

        for element in integrity_elements:
            # dict of href, bool if integrity, integrity hash
            value_parts = element.split()
            new_entry = {}
            new_entry['href'] = None
            new_entry['integrity_active'] = False
            new_entry['integrity_hash'] = None
            for element in value_parts:
                if 'href=' in element:
                    new_entry['href'] = element.split('"')[1]
                if 'integrity' in element:
                    new_entry['integrity_active'] = True
                    new_entry['integrity_hash'] = element.split('"')[1]
                # own SHA check?
            if new_entry not in final_sri_list:
                final_sri_list.append(new_entry)

        # in here for debugging
        requests2 = self.page.document_request_log
        failed_requests = self.page.failed_request_log
        security = self.page.security_state_log

        # not active to not put useless results in json
        # self.result['sri-fail'] = requests

