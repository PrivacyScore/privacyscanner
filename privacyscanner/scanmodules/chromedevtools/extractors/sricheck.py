import pychrome

from privacyscanner.scanmodules.chromedevtools.extractors.base import Extractor

ELEMENT_NODE = 3

class SriExtractor(Extractor):
    def extract_information(self):
        tags = []
        requests = self.page.request_log
        requests2 = self.page.document_request_log

        for request in requests:
            searchterm = request['url'].rsplit('/', 1)[1]
            if searchterm != "":
                search = self.page.tab.DOM.performSearch(query=searchterm)
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
                            tags.append(node['Value'][3])
                            break
                        node_id = node.get('parentId')

        failed_requests = self.page.failed_request_log
        security = self.page.security_state_log

        self.result['sri-fail'] = requests
# self.page.request_log liefert mir für jeden gemachten Request (in einer list) eine enum + eine requestId,
# die ich in failed dann nachsehen kann. BSP für falsche SRi: 1000020549.3

