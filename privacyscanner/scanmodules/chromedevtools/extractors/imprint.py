import warnings
from urllib.parse import urlparse

import pychrome

from privacyscanner.scanmodules.chromedevtools.extractors.base import Extractor
from privacyscanner.scanmodules.chromedevtools.utils import scripts_disabled


ELEMENT_NODE = 1


class ImprintExtractor(Extractor):
    IMPRINT_KEYWORDS = ['imprint', 'impressum', 'contact', 'kontakt', 'about us', 'über uns']

    def extract_information(self):
        # Disable scripts to avoid DOM changes while searching for the imprint.
        with scripts_disabled(self.page.tab, self.options):
            self._extract_imprint()

    def _extract_imprint(self):
        node_id = self.page.tab.DOM.getDocument()['root']['nodeId']
        links = self.page.tab.DOM.querySelectorAll(nodeId=node_id, selector='a')['nodeIds']
        imprint_link = None

        # Use the browsers search to search for the keywords. For each result,
        # we walk up the DOM until we find an ``a'' element. If this element
        # has an href, this is our imprint link. Otherwise, we look for the
        # next search result.
        for keyword in self.IMPRINT_KEYWORDS:
            search = self.page.tab.DOM.performSearch(query=keyword)
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
                    if node['nodeType'] == ELEMENT_NODE and node['nodeName'].lower() == 'a':
                        if not self._is_visible(node_id):
                            break
                        href = self._get_href(node_id)
                        if href:
                            imprint_link = href
                        break
                    node_id = node.get('parentId')
                if imprint_link:
                    break
            if imprint_link:
                break

        # If our browser search does not give results, search more brutally
        # for all links, including those, who are not visible to the user.
        if not imprint_link:
            for link in links:
                try:
                    link_html = self.page.tab.DOM.getOuterHTML(nodeId=link)['outerHTML']
                except pychrome.CallMethodException:
                    # For some reason, nodes seem to disappear in-between,
                    # so just ignore these cases.
                    break
                for order_id, keyword in enumerate(self.IMPRINT_KEYWORDS):
                    if keyword in link_html:
                        href = self._get_href(link)
                        if href:
                            imprint_link = href
                            break
                if imprint_link:
                    break

        if imprint_link:
            if imprint_link.startswith('//'):
                p = urlparse(self.result['final_url'])
                imprint_link = '{}:{}'.format(p.scheme, imprint_link)
            elif imprint_link.startswith('/'):
                p = urlparse(self.result['final_url'])
                imprint_link = '{}://{}{}'.format(p.scheme, p.hostname, imprint_link)
            elif imprint_link.startswith(('https://', 'http://')):
                # Nothing to do, already the full URL
                pass
            else:
                base_url = self.result['final_url'].rsplit('/', 1)[0]
                imprint_link = '{}/{}'.format(base_url, imprint_link)
        self.result['imprint_url'] = imprint_link

    def _get_href(self, node_id):
        attrs = self.page.tab.DOM.getAttributes(nodeId=node_id)['attributes']
        attrs = dict(zip(*[iter(attrs)]*2))
        return attrs.get('href')

    def _is_visible(self, node_id):
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                self.page.tab.DOM.getBoxModel(nodeId=node_id)
            return True
        except pychrome.exceptions.CallMethodException:
            return False
