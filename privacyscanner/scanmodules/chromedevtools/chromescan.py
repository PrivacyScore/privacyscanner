import json
import random
import shutil
import subprocess
import tempfile
import threading
import time
import warnings
from base64 import b64decode
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

import pychrome
from requests.exceptions import ConnectionError

from privacyscanner.exceptions import RetryScan
from privacyscanner.scanmodules.chromedevtools.utils import scripts_disabled
from privacyscanner.utils import kill_everything


CHANGE_WAIT_TIME = 15

# See https://github.com/GoogleChrome/chrome-launcher/blob/master/docs/chrome-flags-for-tools.md
# See also https://peter.sh/experiments/chromium-command-line-switches/
CHROME_OPTIONS = [
    # Disable various background network services, including extension
    # updating, safe browsing service, upgrade detector, translate, UMA
    '--disable-background-networking',

    # Disable fetching safebrowsing lists. Otherwise requires a 500KB
    # download immediately after launch. This flag is likely redundant
    # if disable-background-networking is on
    '--safebrowsing-disable-auto-update',

    # Disable syncing to a Google account
    '--disable-sync',

    # Disable reporting to UMA, but allows for collection
    '--metrics-recording-only',

    # Disable installation of default apps on first run
    '--disable-default-apps',

    # Mute any audio
    '--mute-audio',

    # Skip first run wizards
    '--no-first-run',

    # Disable timers being throttled in background pages/tabs
    '--disable-background-timer-throttling',

    # Disables client-side phishing detection. Likely redundant due to
    # the safebrowsing disable
    '--disable-client-side-phishing-detection',

    # Disable popup blocking
    '--disable-popup-blocking',

    # Reloading a page that came from a POST normally prompts the user.
    '--disable-prompt-on-repost',

    # Disable a few things considered not appropriate for automation.
    # (includes password saving UI, default browser prompt, etc.)
    '--enable-automation',

    # Avoid potential instability of using Gnome Keyring or KDE wallet.
    # crbug.com/571003
    '--password-store=basic',

    # Use mock keychain on Mac to prevent blocking permissions dialogs
    '--use-mock-keychain',

    # Allows running insecure content (HTTP content on HTTPS sites)
    # TODO: Discuss if we want this (might include more cookies etc.)
    # '--allow-running-insecure-content',

    # Disable dialog to update components
    '--disable-component-update',

    # Do autoplay everything.
    '--autoplay-policy=no-user-gesture-required',

    # Disable notifications (Web Notification API)
    '--disable-notifications',

    # Disable the hang monitor
    '--disable-hang-monitor',

    # Disable GPU acceleration
    '--disable-gpu',

    # Run headless
    '--headless'
]

PREFS = {
    'profile': {
        'content_settings': {
            'exceptions': {
                # Allow flash for all sites
                'plugins': {
                    'http://*,*': {
                        'setting': 1
                    },
                    'https://*,*': {
                        'setting': 1
                    }
                }
            }
        }
    },
    'session': {
        'restore_on_startup': 4,  # 4 = Use startup_urls
        'startup_urls': ['about:blank']
    }
}

ON_NEW_DOCUMENT_JAVASCRIPT = """
(function() {
    // Do not move this function somewhere else, because it expected to
    // be found on line 6 by the debugger. It is intentionally left
    // empty because the debugger will intercept calls to it and
    // extract the arguments and the stack trace.
    function log(type, message) {
        var setBreakpointOnThisLine;
    }
    
    window.alert = function() {};
    window.confirm = function() {
        return true;
    };
    window.prompt = function() {
        return true;
    };
    
    __extra_scripts__
})();
""".lstrip()

# TODO: There are still some contexts in which this JavaScript snippet does not
#       run properly. This requires more research.
EXTRACT_ARGUMENTS_JAVASCRIPT = '''
(function(logArguments) {
    let retval = 'null';
    if (logArguments !== null) {
        let duplicateReferences = [];
        // JSON cannot handle arbitrary data structures, especially not those
        // with circular references. Therefore we use a custom handler, that,
        // first, remember serialized objects, second, stringifies an object
        // if possible and dropping it if it is not.
        retval = JSON.stringify(logArguments, function(key, value) {
            if (typeof(value) === 'object' && value !== null) {
                if (duplicateReferences.indexOf(value) !== -1) {
                    try {
                        // This is a very ugly hack here. When we have a
                        // duplicate reference, we have to check if it is
                        // really a duplicate reference or only the same value
                        // occurring twice. Therefore, we try to JSON.stringify
                        // it without custom handler. If it throws an exception,
                        // it is indeed circular and we drop it.
                        JSON.stringify(value)
                    } catch (e) {
                        return;
                    }
                } else {
                    duplicateReferences.push(value);
                }
            }
            return value;
        });
    }
    return retval;
})(typeof(arguments) !== 'undefined' ? Array.from(arguments) : null);
'''.lstrip()

# See comments in ON_NEW_DOCUMENT_JAVASCRIPT
ON_NEW_DOCUMENT_JAVASCRIPT_LINENO = 7


class ChromeBrowserStartupError(Exception):
    pass


class NotReachableError(Exception):
    pass


class DNSNotResolvedError(Exception):
    pass


class ChromeBrowser:
    def __init__(self, debugging_port=9222, chrome_executable=None,
                       profile_directory=None):
        self._debugging_port = debugging_port
        if chrome_executable is None:
            chrome_executable = find_chrome_executable()
        self._chrome_executable = chrome_executable
        self._profile_directory = profile_directory

    def __enter__(self):
        self._temp_dir = tempfile.TemporaryDirectory()
        temp_dirname = self._temp_dir.name
        user_data_dir = Path(temp_dirname) / 'chrome-profile'
        if self._profile_directory is None:
            user_data_dir.mkdir()
            default_dir = user_data_dir / 'Default'
            default_dir.mkdir()
            with (default_dir / 'Preferences').open('w') as f:
                json.dump(PREFS, f)
        else:
            shutil.copytree(self._profile_directory, user_data_dir)
        self._start_chrome(user_data_dir)
        return self.browser

    def _start_chrome(self, user_data_dir):
        extra_opts = [
            '--remote-debugging-port={}'.format(self._debugging_port),
            '--user-data-dir={}'.format(user_data_dir)
        ]
        command = [self._chrome_executable] + CHROME_OPTIONS + extra_opts
        self._p = subprocess.Popen(command, stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL)

        self.browser = pychrome.Browser(url='http://127.0.0.1:{}'.format(
            self._debugging_port))

        # Wait until Chrome is ready
        max_tries = 100
        while max_tries > 0:
            try:
                self.browser.version()
                break
            except ConnectionError:
                time.sleep(0.1)
            max_tries -= 1
        else:
            raise ChromeBrowserStartupError('Could not connect to Chrome')

    def __exit__(self, exc_type, exc_val, exc_tb):
        kill_everything(self._p.pid)
        self._temp_dir.cleanup()


class ChromeScan:
    def __init__(self, extractor_classes):
        self._extractor_classes = extractor_classes

    def scan(self, result, logger, options, meta, debugging_port=9222):
        executable = options['chrome_executable']
        profile_directory = options['profile_directory']
        scanner = PageScanner(self._extractor_classes)
        chrome_error = None
        content = None
        with ChromeBrowser(debugging_port, executable, profile_directory) as browser:
            try:
                content = scanner.scan(browser, result, logger, options)
            except pychrome.TimeoutException:
                if meta.is_first_try:
                    raise RetryScan('First timeout with Chrome.')
                chrome_error = 'timeout'
            except ChromeBrowserStartupError:
                if meta.is_first_try:
                    raise RetryScan('Chrome startup problem.')
                chrome_error = 'startup-problem'
            except DNSNotResolvedError:
                if meta.is_first_try:
                    raise RetryScan('DNS could not be resolved.')
                chrome_error = 'dns-not-resolved'
            except NotReachableError as e:
                if meta.is_first_try:
                    raise RetryScan('Not reachable')
                logger.exception('Neither responses, nor failed requests.')
                chrome_error = 'not-reachable'
        result['chrome_error'] = chrome_error
        result['reachable'] = not bool(chrome_error)
        return content


class PageScanner:
    def __init__(self, extractor_classes):
        self._extractor_classes = extractor_classes
        self._page_loaded = threading.Event()
        self._reset()

    def scan(self, browser, result, logger, options):
        self._tab = browser.new_tab()
        self._tab.start()

        self._page = Page(self._tab)
        for extractor_class in self._extractor_classes:
            self._extractors.append(extractor_class(self._page, result, logger, options))

        javascript_enabled = not options['disable_javascript']

        if javascript_enabled:
            self._register_javascript()

        if not javascript_enabled:
            self._tab.Emulation.setScriptExecutionDisabled(value=True)

        if self._is_headless():
            self._tab.Emulation.setDeviceMetricsOverride(
                width=1920, height=1080, screenWidth=1920, screenHeight=1080,
                deviceScaleFactor=0, mobile=False)

        useragent = self._tab.Browser.getVersion()['userAgent'].replace('Headless', '')
        self._tab.Network.setUserAgentOverride(userAgent=useragent)
        self._register_network_callbacks()
        self._tab.Network.enable()

        self._register_security_callbacks()
        self._tab.Security.enable()
        self._tab.Security.setIgnoreCertificateErrors(ignore=True)

        self._tab.Page.loadEventFired = self._cb_load_event_fired
        self._tab.Page.frameScheduledNavigation = self._cb_frame_scheduled_navigation
        self._tab.Page.frameClearedScheduledNavigation = self._cb_frame_cleared_scheduled_navigation
        extra_scripts = '\n'.join('(function() { %s })();' % script
                                  for script in self._extra_scripts)
        source = ON_NEW_DOCUMENT_JAVASCRIPT.replace('__extra_scripts__', extra_scripts)
        self._tab.Page.addScriptToEvaluateOnNewDocument(source=source)
        self._tab.Page.enable()

        if javascript_enabled:
            self._tab.Debugger.scriptParsed = self._cb_script_parsed
            self._tab.Debugger.scriptFailedToParse = self._cb_script_failed_to_parse
            self._tab.Debugger.paused = self._cb_paused
            self._tab.Debugger.resumed = self._cb_resumed
            self._tab.Debugger.enable()
            # Pause the JavaScript before we navigate to the page. This
            # gives us some time to setup the debugger before any JavaScript
            # runs.
            self._tab.Debugger.pause()

        self._page.scan_start = datetime.utcnow()
        try:
            self._tab.Page.navigate(url=result['site_url'],
                                    _timeout=options.get('timeout', 15))
        except pychrome.TimeoutException:
            self._tab.stop()
            browser.close_tab(self._tab)
            self._reset()
            raise

        # We wait for the page to be loaded. Then we wait until we have the
        # page in a stable state, i.e. not changing the URL anymore.
        load_max_wait = 30
        self._page_loaded.wait(load_max_wait)
        has_responses = bool(self._page.response_log)
        if has_responses:
            total_wait = 60
            time_start = time.time()
            while True:
                # If the document was changed, we have to wait for the page to
                # load again. This will not wait if there was no change,
                # because page_loaded event is already set.
                self._page_loaded.wait(load_max_wait)
                self._page_interaction()
                # We wait 15 seconds after the page has loaded, so that any
                # resources can load. This includes JavaScript which might
                # issue further requests.
                if not self._document_will_change.wait(CHANGE_WAIT_TIME):
                    # OK, our page should be stable now. So we will disable any
                    # further requests by just intercepting them and not
                    # taking care of them.
                    # However, to avoid a race condition, we first disable
                    # scripts shortly to check again.
                    with scripts_disabled(self._tab, options):
                        if self._document_will_change.is_set():
                            # It changed again, so yet another loop :-(
                            continue
                        self._tab.Network.setRequestInterception(patterns=[{
                            'resourceType': 'Document'
                        }])
                    break
                # We will only run this "infinite" loop for up to total_wait
                # seconds. If the document changes over and over again, there
                # is nothing we can evaluate reasonably.
                if time_start + total_wait <= time.time():
                    self._reset()
                    raise NotReachableError('No stable page to scan.')

            response = self._page.final_response
            # If there is no frameId, there is no content that was rendered.
            # This is usually the case, when the site has a redirect.
            if 'frameId' in response['extra']:
                res = self._tab.Page.getResourceContent(frameId=response['extra']['frameId'],
                                                        url=response['url'])
                content = b64decode(res['content']) if res['base64Encoded'] else res['content'].encode()
            else:
                content = b''
        else:
            self._tab.stop()
            browser.close_tab(self._tab)
            if self._page.failed_request_log:
                failed_request = self._page.failed_request_log[0]
                if failed_request.get('errorText') == 'net::ERR_NAME_NOT_RESOLVED':
                    self._reset()
                    raise DNSNotResolvedError('DNS could not be resolved.')
            self._reset()
            raise NotReachableError('Not reachable for unknown reasons.')

        self._tab.Page.disable()
        if javascript_enabled:
            self._tab.Debugger.disable()
        self._unregister_network_callbacks()
        self._unregister_security_callbacks()
        if has_responses:
            self._extract_information()
        self._tab.Network.disable()
        self._tab.Security.disable()
        self._tab.stop()
        browser.close_tab(self._tab)
        self._reset()

        return content

    def _cb_request_will_be_sent(self, request, requestId, **kwargs):
        # To avoid reparsing the URL in many places, we parse them all here
        request['parsed_url'] = urlparse(request['url'])
        request['requestId'] = requestId
        request['document_url'] = kwargs.get('documentURL')
        request['extra'] = kwargs
        if request.get('hasPostData', False):
            if 'postData' in request:
                request['post_data'] = request['postData']
            else:
                post_data = self._tab.Network.getRequestPostData(requestId=requestId)
                # To avoid a too high memory usage by single requests
                # we just store the first 64 KiB of the post data
                request['post_data'] = post_data['postData'][:65536]
        else:
            request['post_data'] = None
        self._page.add_request(request)

        # Redirect requests don't have a received response but issue another
        # "request will be sent" event with a redirectResponse key.
        redirect_response = kwargs.get('redirectResponse')
        if redirect_response is not None:
            self._cb_response_received(redirect_response, requestId)

    def _cb_response_received(self, response, requestId, **kwargs):
        response['requestId'] = requestId
        headers_lower = {}
        for header_name, value in response['headers'].items():
            headers_lower[header_name.lower()] = value
        response['headers_lower'] = headers_lower
        response['extra'] = kwargs
        self._page.add_response(response)

    def _cb_script_parsed(self, **script):
        # The first script loaded is our script we set via the method
        # Page.addScriptToEvaluateOnNewDocument. We want to to attach
        # to the log function, which will be used to analyse the page.
        if not self._debugger_attached.is_set():
            self._log_breakpoint = self._tab.Debugger.setBreakpoint(location={
                'scriptId': script['scriptId'],
                'lineNumber': ON_NEW_DOCUMENT_JAVASCRIPT_LINENO
            })['breakpointId']
            if self._debugger_paused.is_set():
                self._tab.Debugger.resume()
            self._debugger_attached.set()

    def _cb_script_failed_to_parse(self, **kwargs):
        pass

    def _cb_paused(self, **info):
        self._debugger_paused.set()
        if self._log_breakpoint in info['hitBreakpoints']:
            call_frames = []
            for call_frame in info['callFrames']:
                javascript_result = self._tab.Debugger.evaluateOnCallFrame(
                    callFrameId=call_frame['callFrameId'],
                    expression=EXTRACT_ARGUMENTS_JAVASCRIPT)['result']
                if 'value' in javascript_result:
                    args = json.loads(javascript_result['value'])
                else:
                    # TODO: We should look for the error here and handle those
                    #       cases to reliably extract the arguments.
                    args = ['error', None]
                call_frames.append({
                    'url': call_frame['url'],
                    'functionName': call_frame['functionName'],
                    'location': {
                        'lineNumber': call_frame['location']['lineNumber'],
                        'columnNumber': call_frame['location']['columnNumber']
                    },
                    'args': args
                })
            self._receive_log(*call_frames[0]['args'], call_frames[1:])
        if self._debugger_attached.is_set():
            self._tab.Debugger.resume()

    def _cb_resumed(self, **info):
        self._debugger_paused.clear()

    def _cb_load_event_fired(self, timestamp, **kwargs):
        self._page_loaded.set()
    
    def _cb_frame_scheduled_navigation(self, frameId, delay, reason, url, **kwargs):
        # We assume that our scan will finish within 60 seconds including
        # a security margin. So we just ignore scheduled navigations if
        # they are too far in future.
        if delay <= 60:
            self._document_will_change.set()
    
    def _cb_frame_cleared_scheduled_navigation(self, frameId):
        self._document_will_change.clear()

    def _cb_security_state_changed(self, **state):
        self._page.security_state_log.append(state)

    def _cb_loading_failed(self, **failed_request):
        self._page.add_failed_request(failed_request)

    def _register_network_callbacks(self):
        self._tab.Network.requestWillBeSent = self._cb_request_will_be_sent
        self._tab.Network.responseReceived = self._cb_response_received
        self._tab.Network.loadingFailed = self._cb_loading_failed

    def _unregister_network_callbacks(self):
        self._tab.Network.requestWillBeSent = None
        self._tab.Network.responseReceived = None
        self._tab.Network.loadingFailed = None

    def _register_security_callbacks(self):
        self._tab.Security.securityStateChanged = self._cb_security_state_changed

    def _unregister_security_callbacks(self):
        self._tab.Security.securityStateChanged = None

    def _is_headless(self):
        try:
            # The fact that Browser.getWindowsBounds is not available
            # in headless mode is exploited here. Unfortunately, it
            # also shows a warning, which we suppress here.
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                self._tab.Browser.getWindowBounds(windowId=1)
        except pychrome.exceptions.CallMethodException:
            return True
        return False

    def _page_interaction(self):
        layout = self._tab.Page.getLayoutMetrics()
        height = layout['contentSize']['height']
        viewport_height = layout['visualViewport']['clientHeight']
        viewport_width = layout['visualViewport']['clientWidth']
        x = random.randint(0, viewport_width - 1)
        y = random.randint(0, viewport_height - 1)
        # Avoid scrolling too far, since some sites load the start page
        # when scrolling to the bottom (e.g. sueddeutsche.de)
        max_scrolldown = random.randint(int(height / 2.5), int(height / 1.5))
        last_page_y = 0
        while True:
            distance = random.randint(100, 300)
            self._tab.Input.dispatchMouseEvent(
                type='mouseWheel', x=x, y=y, deltaX=0, deltaY=distance)
            layout = self._tab.Page.getLayoutMetrics()
            page_y = layout['visualViewport']['pageY']
            # We scroll down until we have reached max_scrolldown, which was
            # obtained in the beginning. This prevents endless scrolling for
            # sites that dynamically load content (and therefore change their
            # height). In addition we check if the page indeed scrolled; this
            # prevents endless scrolling in case the content's height has
            # decreased.
            if page_y + viewport_height >= max_scrolldown or page_y <= last_page_y:
                break
            last_page_y = page_y
            self._tab.wait(random.uniform(0.050, 0.150))

    def _extract_information(self):
        for extractor in self._extractors:
            extractor.extract_information()

    def _receive_log(self, log_type, message, call_stack):
        for extractor in self._extractors:
            extractor.receive_log(log_type, message, call_stack)

    def _register_javascript(self):
        for extractor in self._extractors:
            extra_javascript = extractor.register_javascript()
            if extra_javascript:
                self._extra_scripts.append(extra_javascript)

    def _reset(self):
        self._page_loaded.clear()
        self._document_will_change = threading.Event()
        self._debugger_attached = threading.Event()
        self._debugger_paused = threading.Event()
        self._log_breakpoint = None
        self._page = None
        self._extractors = []
        self._extra_scripts = []


class Page:
    def __init__(self, tab=None):
        self.request_log = []
        self.document_request_log = []
        self.failed_request_log = []
        self.response_log = []
        self.security_state_log = []
        self.scan_start = None
        self.tab = tab
        self._response_lookup = defaultdict(list)
        self._frame_id = None

    def add_request(self, request):
        # We remember if there were requests that changed the displayed
        # document in the current tab (frameId)
        if self._frame_id is None:
            self._frame_id = request['extra']['frameId']
        document_changed = (request['extra']['type'] == 'Document' and
                            request['extra']['frameId'] == self._frame_id and
                            'redirectResponse' not in request['extra'])
        if document_changed:
            self.document_request_log.append(request)

        self.request_log.append(request)

    def add_failed_request(self, failed_request):
        self.failed_request_log.append(failed_request)

    def add_response(self, response):
        self.response_log.append(response)
        self._response_lookup[response['requestId']].append(response)

    def get_final_response_by_id(self, request_id, fail_silently=False):
        response = self.get_response_chain_by_id(request_id, fail_silently)
        return response[-1] if response is not None else None

    def get_response_chain_by_id(self, request_id, fail_silently=False):
        if request_id not in self._response_lookup:
            if fail_silently:
                return None
            raise KeyError('No response for request id {}.'.format(request_id))
        return self._response_lookup[request_id]

    @property
    def final_response(self):
        request_id = self.document_request_log[-1]['requestId']
        return self.get_final_response_by_id(request_id)


def find_chrome_executable():
    chrome_executable = shutil.which('google-chrome')
    if chrome_executable is None:
        macos_chrome = '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'
        if Path(macos_chrome).exists():
            chrome_executable = macos_chrome
    if chrome_executable is None:
        chrome_executable = shutil.which('chromium')
    if chrome_executable is None:
        chrome_executable = shutil.which('chromium-browser')
    if chrome_executable is None:
        raise ChromeBrowserStartupError('Could not find google-chrome or chromium.')
    return chrome_executable
