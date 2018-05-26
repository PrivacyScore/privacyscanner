import json
import subprocess
import tempfile
import time
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

import pychrome
from requests.exceptions import ConnectionError

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
        'restore_on_startup': 4, # 4 = Use startup_urls
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
    
    __extra_scripts__
})();
""".lstrip()

# See comments in ON_NEW_DOCUMENT_JAVASCRIPT
ON_NEW_DOCUMENT_JAVASCRIPT_LINENO = 7


class AbstractChromeScan:
    def __init__(self, result, logger, options):
        self.result = result
        self.logger = logger
        self.options = options
        self.browser = None
        self.scan_start = None
        self.request_log = []
        self.failed_request_log = []
        self.response_log = []
        self.security_state_log = []
        self._page_loaded = False
        self._debugger_attached = False
        self._log_breakpoint = None
        self._extra_scripts = []

    def scan(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            user_data_dir = Path(temp_dir) / 'chrome-profile'
            user_data_dir.mkdir()
            default_dir = user_data_dir / 'Default'
            default_dir.mkdir()
            with (default_dir / 'Preferences').open('w') as f:
                json.dump(PREFS, f)
            self._run_chrome(user_data_dir)

    def _run_chrome(self, user_data_dir):

        debugging_port = 9222
        extra_opts = [
            '--remote-debugging-port={}'.format(debugging_port),
            '--user-data-dir={}'.format(user_data_dir)
            ]
        p = subprocess.Popen(['google-chrome'] + CHROME_OPTIONS + extra_opts,
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            self._browse(debugging_port)
        finally:
            p.terminate()
            try:
                p.wait(1)
            except subprocess.TimeoutExpired:
                p.kill()
                p.wait()

    def _browse(self, debugging_port):
        self.browser = pychrome.Browser(url='http://127.0.0.1:{}'.format(debugging_port))

        # Wait until Chrome is ready
        max_tries = 20
        while max_tries > 0:
            try:
                chrome_version = self.browser.version()
                break
            except ConnectionError:
                time.sleep(0.1)
            max_tries -= 1
        else:
            self.result['chrome_error'] = 'timeout'
            return

        self._initialize_scripts()

        self.tab = self.browser.new_tab()
        self.tab.start()

        self.tab.Emulation.setDeviceMetricsOverride(width=1920, height=1080,
                                                    screenWidth=1920, screenHeight=1080,
                                                    deviceScaleFactor=0, mobile=False)

        self.tab.Network.requestWillBeSent = self._cb_request_will_be_sent
        self.tab.Network.responseReceived = self._cb_response_received
        self.tab.Network.loadingFailed = self._cb_loading_failed
        self.tab.Network.enable()

        self.tab.Security.securityStateChanged = self._cb_security_state_changed
        self.tab.Security.enable()
        self.tab.Security.setIgnoreCertificateErrors(ignore=True)

        self.tab.Page.loadEventFired = self._cb_load_event_fired
        self.tab.Page.javascriptDialogOpening = self._cb_javascript_dialog_opening
        extra_scripts = '\n'.join('(function() { %s })();' % script
                                  for script in self._extra_scripts)
        source = ON_NEW_DOCUMENT_JAVASCRIPT.replace('__extra_scripts__', extra_scripts)
        self.tab.Page.addScriptToEvaluateOnNewDocument(source=source)
        self.tab.Page.enable()

        self.tab.Debugger.scriptParsed = self._cb_script_parsed
        self.tab.Debugger.scriptFailedToParse = self._cb_script_failed_to_parse
        self.tab.Debugger.paused = self._cb_paused
        self.tab.Debugger.enable()
        # Pause the JavaScript before we navigate to the page. This
        # gives us some time to setup the debugger before any JavaScript
        # runs.
        self.tab.Debugger.pause()

        self.scan_start = datetime.utcnow()
        self.tab.Page.navigate(url=self.result['site_url'], _timeout=30)

        # For some reason, we can not extract information reliably inside
        # a callback, therefore we wait until the load_event_fired
        # callback has been fired. In order to catch JavaScript actions
        # that occur after the load event, we wait another 5 seconds.
        # There is a network idle event which may could be used instead,
        # but that needs to be evaluated.
        max_wait = 30
        time_start = time.time()
        while not self._page_loaded and time.time() - time_start < max_wait:
            self.tab.wait(0.5)
        self.tab.wait(5)
        self._extract_information()
        self.tab.stop()

    def _cb_request_will_be_sent(self, request, requestId, **kwargs):
        # To avoid reparsing the URL in many places, we parse them all here
        request['parsed_url'] = urlparse(request['url'])
        request['requestId'] = requestId
        self.request_log.append(request)
        #print(kwargs['requestId'])
        #print(kwargs)

    def _cb_response_received(self, response, **kwargs):
        self.response_log.append(response)

    def _cb_script_parsed(self, **script):
        # The first script loaded is our script we set via the method
        # Page.addScriptToEvaluateOnNewDocument. We want to to attach
        # to the log function, which will be used to analyse the page.
        if not self._debugger_attached:
            self._log_breakpoint = self.tab.Debugger.setBreakpoint(location={
                'scriptId': script['scriptId'],
                'lineNumber': ON_NEW_DOCUMENT_JAVASCRIPT_LINENO
            })['breakpointId']
            self._debugger_attached = True
            self.tab.Debugger.resume()

    def _cb_script_failed_to_parse(self, **kwargs):
        pass

    def _cb_paused(self, **info):
        if self._log_breakpoint in info['hitBreakpoints']:
            call_frames = []
            expression = ("typeof(arguments) !== 'undefined' ? "
                          "JSON.stringify(Array.from(arguments)) : 'null';")
            for call_frame in info['callFrames']:
                args = json.loads(self.tab.Debugger.evaluateOnCallFrame(
                    callFrameId=call_frame['callFrameId'],
                    expression=expression)['result']['value'])
                call_frames.append({
                    'url': call_frame['url'],
                    'functionName': call_frame['functionName'],
                    'location': {
                        'lineNumber': call_frame['location']['lineNumber'],
                        'columnNumber': call_frame['location']['columnNumber']
                    },
                    'args': args
                })
            self.tab.Debugger.resume()
            self._receive_log(*call_frames[0]['args'], call_frames[1:])

    def _cb_load_event_fired(self, timestamp, **kwargs):
        self._page_loaded = True

    def _cb_javascript_dialog_opening(self, **kwargs):
        self.tab.Page.handleJavaScriptDialog(accept=True)

    def _cb_security_state_changed(self, **state):
        self.security_state_log.append(state)

    def _cb_loading_failed(self, **failed_request):
        self.failed_request_log.append(failed_request)

    def _extract_information(self):
        raise NotImplementedError('Please implement me')

    def _receive_log(self, log_type, message, call_stack):
        pass

    def _initialize_scripts(self):
        pass