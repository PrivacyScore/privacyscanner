Changelog
=========

0.7.6
-----

* Fix: run\_workers command will no longer run into an infinite loop.
* Fix: Google Analytics detection did not handle the case when aip is not
       set correctly.

0.7.5
-----

* Fix: POST data extraction failed under certain circumstances.

0.7.4
-----

* Fix: Also look into POST data for Google Analytics request to find aip=1

0.7.3
-----

* Fix: Check for \_\_utm.gif in Google Analytics check instead of utm.gif
* Fix: Do not consider gtm/js requests as tracking requests for Google
       Analytics, since they just load the GTM configuration. This fixes
       a bug where a site is mistakenly detected as not using the anonymize IP
       extension.
* Start counter for numeric locks at zero instead of one. This makes the
  remote debugging ports for Google Chrome used by the "scan" command
  consistent with those used the "run\_workers" command.

0.7.2
-----

* Fix: More robust serialization of arguments to the log Javascript function.
  This fixes fingeprinting detection with call stacks containing circular
  references in the function arguments.
* Fix: Set OpenSSL security level to 0. This will fix some exceptions that
  OpenSSL will raise for weak configurations of the server, e.g. small DH key.
* Fix max-age check for HSTS preloading

0.7.1
-----

* Fix includeSubDomains check for HSTS preloading.

0.7.0
-----

* Fix hanging browser when alerts are shown.
* Feature: Implement simple detection of canvas browser fingerprinting

0.6.1
-----

* Fix bug with HSTS Preload detection on HTTP only sites.

0.6.0
-----

* Fix duplicate entries in the redirect.
* Fix exception with DNS lookups for non-existing records if there are multiple
  nameservers to be asked.
* Feature: Implement HSTS preload checks

0.5.5
-----

* Fix: (Delayed) redirects via meta tags or JavaScript will produce correct
  results now instead of crashing with an exception when accessing the
  page content (calling Page.getResourceContent). Fixes GitHub issue #17.

0.5.4
-----

* Update ciphersuite list to include the ciphers that are supported by the
  OpenSSL binaries in testssl.sh. This should resolve exceptions when
  testssh.sh finds a ciphersuite that is not available in either the
  our integrated ciphersuite list or the system's OpenSSL library.

0.5.3
-----

* Fix: testsslsh will only scan if there is actually (START)TLS.
* Fix: mail scan module will add reachable=False key instead of throwing
  an exception when the mailserver is not reachable.
* Fix: TLS 1.3 will be detected correctly instead of throwing an exception.

0.5.2
-----

* Use more robust method to terminate Chrome.

0.5.1
-----

* Fix Python3.5 compatibility.
* Add support for older OpenSSL versions in Python.

0.5.0
-----

* Log files are written to dedicated `logs` directory.
* Allow to set options to all scan modules via `__all__` module name.
* Allow to configure `STORAGE_PATH`, where dependencies like GeoIP database
  and alike are stored. Defaults to `~/.local/share/privacyscanner`.
* Fix `print_master_config` command.
* The `privacyscanner scan` command can now run concurrently.
* Add `disable_javascript` option to chromedevtools scan module.
* The result key `tls` has been renamed to `https`.
* Rescan a HTTP site with HTTPS if it is available.
* Add information about the HTTP-\>HTTPS and vice versa redirects to the result.
* logger is now available as attribute on a scanning module.
* Add dns module which gathers DNS and GeoIP information for all redirecting
  sites up to the final URL and MX records for the site url itself.
* network scan module has been removed, functionality moved to chromedevtools
  and the dns scan module.
* Add mail scan module. Gathers some mail functionality and TLS information
  about the mailserver.
* Add testsslsh scan module which performs extensive TLS checks using testssl.sh
  from Dirk Wetter (https://testssl.sh). These are actually two scan modules:
  `testsslsh_https` for HTTPS and `testsslsh_mail` for STMP, sharing the same
  code basis.
* Avoid DOM changes during imprint search. This should resolve some exceptions
  that occured in that extractor.
* Show error message when dependencies are not installed instead of raising an
  exception that bubbles up to the user.
* Try to autodetect Google Chrome on MacOS.
* Users can provide the path to the Google Chrome executable using the
 `chrome_executable` scan module option on chromedevtools.
* Add Docker and Docker Compose files to serverleaks scan module.
* Also look for `chromium-browser` to find Chrome (Fedora).

0.4.0
-----

* Use classes for scan modules instead of python modules.
* Improve command line arguments (-c for config, -m for scan modules).
* Add redirect\_chain key to result (chromedevtools).
* Change data structure for requests and responses (chromedevtools).
* Make Debugger resumption more robust (chromedevtools).

0.3.2
-----

* Rebuild packages because 0.3.1 contained some uncomitted changes.

0.3.1
-----

* Bugfix: JavaScript got never resumed after being paused by the Debugger.

0.3.0
-----

* Fix --config argument
* Add RequestExtractor.save\_headers option to chromedevtools options.

  This will store all request and response headers for each individual request
  to the result JSON.

0.2.1
-----

* Fix Python 3.5 compatibility (ModuleNotFoundError is not available in 3.5)

0.2
---

* Initial public release
