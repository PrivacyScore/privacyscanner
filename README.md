privacyscanner
==============

Usage
-----

Before first use, you have to download the dependencies of privacyscanner.
These include the MaxMind GeoIP2 database and the Easylist adblock lists.
For convenience, most dependencies can be downloaded with:

    privacyscanner update_dependencies

Those dependencies will be stored in `~/.local/share/privacyscanner`. In
addition, google-chrome or chromium have to be installed and available in
your PATH.

Scanning a single website, e.g. http://example.com/, can be done by running:

    privacyscanner scan http://example.com/

It will output the scan result in Python object syntax and it will create a
directory for the website in your current working directory. This directory
contains the scan result as JSON file as well as associated files (e.g. the
screenshot of the site) and the corresponding log files of the scan.

For more details, see `privacyscanner --help` and dive into the source :-)

Development
-----------

Check out repository, change directory into repository root. Then install
with:

    pip install --editable .

Unfortunately, there is no development documentation currently. You have
to consult the source code.
