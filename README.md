privacyscanner
==============

Installation
------------

privacyscanner needs a Python 3 runtime. Depending on your environment you
may also need the Python 3 header files in order to instal privacyscanner.
For instance, on Debian and Ubuntu Linux you should be able
to obtain all necessary files by executing:

    sudo apt-get install python3 python3-pip python3-dev

privacyscanner is distributed via PyPI and can be easily installed using pip:

    python3 -m venv venv
    source venv/bin/activate
    pip install wheel
    pip install privacyscanner

Before first use, you have to download the dependencies of privacyscanner.
These include the MaxMind GeoIP2 database and the Easylist adblock lists.
For convenience, most dependencies can be downloaded with:

    privacyscanner update_dependencies

Those dependencies will be stored in `~/.local/share/privacyscanner`. In
addition, google-chrome or chromium have to be installed and available in
your PATH. For Debian-based systems this can be done with:

    apt install chromium

Note: Due to changes in the licensing, GeoIP database of MaxMind cannot be
downloaded without license key anymore. You therefore have to register an
account at maxmind.com and enter your license key to your privacyscanner
configuration file at `~/.config/privacyscanner/config.py` as follows:

    SCAN_MODULE_OPTIONS = {
        'dns': {
            'geoip_license_key': 'YOUR-LICENSE-KEY'
        }
    }
    
For more information about the new licensing of the GeoIP database see:
https://blog.maxmind.com/2019/12/18/significant-changes-to-accessing-and-using-geolite2-databases/

Usage
-----

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
