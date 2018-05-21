privacyscanner
==============

Usage
-----

See `privacyscanner --help`.

Development
-----------

Check out repository, change directory into repository root. Then install
with:

    pip install --editable .

An external requirement is [MaxMinds GeoLite2 Country Database](https://dev.maxmind.com/geoip/geoip2/geolite2/). Download it and place it in one of the follwing locations:

    ~/.local/share/GeoIP/GeoLite2-Country.mmdb
    /var/lib/GeoIP/GeoLite2-Country.mmdb
    /usr/local/var/GeoIP/GeoLite2-Country.mmdb
    /usr/local/share/GeoIP/GeoLite2-Country.mmdb
    /usr/share/GeoIP/GeoLite2-Country.mmdb

License
-------

All code, apart from the exceptions listed below, is dual licensed under the [MIT](https://opensource.org/licenses/MIT)
and [GPLv3+](https://opensource.org/licenses/GPL-3.0) license.

Exceptions:

* OpenWPM scanmodule (openwpm.py and openwpm_wrapper.py in privacyscore/scanmodules) is GPLv3 only.
