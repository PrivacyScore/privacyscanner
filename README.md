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

