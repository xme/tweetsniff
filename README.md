tweetsniff.py
=============
Grabs a user's Twitter feed and tweets with specific keywords via the Twitter API for local processing
(storing to ElasticSearch, regex highlighting, etc)

Installation
------------
The following Python modules are required:
- twitter
- elasticsearch
- termcolor
- dateutil
- hashlib
- urllib
- httplib

Install them with: pip install <module>

Valid Twitter API key & token are required, see https://apps.twitter.com/

Usage
-----
<pre>
usage: tweetsniff.py [-h] [-c CONFIG]

Display a Tweet feed

optional arguments:
  -h, --help            show this help message and exit
  -c CONFIG, --config CONFIG
                        configuration file (default: /etc/tweetsniff.conf)
</pre>

Expand URLs
----
- Enable in config with "process_urls: True"
- urllib2.url provides the same features but gets sometimes rejected by sites (403)
- URLs have to be part of the twitter URL object, otherwise they do not get recognized
- not yet in writeCEFEvent
- ES object contains URL, expanded URL, MD5 and SHA1 of the (expanded) URL

Todo
----
- Add more statistics