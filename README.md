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

Todo
----
- Add more statistics
