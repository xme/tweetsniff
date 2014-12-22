#!/usr/bin/env python
#
# Author: Xavier Mertens <xavier@rootshell.be>
# Copyright: GPLv3 (http://gplv3.fsf.org/)
# Feel free to use the code, but please share the changes you've made
# 
import argparse
import errno
import ConfigParser
import json
import os
import re
import signal
import sys
import syslog
import time
import twitter
from datetime import datetime
from dateutil import parser
from dateutil import tz
from elasticsearch import Elasticsearch
from termcolor import colored

api = None
regex = None

# Default configuration 
config = { 'statusFile': '/var/run/tweetsniff.status' }

def sigHandler(s, f):

	"""Cleanup once CTRL-C is received"""

	print "Killed."
	sys.exit(0)

def writeLog(msg):
        syslog.openlog(logoption=syslog.LOG_PID,facility=syslog.LOG_MAIL)
        syslog.syslog(msg)
        return

def time2Local(s):

	"""Convert a 'created_at' date (UTC) to local time"""

	if not s:
		utc = datetime.utcnow()
	else:
		utc = datetime.strptime(parser.parse(s).strftime('%Y-%m-%d %H:%M:%S'), '%Y-%m-%d %H:%M:%S')

	from_zone = tz.tzutc()
	to_zone = tz.tzlocal()
	utc = utc.replace(tzinfo=from_zone)
	return(utc.astimezone(to_zone))

def indexEs(tweet):

	"""Index a new Tweet in Elasticsearch"""

	doc = tweet.AsDict()
	# Delete 'retweeted_status' - to be fixed later
	if 'retweeted_status' in doc:
		del doc['retweeted_status']
	# Delete 'urls' - to be fixed later?
	if 'urls' in doc:
		del doc['urls']

	# To fix: support different timezones? (+00:00
	try:
		doc['@timestamp'] = parser.parse(doc['created_at']).strftime("%Y-%m-%dT%H:%M:%S+00:00")
		res = es.index(index=esIndex, doc_type='tweet', body=doc)
        except:
                print "[Warning] Can't connect to %s" % esServer

	return

def updateTimeline(first_id):

	"""Get new Tweets from twitter.com"""

	try:
		timeline = api.GetHomeTimeline(since_id=first_id)
	except twitter.error.TwitterError as e:
		print "[Error] Twitter returned: %s (%d)" % (e[0][0]['message'], e[0][0]['code'])
		return first_id

	if not timeline:
		return first_id

	last_id = 0
	for t in reversed(timeline):
		text = t.text
		for r in regex:
			if r:
				if re.search('('+r+')', text, re.I):
					text = text.replace(r, colored(r, highlightColor))

		print "%s | %15s | %s" % (time2Local(t.created_at).strftime("%H:%M:%S"),
					t.user.screen_name,
					text)
		if es:
			indexEs(t)
		if (t.id > last_id):
			last_id = t.id
	return(last_id)
	
def main():
	global api
	global config
	global es
	global regex
	global highlightColor
	global esIndex

	signal.signal(signal.SIGINT, sigHandler)

	parser = argparse.ArgumentParser(
		description='Display a Tweet feed')
	parser.add_argument('-c', '--config',
		dest = 'configFile',
		help = 'configuration file (default: /etc/tweetsniff.conf)',
		metavar = 'CONFIG')
	args = parser.parse_args()

	if not args.configFile:
		args.configFile = '/etc/tweetsniff.conf'

	try:
		c = ConfigParser.ConfigParser()
		c.read(args.configFile)
		# Twitter config
		consumerKey = c.get('twitterapi', 'consumer_key')
		consumerSecret = c.get('twitterapi', 'consumer_secret')
		accessTokenKey = c.get('twitterapi', 'access_token_key')
		accessTokenSecret = c.get('twitterapi', 'access_token_secret')
		config['statusFile'] = c.get('twitterapi', 'status_file')
		#Highligts
		highlightColor = c.get('highlight', 'color')
		highlightRegex = c.get('highlight', 'regex')
		# Elasticsearch config (optional)
		esServer = c.get('elasticsearch', 'server')
		esIndex = c.get('elasticsearch', 'index')
	except OSError as e:
		writeLog('Cannot read config file %s: %s' % (args.configFile, e.errno()))
		exit

	print "DEBUG: %s, %s, %s, %s" % (consumerKey,consumerSecret,accessTokenKey,accessTokenSecret)
	print "DEBUG: Regex: %s" % highlightRegex

	if highlightRegex:
		regex = highlightRegex.split('\n')

	try:
		api = twitter.Api(consumer_key = consumerKey,
			consumer_secret = consumerSecret,
			access_token_key = accessTokenKey,
			access_token_secret = accessTokenSecret)
	except:
		print "[Error] Can't connect to twitter.com" 
		sys.exit(1)

	if esServer:
		try:
			es = Elasticsearch(
				[esServer]
				)
		except:
			print "[Warning] Can't connect to %s" % esServer


	if not os.path.isfile(config['statusFile']):
		print "DEBUG: Status file not found, starting new feed"
		first_id = 0
	else:
		fd = open(config['statusFile'], 'r')
                first_id = fd.read()
                fd.close()
		print "DEBUG: Restarting feed from ID %s" % first_id

	while 1:
		first_id = updateTimeline(first_id)
		fd = open(config['statusFile'], 'w')
		fd.write(str(first_id))
		fd.close()
		time.sleep(65)

if __name__ == '__main__':
	main()
