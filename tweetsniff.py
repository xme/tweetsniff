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

# Default configuration 
config = {
	'statusFile': '/var/run/tweetsniff.status',
	'keywords': '',
	'regex': '',
	'highlightColor': 'red',
	'keywordColor': 'blue'
}

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

def updateTimeline(timeline_id):

	"""Get new Tweets from twitter.com"""

	try:
		timeline = api.GetHomeTimeline(since_id=timeline_id)
	except twitter.error.TwitterError as e:
		print "[Error] Twitter returned: %s (%d)" % (e[0][0]['message'], e[0][0]['code'])
		return timeline_id

	if not timeline:
		return timeline_id

	last_id = 0
	for t in reversed(timeline):
		text = t.text
		for r in config['regex']:
			if r:
				if re.search('('+r+')', text, re.I):
					text = text.replace(r, colored(r, config['highlightColor']))

		print "%s | %15s | %s" % (time2Local(t.created_at).strftime("%H:%M:%S"),
					t.user.screen_name,
					text)
		if es:
			indexEs(t)
		if (t.id > last_id):
			last_id = t.id
	return(last_id)

def updateSearch(search_id):

	"""Get new Tweets containing specific keywords"""

	for keyword in config['keywords']:
		if not keyword:
			continue
		print "DEBUG:  Keyword = %s" % keyword
		try:
			tweets = api.GetSearch(term=keyword, since_id=search_id)
		except twitter.error.TwitterError as e:
			print "[Error] Twitter returned: %s (%d)" % (e[0][0]['message'], e[0][0]['code'])
			return(search_id)

		if not tweets:
			return(search_id) 

		last_id = 0
		for t in reversed(tweets):
			text = t.text

			# Highlight keyword
			if re.search('('+keyword+')', text, re.I):
				text = text.replace(keyword, colored(keyword, config['keywordColor']))

			for r in config['regex']:
				if r:
					if re.search('('+r+')', text, re.I):
						text = text.replace(r, colored(r, config['highlightColor']))

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
		config['highlightColor'] = c.get('highlight', 'color')
		highlightRegex = c.get('highlight', 'regex')
		# Search
		searchKeywords = c.get('search', 'keywords')
		config['keywordColor'] = c.get('search', 'color')
		# Elasticsearch config (optional)
		esServer = c.get('elasticsearch', 'server')
		esIndex = c.get('elasticsearch', 'index')
	except OSError as e:
		writeLog('Cannot read config file %s: %s' % (args.configFile, e.errno()))
		exit

	print "DEBUG: %s, %s, %s, %s" % (consumerKey,consumerSecret,accessTokenKey,accessTokenSecret)
	print "DEBUG: Regex: %s" % highlightRegex

	if searchKeywords:
		config['keywords'] = searchKeywords.split('\n')
		print "DEBUG: keywords = %s" % config['keywords']

	if highlightRegex:
		config['regex'] = highlightRegex.split('\n')

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
		timeline_id = 0
		search_id = 0
		
	else:
		fd = open(config['statusFile'], 'r')
                data = fd.read().split(',')
		timeline_id = data[0]
		search_id = data[1]
                fd.close()
		print "DEBUG: Restarting feed from ID %s/%s" % (timeline_id, search_id)

	while 1:
		timeline_id = updateTimeline(timeline_id)
		search_id = updateSearch(search_id)
		fd = open(config['statusFile'], 'w')
		fd.write("%s,%s" % (str(timeline_id), str(search_id)))
		fd.close()
		sleep_home = api.GetAverageSleepTime('statuses/home_timeline')
		sleep_search = api.GetAverageSleepTime('search/tweets')
		print "DEBUG: Sleep = %s / %s" % (sleep_home, sleep_search)
		if sleep_search > sleep_home:
			time.sleep(sleep_search)
		else:
			time.sleep(sleep_home)

if __name__ == '__main__':
	main()
