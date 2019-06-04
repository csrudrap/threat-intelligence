"""
Usage: python populate_db.py --gsb-url <gsb-url[:port-num]> --mongod-url <mongod-url>
"""

from mongoengine import *
import datetime
import feedparser
import threading
from bs4 import BeautifulSoup
import urllib2
from dateutil import parser, tz
import json
import time
import signal
import sys
import subprocess
import re
import argparse
import logging
import dns.resolver

sigint_exit = False
args = None
keys_d = None


class UrlRecordFeed(DynamicDocument):
    url = StringField()
    ip = StringField()
    origin = StringField()
    time_inserted = DateTimeField(default=datetime.datetime.utcnow) # When we insert into the DB.
    time_reported = DateTimeField(default=datetime.datetime.utcnow)
    gsb = StringField(default="OK")


class FeedProcessor:
    dns_nameservers = ["8.8.8.8", "9.9.9.9", "199.85.126.20", "208.67.222.222"]
    max_time_val = 7200
    min_time_val = 120
    avg_time_val = 1920
    def __init__(self, args, keys_d):
        self.args = args
        self.keys_d = keys_d

    def sigint_handler(self, signal, frame):
        print "\nSIGINT encountered, exiting threads."
        try:
            grep_op = subprocess.check_output("ps -ef | grep populate_db.py", shell=True)
            pid_to_kill = re.match(r"""[a-zA-Z\+]+\s+([0-9]+)""", grep_op).group(1)
            kill_cmd = "kill -KILL {}".format(pid_to_kill)
            subprocess.check_output(kill_cmd, shell=True)
        except subprocess.CalledProcessError as e:
            print e
            sys.exit(0)
        sigint_exit = True


    def get_gsb(self, url):
        if not url or url is '':
            logging.error("Null value for URL in get_gsb.")
            return "NULL"
        url_gsb_agent = 'http://{}/v4/threatMatches:find'.format(self.args[0].gsb_url)
        data = '{"threatInfo": {"threatEntries": [{"url": "' + url + '"}]}}'
        try:
            logging.info("URL for which GSB check is being done: {}".format(url))
            request = urllib2.Request(url_gsb_agent, data, {'Content-Type': 'application/json'})
            response = urllib2.urlopen(request).read()
            res_json = json.loads(response)
            if res_json.get('matches') is not None and len(res_json['matches']) > 0:
                if res_json['matches'][0].get('threatType') is not None:
                    return res_json['matches'][0]['threatType']
            logging.debug("No GSB match for URL {}. Sticking to the default value of \"OK\".".format(url))
        except Exception as e:
            try:
                logging.exception("GSB Exception with URL {}. Returning null".format(url))
                return "NULL"
            except UnicodeEncodeError, UnicodeDecodeError:
                logging.exception("GSB Exception for a URL that cannot be decoded into ASCII. Returning null")
                return "NULL"


    def convert_to_timestamp(self, verbose_date):
        # Hosts file input format: 2/7/2018 2:59:45 PM
        # URL Query input format: 2018-02-21 07:29:54 CET
        # Hack for CET Timezone. Reduce an hour and replace with UTC.

        try:
            dt = parser.parse(verbose_date, tzinfos={"UTC": tz.gettz("UTC")})
            if "CET" in verbose_date:
                dt -= datetime.timedelta(hours=1)
            return dt
        except ValueError, OverflowError:
            return None

    def extract_domain_from_url(self, url):
        m = re.match(r"""([a-z]+://)?([a-zA-Z0-9\-]+\.[a-z]+)(.*?)""", url)
        if m:
            try:
                domain = m.group(2)
                return domain
            except IndexError:
                logging.exception("Cannot extract group 2 from regex for URL {}.".format(url))
                return None
        else:
            logging.error("No domain match found for URL {}.".format(url))
            return None

    def dns_check(self, url):
        domain = self.extract_domain_from_url(url)
        try:
            dns_resolver = dns.resolver.Resolver()
            dns_resolver.nameservers.extend(self.dns_nameservers)
            dns_resolver.timeout = 2
            dns_resolver.lifetime = 2
            answers = dns_resolver.query(domain, 'A')
            if len(answers) > 0:
                if answers[0].address:
                    return True
                else:
                    logging.error("Attribute address not found for domain {}".format(domain))
                    return False
            else:
                logging.error("DNS response received for domain {} but no answers.".format(domain))
                return False
        except (dns.resolver.NXDOMAIN, dns.resolver.YXDOMAIN), e:
            logging.exception("Exception on DNS lookup for {}.".format(domain))
            return False
        except (TypeError, dns.resolver.NoNameservers), e:
            logging.exception("Exception on DNS lookup for {}.".format(domain))
            return False
        except (dns.exception.Timeout, dns.resolver.NoAnswer), e:
            logging.exception("Exception on DNS lookup for {}.".format(domain))
            return False

    # Feeds.
    # Generic format:
    # set initial timeval
    # provide feed URL
    # while True:
    #    fetch feed
    #    adjust timeval

    def phishtank_worker(self):
        # Fetch feeds every hour, as they are updated every hour by PhishTank.
        key = self.keys_d.get("PhishTank")
        try:
            assert key is not None
        except AssertionError:
            logging.exception("PhishTank API key is None")
            return
        while True:
            api_url = "https://data.phishtank.com/data/{}/online-valid.json.bz".format(key)
            try:
                response = urllib2.urlopen(api_url)
            except urllib2.HTTPError as e:
                logging.exception("HTTP Error fetching feeds from {}.".format(api_url))
            text = response.read()
            try:
                json_content = json.loads(text)
            except ValueError as e:
                logging.exception("JSON could not be loaded for PhishTank feeds.")
            try:
                assert json_content is not None and len(json_content) > 0
            except AssertionError:
                logging.exception("JSON content loaded is empty for PhishTank feeds.")
            for i in range(len(json_content)):
                url_val = json_content[i].get('url')
                details = json_content[i].get('details')
                ip_val = details[0].get('ip_address') if len(details) > 0 else None
                is_verified = json_content[i].get('verified')
                # Time format is correct, Mongoengine will convert to a Date.
                if is_verified == 'yes':
                    reported_time = json_content[i].get('verification_time')
                else:
                    reported_time = json_content[i].get('submission_time')
                announcing_network = json_content[i].get('announcing_network')
                objs = UrlRecordFeed.objects(url=url_val, ip=ip_val, time_reported=reported_time, origin="PhishTank")
                if objs == None or len(objs) < 1:
                    gsb_val = self.get_gsb(url_val)
                    urlr = UrlRecordFeed(url=url_val, ip=ip_val, time_reported=reported_time, gsb=gsb_val, origin="PhishTank")
                    urlr.classification = "PSH"
                    urlr.announcing_network = announcing_network
                    urlr.save()
            time.sleep(3600)

    def cybercrime_tracker_worker(self):
        # If num of objects inserted is lower than, say, 10, increase the time by 10. We are too fast.
        # If no objects were duplicate, make the time half. We are too slow.
        timeval = self.min_time_val   # Start off with 2 minutes.
        num_tries = 0
        feed_url = "http://cybercrime-tracker.net/rss.xml"
        while True:
            num_duplicate_objects = 0
            num_objects_inserted = 0
            feed = feedparser.parse(feed_url)
            if feed.get("entries") and len(feed["entries"]) > 0:
                # Reset num_tries to 0 because we can reach the feed.
                num_tries = 0
                for i in range(len(feed["entries"])):
                    published_parsed = feed["entries"][i].get("published_parsed")
                    date_val = datetime.datetime(*published_parsed[:6]) if published_parsed else None
                    url_val = feed["entries"][i].get("title")
                    class_val = ""
                    ip_val = ""
                    if feed["entries"][i].get("summary"):
                        s = feed["entries"][i]["summary"]
                        try:
                            class_val = s[s.index("Type:") + 5 : s.index("- IP")].strip()
                            ip_val = s[s.index("- IP") + 4:].strip()
                        except ValueError as e:
                            logging.exception("Substring not found from Cybercrime Tracker for i = {} and URL = {}".format(i, url_val))
                    objs = UrlRecordFeed.objects(url=url_val, ip=ip_val, time_reported=date_val, origin="CybercrimeTracker")
                    if objs == None or len(objs) < 1:
                        gsb_val = self.get_gsb(url_val)
                        urlr = UrlRecordFeed(url=url_val, ip=ip_val, time_reported=date_val, gsb=gsb_val, origin="CybercrimeTracker")
                        urlr.classification = class_val
                        urlr.save()
                        num_objects_inserted += 1
                    else:
                        # Duplicate object
                        num_duplicate_objects += 1
            else:
                logging.info("Feed from {} is None. Trying again.".format(feed_url))
                num_tries += 1
            if num_tries >= 10:
                logging.error("Feed from {} unreachable. Quitting after trying 10 consecutive times.".format(feed_url))
                return
            if num_objects_inserted <= 10 and timeval <= self.max_time_val:
                timeval *= 2
            elif num_duplicate_objects == 0 and timeval >= 2:
                timeval = self.min_time_val
            elif timeval > self.max_time_val:
                timeval = self.avg_time_val
            # else: Keep timeval as it is.
            logging.info("Cybercrime-Tracker timeval: " + str(timeval))
            time.sleep(timeval)


    def hosts_file_worker(self):
        # If num of objects inserted is lower than, say, 10, increase the time by 10. We are too fast.
        # If no objects were duplicate, start over. We are too slow.
        num_tries = 0
        timeval = self.min_time_val   # Start off with 2 minutes.
        feed_url = "https://hosts-file.net/rss.asp"
        while True:
            num_duplicate_objects = 0
            num_objects_inserted = 0
            feed = feedparser.parse(feed_url)
            if feed.get("entries") and len(feed["entries"]) > 0:
                # Reset num_tries to 0 because we can reach the feed.
                num_tries = 0
                for i in range(len(feed["entries"])):
                    if feed["entries"][i].get("summary_detail") and feed["entries"][i]["summary_detail"].get("value"):
                        entries = feed["entries"][i]["summary_detail"]["value"]
                        values = entries.split("<br />")
                        try:
                            assert len(values) >= 4
                        except AssertionError as e:
                            logging.exception("No well formed summary detail value for Entry, for {}.".format(feed["entries"][i]))
                            continue
                        url_val = values[0].split(':')[1].strip()
                        ip_val = values[1].split(':')[1].strip()
                        class_val = values[2].split(':')[1].strip()
                        verbose_time = ':'.join(values[3].split(':')[2:4])
                        verbose_date = values[3].split(':')[1].strip() + ':' + verbose_time.strip()
                        date_val = self.convert_to_timestamp(verbose_date) #1:4 because of hr:min:sec
                        objs = UrlRecordFeed.objects(url=url_val, ip=ip_val, time_reported=date_val, origin="HostsFile")
                        if objs == None or len(objs) < 1:
                            gsb_val = self.get_gsb(url_val)
                            urlr = UrlRecordFeed(url=url_val, ip=ip_val, time_reported=date_val, gsb=gsb_val, origin="HostsFile")
                            urlr.classification = class_val
                            urlr.save()
                            num_objects_inserted += 1
                        else:
                            num_duplicate_objects += 1
            else:
                logging.error("Feed from {} is None. Trying again.".format(feed_url))
                num_tries += 1
            if num_tries >= 10:
                logging.error("Feed from {} unreachable. Quitting after trying 10 consecutive times.".format(feed_url))
                return
            if num_objects_inserted <= 10 and timeval <= self.max_time_val:
                timeval *= 2
            elif num_duplicate_objects == 0 and timeval >= 2:
                timeval = self.min_time_val
            elif timeval > self.max_time_val:
                timeval = self.avg_time_val
            # else keep timeval as it is.
            logging.info("HostsFile timeval: " + str(timeval))
            time.sleep(timeval)

    def cymon_virustotal_worker(self):
        cymon_url = "https://app.cymon.io/feeds/AVvtXgiw2c0QRQctzx4e"
        timeval = self.min_time_val   # Start off with 2 minutes.
        while True:
            num_tries = 0
            while num_tries < 10:
                try:
                    num_tries += 1
                    content = urllib2.urlopen(cymon_url).read()
                    break
                except urllib2.HTTPError as e:
                    # Sleep for 4 minutes and try again.
                    logging.exception("HTTPError while trying to fetch {} (VirusTotal). Sleeping for 4 minutes before trying again.".format(cymon_url))
                    time.sleep(240)
            if num_tries >= 10 and content is None:
                # If we have exceeded 10 tries, give up, log and return.
                logging.error("Exceeded 10 tries in reading the HTML from {}. Exiting now.".format(url))
                return
            soup = BeautifulSoup(content, "html.parser")
            try:
                assert soup is not None
            except AssertionError as e:
                logging.exception("soup is None from content obtained from {} (VirusTotal)".format(cymon_url))
                return
            feeds_scripts = soup.find_all("script", {"charset" : "UTF-8"}, {"data-reactid": "22"})
            if len(feeds_scripts) == 0:
                logging.error("Could not parse scripts from {}.".format(cymon_url))
            feeds_firstscript = feeds_scripts[0]
            feed_text = feeds_firstscript.getText().encode('utf-8')
            feeds_json = json.loads(feed_text[14:-1])    # First 13 are 'window.__data='. Last is ';'
            # feeds_json has 'searchThreats'. Look for 'data' in that, which is a JSON array of feeds.
            if not feeds_json.get('searchThreats'):
                logging.error("Could not find searchThreats as a key in the JSON from {}.".format(cymon_url))
                return
            searchThreats = feeds_json.get('searchThreats')
            feeds_list = searchThreats.get('data')
            try:
                assert isinstance(feeds_list, list)
            except AssertionError as e:
                logging.exception("Feeds obtained is not a list of feeds from {} (VirusTotal).".format(cymon_url))
                return
            # If num of objects inserted is lower than, say, 10, increase the time by 10. We are too fast.
            # If no objects were duplicate, start over from the beginning. We are too slow.
            num_duplicate_objects = 0
            num_objects_inserted = 0
            for feed in feeds_list:
                # Iterate through and get info.
                try:
                    assert isinstance(feed, dict)
                except AssertionError as e:
                    logging.exception("Feed is not a dict from {}.".format(cymon_url))
                    return
                tags = feed.get('tags')
                if tags:
                    if isinstance(tags, str):
                        classification = tags.encode('utf-8')
                    elif isinstance(tags, list):
                        classification = ', '.join(feed.get('tags')).encode('utf-8')
                    else:
                        classification = "unknown"
                origin_val = "Cymon-VirusTotal"
                country_val = feed.get("location").get("country") if feed.get("location") else None
                if feed.get("ioc"):
                    domain_val = feed.get("ioc").get("domain")
                    ip_val = feed.get("ioc").get("ip")
                    url_val = feed.get("ioc").get("url")
                    time_reported_val = feed.get("timestamp")
                    objs = UrlRecordFeed.objects(time_reported=time_reported_val, ip=ip_val, url=url_val, origin="Cymon-VirusTotal")
                    if objs == None or len(objs) < 1:
                        gsb_val = self.get_gsb(url_val)
                        urlr = UrlRecordFeed(url=url_val, ip=ip_val, time_reported=time_reported_val, gsb=gsb_val, origin=origin_val)
                        urlr.classification = classification
                        urlr.domain = domain_val
                        urlr.save()
                        num_objects_inserted += 1
                    else:
                        # Duplicate object
                        num_duplicate_objects += 1
            if num_objects_inserted <= 10 and timeval <= self.max_time_val:
                timeval *= 2
            elif num_duplicate_objects == 0 and timeval >= 2:
                timeval = self.min_time_val
            elif timeval > self.max_time_val:
                timeval = self.avg_time_val
            # else: Keep timeval as it is.
            logging.info("Cymon-VirusTotal timeval: " + str(timeval))
            time.sleep(timeval)

    def cymon_openphish_worker(self):
        cymon_url = "https://app.cymon.io/feeds/AVsGgHRIVjrVcoBZyoiV"
        timeval = self.min_time_val   # Start off with 2 minutes.
        while True:
            num_tries = 0
            while num_tries < 10:
                try:
                    num_tries += 1
                    content = urllib2.urlopen(cymon_url).read()
                    break
                except urllib2.HTTPError as e:
                    # Sleep for 4 minutes and try again.
                    logging.exception("HTTPError while trying to fetch {} (OpenPhish). Sleeping for 4 minutes before trying again.".format(cymon_url))
                    time.sleep(240)
            if num_tries >= 10 and content is None:
                # If we have exceeded 10 tries, give up, log and return.
                logging.error("Exceeded 10 tries in reading the HTML from {}. Exiting now.".format(cymon_url))
                return
            soup = BeautifulSoup(content, "html.parser")
            try:
                assert soup is not None
            except AssertionError as e:
                logging.exception("soup is None from content obtained from {} (OpenPhish)".format(cymon_url))
                return
            feeds_scripts = soup.find_all("script", {"charset" : "UTF-8"}, {"data-reactid": "22"})
            if len(feeds_scripts) == 0:
                logging.error("Could not parse scripts from {} (OpenPhish).".format(cymon_url))
            feeds_firstscript = feeds_scripts[0]
            feed_text = feeds_firstscript.getText().encode('utf-8')
            feeds_json = json.loads(feed_text[14:-1])    # First 13 are 'window.__data='. Last is ';'
            # feeds_json has 'searchThreats'. Look for 'data' in that, which is a JSON array of feeds.
            if not feeds_json.get('searchThreats'):
                logging.error("Could not find searchThreats as a key in the JSON from {} (OpenPhish).".format(cymon_url))
                return
            searchThreats = feeds_json.get('searchThreats')
            feeds_list = searchThreats.get('data')
            try:
                assert isinstance(feeds_list, list)
            except AssertionError as e:
                logging.exception("Feeds obtained is not a list of feeds from {} (OpenPhish).".format(cymon_url))
                return
            # If num of objects inserted is lower than, say, 10, increase the time by 10. We are too fast.
            # If no objects were duplicate, start over from the beginning. We are too slow.
            num_duplicate_objects = 0
            num_objects_inserted = 0
            for feed in feeds_list:
                # Iterate through and get info.
                try:
                    assert isinstance(feed, dict)
                except AssertionError as e:
                    logging.exception("Feed is not a dict from {}.".format(cymon_url))
                    return
                tags = feed.get('tags')
                if tags:
                    if isinstance(tags, str):
                        classification = tags.encode('utf-8')
                    elif isinstance(tags, list):
                        classification = ', '.join(feed.get('tags')).encode('utf-8')
                    else:
                        classification = "unknown"
                origin_val = "Cymon-OpenPhish"
                country_val = feed.get("location").get("country") if feed.get("location") else None
                if feed.get("ioc"):
                    domain_val = feed.get("ioc").get("domain")
                    ip_val = feed.get("ioc").get("ip")
                    url_val = feed.get("ioc").get("hostname")
                    time_reported_val = feed.get("timestamp")
                    objs = UrlRecordFeed.objects(time_reported=time_reported_val, ip=ip_val, url=url_val, origin="Cymon-OpenPhish")
                    if objs == None or len(objs) < 1:
                        gsb_val = self.get_gsb(url_val)
                        urlr = UrlRecordFeed(url=url_val, ip=ip_val, time_reported=time_reported_val, gsb=gsb_val, origin=origin_val)
                        urlr.classification = classification
                        urlr.domain = domain_val
                        urlr.save()
                        num_objects_inserted += 1
                    else:
                        # Duplicate object
                        num_duplicate_objects += 1
            if num_objects_inserted <= 10 and timeval <= self.max_time_val:
                timeval *= 2
            elif num_duplicate_objects == 0 and timeval >= 2:
                timeval = self.min_time_val
            elif timeval > self.max_time_val:
                timeval = self.avg_time_val
            # else: Keep timeval as it is.
            logging.info("Cymon-OpenPhish timeval: " + str(timeval))
            time.sleep(timeval)

    def cymon_norton_worker(self):
        cymon_url = "https://app.cymon.io/feeds/AVsGbi0WVjrVcoBZyoiT"
        timeval = self.min_time_val   # Start off with 2 minutes.
        while True:
            num_tries = 0
            while num_tries < 10:
                try:
                    num_tries += 1
                    content = urllib2.urlopen(cymon_url).read()
                    break
                except urllib2.HTTPError as e:
                    # Sleep for 4 minutes and try again.
                    logging.exception("HTTPError while trying to fetch {} (Norton). Sleeping for 4 minutes before trying again.".format(cymon_url))
                    time.sleep(240)
            if num_tries >= 10 and content is None:
                # If we have exceeded 10 tries, give up, log and return.
                logging.error("Exceeded 10 tries in reading the HTML from {}. Exiting now.".format(cymon_url))
                return
            soup = BeautifulSoup(content, "html.parser")
            try:
                assert soup is not None
            except AssertionError as e:
                logging.exception("soup is None from content obtained from {}".format(cymon_url))
                return
            feeds_scripts = soup.find_all("script", {"charset" : "UTF-8"}, {"data-reactid": "22"})
            if len(feeds_scripts) == 0:
                logging.error("Could not parse scripts from {} (Norton).".format(cymon_url))
            feeds_firstscript = feeds_scripts[0]
            feed_text = feeds_firstscript.getText().encode('utf-8')
            feeds_json = json.loads(feed_text[14:-1])    # First 13 are 'window.__data='. Last is ';'
            # feeds_json has 'searchThreats'. Look for 'data' in that, which is a JSON array of feeds.
            if not feeds_json.get('searchThreats'):
                logging.error("Could not find searchThreats as a key in the JSON from {} (Norton).".format(cymon_url))
                return
            searchThreats = feeds_json.get('searchThreats')
            feeds_list = searchThreats.get('data')
            try:
                assert isinstance(feeds_list, list)
            except AssertionError as e:
                logging.exception("Feeds obtained is not a list of feeds from {}.".format(cymon_url))
                return
            # If num of objects inserted is lower than, say, 10, increase the time by 10. We are too fast.
            # If no objects were duplicate, start over from the beginning. We are too slow.
            num_duplicate_objects = 0
            num_objects_inserted = 0
            for feed in feeds_list:
                # Iterate through and get info.
                try:
                    assert isinstance(feed, dict)
                except AssertionError as e:
                    logging.exception("Feed is not a dict from {}.".format(cymon_url))
                    return
                tags = feed.get('tags')
                if tags:
                    if isinstance(tags, str):
                        classification = tags.encode('utf-8')
                    elif isinstance(tags, list):
                        classification = ', '.join(feed.get('tags')).encode('utf-8')
                    else:
                        classification = "unknown"
                origin_val = "Cymon-Norton"
                country_val = feed.get("location").get("country") if feed.get("location") else None
                if feed.get("ioc"):
                    domain_val = feed.get("ioc").get("domain")
                    ip_val = feed.get("ioc").get("ip")
                    url_val = feed.get("ioc").get("hostname")
                    time_reported_val = feed.get("timestamp")
                    objs = UrlRecordFeed.objects(time_reported=time_reported_val, ip=ip_val, url=url_val, origin="Cymon-Norton")
                    if objs == None or len(objs) < 1:
                        gsb_val = self.get_gsb(url_val)
                        urlr = UrlRecordFeed(url=url_val, ip=ip_val, time_reported=time_reported_val, gsb=gsb_val, origin=origin_val)
                        urlr.classification = classification
                        urlr.domain = domain_val
                        urlr.save()
                        num_objects_inserted += 1
                    else:
                        # Duplicate object
                        num_duplicate_objects += 1
            if num_objects_inserted <= 10 and timeval <= self.max_time_val:
                timeval *= 2
            elif num_duplicate_objects == 0 and timeval >= 2:
                timeval = self.min_time_val
            elif timeval > self.max_time_val:
                timeval = self.avg_time_val
            # else: Keep timeval as it is.
            logging.info("Cymon-Norton timeval: " + str(timeval))
            time.sleep(timeval)

    def urlquery_worker(self):
        url = "https://urlquery.net/"
        timeval = self.min_time_val   # Start off with 2 minutes.
        while True:
            num_tries = 0
            while num_tries < 10:
                try:
                    num_tries += 1
                    content = urllib2.urlopen(url).read()
                    break
                except urllib2.HTTPError as e:
                    # Sleep for 4 minutes and try again.
                    logging.exception("HTTPError while trying to fetch {}. Sleeping for 4 minutes before trying again.".format(url))
                    time.sleep(240)
            if num_tries >= 10:
                # If we have exceeded 10 tries, give up, log and return.
                logging.error("Exceeded 10 tries in reading the HTML from {}. Exiting now.".format(url))
                return
            soup = BeautifulSoup(content, "html.parser")
            try:
                assert soup is not None
            except AssertionError as e:
                logging.exception("soup is None from content obtained from {}".format(url))
                return
            table_feed = soup.find_all("table")
            table_rows = []

            # If num of objects inserted is lower than, say, 10, increase the time by 10. We are too fast.
            # If no objects were duplicate, make the time half. We are too slow.
            num_duplicate_objects = 0
            num_objects_inserted = 0
            for table in table_feed:
                if table.has_attr("class"):
                    table_rows = table.find_all("tr")[1:]
            for row in table_rows:
                url_val = ""
                ip_val = ""
                time_val = datetime.datetime.now()
                mal_type_val = ""
                cols = row.find_all("td")
                for col in cols:
                    if col.center is not None:
                        time_str = str(col.center).strip("center>").strip("<center>").strip("</")
                        time_val = self.convert_to_timestamp(time_str)
                    elif col.a is not None:
                        url_val = col.a["title"]
                    elif col.b is not None:
                        mal_type_val = str(col.b).strip("</b>").strip("<b>")
                    elif col.img is not None:
                        ip_val = str(col)[:-5].split(">")[-1]
                objs = UrlRecordFeed.objects(time_reported=time_val, ip=ip_val, url=url_val, origin="UrlQ")
                if objs == None or len(objs) < 1:
                    gsb_val = self.get_gsb(url_val)
                    urlr = UrlRecordFeed(time_reported=time_val, ip=ip_val, url=url_val, gsb=gsb_val, origin="UrlQ")
                    urlr.mal_type = mal_type_val
                    urlr.save()
                    num_objects_inserted += 1
                else:
                    # Duplicate object
                    num_duplicate_objects += 1
            if num_objects_inserted <= 10 and timeval <= self.max_time_val:
                timeval *= 2
            elif num_duplicate_objects == 0 and timeval >= 2:
                timeval = self.min_time_val
            elif timeval > self.max_time_val:
                timeval = self.avg_time_val
            # else: Keep timeval as it is.
            logging.info("UrlQ timeval: " + str(timeval))
            time.sleep(timeval)
            

def main():
    # Spawn threads, one for each feed.
    # gsb-host and mongod-host should be passed on command line
    parser = argparse.ArgumentParser()
    parser.add_argument('-g', '--gsb-url', help='GSB Agent URL', dest='gsb_url')
    parser.add_argument('-m','--mongod-url', help='Mongo DB Server URL', dest='mongod_url')
    args = parser.parse_known_args()

    # Fetch API keys from apikeys.conf
    with open('apikeys.conf') as f:
        keys_raw = f.read().split('\n')
        keys_d = dict()
        for i in keys_raw:
            if i is not None and i is not '':
                keys_d[i.split(':')[0]] = i.split(':')[1]

    feedProcessor = FeedProcessor(args, keys_d)
    signal.signal(signal.SIGINT, feedProcessor.sigint_handler)
    connect("threatint", host=args[0].mongod_url)
    logging.basicConfig(filename="url_record.log", level=logging.INFO)
    for i in sorted(dir(feedProcessor)):
        if i.endswith('_worker'):
            # Worker methods that fetch a feed and add to DB end with '_worker'. Start them all.
            new_thread = threading.Thread(target=getattr(feedProcessor, i))
            try:
                new_thread.start()
                logging.info("Started thread with target {}.".format(i))
            except RuntimeError:
                logging.exception("Could not start thread with target {}. Already started?".format(i))
    # Start a thread that queries the DB one by one and updates DNS query values.
    while sigint_exit == False: # Hack to keep main thread active to catch SIGINT to kill the entire process. 
        time.sleep(2)
    sys.exit(0)


if __name__ == "__main__":
    main()
