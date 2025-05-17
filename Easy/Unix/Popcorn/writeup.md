## Popcorn 

### Lab Details 

- Difficulty: Easy
- Type: Linux

#### Tasks
Q1: How many TCP ports are listening on Popcorn?
 - `nmap -sT -T -vv -A -p- -oA Popcorn target_ip`
 - 2 ports (ssh and http)

Q2: What is the relative path on the webserver to a file sharing service?
 - web enum using ffuf 
 - `ffuf -u http://popcorn.htb/FUZZ -w /usr/share/wordlists/dirb/big.txt
```
[Status: 301, Size: 312, Words: 20, Lines: 10, Duration: 319ms]
    * FUZZ: torrent
```
 - answer: torrent

Q3: What HTTP request header is being used to filter uploaded content?
 - curl -i target_ip 
```
...
Pragma: no-cache
Vary: Accept-Encoding
Content-Length: 4613
Content-Type: text/html
...
```
- answer: Content-Type 

Q4: What user is the webserver running as?
 - enum http://popcorn.htb/torrent/
 - able to register a new user 
 - target site has upload funcationality
 - upload vulnerability exists https://vulners.com/exploitdb/EDB-ID:11746
 - need to first upload a .torrent file and exploit upload vulnerability for file icon
 - use ctorrent to generate a .torrent file, use any file as base 
```
torrent -t -u "http://tracker1.com/announce" -s newtorrent.torrent myfile
Create hash table: 1/1
Create metainfo file test.torrent successful.
```
 - after upload, exploit file icon upload, file icon has weak sanitization
 ![[burpsuite_fileicon_upload.png]]
 - get the shell by visiting the uploaded torrent file, right click on the "image not found" and inspect element
 ![[locate_shell.png]]
 - whoami to confirm user, user: www-data
 ![[web_shell.png]]

Q5: Submit the flag located in the george user's home directory.
 - `cat /home/user.txt`

Q6: What is the 2010 CVE ID for a privilege escalation vulnerability in Linux PAM having to do with the message of the day?
 - load linpeas.sh from remote and run 
 - potential CVE from linpeas output 
```
╔══════════╣ Executing Linux Exploit Suggester
╚ https://github.com/mzet-/linux-exploit-suggester
...
[+] [CVE-2010-0832] PAM MOTD

   Details: https://www.exploit-db.com/exploits/14339/
   Exposure: probable
   Tags: [ ubuntu=9.10|10.04 ]
   Download URL: https://www.exploit-db.com/download/14339
   Comments: SSH access to non privileged user is needed
...

```
Q7: Submit the flag located in the root user's home directory.
- download CVE-2010-0832 from https://github.com/infinite-horizon219/Unix-Privilege-Escalation-Exploits-Pack/blob/master/2010/CVE-2010-0832.sh
- load and run CVE-2010-0832 to gain root shell


#### Lesson Learned
