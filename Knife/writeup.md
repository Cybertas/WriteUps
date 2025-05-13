## Knife
### Lab Details
 - Difficulty: Easy 
 - Type: Web, HTTP, PHP, Linux, Priv-Esc

#### Enum ####
Q1: How many ports on running on the target machine
 - Run Nmap 
  - nmap -target-ip -sT -p- -T4 <!---searches for all TCP ports -->
Q2: What is the PHP version
 - Run Ffuf for file discovery, try to find a file that might contain info for php version
 - curl -I http://10.10.10.242
    <!--example response
    HTTP/1.1 200 OK
    Date: Mon, 12 May 2025 11:01:34 GMT
    Server: Apache/2.4.41 (Ubuntu)
    X-Powered-By: PHP/8.1.0-dev
    Content-Type: text/html; charset=UTF-8 
     -->
Q3: What HTTP Header can you use to perform inject
 - According to the guide https://amsghimire.medium.com/php-8-1-0-dev-backdoor-cb224e7f5914
 - User-agentt is the header field that can be used to inject code
Q4: What user is the web server running as?
 - Use burpsuite for RCE
 - ![[Burp_RCE.png]]
Q5: Submit the flag located in the James user's home directory.
- Use burpsuite to inject a reverse shell
- Used https://www.revshells.com/ to generate a reverse shell
- Payload: nc mkfifo 
- ![[Burp_ReverseShell.png]]
Q6: Submit the flag located in root's home directory.
 - Run linPeas.sh 
 ```
 ╔══════════╣ Checking 'sudo -l', /etc/sudoers, and /etc/sudoers.d
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sudo-and-suid                                                                                                                                                
Matching Defaults entries for james on knife:                                                                                                                                                                                   
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User james may run the following commands on knife:
    (root) NOPASSWD: /usr/bin/knife

```
- User james is able to run program knife as root without password 
- https://gtfobins.github.io/gtfobins/knife/ - exploit the sudo privilege to gain root access. 
- Can be done using by executing a revershell or just use cat to display the flag.txt content.