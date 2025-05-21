## Access 

### Lab Details 

- Difficulty: Easy
- Type: Windows

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
- to interact with mdb file, tool like Mdbtools can be installed. 
```
# list tables in mdb
mdb-tables backup.mdb

# list tables 1 table name per line
mdb-tables backup.mdb -1

# output data in a table in json format
mdb-json backup.md auth_user
- table auth_user looks interesting below is the data
```
{"id":25,"username":"admin","password":"admin","Status":1,"last_login":"08/23/18 21:11:47","RoleID":26}
{"id":27,"username":"engineer","password":"access4u@security","Status":1,"last_login":"08/23/18 21:13:36","RoleID":26}
{"id":28,"username":"backup_admin","password":"admin","Status":1,"last_login":"08/23/18 21:14:02","RoleID":26}
```

Q4: What is the password for Access Control.zip?
- Access Control.zip is located in Engineers directory in target ftp server 
- to obtain the password we will need to use `zip2john` then crack it with `john`
- however we can also try using the password found in the mdb file to access it
- password = `access4u@security`

Q5: What is the password for the security user?
- we get Access Control.pst file which is used to stored Microsoft Outlook data
- install `pst-utls` tool to interact with `.pst` file
- we can use `readpst` to convert `.pst` to kmail format then view it in kmail
```


#### Lesson Learned
 - Ways to interact with .mdb files 
 - Ways to interact with .pst files 
