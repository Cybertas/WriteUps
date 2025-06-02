## Soccer

### Lab Details 

- Difficulty: Easy
- Type: Linux

#### Tasks
Q1: What version of nginx is running on Soccer?
- run nmap `nmap -sT -T4 -vv -A -p- -Pn -oA Soccer 10.10.11.194`
```
<snip>
80/tcp    open     http            syn-ack     nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Did not follow redirect to http://soccer.htb/
<snip>
```


#### Resources

#### Lesson Learned
